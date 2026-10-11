//! The running node: per-socket state, datagram dispatch, outgoing queries,
//! external-IP voting, bootstrap and maintenance.
//!
//! Lock order: `Inner::own` before any `SocketNode::state`; never two
//! `SocketNode::state` locks at once; `shared`, the budgets and the sampler
//! frontiers are taken alone.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dc4_core::DhtKey;

use futures::future::join_all;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::compact::{AddrPolicy, CompactNode, Family, OwnAddrs, canonical_addr, canonical_ip};
use crate::config::DhtConfig;
use crate::krpc::{
    self, Body, DecodeError, KrpcError, MAX_DATAGRAM_OUT, Message, Method, Query, Response, Want,
};
use crate::lookup;
use crate::net::{
    self, IpVoter, MAX_PENDING_PER_SOCKET, Pending, Reply, Transactions, normalize_addr,
};
use crate::node_id::{NodeId, bep42_random_id, is_bep42_valid};
use crate::peer_store::PeerStore;
use crate::ratelimit::{InboundLimiter, QuerySpacing, ResponderBudget, TokenBucket};
use crate::responder::{self, AnswerContext, wanted};
use crate::routing::{K, RoutingTable, TableConfig};
use crate::sampler::Sampler;
use crate::state::{self, IdentityState, MAX_SAVED_NODES, STATE_VERSION, SavedNode, StateFile};
use crate::stats::{Counters, DhtStatsSnapshot, DropReason, incr};
use crate::token::TokenSecrets;
use crate::util::{after, after_skip, lock, remaining_budget};
use crate::{Discovered, Error, Source};
use lru::LruCache;

/// Good routing-table nodes wanted per family: bootstrap continues below
/// it, and the crawl role is ready at or above it (design §13).
pub const MIN_GOOD_NODES: usize = 8;
/// Receive buffer size; a datagram that fills it is treated as oversized (design §3).
pub(crate) const RECV_BUFFER_LEN: usize = 2048;
/// Resolved bootstrap endpoints kept per socket.
pub(crate) const MAX_ROUTERS: usize = 32;
/// Bytes taken from the responder budget before a reply is built: one full
/// datagram (1 024 fits in u32). The unused part is returned after encoding.
const REPLY_RESERVATION: u32 = MAX_DATAGRAM_OUT as u32;
/// Time allowed for resolving one bootstrap host.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent bucket-refresh lookups per socket.
const MAX_CONCURRENT_REFRESH: usize = 2;
/// Nodes taken from one response for the sampler frontier.
const MAX_FRONTIER_NODES_PER_RESPONSE: usize = 32;
/// Consecutive receive errors after which the receive loop pauses.
const RECV_ERROR_BURST: u32 = 64;
/// Pause after a burst of receive errors.
const RECV_ERROR_PAUSE: Duration = Duration::from_millis(100);
/// Shortest sleep while waiting for the send budget.
const MIN_BUDGET_WAIT: Duration = Duration::from_millis(1);
/// Longest time `shutdown` waits for tasks before aborting them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
/// Closest responded nodes remembered per scraped key (win 2 start sets).
const SCRAPE_CACHE_WRITE_BACK: usize = 16;
/// Most nodes kept per cached key (fresh closest first, then survivors).
const SCRAPE_CACHE_NODES_PER_KEY: usize = 32;

/// Why a query produced no response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QueryError {
    /// The address is not allowed (not dialable, wrong family or ours).
    Filtered,
    /// The send budget or per-address spacing did not allow it in time.
    Throttled,
    /// Too many queries are outstanding on this socket.
    Busy,
    /// The caller's last check before sending said no.
    Gated,
    /// Encoding or sending failed.
    Send,
    Timeout,
    Remote(KrpcError),
    Malformed,
    Cancelled,
}

struct BootstrapSchedule {
    next_at: Instant,
    delay: Duration,
}

pub(crate) struct SocketState {
    pub(crate) id: NodeId,
    pub(crate) table: RoutingTable,
    pub(crate) txns: Transactions,
    pub(crate) voter: IpVoter,
    /// The voted (or saved) external IP of this family.
    pub(crate) external_ip: Option<IpAddr>,
    pub(crate) last_id_change: Option<Instant>,
    /// Resolved bootstrap endpoints; never added to the routing table.
    pub(crate) routers: HashSet<SocketAddr>,
}

/// One UDP socket with its own node ID and routing table (BEP 32, BEP 45).
pub(crate) struct SocketNode {
    pub(crate) family: Family,
    pub(crate) socket: UdpSocket,
    pub(crate) local_addr: SocketAddr,
    pub(crate) state: Mutex<SocketState>,
    /// Contacts from the state file, used as bootstrap seeds.
    saved_contacts: Vec<CompactNode>,
    bootstrap: Mutex<BootstrapSchedule>,
    bootstrap_running: AtomicBool,
    rebootstrap: AtomicBool,
    refreshes_running: AtomicUsize,
}

/// State shared by both sockets.
pub(crate) struct Shared {
    pub(crate) tokens: TokenSecrets,
    pub(crate) store: PeerStore,
    pub(crate) inbound: InboundLimiter,
    pub(crate) spacing: QuerySpacing,
}

pub(crate) struct Inner {
    pub(crate) cfg: DhtConfig,
    pub(crate) policy: AddrPolicy,
    pub(crate) sockets: Vec<Arc<SocketNode>>,
    pub(crate) shared: Mutex<Shared>,
    /// Our own addresses; replaced when an external IP is voted in.
    own: Mutex<Arc<OwnAddrs>>,
    /// The outgoing query budget.
    budget: Mutex<TokenBucket>,
    /// The dedicated BEP 33 scrape budget: scrapes never starve the crawl
    /// bucket and crawl bursts never starve scrapes. Per-address spacing
    /// stays shared (one query per second per host across both kinds).
    scrape_budget: Mutex<TokenBucket>,
    /// The dedicated fetch budget: fetch traversals never
    /// starve scrapes and scrape bursts never starve fetches. Spacing stays
    /// shared like above.
    fetch_budget: Mutex<TokenBucket>,
    /// Closest-node lists of recent scrapes, reused as the start set of
    /// repeat scrapes (bep33.md §2/§12 win 2). `None` disables the cache
    /// (`scrape_node_cache_keys == 0`).
    scrape_nodes: Option<Mutex<LruCache<DhtKey, Vec<CompactNode>>>>,
    /// The reply budget, separate from the query budget.
    responder_budget: Mutex<ResponderBudget>,
    pub(crate) counters: Counters,
    sink: mpsc::Sender<Discovered>,
    pub(crate) cancel: CancellationToken,
    /// Long-lived tasks (receive loops, maintenance, sampler workers).
    pub(crate) tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Short-lived jobs (pings, refreshes, bootstraps).
    jobs: Mutex<JoinSet<()>>,
    pub(crate) sampler: Option<Sampler>,
}

/// Whether `addr` may be used on a socket of `family`: same family,
/// canonical (no IPv4-mapped IPv6) and dialable.
fn usable(addr: &SocketAddr, family: Family, policy: AddrPolicy) -> bool {
    Family::of(addr) == family && canonical_addr(*addr) == *addr && policy.dialable(addr)
}

/// The saved external IP of `family`, if it is still acceptable.
fn saved_external_ip(
    saved: Option<&IdentityState>,
    family: Family,
    policy: AddrPolicy,
) -> Option<IpAddr> {
    saved
        .and_then(|s| s.external_ip)
        .map(canonical_ip)
        .filter(|ip| Family::of_ip(ip) == family && policy.dialable_ip(*ip))
}

/// A bound socket and its actual address.
type Bound = (Family, UdpSocket, SocketAddr);

/// Binds the configured sockets (design §7): `identities` ports per family,
/// `dht_port + i`. An IPv4 bind failure is an error. IPv6 is skipped with a
/// warning when `bind_v6` is unspecified and the host has no global IPv6
/// address; per-port IPv6 failures warn and skip that identity. Either is
/// an error only if no socket is left.
fn bind_sockets(cfg: &DhtConfig) -> Result<Vec<Bound>, Error> {
    let mut out = Vec::new();
    let n = cfg.identities.max(1) as usize;
    if let Some(addr) = cfg.bind_v4 {
        for i in 0..n {
            // Port 0 means any port: every identity binds its own ephemeral
            // port instead of deriving from 0.
            let port = if addr.port() == 0 {
                0
            } else {
                addr.port().wrapping_add(i as u16)
            };
            let addr = SocketAddr::new(addr.ip(), port);
            let socket = net::bind_udp(addr).map_err(|source| Error::Bind { addr, source })?;
            let local = socket
                .local_addr()
                .map_err(|source| Error::Bind { addr, source })?;
            out.push((Family::V4, socket, local));
        }
    }
    let Some(addr) = cfg.bind_v6 else {
        return Ok(out);
    };
    if addr.ip().is_unspecified() && !net::has_global_ipv6() {
        if out.is_empty() {
            return Err(Error::NoSocket);
        }
        tracing::warn!("the host has no global IPv6 address; the DHT runs on IPv4 only");
        return Ok(out);
    }
    for i in 0..n {
        let port = if addr.port() == 0 {
            0
        } else {
            addr.port().wrapping_add(i as u16)
        };
        let addr = SocketAddr::new(addr.ip(), port);
        match net::bind_udp(addr).and_then(|socket| socket.local_addr().map(|local| (socket, local))) {
            Ok((socket, local)) => out.push((Family::V6, socket, local)),
            Err(source) if out.is_empty() => return Err(Error::Bind { addr, source }),
            Err(e) => {
                tracing::warn!(error = %e, addr = %addr, "cannot bind an IPv6 DHT socket; that identity runs on IPv4 only")
            }
        }
    }
    Ok(out)
}

impl SocketNode {
    fn new(
        (family, socket, local_addr): Bound,
        saved: Option<&IdentityState>,
        cfg: &DhtConfig,
        policy: AddrPolicy,
        own: Arc<OwnAddrs>,
        now: Instant,
    ) -> Self {
        let external_ip = saved_external_ip(saved, family, policy);
        let mut id = saved.map_or_else(NodeId::random, |s| s.id);
        if let Some(ip) = external_ip
            && !is_bep42_valid(&id, ip)
        {
            id = match cfg.bep42_r {
                Some(r) => crate::node_id::bep42_id_for_r(ip, r),
                None => bep42_random_id(ip),
            };
        }
        let saved_contacts = saved
            .map(|s| {
                s.nodes
                    .iter()
                    .filter(|n| {
                        usable(&n.addr, family, policy)
                            && n.id != id
                            && !own.contains(&n.addr, policy)
                    })
                    .take(MAX_SAVED_NODES)
                    .map(|n| CompactNode {
                        id: n.id,
                        addr: n.addr,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let tuning = &cfg.tuning;
        let table = TableConfig {
            family,
            questionable_after: tuning.node_questionable_after,
            policy,
            own,
        };
        let state = SocketState {
            id,
            table: RoutingTable::new(id, now, table),
            txns: Transactions::new(MAX_PENDING_PER_SOCKET),
            voter: IpVoter::new(tuning.external_ip_votes, tuning.external_ip_vote_ttl),
            external_ip,
            last_id_change: None,
            routers: HashSet::new(),
        };
        Self {
            family,
            socket,
            local_addr,
            state: Mutex::new(state),
            saved_contacts,
            bootstrap: Mutex::new(BootstrapSchedule {
                next_at: now,
                delay: tuning.bootstrap_retry_base,
            }),
            bootstrap_running: AtomicBool::new(false),
            rebootstrap: AtomicBool::new(false),
            refreshes_running: AtomicUsize::new(0),
        }
    }
}

/// What a reply delivery needs beyond the body itself: where it came from,
/// what the sender saw us as, whether the sender is read-only (BEP 43) and
/// when it arrived. Grouped so the delivery functions stay under the
/// argument-count lint.
#[derive(Clone, Copy)]
struct ReplyMeta {
    reported_ip: Option<SocketAddr>,
    from: SocketAddr,
    sender_read_only: bool,
    now: Instant,
}

impl Inner {
    /// Binds the sockets and builds the node state (no tasks yet).
    pub(crate) async fn new(
        cfg: DhtConfig,
        sink: mpsc::Sender<Discovered>,
    ) -> Result<Inner, Error> {
        cfg.validate()?;
        let policy = AddrPolicy {
            allow_private: cfg.allow_private_addrs,
            by_endpoint: cfg.tuning.limits_by_endpoint,
        };
        let saved = match cfg.state_file.clone() {
            Some(path) => tokio::task::spawn_blocking(move || state::load(&path))
                .await
                .ok()
                .flatten(),
            None => None,
        };
        let bound = bind_sockets(&cfg)?;
        let now = Instant::now();
        // Identity index within the family: bind order is stable across
        // restarts, so entry i backs socket i.
        let mut next_index = std::collections::HashMap::new();
        let mut own = OwnAddrs::default();
        for (family, _, local) in &bound {
            let index = next_index.entry(*family).or_insert(0);
            let saved = saved
                .as_ref()
                .and_then(|s| s.identities(*family).get(*index));
            own.add(*local);
            if let Some(ip) = saved_external_ip(saved, *family, policy) {
                own.add(SocketAddr::new(ip, local.port()));
            }
            *index += 1;
        }
        let own = Arc::new(own);
        let mut next_index = std::collections::HashMap::new();
        let sockets = bound
            .into_iter()
            .map(|b| {
                let index = next_index.entry(b.0).or_insert(0);
                let saved = saved
                    .as_ref()
                    .and_then(|s| s.identities(b.0).get(*index));
                *index += 1;
                Arc::new(SocketNode::new(
                    b,
                    saved,
                    &cfg,
                    policy,
                    Arc::clone(&own),
                    now,
                ))
            })
            .collect();
        let tuning = &cfg.tuning;
        let shared = Shared {
            tokens: TokenSecrets::new(now, tuning.token_rotation),
            store: PeerStore::new(tuning.peer_ttl).with_policy(policy),
            inbound: InboundLimiter::new(tuning.inbound_rate, tuning.inbound_burst, policy),
            spacing: QuerySpacing::new(tuning.per_address_query_spacing, policy),
        };
        let budget = TokenBucket::new(cfg.max_packets_per_sec, cfg.max_packets_per_sec, now);
        let scrape_budget =
            TokenBucket::new(cfg.scrape_packets_per_sec, cfg.scrape_packets_per_sec, now);
        let fetch_budget =
            TokenBucket::new(cfg.fetch_packets_per_sec, cfg.fetch_packets_per_sec, now);
        let responder_budget = ResponderBudget::new(
            tuning.responder_replies_per_sec,
            tuning.responder_bytes_per_sec,
            now,
        );
        let sampler = cfg.sampler.then(|| Sampler::new(now));
        let scrape_nodes = NonZeroUsize::new(cfg.tuning.scrape_node_cache_keys)
            .map(|cap| Mutex::new(LruCache::new(cap)));
        Ok(Inner {
            policy,
            sockets,
            shared: Mutex::new(shared),
            own: Mutex::new(own),
            budget: Mutex::new(budget),
            scrape_budget: Mutex::new(scrape_budget),
            fetch_budget: Mutex::new(fetch_budget),
            scrape_nodes,
            responder_budget: Mutex::new(responder_budget),
            counters: Counters::default(),
            sink,
            cancel: CancellationToken::new(),
            tasks: Mutex::new(Vec::new()),
            jobs: Mutex::new(JoinSet::new()),
            sampler,
            cfg,
        })
    }

    /// Starts the receive loops, the maintenance task and the sampler workers.
    pub(crate) fn spawn_tasks(self: &Arc<Self>) {
        let mut handles = Vec::new();
        for sock in &self.sockets {
            handles.push(tokio::spawn(recv_loop(Arc::clone(self), Arc::clone(sock))));
        }
        handles.push(tokio::spawn(maintenance(Arc::clone(self))));
        if self.sampler.is_some() {
            for worker in 0..self.cfg.sampler_concurrency {
                handles.push(tokio::spawn(crate::sampler::worker(
                    Arc::clone(self),
                    worker,
                )));
            }
        }
        lock(&self.tasks).extend(handles);
    }

    pub(crate) fn socket(&self, family: Family) -> Option<&Arc<SocketNode>> {
        self.sockets.iter().find(|s| s.family == family)
    }

    /// Records a sighting of life for sampler live-probing.
    /// Pre-filtered by the address chokepoint; the query path re-checks
    /// anyway. Silent when the sampler is off.
    pub(crate) fn offer_live(&self, addr: SocketAddr) {
        if !self.policy.dialable(&addr) {
            return;
        }
        if let Some(sampler) = self.sampler.as_ref() {
            sampler.offer_live(addr);
        }
    }

    /// Cached closest nodes for `key`, as the start set of a repeat scrape
    /// (bep33.md §2/§12 win 2). Empty when the cache is disabled or cold; a
    /// cache hit is a start set only, never proof of no-route (§4 death
    /// rule: death still needs both families attempted in this round).
    pub(crate) fn scrape_cache_seeds(&self, key: &DhtKey) -> Vec<CompactNode> {
        let Some(cache) = self.scrape_nodes.as_ref() else {
            return Vec::new();
        };
        lock(cache).get(key).cloned().unwrap_or_default()
    }

    /// Remembers the closest responded nodes of a finished scrape as the
    /// start set of the next one. Fresh closest first, then surviving
    /// older entries (deduped by address), capped per key.
    pub(crate) fn scrape_cache_store(
        &self,
        key: DhtKey,
        closest: &[(CompactNode, Option<Vec<u8>>)],
    ) {
        let Some(cache) = self.scrape_nodes.as_ref() else {
            return;
        };
        let mut fresh: Vec<CompactNode> = closest
            .iter()
            .take(SCRAPE_CACHE_WRITE_BACK)
            .map(|(n, _)| *n)
            .collect();
        let mut cache = lock(cache);
        if let Some(old) = cache.get(&key).cloned() {
            for n in old {
                if fresh.len() >= SCRAPE_CACHE_NODES_PER_KEY {
                    break;
                }
                if !fresh.iter().any(|f| f.addr == n.addr) {
                    fresh.push(n);
                }
            }
        }
        cache.put(key, fresh);
    }

    /// Sleeps for `d`; false if the node was shut down meanwhile.
    pub(crate) async fn sleep(&self, d: Duration) -> bool {
        tokio::select! {
            () = tokio::time::sleep(d) => true,
            () = self.cancel.cancelled() => false,
        }
    }

    /// Delivers a discovery without ever blocking.
    pub(crate) fn emit(&self, event: Discovered) {
        match self.sink.try_send(event) {
            Ok(()) => incr(&self.counters.discovered_emitted),
            Err(_) => incr(&self.counters.discovered_dropped),
        }
    }

    /// Our own addresses (bound and voted).
    pub(crate) fn own(&self) -> Arc<OwnAddrs> {
        Arc::clone(&lock(&self.own))
    }

    pub(crate) fn own_ids(&self) -> Vec<NodeId> {
        self.sockets.iter().map(|s| lock(&s.state).id).collect()
    }

    /// Rebuilds our own addresses after an external-IP change and hands them
    /// to the routing tables.
    fn refresh_own(&self, now: Instant) {
        let mut current = lock(&self.own);
        let mut own = OwnAddrs::default();
        for sock in &self.sockets {
            let external = lock(&sock.state).external_ip;
            own.add(sock.local_addr);
            if let Some(ip) = external {
                own.add(SocketAddr::new(ip, sock.local_addr.port()));
            }
        }
        let own = Arc::new(own);
        for sock in &self.sockets {
            lock(&sock.state).table.set_own(Arc::clone(&own), now);
        }
        *current = own;
    }

    /// Whether a query may go to `addr` on a socket of `family`.
    fn may_contact(&self, family: Family, addr: &SocketAddr) -> bool {
        usable(addr, family, self.policy) && !self.own().contains(addr, self.policy)
    }

    fn want_for(&self, method: &Method) -> Option<Want> {
        let both = self.sockets.len() > 1;
        match method {
            Method::FindNode { .. }
            | Method::GetPeers { .. }
            | Method::SampleInfohashes { .. }
            | Method::Other { .. } => both.then_some(Want { n4: true, n6: true }),
            Method::Ping | Method::AnnouncePeer { .. } => None,
        }
    }

    async fn acquire_budget(&self, max_wait: Duration) -> bool {
        let give_up = after(Instant::now(), max_wait);
        loop {
            let now = Instant::now();
            let wait = {
                let mut budget = lock(&self.budget);
                if budget.try_acquire(now) {
                    return true;
                }
                budget.wait_time(now)
            };
            let wake = after_skip(now, wait.max(MIN_BUDGET_WAIT));
            if wake > give_up {
                return false;
            }
            tokio::select! {
                () = tokio::time::sleep_until(wake) => {}
                () = self.cancel.cancelled() => return false,
            }
        }
    }

    async fn acquire_scrape_budget(&self, max_wait: Duration) -> bool {
        let give_up = after(Instant::now(), max_wait);
        loop {
            let now = Instant::now();
            let wait = {
                let mut budget = lock(&self.scrape_budget);
                if budget.try_acquire(now) {
                    return true;
                }
                budget.wait_time(now)
            };
            let wake = after_skip(now, wait.max(MIN_BUDGET_WAIT));
            if wake > give_up {
                return false;
            }
            tokio::select! {
                () = tokio::time::sleep_until(wake) => {}
                () = self.cancel.cancelled() => return false,
            }
        }
    }

    async fn acquire_fetch_budget(&self, max_wait: Duration) -> bool {
        let give_up = after(Instant::now(), max_wait);
        loop {
            let now = Instant::now();
            let wait = {
                let mut budget = lock(&self.fetch_budget);
                if budget.try_acquire(now) {
                    return true;
                }
                budget.wait_time(now)
            };
            let wake = after_skip(now, wait.max(MIN_BUDGET_WAIT));
            if wake > give_up {
                return false;
            }
            tokio::select! {
                () = tokio::time::sleep_until(wake) => {}
                () = self.cancel.cancelled() => return false,
            }
        }
    }

    /// Sends one query and waits for its reply. Timeouts count as failures
    /// in the routing table; replies are processed by the receive loop.
    pub(crate) async fn query(
        &self,
        sock: &SocketNode,
        addr: SocketAddr,
        method: Method,
        expect: Option<NodeId>,
    ) -> Result<Response, QueryError> {
        self.query_gated(sock, addr, method, expect, &|_| true)
            .await
    }

    /// [`query`](Self::query) with a last check: `gate` is called right
    /// before the datagram is sent, and nothing is sent if it says no.
    pub(crate) async fn query_gated<G>(
        &self,
        sock: &SocketNode,
        addr: SocketAddr,
        method: Method,
        expect: Option<NodeId>,
        gate: &G,
    ) -> Result<Response, QueryError>
    where
        G: Fn(Instant) -> bool + Sync,
    {
        let timeout = self.cfg.tuning.query_timeout;
        self.query_gated_with_timeout(sock, addr, method, expect, gate, timeout)
            .await
    }

    /// [`query_gated`](Self::query_gated) with an explicit transaction
    /// deadline instead of `tuning.query_timeout`.
    pub(crate) async fn query_gated_with_timeout<G>(
        &self,
        sock: &SocketNode,
        addr: SocketAddr,
        method: Method,
        expect: Option<NodeId>,
        gate: &G,
        timeout: Duration,
    ) -> Result<Response, QueryError>
    where
        G: Fn(Instant) -> bool + Sync,
    {
        let addr = normalize_addr(addr);
        let tuning = &self.cfg.tuning;
        let counters = self.counters.family(sock.family);
        if !self.may_contact(sock.family, &addr) {
            return Err(QueryError::Filtered);
        }
        if self.cancel.is_cancelled() {
            return Err(QueryError::Cancelled);
        }
        let spacing =
            lock(&self.shared)
                .spacing
                .reserve(&addr, Instant::now(), tuning.max_send_wait);
        let Some(wait) = spacing else {
            counters.drop_packet(DropReason::ThrottledSpacing);
            return Err(QueryError::Throttled);
        };
        let waited_from = Instant::now();
        if !wait.is_zero() && !self.sleep(wait).await {
            lock(&self.shared).spacing.release(&addr, Instant::now());
            return Err(QueryError::Cancelled);
        }
        // Spacing and the send budget share one `max_send_wait`: the budget
        // wait only gets the remainder instead of a second full bound.
        let remaining = remaining_budget(tuning.max_send_wait, waited_from.elapsed());
        if !self.acquire_budget(remaining).await {
            lock(&self.shared).spacing.release(&addr, Instant::now());
            if self.cancel.is_cancelled() {
                return Err(QueryError::Cancelled);
            }
            counters.drop_packet(DropReason::ThrottledBudgetMain);
            return Err(QueryError::Throttled);
        }
        let now = Instant::now();
        if !gate(now) {
            lock(&self.budget).refund(1);
            lock(&self.shared).spacing.release(&addr, Instant::now());
            return Err(QueryError::Gated);
        }

        let (tx, rx) = oneshot::channel();
        let deadline = after(now, timeout);
        let want = self.want_for(&method);
        let (id, tid) = {
            let mut st = lock(&sock.state);
            let id = st.id;
            let Some(tid) = st.txns.insert(
                addr,
                Pending {
                    tx,
                    deadline,
                    expect,
                },
                now,
            ) else {
                drop(st);
                lock(&self.budget).refund(1);
                lock(&self.shared).spacing.release(&addr, Instant::now());
                counters.drop_packet(DropReason::ThrottledTxnFull);
                return Err(QueryError::Busy);
            };
            // Drop the lock before encoding: bencode + trim never touch
            // shared state, and holding `state` across it couples every
            // query's tail latency to the slowest encoder (B-004).
            (id, tid)
        };
        let msg = Message {
            tid: tid.to_vec(),
            version: Some(self.cfg.client_version.to_vec()),
            ip: None,
            read_only: self.cfg.read_only,
            body: Body::Query(Query {
                id,
                want,
                method: method.clone(),
            }),
        };
        let packet = match krpc::encode(&msg) {
            Ok(packet) => packet,
            Err(_) => {
                lock(&sock.state).txns.remove(tid, &addr);
                lock(&self.budget).refund(1);
                lock(&self.shared).spacing.release(&addr, Instant::now());
                counters.drop_packet(DropReason::SendError);
                return Err(QueryError::Send);
            }
        };
        if sock.socket.send_to(&packet, addr).await.is_err() {
            lock(&sock.state).txns.remove(tid, &addr);
            lock(&self.budget).refund(1);
            lock(&self.shared).spacing.release(&addr, Instant::now());
            counters.drop_packet(DropReason::SendError);
            return Err(QueryError::Send);
        }
        incr(&counters.packets_out);
        self.counters.queries_sent.count(&method);

        let reply = tokio::select! {
            r = tokio::time::timeout_at(deadline, rx) => r,
            () = self.cancel.cancelled() => {
                lock(&sock.state).txns.remove(tid, &addr);
                return Err(QueryError::Cancelled);
            }
        };
        match reply {
            Ok(Ok(Reply::Response(r))) => Ok(r),
            Ok(Ok(Reply::Error(e))) => Err(QueryError::Remote(e)),
            Ok(Ok(Reply::Malformed)) => Err(QueryError::Malformed),
            Ok(Err(_)) | Err(_) => {
                {
                    let mut st = lock(&sock.state);
                    st.txns.remove(tid, &addr);
                    st.table.on_failure(&addr, Instant::now());
                }
                incr(&self.counters.timeouts);
                Err(QueryError::Timeout)
            }
        }
    }

    /// [`query`](Self::query) for BEP 33 scrapes: same per-address spacing
    /// (scrape + crawl queries to one host never double up past 1/s) but a
    /// dedicated token bucket, and the more lenient per-RPC scrape timeout.
    /// Lock order stays `spacing → budget`, as in [`query_gated`](Self::query_gated).
    pub(crate) async fn query_scrape(
        &self,
        sock: &SocketNode,
        addr: SocketAddr,
        method: Method,
        expect: Option<NodeId>,
    ) -> Result<Response, QueryError> {
        let addr = normalize_addr(addr);
        let tuning = &self.cfg.tuning;
        let counters = self.counters.family(sock.family);
        if !self.may_contact(sock.family, &addr) {
            return Err(QueryError::Filtered);
        }
        if self.cancel.is_cancelled() {
            return Err(QueryError::Cancelled);
        }
        let spacing =
            lock(&self.shared)
                .spacing
                .reserve(&addr, Instant::now(), tuning.max_send_wait);
        let Some(wait) = spacing else {
            counters.drop_packet(DropReason::ThrottledSpacing);
            return Err(QueryError::Throttled);
        };
        let waited_from = Instant::now();
        if !wait.is_zero() && !self.sleep(wait).await {
            lock(&self.shared).spacing.release(&addr, Instant::now());
            return Err(QueryError::Cancelled);
        }
        // Spacing and the send budget share one `max_send_wait`: the budget
        // wait only gets the remainder instead of a second full bound.
        let remaining = remaining_budget(tuning.max_send_wait, waited_from.elapsed());
        if !self.acquire_scrape_budget(remaining).await {
            lock(&self.shared).spacing.release(&addr, Instant::now());
            if self.cancel.is_cancelled() {
                return Err(QueryError::Cancelled);
            }
            counters.drop_packet(DropReason::ThrottledBudgetScrape);
            return Err(QueryError::Throttled);
        }
        let now = Instant::now();
        let (tx, rx) = oneshot::channel();
        let deadline = after(now, tuning.scrape_query_timeout);
        let want = self.want_for(&method);
        let (id, tid) = {
            let mut st = lock(&sock.state);
            let id = st.id;
            let Some(tid) = st.txns.insert(
                addr,
                Pending {
                    tx,
                    deadline,
                    expect,
                },
                now,
            ) else {
                drop(st);
                lock(&self.scrape_budget).refund(1);
                lock(&self.shared).spacing.release(&addr, Instant::now());
                counters.drop_packet(DropReason::ThrottledTxnFull);
                return Err(QueryError::Busy);
            };
            (id, tid)
        };
        let msg = Message {
            tid: tid.to_vec(),
            version: Some(self.cfg.client_version.to_vec()),
            ip: None,
            read_only: self.cfg.read_only,
            body: Body::Query(Query {
                id,
                want,
                method: method.clone(),
            }),
        };
        let packet = match krpc::encode(&msg) {
            Ok(packet) => packet,
            Err(_) => {
                lock(&sock.state).txns.remove(tid, &addr);
                lock(&self.scrape_budget).refund(1);
                lock(&self.shared).spacing.release(&addr, Instant::now());
                counters.drop_packet(DropReason::SendError);
                return Err(QueryError::Send);
            }
        };
        if sock.socket.send_to(&packet, addr).await.is_err() {
            lock(&sock.state).txns.remove(tid, &addr);
            lock(&self.scrape_budget).refund(1);
            lock(&self.shared).spacing.release(&addr, Instant::now());
            counters.drop_packet(DropReason::SendError);
            return Err(QueryError::Send);
        }
        incr(&counters.packets_out);
        self.counters.queries_sent.count(&method);

        let reply = tokio::select! {
            r = tokio::time::timeout_at(deadline, rx) => r,
            () = self.cancel.cancelled() => {
                lock(&sock.state).txns.remove(tid, &addr);
                return Err(QueryError::Cancelled);
            }
        };
        match reply {
            Ok(Ok(Reply::Response(r))) => Ok(r),
            Ok(Ok(Reply::Error(e))) => Err(QueryError::Remote(e)),
            Ok(Ok(Reply::Malformed)) => Err(QueryError::Malformed),
            Ok(Err(_)) | Err(_) => {
                {
                    let mut st = lock(&sock.state);
                    st.txns.remove(tid, &addr);
                    st.table.on_failure(&addr, Instant::now());
                }
                incr(&self.counters.timeouts);
                Err(QueryError::Timeout)
            }
        }
    }

    /// [`query`](Self::query) for fetch traversals: identical
    /// to [`query_scrape`](Self::query_scrape) — same per-address spacing,
    /// same lenient scrape per-RPC timeout — but charging the dedicated
    /// fetch bucket instead of the scrape bucket.
    /// Lock order stays `spacing → budget`, as in [`query_gated`](Self::query_gated).
    pub(crate) async fn query_fetch(
        &self,
        sock: &SocketNode,
        addr: SocketAddr,
        method: Method,
        expect: Option<NodeId>,
    ) -> Result<Response, QueryError> {
        let addr = normalize_addr(addr);
        let tuning = &self.cfg.tuning;
        let counters = self.counters.family(sock.family);
        if !self.may_contact(sock.family, &addr) {
            return Err(QueryError::Filtered);
        }
        if self.cancel.is_cancelled() {
            return Err(QueryError::Cancelled);
        }
        let spacing =
            lock(&self.shared)
                .spacing
                .reserve(&addr, Instant::now(), tuning.max_send_wait);
        let Some(wait) = spacing else {
            counters.drop_packet(DropReason::ThrottledSpacing);
            return Err(QueryError::Throttled);
        };
        let waited_from = Instant::now();
        if !wait.is_zero() && !self.sleep(wait).await {
            lock(&self.shared).spacing.release(&addr, Instant::now());
            return Err(QueryError::Cancelled);
        }
        // Spacing and the send budget share one `max_send_wait`: the budget
        // wait only gets the remainder instead of a second full bound.
        let remaining = remaining_budget(tuning.max_send_wait, waited_from.elapsed());
        if !self.acquire_fetch_budget(remaining).await {
            lock(&self.shared).spacing.release(&addr, Instant::now());
            if self.cancel.is_cancelled() {
                return Err(QueryError::Cancelled);
            }
            counters.drop_packet(DropReason::ThrottledBudgetFetch);
            return Err(QueryError::Throttled);
        }
        let now = Instant::now();
        let (tx, rx) = oneshot::channel();
        let deadline = after(now, tuning.scrape_query_timeout);
        let want = self.want_for(&method);
        let (id, tid) = {
            let mut st = lock(&sock.state);
            let id = st.id;
            let Some(tid) = st.txns.insert(
                addr,
                Pending {
                    tx,
                    deadline,
                    expect,
                },
                now,
            ) else {
                drop(st);
                lock(&self.fetch_budget).refund(1);
                lock(&self.shared).spacing.release(&addr, Instant::now());
                counters.drop_packet(DropReason::ThrottledTxnFull);
                return Err(QueryError::Busy);
            };
            (id, tid)
        };
        let msg = Message {
            tid: tid.to_vec(),
            version: Some(self.cfg.client_version.to_vec()),
            ip: None,
            read_only: self.cfg.read_only,
            body: Body::Query(Query {
                id,
                want,
                method: method.clone(),
            }),
        };
        let packet = match krpc::encode(&msg) {
            Ok(packet) => packet,
            Err(_) => {
                lock(&sock.state).txns.remove(tid, &addr);
                lock(&self.fetch_budget).refund(1);
                lock(&self.shared).spacing.release(&addr, Instant::now());
                counters.drop_packet(DropReason::SendError);
                return Err(QueryError::Send);
            }
        };
        if sock.socket.send_to(&packet, addr).await.is_err() {
            lock(&sock.state).txns.remove(tid, &addr);
            lock(&self.fetch_budget).refund(1);
            lock(&self.shared).spacing.release(&addr, Instant::now());
            counters.drop_packet(DropReason::SendError);
            return Err(QueryError::Send);
        }
        incr(&counters.packets_out);
        self.counters.queries_sent.count(&method);

        let reply = tokio::select! {
            r = tokio::time::timeout_at(deadline, rx) => r,
            () = self.cancel.cancelled() => {
                lock(&sock.state).txns.remove(tid, &addr);
                return Err(QueryError::Cancelled);
            }
        };
        match reply {
            Ok(Ok(Reply::Response(r))) => Ok(r),
            Ok(Ok(Reply::Error(e))) => Err(QueryError::Remote(e)),
            Ok(Ok(Reply::Malformed)) => Err(QueryError::Malformed),
            Ok(Err(_)) | Err(_) => {
                {
                    let mut st = lock(&sock.state);
                    st.txns.remove(tid, &addr);
                    st.table.on_failure(&addr, Instant::now());
                }
                incr(&self.counters.timeouts);
                Err(QueryError::Timeout)
            }
        }
    }

    /// Handles one received datagram (already size-checked).
    fn handle_datagram(&self, sock: &SocketNode, datagram: &[u8], from: SocketAddr) {
        let now = Instant::now();
        let counters = self.counters.family(sock.family);
        if !usable(&from, sock.family, self.policy) {
            counters.drop_packet(DropReason::Filtered);
            return;
        }
        // Replies to our own queries are not charged to the sender's inbound
        // bucket, so spoofed junk cannot make us drop them. Only endpoints we
        // are waiting for skip the charge before decoding.
        let expecting = lock(&sock.state).txns.expects(&from);
        if !expecting && !self.allow_inbound(sock, &from, now) {
            return;
        }
        let decoded = krpc::decode(datagram);
        if expecting {
            let reply_tid = match &decoded {
                Ok(Message {
                    tid,
                    body: Body::Response(_) | Body::Error(_),
                    ..
                })
                | Err(DecodeError::BadReply { tid }) => Some(tid),
                _ => None,
            };
            // Claim our transaction atomically instead of `contains` (peek)
            // + `take` in `on_reply` (B-004): one lock + one lookup instead
            // of two, and no peek-then-claim race. A claimed reply is ours,
            // so it skips the second inbound charge; anything else is gated
            // by the bucket as before. NOTE: the `take` must be its own `let`
            // statement — an `if let ... = lock(...).take()` scrutinee would
            // keep the guard alive through the block and deadlock in
            // `learn_from_response` below (non-reentrant mutex).
            if let Some(tid) = reply_tid {
                let claimed = lock(&sock.state).txns.take(tid, &from);
                if let Some(pending) = claimed {
                    self.on_claimed_reply(sock, pending, decoded, from, now);
                    return;
                }
            }
            if !self.allow_inbound(sock, &from, now) {
                return;
            }
        }
        match decoded {
            Ok(msg) => match msg.body {
                Body::Query(query) => {
                    self.on_query(sock, &msg.tid, msg.read_only, &query, from, now)
                }
                Body::Response(response) => self.on_reply(
                    sock,
                    &msg.tid,
                    Ok(response),
                    ReplyMeta {
                        reported_ip: msg.ip,
                        from,
                        sender_read_only: msg.read_only,
                        now,
                    },
                ),
                Body::Error(error) => self.on_reply(
                    sock,
                    &msg.tid,
                    Err(error),
                    ReplyMeta {
                        reported_ip: msg.ip,
                        from,
                        sender_read_only: false,
                        now,
                    },
                ),
            },
            Err(DecodeError::BadQuery { tid, code, message }) => {
                self.counters.queries_received.count_other();
                if self.cfg.read_only || !self.reserve_reply(sock.family, now) {
                    return;
                }
                let reply =
                    responder::error_reply(from, self.cfg.client_version, &tid, code, message);
                incr(&self.counters.errors_sent);
                self.send_reply(sock, &reply, from);
            }
            Err(DecodeError::BadReply { tid }) => {
                let pending = lock(&sock.state).txns.take(&tid, &from);
                match pending {
                    Some(p) => {
                        incr(&self.counters.errors_received);
                        let _ = p.tx.send(Reply::Malformed);
                    }
                    None => counters.drop_packet(DropReason::Malformed),
                }
            }
            Err(DecodeError::Unusable) => counters.drop_packet(DropReason::Malformed),
        }
    }

    /// Charges one datagram to the sender's inbound bucket, or counts it as dropped.
    fn allow_inbound(&self, sock: &SocketNode, from: &SocketAddr, now: Instant) -> bool {
        if lock(&self.shared).inbound.allow(from, now) {
            return true;
        }
        self.counters
            .family(sock.family)
            .drop_packet(DropReason::RateLimited);
        false
    }

    fn closest_in(
        &self,
        family: Family,
        target: &NodeId,
        exclude: &SocketAddr,
        now: Instant,
    ) -> Option<Vec<CompactNode>> {
        // Every identity of the family answers with the union of their
        // tables: each is a distinct node, and the response carries the
        // closest nodes we know. One socket behaves exactly as before.
        let mut merged: Vec<CompactNode> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for sock in self.sockets.iter().filter(|s| s.family == family) {
            let st = lock(&sock.state);
            for n in st.table.closest(target, K.saturating_add(1), now, true) {
                if n.addr != *exclude && seen.insert(n.addr) {
                    merged.push(n);
                }
            }
        }
        if self.sockets.iter().all(|s| s.family != family) {
            return None;
        }
        merged.sort_by(|a, b| a.id.distance(target).cmp(&b.id.distance(target)));
        merged.truncate(K);
        Some(merged)
    }

    /// Takes one reply from the responder budget, or counts the query as dropped.
    fn reserve_reply(&self, family: Family, now: Instant) -> bool {
        if lock(&self.responder_budget).try_reserve(REPLY_RESERVATION, now) {
            return true;
        }
        self.counters
            .family(family)
            .drop_packet(DropReason::ResponderBudget);
        false
    }

    fn on_query(
        &self,
        sock: &SocketNode,
        tid: &[u8],
        sender_read_only: bool,
        query: &Query,
        from: SocketAddr,
        now: Instant,
    ) {
        self.counters.queries_received.count(&query.method);
        // BEP 43: a read-only node answers nothing. Beyond the responder
        // budget, queries are dropped unanswered.
        if self.cfg.read_only || !self.reserve_reply(sock.family, now) {
            return;
        }
        let own_id = {
            let mut st = lock(&sock.state);
            // Learn about the sender, unless it is read-only, ourselves or a router.
            if !sender_read_only && query.id != st.id && !st.routers.contains(&from) {
                let bep42 = is_bep42_valid(&query.id, from.ip());
                st.table.on_query(query.id, from, bep42, now);
            }
            st.id
        };
        let want = wanted(query.want, sock.family);
        let (nodes, nodes6) = match query.method.target() {
            Some(target) => (
                want.n4
                    .then(|| self.closest_in(Family::V4, &target, &from, now))
                    .flatten(),
                want.n6
                    .then(|| self.closest_in(Family::V6, &target, &from, now))
                    .flatten(),
            ),
            None => (None, None),
        };
        let ctx = AnswerContext {
            own_id,
            transport: sock.family,
            src: from,
            now,
            version: self.cfg.client_version,
            tuning: &self.cfg.tuning,
            policy: self.policy,
            nodes,
            nodes6,
        };
        let answer = {
            let mut guard = lock(&self.shared);
            let shared = &mut *guard;
            responder::answer(&ctx, tid, query, &shared.tokens, &mut shared.store)
        };
        if let Some(event) = answer.event {
            // an inbound announce endpoint just
            // proved itself live — feed the sampler's live ring.
            if event.source == Source::Announce {
                self.offer_live(from);
            }
            self.emit(event);
        }
        if answer.is_error {
            incr(&self.counters.errors_sent);
        }
        self.send_reply(sock, &answer.reply, from);
    }

    /// Sends a reply that holds a responder reservation, without waiting.
    /// The unused part of the reservation is returned first.
    fn send_reply(&self, sock: &SocketNode, msg: &Message, to: SocketAddr) {
        let counters = self.counters.family(sock.family);
        let encoded = krpc::encode(msg);
        let used = encoded.as_ref().map_or(0, Vec::len);
        let unused = u32::try_from(MAX_DATAGRAM_OUT.saturating_sub(used)).unwrap_or(0);
        lock(&self.responder_budget).refund_bytes(unused);
        let Ok(bytes) = encoded else {
            counters.drop_packet(DropReason::SendError);
            return;
        };
        match sock.socket.try_send_to(&bytes, to) {
            Ok(_) => incr(&counters.packets_out),
            Err(_) => counters.drop_packet(DropReason::SendError),
        }
    }

    fn on_reply(
        &self,
        sock: &SocketNode,
        tid: &[u8],
        body: Result<Response, KrpcError>,
        meta: ReplyMeta,
    ) {
        let pending = lock(&sock.state).txns.take(tid, &meta.from);
        let Some(pending) = pending else {
            // Unknown (transaction, endpoint): late, or not ours.
            self.counters
                .family(sock.family)
                .drop_packet(DropReason::Unsolicited);
            return;
        };
        self.deliver_reply(sock, pending, body, meta);
    }

    /// Delivers an already-claimed reply. `handle_datagram` calls this on the
    /// fast path (transaction atomically taken); `on_reply` calls it after
    /// taking.
    fn deliver_reply(
        &self,
        sock: &SocketNode,
        pending: Pending,
        body: Result<Response, KrpcError>,
        meta: ReplyMeta,
    ) {
        let reply = match body {
            Ok(response) => {
                incr(&self.counters.responses_received);
                self.learn_from_response(sock, &response, pending.expect, meta);
                Reply::Response(response)
            }
            Err(error) => {
                incr(&self.counters.errors_received);
                Reply::Error(error)
            }
        };
        let _ = pending.tx.send(reply);
    }

    /// Dispatches a reply-shaped datagram whose transaction was already
    /// claimed (fast path). Only response/error/malformed shapes reach here:
    /// the caller takes the transaction only when the decoded reply ID is
    /// present, which those shapes alone provide.
    fn on_claimed_reply(
        &self,
        sock: &SocketNode,
        pending: Pending,
        decoded: Result<Message, DecodeError>,
        from: SocketAddr,
        now: Instant,
    ) {
        match decoded {
            Ok(msg) => match msg.body {
                Body::Response(response) => {
                    self.deliver_reply(
                        sock,
                        pending,
                        Ok(response),
                        ReplyMeta {
                            reported_ip: msg.ip,
                            from,
                            sender_read_only: msg.read_only,
                            now,
                        },
                    );
                }
                Body::Error(error) => {
                    self.deliver_reply(
                        sock,
                        pending,
                        Err(error),
                        ReplyMeta {
                            reported_ip: msg.ip,
                            from,
                            sender_read_only: false,
                            now,
                        },
                    );
                }
                Body::Query(_) => {
                    // Unreachable by construction (see above): degrade to a
                    // drop, so a logic error costs one query timeout, never a
                    // panic in the network path.
                    debug_assert!(false, "claimed reply with query body");
                    self.counters
                        .family(sock.family)
                        .drop_packet(DropReason::Malformed);
                    let _ = pending.tx.send(Reply::Malformed);
                }
            },
            Err(DecodeError::BadReply { .. }) => {
                incr(&self.counters.errors_received);
                let _ = pending.tx.send(Reply::Malformed);
            }
            Err(_) => {
                // Unreachable by construction (see above); same safe fallback.
                debug_assert!(false, "claimed reply with non-reply error");
                self.counters
                    .family(sock.family)
                    .drop_packet(DropReason::Malformed);
                let _ = pending.tx.send(Reply::Malformed);
            }
        }
    }

    /// Updates the routing table, the external-IP vote and the sampler
    /// frontier from a response to one of our queries. A response with the
    /// top-level `ro` flag (BEP 43) is delivered to the querier but teaches
    /// us nothing: no table entry, no IP vote, no sampler candidates.
    fn learn_from_response(
        &self,
        sock: &SocketNode,
        response: &Response,
        expect: Option<NodeId>,
        meta: ReplyMeta,
    ) {
        let ReplyMeta {
            reported_ip,
            from,
            sender_read_only,
            now,
        } = meta;
        let (external_changed, switched) = {
            let mut st = lock(&sock.state);
            // An answer under another ID is a failure of the expected entry;
            // the ID that did answer is learned like any other responder,
            // unless it is read-only.
            if let Some(expected) = expect
                && expected != response.id
            {
                st.table.on_wrong_id(&expected, &from, now);
            }
            if sender_read_only {
                // BEP 43: a read-only responder teaches us nothing — no
                // table entry, no IP vote, no sampler candidates below.
                (false, false)
            } else {
                if response.id != st.id && !st.routers.contains(&from) {
                    let bep42 = is_bep42_valid(&response.id, from.ip());
                    st.table.on_response(response.id, from, bep42, now);
                }
                // Only the top-level `ip` of a response to our own query votes.
                match reported_ip.map(|a| canonical_ip(a.ip())) {
                    Some(ip)
                        if Family::of_ip(&ip) == sock.family && self.policy.dialable_ip(ip) =>
                    {
                        match st.voter.record(self.policy.voter_key(&from), ip, now) {
                            Some(winner) => self.on_external_ip(&mut st, winner, now),
                            None => (false, false),
                        }
                    }
                    _ => (false, false),
                }
            }
        };
        if external_changed {
            self.refresh_own(now);
        }
        if switched {
            incr(&self.counters.node_id_changes);
            sock.rebootstrap.store(true, Ordering::SeqCst);
            tracing::info!(
                family = sock.family.as_str(),
                "external address confirmed; switched to a BEP 42 node ID"
            );
        }
        if sender_read_only {
            return;
        }
        if let Some(sampler) = &self.sampler {
            let own_ids = self.own_ids();
            let own = self.own();
            for (family, nodes) in [
                (Family::V4, &response.nodes),
                (Family::V6, &response.nodes6),
            ] {
                let Some(nodes) = nodes else { continue };
                if self.socket(family).is_none() {
                    continue;
                }
                let candidates: Vec<CompactNode> = nodes
                    .iter()
                    .take(MAX_FRONTIER_NODES_PER_RESPONSE)
                    .filter(|n| {
                        usable(&n.addr, family, self.policy)
                            && !own_ids.contains(&n.id)
                            && !own.contains(&n.addr, self.policy)
                    })
                    .copied()
                    .collect();
                sampler.offer(family, &candidates, now);
            }
        }
    }

    /// Records the vote winner and switches to a BEP 42 ID when the current
    /// one is not valid for it, at most once per `id_change_min_interval`.
    /// Returns whether the external IP changed and whether the ID changed.
    fn on_external_ip(&self, st: &mut SocketState, winner: IpAddr, now: Instant) -> (bool, bool) {
        let changed = st.external_ip != Some(winner);
        st.external_ip = Some(winner);
        if is_bep42_valid(&st.id, winner) {
            return (changed, false);
        }
        let interval = self.cfg.tuning.id_change_min_interval;
        let allowed = st
            .last_id_change
            .is_none_or(|t| now.saturating_duration_since(t) >= interval);
        if !allowed {
            return (changed, false);
        }
        let new_id = match self.cfg.bep42_r {
            Some(r) => crate::node_id::bep42_id_for_r(winner, r),
            None => bep42_random_id(winner),
        };
        st.table = st.table.rebuild(new_id, now);
        st.id = new_id;
        st.last_id_change = Some(now);
        (changed, true)
    }

    fn spawn_job<F>(&self, job: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        lock(&self.jobs).spawn(job);
    }

    /// Writes the state file (if configured).
    pub(crate) async fn save_state(&self) {
        let Some(path) = self.cfg.state_file.clone() else {
            return;
        };
        let now = Instant::now();
        let mut file = StateFile {
            version: STATE_VERSION,
            v4: Vec::new(),
            v6: Vec::new(),
        };
        for sock in &self.sockets {
            let identity = {
                let st = lock(&sock.state);
                let mut nodes: Vec<SavedNode> = st
                    .table
                    .export(MAX_SAVED_NODES, now)
                    .into_iter()
                    .map(|n| SavedNode {
                        id: n.id,
                        addr: n.addr,
                    })
                    .collect();
                if nodes.is_empty() {
                    // Keep the old contacts rather than forget them while offline.
                    nodes = sock
                        .saved_contacts
                        .iter()
                        .map(|n| SavedNode {
                            id: n.id,
                            addr: n.addr,
                        })
                        .collect();
                }
                IdentityState {
                    id: st.id,
                    external_ip: st.external_ip,
                    nodes,
                }
            };
            match sock.family {
                Family::V4 => file.v4.push(identity),
                Family::V6 => file.v6.push(identity),
            }
        }
        match tokio::task::spawn_blocking(move || state::save(&path, &file)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "cannot write DHT state file"),
            Err(e) => tracing::warn!(error = %e, "DHT state writer failed"),
        }
    }

    /// Good routing-table nodes over both families.
    pub(crate) fn good_nodes(&self) -> usize {
        let now = Instant::now();
        self.sockets
            .iter()
            .map(|s| lock(&s.state).table.good_count(now))
            .fold(0, usize::saturating_add)
    }

    /// Counters plus current sizes.
    pub(crate) fn stats(&self) -> DhtStatsSnapshot {
        let mut stats = self.counters.snapshot();
        let now = Instant::now();
        for sock in &self.sockets {
            let (routing_nodes, good_nodes, pending_queries) = {
                let st = lock(&sock.state);
                (st.table.len(), st.table.good_count(now), st.txns.len())
            };
            let family = stats.family_mut(sock.family);
            family.enabled = true;
            family.routing_nodes = family
                .routing_nodes
                .saturating_add(routing_nodes);
            family.good_nodes = family.good_nodes.saturating_add(good_nodes);
            family.pending_queries = family
                .pending_queries
                .saturating_add(pending_queries);
            if let Some(sampler) = &self.sampler {
                (family.sampler_frontier, family.sampler_visited) = sampler.sizes(sock.family);
            }
        }
        stats.peer_store_keys = lock(&self.shared).store.len();
        stats
    }

    /// Stops every task and writes the state file.
    pub(crate) async fn shutdown(&self) {
        self.cancel.cancel();
        let handles = std::mem::take(&mut *lock(&self.tasks));
        let mut jobs = std::mem::take(&mut *lock(&self.jobs));
        let abort_handles: Vec<_> = handles.iter().map(JoinHandle::abort_handle).collect();
        let wait_all = async {
            for handle in handles {
                let _ = handle.await;
            }
            while jobs.join_next().await.is_some() {}
        };
        if tokio::time::timeout(SHUTDOWN_GRACE, wait_all)
            .await
            .is_err()
        {
            tracing::warn!("DHT tasks did not stop in time; aborting them");
            for handle in abort_handles {
                handle.abort();
            }
            // Dropping the JoinSet at the end of this function would abort the
            // jobs too, but only after the state file is written. Abort them
            // first so no job touches the routing table during the save.
            jobs.abort_all();
        }
        self.save_state().await;
    }
}

/// Reads datagrams from one socket until shutdown.
async fn recv_loop(inner: Arc<Inner>, sock: Arc<SocketNode>) {
    let counters = inner.counters.family(sock.family);
    let mut buf = vec![0u8; RECV_BUFFER_LEN];
    let mut errors: u32 = 0;
    loop {
        let received = tokio::select! {
            () = inner.cancel.cancelled() => break,
            r = sock.socket.recv_from(&mut buf) => r,
        };
        let (len, from) = match received {
            Ok(r) => {
                errors = 0;
                r
            }
            Err(e) => {
                // Unconnected UDP sockets may report ICMP errors from earlier sends.
                incr(&counters.recv_errors);
                errors = errors.saturating_add(1);
                if errors >= RECV_ERROR_BURST {
                    tracing::debug!(error = %e, "repeated UDP receive errors");
                    errors = 0;
                    if !inner.sleep(RECV_ERROR_PAUSE).await {
                        break;
                    }
                }
                continue;
            }
        };
        incr(&counters.packets_in);
        if len >= buf.len() {
            // It filled the buffer, so it may have been truncated: drop it.
            counters.drop_packet(DropReason::Oversized);
            continue;
        }
        let Some(datagram) = buf.get(..len) else {
            continue;
        };
        inner.handle_datagram(&sock, datagram, normalize_addr(from));
    }
}

/// Periodic work: token rotation, peer expiry, transaction sweeping, liveness
/// pings, bucket refreshes, bootstrap retries and state saving.
async fn maintenance(inner: Arc<Inner>) {
    let tuning = inner.cfg.tuning.clone();
    let mut tick = tokio::time::interval(tuning.maintenance_interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_save = Instant::now();
    loop {
        tokio::select! {
            () = inner.cancel.cancelled() => break,
            _ = tick.tick() => {}
        }
        let now = Instant::now();
        {
            let mut shared = lock(&inner.shared);
            shared.tokens.maybe_rotate(now);
            shared.store.expire(now);
        }
        {
            let mut jobs = lock(&inner.jobs);
            while jobs.try_join_next().is_some() {}
        }
        for sock in &inner.sockets {
            let (pings, refresh, good) = {
                let mut st = lock(&sock.state);
                st.txns.sweep(now);
                let pings =
                    st.table
                        .ping_candidates(now, tuning.ping_interval, tuning.max_pings_per_round);
                let free = MAX_CONCURRENT_REFRESH
                    .saturating_sub(sock.refreshes_running.load(Ordering::SeqCst));
                let refresh = st
                    .table
                    .refresh_targets(now, tuning.bucket_refresh_interval, free);
                for (idx, _) in &refresh {
                    st.table.mark_refreshed(*idx, now);
                }
                (pings, refresh, st.table.good_count(now))
            };
            for node in pings {
                let (inner2, sock2) = (Arc::clone(&inner), Arc::clone(sock));
                inner.spawn_job(async move {
                    let _ = inner2
                        .query(&sock2, node.addr, Method::Ping, Some(node.id))
                        .await;
                });
            }
            for (idx, target) in refresh {
                sock.refreshes_running.fetch_add(1, Ordering::SeqCst);
                let (inner2, sock2) = (Arc::clone(&inner), Arc::clone(sock));
                inner.spawn_job(async move {
                    let _guard = CountGuard(&sock2.refreshes_running);
                    let deadline = after(Instant::now(), inner2.cfg.tuning.lookup_timeout);
                    let outcome =
                        lookup::find_node(&inner2, &sock2, target, Vec::new(), deadline).await;
                    if outcome.closest.is_empty() {
                        // The refresh reached no live node: leave the bucket
                        // due so the next round retries it.
                        let now = Instant::now();
                        let interval = inner2.cfg.tuning.bucket_refresh_interval;
                        lock(&sock2.state)
                            .table
                            .mark_refresh_due(idx, now, interval);
                    }
                });
            }
            maybe_bootstrap(&inner, sock, good, now);
        }
        if inner.cfg.state_file.is_some()
            && now.saturating_duration_since(last_save) >= tuning.state_save_interval
        {
            last_save = now;
            inner.save_state().await;
        }
    }
}

/// Decrements a counter when dropped.
struct CountGuard<'a>(&'a AtomicUsize);

impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        // A compare-exchange loop rather than `fetch_update`, which newer
        // toolchains deprecate.
        let mut current = self.0.load(Ordering::SeqCst);
        while let Err(actual) = self.0.compare_exchange_weak(
            current,
            current.saturating_sub(1),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            current = actual;
        }
    }
}

/// Clears a flag when dropped.
pub(crate) struct FlagGuard<'a>(pub(crate) &'a AtomicBool);

impl Drop for FlagGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn maybe_bootstrap(inner: &Arc<Inner>, sock: &Arc<SocketNode>, good: usize, now: Instant) {
    let tuning = &inner.cfg.tuning;
    let forced = sock.rebootstrap.swap(false, Ordering::SeqCst);
    {
        let mut schedule = lock(&sock.bootstrap);
        if good >= MIN_GOOD_NODES && !forced {
            schedule.delay = tuning.bootstrap_retry_base;
            return;
        }
        if !forced && now < schedule.next_at {
            return;
        }
        if sock.bootstrap_running.swap(true, Ordering::SeqCst) {
            if forced {
                sock.rebootstrap.store(true, Ordering::SeqCst);
            }
            return;
        }
        schedule.next_at = after(now, schedule.delay);
        schedule.delay = schedule
            .delay
            .saturating_mul(2)
            .min(tuning.bootstrap_retry_max);
    }
    let (inner2, sock2) = (Arc::clone(inner), Arc::clone(sock));
    inner.spawn_job(async move {
        let _guard = FlagGuard(&sock2.bootstrap_running);
        bootstrap(&inner2, &sock2).await;
    });
}

/// Merges freshly resolved bootstrap `routers` into the known set without
/// exceeding [`MAX_ROUTERS`]: known routers are always kept and overflow is
/// dropped (a bad DNS round can no longer flush every good router). The
/// dropped addresses are still queried this round by the caller; they are
/// just not remembered.
fn merge_routers(known: &mut HashSet<SocketAddr>, fresh: &[SocketAddr]) {
    for addr in fresh.iter().copied() {
        if known.len() >= MAX_ROUTERS {
            break;
        }
        known.insert(addr);
    }
}

/// Resolves the routers, asks them and the saved contacts for nodes near our
/// own ID, then runs a lookup for our own ID.
async fn bootstrap(inner: &Inner, sock: &SocketNode) {
    let mut routers: Vec<SocketAddr> = Vec::new();
    for (index, host) in inner.cfg.bootstrap.iter().enumerate() {
        let resolved = tokio::select! {
            r = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(host.as_str())) => r,
            () = inner.cancel.cancelled() => return,
        };
        match resolved {
            Ok(Ok(addrs)) => {
                for addr in addrs.map(normalize_addr) {
                    let fresh = !routers.contains(&addr) && routers.len() < MAX_ROUTERS;
                    if fresh && usable(&addr, sock.family, inner.policy) {
                        routers.push(addr);
                    }
                }
            }
            // The host may be an address literal, so it is logged at trace level only.
            Ok(Err(e)) => {
                tracing::debug!(index, error = %e, "cannot resolve a DHT bootstrap host");
                tracing::trace!(host = %host, "unresolved DHT bootstrap host");
            }
            Err(_) => {
                tracing::debug!(index, "DHT bootstrap host resolution timed out");
                tracing::trace!(host = %host, "DHT bootstrap host timed out");
            }
        }
    }
    let own_id = {
        let mut st = lock(&sock.state);
        merge_routers(&mut st.routers, &routers);
        st.id
    };
    let replies = join_all(
        routers
            .iter()
            .map(|r| inner.query(sock, *r, Method::FindNode { target: own_id }, None)),
    )
    .await;
    let mut seeds = sock.saved_contacts.clone();
    for reply in replies.into_iter().flatten() {
        let nodes = match sock.family {
            Family::V4 => reply.nodes,
            Family::V6 => reply.nodes6,
        };
        seeds.extend(nodes.unwrap_or_default());
    }
    let deadline = after(Instant::now(), inner.cfg.tuning.lookup_timeout);
    let outcome = lookup::find_node(inner, sock, own_id, seeds, deadline).await;
    tracing::debug!(
        family = sock.family.as_str(),
        responders = outcome.closest.len(),
        "DHT bootstrap round finished"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([9, 9, 9, 9], port))
    }

    #[test]
    fn merge_routers_keeps_known_and_drops_overflow() {
        let mut known: HashSet<SocketAddr> = (0..MAX_ROUTERS as u16).map(addr).collect();
        // One bad DNS round with fresh addresses flushes nothing.
        merge_routers(&mut known, &[addr(1000), addr(1001)]);
        assert_eq!(known.len(), MAX_ROUTERS);
        assert!(known.contains(&addr(0)));
        assert!(!known.contains(&addr(1000)));
    }

    #[test]
    fn merge_routers_fills_room_and_ignores_duplicates() {
        let mut known: HashSet<SocketAddr> = [addr(1), addr(2)].into_iter().collect();
        merge_routers(&mut known, &[addr(2), addr(3), addr(4)]);
        assert!(known.contains(&addr(1)));
        assert!(known.contains(&addr(3)));
        assert!(known.contains(&addr(4)));
        assert_eq!(known.len(), 4);
    }
}

    #[tokio::test]
    async fn bind_sockets_gives_each_identity_its_own_port() {
        let mut cfg = DhtConfig::default();
        cfg.bind_v4 = Some("127.0.0.1:0".parse().unwrap());
        cfg.bind_v6 = None;
        cfg.identities = 3;
        let bound = bind_sockets(&cfg).unwrap();
        assert_eq!(bound.len(), 3);
        let mut ports: Vec<u16> = bound.iter().map(|(_, _, local)| local.port()).collect();
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), 3, "identities must not share a port");
        assert!(bound.iter().all(|(family, ..)| *family == Family::V4));
    }

    #[tokio::test]
    async fn bind_sockets_single_identity_is_todays_behavior() {
        let mut cfg = DhtConfig::default();
        cfg.bind_v4 = Some("127.0.0.1:0".parse().unwrap());
        cfg.bind_v6 = None;
        cfg.identities = 1;
        let bound = bind_sockets(&cfg).unwrap();
        assert_eq!(bound.len(), 1);
    }
