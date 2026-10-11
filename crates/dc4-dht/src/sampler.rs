//! BEP 51 sampler: walks the DHT asking nodes for samples of their keys.
//!
//! Each address family has a bounded *frontier* of candidate nodes (fed from
//! the routing table and from `nodes`/`nodes6` in every response) and a
//! bounded *visited* map from a node to the earliest time it may be sampled
//! again. A node is remembered by its endpoint and, once it has answered, by
//! its node ID too.
//!
//! Only expired entries are removed first when the visited map needs room.
//! If that is not enough, unexpired entries with the farthest next-sample
//! time first (the long 6h unsupported skips) are evicted too, excluding
//! in-flight keys, until the new node fits or nothing more can go. A pick
//! refused for lack of room reports `sampler_visited_full` until entries
//! expire or are evicted. Right before a query is
//! sent, the node's recorded time is checked once more; a failure there is
//! counted in `sampler_early`, which must stay 0, and nothing is sent.
//!
//! The next sample time honours the node's `interval` (at least
//! `sample_min_resample`). Nodes without BEP 51 support, or that do not
//! answer, are skipped for longer. An empty frontier triggers a `find_node`
//! walk towards a random target.
//!
//! The frontier serves the freshest candidates: when full, a new node pushes
//! out the oldest one, and entries older than [`FRONTIER_MAX_AGE_SECS`] are
//! discarded. At most [`MAX_SAMPLES_PER_REPLY`] samples are taken from one
//! reply, none from a reply under an unexpected node ID, and one /24 (IPv4)
//! or /48 (IPv6) yields at most [`SAMPLES_PER_NETWORK`] samples per
//! [`SAMPLE_QUOTA_WINDOW`].

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use dc4_core::DhtKey;
use lru::LruCache;

use crate::compact::{AddrPolicy, CompactNode, Family, canonical_ip};
use crate::config::DhtTuning;
use crate::krpc::{Method, Response};
use crate::lookup;
use crate::node::{FlagGuard, Inner, QueryError, SocketNode};
use crate::node_id::NodeId;
use crate::ratelimit::{RATE_MAP_CAPACITY, WindowQuota};
use crate::responder::MAX_SAMPLE_INTERVAL_SECS;
use crate::stats::{add, incr};
use crate::util::{after, after_skip, lock};
use crate::{Discovered, Source};

/// Candidate nodes waiting to be sampled, per family (design §3).
pub(crate) const FRONTIER_CAPACITY: usize = 200_000;
/// Entries in the visited map, per family (design §3).
pub(crate) const VISITED_CAPACITY: usize = 4_000_000;
/// Queue entries inspected per pick before giving up.
const MAX_POPS_PER_PICK: usize = 256;
/// Shortest time between two scans of a full visited map, in seconds.
const MIN_PRUNE_GAP_SECS: u32 = 10;
/// A queued candidate older than this is stale (BEP 5: good for 15 minutes).
pub(crate) const FRONTIER_MAX_AGE_SECS: u32 = 900;
/// Samples taken from one reply (the most BEP 51 nodes send); the rest are ignored.
pub(crate) const MAX_SAMPLES_PER_REPLY: usize = 20;
/// Samples one source network may yield per window.
pub(crate) const SAMPLES_PER_NETWORK: u32 = 200;
/// The window of [`SAMPLES_PER_NETWORK`].
pub(crate) const SAMPLE_QUOTA_WINDOW: Duration = Duration::from_secs(600);
/// Source networks tracked by the sample quota.
const SAMPLE_QUOTA_CAPACITY: NonZeroUsize = RATE_MAP_CAPACITY;
/// Consecutive-timeout strikes tracked per address for the backoff ladder.
const TIMEOUT_STRIKE_CAPACITY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(262_143);

/// Skip after `strikes` consecutive timeouts: base, 2*base, 4*base, then max.
/// Saturates and never exceeds `max`.
pub(crate) fn timeout_backoff(strikes: u8, base: Duration, max: Duration) -> Duration {
    let mut skip = base.min(max);
    if base >= max {
        return skip;
    }
    for _ in 1..strikes {
        skip = skip.saturating_mul(2).min(max);
        if skip >= max {
            break;
        }
    }
    skip
}

/// What a node is remembered by in the visited map.
#[derive(Hash)]
enum VisitKey<'a> {
    Endpoint(&'a SocketAddr),
    Id(&'a NodeId),
}

/// A node picked for sampling. Its keys stay in flight until
/// [`Frontier::finish`].
#[derive(Debug)]
pub(crate) struct Ticket {
    pub(crate) node: CompactNode,
    endpoint_key: u64,
    id_key: u64,
    /// Visited-map slots promised to this ticket.
    reserved: usize,
}

/// What [`Frontier::pick`] found.
#[derive(Debug)]
pub(crate) enum Pick {
    /// A node to sample now.
    Node(Ticket),
    /// No eligible node was found in this scan. Skipped entries stay queued,
    /// so a later pick resumes with them.
    Empty,
    /// Only new nodes were queued, and the visited map is full of unexpired entries.
    Full,
}

pub(crate) struct Frontier {
    /// Candidates with the time they were queued (seconds since `epoch`).
    queue: VecDeque<(CompactNode, u32)>,
    queued: HashSet<SocketAddr>,
    /// Keyed hash of a [`VisitKey`] → earliest next sample, in whole seconds since `epoch`.
    visited: HashMap<u64, u32>,
    /// Keys of the nodes being sampled.
    in_flight: HashSet<u64>,
    /// Visited-map slots promised to outstanding tickets.
    reserved: usize,
    /// No scan of a full visited map before this time (seconds since `epoch`).
    next_prune: u32,
    hasher: RandomState,
    epoch: Instant,
    queue_cap: usize,
    visited_cap: usize,
}

impl Frontier {
    pub(crate) fn new(epoch: Instant) -> Self {
        Self::with_capacity(epoch, FRONTIER_CAPACITY, VISITED_CAPACITY)
    }

    pub(crate) fn with_capacity(epoch: Instant, queue_cap: usize, visited_cap: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            queued: HashSet::new(),
            visited: HashMap::new(),
            in_flight: HashSet::new(),
            reserved: 0,
            next_prune: 0,
            hasher: RandomState::new(),
            epoch,
            queue_cap,
            visited_cap,
        }
    }

    /// Queued candidates.
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    /// Entries in the visited map.
    pub(crate) fn visited_len(&self) -> usize {
        self.visited.len()
    }

    fn secs_floor(&self, t: Instant) -> u32 {
        u32::try_from(t.saturating_duration_since(self.epoch).as_secs()).unwrap_or(u32::MAX)
    }

    fn secs_ceil(&self, t: Instant) -> u32 {
        let d = t.saturating_duration_since(self.epoch);
        let secs = if d.subsec_nanos() > 0 {
            d.as_secs().saturating_add(1)
        } else {
            d.as_secs()
        };
        u32::try_from(secs).unwrap_or(u32::MAX)
    }

    fn key(&self, key: VisitKey<'_>) -> u64 {
        self.hasher.hash_one(key)
    }

    fn keys(&self, node: &CompactNode) -> (u64, u64) {
        (
            self.key(VisitKey::Endpoint(&node.addr)),
            self.key(VisitKey::Id(&node.id)),
        )
    }

    /// Whether the recorded time of `key` has come (or there is none).
    fn due(&self, key: u64, now_secs: u32) -> bool {
        self.visited.get(&key).is_none_or(|next| *next <= now_secs)
    }

    fn available(&self, key: u64, now_secs: u32) -> bool {
        !self.in_flight.contains(&key) && self.due(key, now_secs)
    }

    /// Whether `node` may be picked at `now`.
    pub(crate) fn eligible(&self, node: &CompactNode, now: Instant) -> bool {
        let now = self.secs_floor(now);
        let (endpoint, id) = self.keys(node);
        self.available(endpoint, now) && self.available(id, now)
    }

    /// Queues `node` if it is eligible and not queued yet. A full queue
    /// drops its oldest entry to make room.
    pub(crate) fn offer(&mut self, node: CompactNode, now: Instant) -> bool {
        if self.queue_cap == 0 || self.queued.contains(&node.addr) || !self.eligible(&node, now) {
            return false;
        }
        while self.queue.len() >= self.queue_cap {
            match self.queue.pop_front() {
                Some((old, _)) => {
                    self.queued.remove(&old.addr);
                }
                None => break,
            }
        }
        self.queued.insert(node.addr);
        self.queue.push_back((node, self.secs_floor(now)));
        true
    }

    /// Puts a skipped entry back for a later pick, keeping its original
    /// queue time so it still ages out via [`FRONTIER_MAX_AGE_SECS`].
    fn requeue(&mut self, node: CompactNode, queued_at: u32) {
        self.queued.insert(node.addr);
        self.queue.push_back((node, queued_at));
    }

    /// Takes the next eligible node and marks it in flight. Also returns how
    /// many new nodes were dropped because the visited map is full.
    ///
    /// Skipped entries that may become eligible later (not due yet, or no
    /// visited-map room right now) are kept for a later pick; only stale
    /// entries are dropped. The scan stops after one full pass over the
    /// queued entries (or [`MAX_POPS_PER_PICK`] pops), so a verdict of
    /// [`Pick::Empty`] means nothing queued was eligible, not that the
    /// queue is drained.
    pub(crate) fn pick(&mut self, now: Instant) -> (Pick, u64) {
        let now_secs = self.secs_floor(now);
        let mut refused = 0u64;
        let mut examined = 0usize;
        let pass_len = self.queue.len();
        for _ in 0..MAX_POPS_PER_PICK {
            if examined >= pass_len {
                break;
            }
            let Some((node, queued_at)) = self.queue.pop_front() else {
                break;
            };
            examined = examined.saturating_add(1);
            self.queued.remove(&node.addr);
            if now_secs.saturating_sub(queued_at) > FRONTIER_MAX_AGE_SECS {
                continue;
            }
            let (endpoint_key, id_key) = self.keys(&node);
            if !self.available(endpoint_key, now_secs) || !self.available(id_key, now_secs) {
                self.requeue(node, queued_at);
                continue;
            }
            // Mark the keys first, so that pruning keeps this node's expired
            // entries and `needed` stays exact.
            self.in_flight.insert(endpoint_key);
            self.in_flight.insert(id_key);
            let needed = [endpoint_key, id_key]
                .iter()
                .filter(|k| !self.visited.contains_key(k))
                .count();
            if !self.make_room(needed, now_secs) {
                self.in_flight.remove(&endpoint_key);
                self.in_flight.remove(&id_key);
                refused = refused.saturating_add(1);
                self.requeue(node, queued_at);
                continue;
            }
            self.reserved = self.reserved.saturating_add(needed);
            let ticket = Ticket {
                node,
                endpoint_key,
                id_key,
                reserved: needed,
            };
            return (Pick::Node(ticket), refused);
        }
        let pick = if refused > 0 { Pick::Full } else { Pick::Empty };
        (pick, refused)
    }

    /// Whether the node of `ticket` may be queried at `now`. The send path
    /// asks this right before sending.
    pub(crate) fn send_allowed(&self, ticket: &Ticket, now: Instant) -> bool {
        let now = self.secs_floor(now);
        self.due(ticket.endpoint_key, now) && self.due(ticket.id_key, now)
    }

    /// Records that the node of `ticket` may be sampled again at `next_at`.
    /// `answered_as` is the ID it answered with, if it answered.
    pub(crate) fn finish(&mut self, ticket: Ticket, answered_as: Option<NodeId>, next_at: Instant) {
        self.in_flight.remove(&ticket.endpoint_key);
        self.in_flight.remove(&ticket.id_key);
        self.reserved = self.reserved.saturating_sub(ticket.reserved);
        let at = self.secs_ceil(next_at);
        // The slots for the ticket's own keys were reserved when it was picked.
        self.set_next(ticket.endpoint_key, at);
        match answered_as {
            Some(id) if id == ticket.node.id => self.set_next(ticket.id_key, at),
            Some(id) => {
                // Another ID: remembered too, if there is room and no other
                // ticket is using it.
                let key = self.key(VisitKey::Id(&id));
                let room = self.visited.contains_key(&key) || self.fits(1);
                if room && !self.in_flight.contains(&key) {
                    self.set_next(key, at);
                }
            }
            None => {}
        }
    }

    /// Sets the next sample time of `key`, never moving it earlier.
    fn set_next(&mut self, key: u64, at: u32) {
        let next = self.visited.entry(key).or_insert(at);
        *next = (*next).max(at);
        self.next_prune = self.next_prune.min(at);
    }

    fn fits(&self, needed: usize) -> bool {
        self.visited
            .len()
            .saturating_add(self.reserved)
            .saturating_add(needed)
            <= self.visited_cap
    }

    /// Makes room for `needed` new entries: first by forgetting expired
    /// ones, then by evicting unexpired entries with the farthest next-sample
    /// time first. Entries of nodes in flight are always kept.
    fn make_room(&mut self, needed: usize, now_secs: u32) -> bool {
        if self.fits(needed) {
            return true;
        }
        if now_secs < self.next_prune {
            return false;
        }
        let in_flight = &self.in_flight;
        let mut earliest = u32::MAX;
        self.visited.retain(|key, next| {
            if *next > now_secs {
                earliest = earliest.min(*next);
                return true;
            }
            in_flight.contains(key)
        });
        if self.fits(needed) {
            self.next_prune = earliest.max(now_secs.saturating_add(MIN_PRUNE_GAP_SECS));
            return true;
        }
        // Still full: evict unexpired entries, farthest next-sample first.
        let mut evict: Vec<(u64, u32)> = self
            .visited
            .iter()
            .filter(|(key, next)| !in_flight.contains(key) && **next > now_secs)
            .map(|(key, next)| (*key, *next))
            .collect();
        evict.sort_unstable_by_key(|(_, next)| std::cmp::Reverse(*next));
        let mut freed = 0usize;
        let shortfall = needed
            .saturating_add(self.reserved)
            .saturating_add(self.visited.len())
            .saturating_sub(self.visited_cap);
        for (key, _) in evict {
            if freed >= shortfall {
                break;
            }
            if self.visited.remove(&key).is_some() {
                freed = freed.saturating_add(1);
            }
        }
        earliest = u32::MAX;
        for next in self.visited.values() {
            if *next > now_secs {
                earliest = earliest.min(*next);
            }
        }
        self.next_prune = earliest.max(now_secs.saturating_add(MIN_PRUNE_GAP_SECS));
        self.fits(needed)
    }
}

/// Live addresses known to hold stores, for direct sampling.
/// Bounded and LRU-ish: full evicts the oldest. Memory ~130KB, negligible.
pub(crate) const LIVE_RING_CAP: usize = 4096;
/// Consecutive probe failures (errors or empty answers) that evict an entry.
const LIVE_MAX_FAILS: u32 = 3;

struct LiveEntry {
    addr: SocketAddr,
    fails: u32,
}

/// Addresses that recently proved live (successful fetches, connected hint
/// peers, inbound `announce_peer` endpoints). `sample_infohashes` needs no
/// node ID, so bare addresses are enough to query.
pub(crate) struct LiveRing {
    entries: VecDeque<LiveEntry>,
    index: HashSet<SocketAddr>,
}

impl LiveRing {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            index: HashSet::new(),
        }
    }

    /// Records a sighting of life; resets the fail count. Bounded: the
    /// oldest entry leaves at capacity.
    fn offer(&mut self, addr: SocketAddr) {
        if self.index.contains(&addr) {
            if let Some(e) = self.entries.iter_mut().find(|e| e.addr == addr) {
                e.fails = 0;
            }
            return;
        }
        while self.entries.len() >= LIVE_RING_CAP {
            if let Some(old) = self.entries.pop_front() {
                self.index.remove(&old.addr);
            } else {
                break;
            }
        }
        self.entries.push_back(LiveEntry { addr, fails: 0 });
        self.index.insert(addr);
    }

    /// A random entry of `family`, if any. Empty ring degrades to no probe,
    /// never panics — important at cold start.
    fn pick(&self, family: Family) -> Option<SocketAddr> {
        let mut n = 0usize;
        let mut chosen: Option<SocketAddr> = None;
        for e in &self.entries {
            if Family::of(&e.addr) != family {
                continue;
            }
            n = n.saturating_add(1);
            // Reservoir sampling: single pass, uniform, no allocation.
            if rand::random_range(0..n) == 0 {
                chosen = Some(e.addr);
            }
        }
        chosen
    }

    /// Records a probe verdict. `Some(true)` resets the fail count;
    /// `Some(false)` strikes (evicts at [`LIVE_MAX_FAILS`); returns true
    /// when evicted); `None` leaves the entry alone — filtered, throttled,
    /// cancelled or busy is no verdict on the address.
    /// A re-offered address resets via [`LiveRing::offer`].
    fn note(&mut self, addr: SocketAddr, live: Option<bool>) -> bool {
        let Some(fails) = self
            .entries
            .iter_mut()
            .find(|e| e.addr == addr)
            .map(|e| &mut e.fails)
        else {
            return false;
        };
        match live {
            Some(true) => {
                *fails = 0;
                false
            }
            Some(false) => {
                *fails = fails.saturating_add(1);
                if *fails >= LIVE_MAX_FAILS {
                    self.entries.retain(|e| e.addr != addr);
                    self.index.remove(&addr);
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Sampler state shared by the workers of both families.
pub(crate) struct Sampler {
    /// Samples each source network may still yield.
    quota: Mutex<WindowQuota>,
    /// Consecutive `sample_infohashes` timeouts per address (backoff ladder).
    timeouts: Mutex<LruCache<SocketAddr, u8>>,
    v4: Mutex<Frontier>,
    v6: Mutex<Frontier>,
    refilling_v4: AtomicBool,
    refilling_v6: AtomicBool,
    /// Live addresses for direct probing.
    live: Mutex<LiveRing>,
}

impl Sampler {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            quota: Mutex::new(WindowQuota::new(
                SAMPLES_PER_NETWORK,
                SAMPLE_QUOTA_WINDOW,
                SAMPLE_QUOTA_CAPACITY,
            )),
            timeouts: Mutex::new(LruCache::new(TIMEOUT_STRIKE_CAPACITY)),
            v4: Mutex::new(Frontier::new(now)),
            v6: Mutex::new(Frontier::new(now)),
            refilling_v4: AtomicBool::new(false),
            refilling_v6: AtomicBool::new(false),
            live: Mutex::new(LiveRing::new()),
        }
    }

    /// Consecutive timeouts of `addr` after recording one more, capped.
    fn timeout_strike(&self, addr: SocketAddr) -> u8 {
        let mut strikes = lock(&self.timeouts);
        let n = strikes
            .get(&addr)
            .copied()
            .unwrap_or(0)
            .saturating_add(1)
            .max(1);
        strikes.put(addr, n);
        n
    }

    /// Forgets the timeout strikes of `addr` (any non-timeout outcome).
    fn clear_timeout_strike(&self, addr: SocketAddr) {
        lock(&self.timeouts).pop(&addr);
    }

    fn frontier(&self, family: Family) -> &Mutex<Frontier> {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }

    fn refilling(&self, family: Family) -> &AtomicBool {
        match family {
            Family::V4 => &self.refilling_v4,
            Family::V6 => &self.refilling_v6,
        }
    }

    /// Offers already-filtered nodes of `family`. Returns how many were queued.
    pub(crate) fn offer(&self, family: Family, nodes: &[CompactNode], now: Instant) -> usize {
        let mut frontier = lock(self.frontier(family));
        nodes.iter().filter(|n| frontier.offer(**n, now)).count()
    }

    /// Offers a live address for direct probing. Bare
    /// addresses only — `sample_infohashes` needs no node ID.
    pub(crate) fn offer_live(&self, addr: SocketAddr) {
        lock(&self.live).offer(addr);
    }

    /// Takes up to [`MAX_SAMPLES_PER_REPLY`] of `samples` answered by `node`
    /// as `answered_as`, within the quota of the node's network.
    pub(crate) fn accept_samples(
        &self,
        policy: AddrPolicy,
        node: &CompactNode,
        answered_as: &NodeId,
        mut samples: Vec<DhtKey>,
        now: Instant,
    ) -> Vec<DhtKey> {
        if *answered_as != node.id {
            return Vec::new();
        }
        let network = policy.voter_key(&node.addr);
        let mut quota = lock(&self.quota);
        let allowed = usize::try_from(quota.remaining(&network, now)).unwrap_or(usize::MAX);
        samples.truncate(MAX_SAMPLES_PER_REPLY.min(allowed));
        quota.charge(
            network,
            u32::try_from(samples.len()).unwrap_or(u32::MAX),
            now,
        );
        samples
    }

    /// Queued candidates and visited entries of `family`.
    pub(crate) fn sizes(&self, family: Family) -> (usize, usize) {
        let frontier = lock(self.frontier(family));
        (frontier.len(), frontier.visited_len())
    }

    /// Ingests an Ok `sample_infohashes` response: clears the timeout
    /// strike, honours the interval skip, takes quota-bounded samples and
    /// emits them as `Source::Sample`. Shared by the frontier path and the
    /// live-probe path so probes flow through the normal
    /// admission path with no admission changes. Returns the resample
    /// decision plus the accepted sample count (0 = empty answer).
    fn ingest_ok(
        &self,
        inner: &Inner,
        sock: &SocketNode,
        node: &CompactNode,
        response: &Response,
    ) -> (Option<NodeId>, Duration, usize) {
        let tuning = &inner.cfg.tuning;
        self.clear_timeout_strike(node.addr);
        let (answered_as, skip) = sample_skip(&node.id, response, tuning);
        let mut count = 0usize;
        if answered_as.is_some()
            && let Some(samples) = response.samples.clone()
        {
            let samples = self.accept_samples(
                inner.policy,
                node,
                &response.id,
                samples,
                Instant::now(),
            );
            count = samples.len();
            let total = u64::try_from(count).unwrap_or(u64::MAX);
            add(&inner.counters.family(sock.family).samples, total);
            let from = canonical_ip(node.addr.ip());
            for key in samples {
                inner.emit(Discovered {
                    key,
                    source: Source::Sample,
                    peer: None,
                    seed: false,
                    from,
                });
            }
        }
        (answered_as, skip, count)
    }
}

/// Finishes a ticket, also when the sampling task is dropped midway.
struct TicketGuard<'a> {
    frontier: &'a Mutex<Frontier>,
    ticket: Option<Ticket>,
    /// Skip time used when the task ends without an outcome.
    fallback: Duration,
}

impl TicketGuard<'_> {
    fn finish(mut self, answered_as: Option<NodeId>, next_at: Instant) {
        if let Some(ticket) = self.ticket.take() {
            lock(self.frontier).finish(ticket, answered_as, next_at);
        }
    }
}

impl Drop for TicketGuard<'_> {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            let next_at = after_skip(Instant::now(), self.fallback);
            lock(self.frontier).finish(ticket, None, next_at);
        }
    }
}

/// One sampler worker; workers are spread over the address families.
pub(crate) async fn worker(inner: Arc<Inner>, index: usize) {
    let Some(sampler) = inner.sampler.as_ref() else {
        return;
    };
    let Some(count) = NonZeroUsize::new(inner.sockets.len()) else {
        return;
    };
    let Some(sock) = inner.sockets.get(index % count).cloned() else {
        return;
    };
    let idle = inner.cfg.tuning.sampler_idle_wait;
    while !inner.cancel.is_cancelled() {
        // a fraction of picks probe a random live address
        // instead of traversing the frontier. Empty ring degrades to the
        // frontier below, never panics — important at cold start. (The
        // pick is bound before the branch so no lock guard is held
        // across the probe's await.)
        let live_addr = if live_probe_due(&inner.cfg.tuning) {
            lock(&sampler.live).pick(sock.family)
        } else {
            None
        };
        if let Some(addr) = live_addr {
            sample_live(&inner, sampler, &sock, addr).await;
            continue;
        }
        let (pick, refused) = lock(sampler.frontier(sock.family)).pick(Instant::now());
        add(&inner.counters.sampler_visited_full, refused);
        let keep_going = match pick {
            Pick::Node(ticket) => {
                sample_one(&inner, sampler, &sock, ticket).await;
                true
            }
            // The visited map is full: wait for entries to expire.
            Pick::Full => inner.sleep(idle).await,
            Pick::Empty => {
                incr(&inner.counters.sampler_pick_empty);
                refill(&inner, sampler, &sock).await || inner.sleep(idle).await
            }
        };
        if !keep_going {
            break;
        }
    }
}

async fn sample_one(inner: &Inner, sampler: &Sampler, sock: &SocketNode, ticket: Ticket) {
    let tuning = &inner.cfg.tuning;
    let node = ticket.node;
    let frontier = sampler.frontier(sock.family);
    let guard = TicketGuard {
        frontier,
        ticket: Some(ticket),
        fallback: tuning.sample_min_resample,
    };
    // The last check before the datagram leaves: never sample a node early.
    let gate = |now: Instant| {
        let allowed = guard
            .ticket
            .as_ref()
            .is_some_and(|t| lock(frontier).send_allowed(t, now));
        if !allowed {
            incr(&inner.counters.sampler_early);
        }
        allowed
    };
    let method = Method::SampleInfohashes {
        target: NodeId::random(),
    };
    let result = inner
        .query_gated_with_timeout(
            sock,
            node.addr,
            method,
            Some(node.id),
            &gate,
            tuning.sampler_query_timeout,
        )
        .await;
    let (answered_as, skip) = match result {
        Ok(response) => {
            let (answered_as, skip, _) = sampler.ingest_ok(inner, sock, &node, &response);
            (answered_as, skip)
        }
        Err(QueryError::Timeout) => {
            let strikes = sampler.timeout_strike(node.addr);
            (
                None,
                timeout_backoff(
                    strikes,
                    tuning.sample_timeout_skip,
                    tuning.sample_unsupported_skip,
                ),
            )
        }
        Err(QueryError::Remote(_) | QueryError::Malformed) => {
            sampler.clear_timeout_strike(node.addr);
            (None, tuning.sample_unsupported_skip)
        }
        Err(_) => {
            sampler.clear_timeout_strike(node.addr);
            (None, tuning.sample_min_resample)
        }
    };
    guard.finish(answered_as, after_skip(Instant::now(), skip));
}

/// One direct probe of a live address: the same
/// `sample_infohashes` query the frontier path sends, travelling the normal
/// `query()` path so `may_contact` filtering, per-addr spacing and budgets
/// apply unchanged (a reallocation inside existing budgets, no new abuse
/// surface). No ticket, no frontier finish; the responder is attributed by
/// whatever ID answers (`expect: None`).
async fn sample_live(inner: &Inner, sampler: &Sampler, sock: &SocketNode, addr: SocketAddr) {
    let tuning = &inner.cfg.tuning;
    let method = Method::SampleInfohashes {
        target: NodeId::random(),
    };
    let result = inner
        .query_gated_with_timeout(
            sock,
            addr,
            method,
            None,
            &|_| true,
            tuning.sampler_query_timeout,
        )
        .await;
    // Only network verdicts count: timeouts and broken replies strike,
    // filtered/throttled/cancelled/busy sends leave the entry alone.
    let verdict = match &result {
        Ok(response) => {
            let node = CompactNode {
                id: response.id,
                addr,
            };
            let (_, _, count) = sampler.ingest_ok(inner, sock, &node, response);
            Some(count > 0)
        }
        Err(QueryError::Timeout | QueryError::Remote(_) | QueryError::Malformed) => {
            sampler.timeout_strike(addr);
            Some(false)
        }
        Err(_) => None,
    };
    if lock(&sampler.live).note(addr, verdict) {
        incr(&inner.counters.sampler_live_evicted);
    }
}

/// Whether this pick probes a live address. NaN share is belt-and-braces
/// false here (validation already rejects it).
fn live_probe_due(tuning: &DhtTuning) -> bool {
    let share = tuning.sampler_live_share;
    share > 0.0 && rand::random::<f64>() < share
}

/// Backoff and visited identity for a sample response, without touching
/// the quota or emitting anything. A wrong-ID answer is treated as
/// unsupported: its samples are dropped, the stranger's ID is not
/// remembered, and the endpoint backs off for `sample_unsupported_skip`
/// instead of the (attacker-chosen) interval.
fn sample_skip(
    node_id: &NodeId,
    response: &Response,
    tuning: &DhtTuning,
) -> (Option<NodeId>, Duration) {
    if response.id != *node_id {
        return (None, tuning.sample_unsupported_skip);
    }
    let skip = match &response.samples {
        Some(_) => {
            let interval = response
                .interval
                .and_then(|i| u64::try_from(i).ok())
                .unwrap_or(0)
                .min(MAX_SAMPLE_INTERVAL_SECS);
            Duration::from_secs(interval).max(tuning.sample_min_resample)
        }
        None => tuning.sample_unsupported_skip,
    };
    (Some(response.id), skip)
}

/// Refills the frontier from the routing table, or by walking towards a
/// random target. Returns true if the frontier has work.
async fn refill(inner: &Inner, sampler: &Sampler, sock: &SocketNode) -> bool {
    let now = Instant::now();
    let nodes: Vec<CompactNode> = {
        let st = lock(&sock.state);
        st.table.closest(&NodeId::random(), usize::MAX, now, false)
    };
    if sampler.offer(sock.family, &nodes, now) > 0 {
        return true;
    }
    let flag = sampler.refilling(sock.family);
    if flag.swap(true, Ordering::SeqCst) {
        return false;
    }
    let _guard = FlagGuard(flag);
    let deadline = after(now, inner.cfg.tuning.lookup_timeout);
    lookup::find_node(inner, sock, NodeId::random(), Vec::new(), deadline).await;
    lock(sampler.frontier(sock.family)).len() > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const SEC: Duration = Duration::from_secs(1);
    const HOUR: Duration = Duration::from_secs(3600);

    fn addr(i: u32) -> SocketAddr {
        SocketAddr::from(([8, (i >> 8) as u8, i as u8, 1], 6881))
    }

    fn id(i: u32) -> NodeId {
        let mut id = [0xaa; 20];
        id[..4].copy_from_slice(&i.to_be_bytes());
        NodeId(id)
    }

    fn node(i: u32) -> CompactNode {
        CompactNode {
            id: id(i),
            addr: addr(i),
        }
    }

    fn picked(f: &mut Frontier, now: Instant) -> Ticket {
        match f.pick(now) {
            (Pick::Node(t), _) => t,
            other => panic!("expected a node, got {other:?}"),
        }
    }

    fn check_bounds(f: &Frontier) {
        assert!(f.visited.len() + f.reserved <= f.visited_cap);
        assert!(f.queue.len() <= f.queue_cap);
        assert_eq!(f.queue.len(), f.queued.len());
    }

    #[test]
    fn frontier_dedups_and_bounds() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 3, 100);
        assert!(f.offer(node(1), t0));
        assert!(!f.offer(node(1), t0));
        assert!(f.offer(node(2), t0));
        assert!(f.offer(node(3), t0));
        assert!(!f.offer(node(3), t0));
        assert_eq!(f.len(), 3);
        let t = picked(&mut f, t0);
        assert_eq!(t.node, node(1));
        // Full: a newcomer pushes out the oldest entry.
        assert!(f.offer(node(4), t0));
        assert!(f.offer(node(5), t0));
        assert_eq!(f.len(), 3);
        assert!(!f.queued.contains(&addr(2)));
        // In flight: it cannot be queued again, under its endpoint or its ID.
        assert!(!f.offer(node(1), t0));
        assert!(!f.offer(
            CompactNode {
                id: id(1),
                addr: addr(9)
            },
            t0
        ));
        assert!(!f.offer(
            CompactNode {
                id: id(9),
                addr: addr(1)
            },
            t0
        ));
        f.finish(t, Some(id(1)), t0);
        assert!(f.offer(node(1), t0));
        check_bounds(&f);
    }

    #[test]
    fn full_frontier_serves_fresh_nodes() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 3, 100);
        for i in 1..=3 {
            assert!(f.offer(node(i), t0));
        }
        // An hour later a newly learned node still gets in, and is served
        // before the stale entries.
        let later = t0 + HOUR;
        assert!(f.offer(node(4), later));
        assert_eq!(picked(&mut f, later).node, node(4));
        check_bounds(&f);
    }

    #[test]
    fn stale_entries_are_skipped() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 10, 100);
        assert!(f.offer(node(1), t0));
        assert!(f.offer(node(2), t0 + HOUR));
        assert_eq!(picked(&mut f, t0 + HOUR).node, node(2));
        assert_eq!(f.len(), 0);
        check_bounds(&f);
    }

    #[test]
    fn skipped_not_due_nodes_stay_queued() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 10, 100);
        assert!(f.offer(node(1), t0));
        assert!(f.offer(node(2), t0));
        let t = picked(&mut f, t0);
        // Node 1 answers with node 2's ID, so node 2 is not due for a minute.
        f.finish(t, Some(id(2)), t0 + 60 * SEC);
        let (pick, _) = f.pick(t0);
        assert!(matches!(pick, Pick::Empty));
        // Not due is not gone: it waits for a later pick instead of being
        // evicted and needing a re-offer.
        assert_eq!(f.len(), 1);
        check_bounds(&f);
        assert_eq!(picked(&mut f, t0 + 61 * SEC).node, node(2));
        check_bounds(&f);
    }

    #[test]
    fn visited_full_nodes_stay_queued() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 3, 1);
        assert!(f.offer(node(1), t0));
        let (pick, refused) = f.pick(t0);
        assert!(matches!(pick, Pick::Full));
        assert_eq!(refused, 1);
        // No room right now is not gone either: the entry stays queued.
        assert_eq!(f.len(), 1);
        check_bounds(&f);
    }

    #[test]
    fn wrong_id_sample_responses_back_off_unsupported() {
        let tuning = DhtTuning::default();
        let node = NodeId([7; 20]);
        let keys = vec![DhtKey([1; 20])];
        // Right ID with samples: answered as self, interval-based skip.
        let ok = Response {
            id: node,
            samples: Some(keys.clone()),
            interval: Some(0),
            ..Response::default()
        };
        let (answered_as, skip) = sample_skip(&node, &ok, &tuning);
        assert_eq!(answered_as, Some(node));
        assert_eq!(skip, tuning.sample_min_resample);
        // Wrong ID with samples and interval 0: unsupported backoff, and no
        // visited identity for the stranger's ID.
        let spoof = Response {
            id: NodeId([9; 20]),
            samples: Some(keys),
            interval: Some(0),
            ..Response::default()
        };
        let (answered_as, skip) = sample_skip(&node, &spoof, &tuning);
        assert_eq!(answered_as, None);
        assert_eq!(skip, tuning.sample_unsupported_skip);
        // Wrong ID without samples: same treatment.
        let silent = Response {
            id: NodeId([9; 20]),
            ..Response::default()
        };
        let (answered_as, skip) = sample_skip(&node, &silent, &tuning);
        assert_eq!(answered_as, None);
        assert_eq!(skip, tuning.sample_unsupported_skip);
    }

    #[test]
    fn replies_yield_bounded_samples() {
        let t0 = Instant::now();
        let s = Sampler::new(t0);
        let policy = AddrPolicy::default();
        let keys = |n: u8| -> Vec<DhtKey> { (0..n).map(|i| DhtKey([i; 20])).collect() };
        let a = node(1);
        assert_eq!(s.accept_samples(policy, &a, &a.id, keys(90), t0).len(), 20);
        assert_eq!(s.accept_samples(policy, &a, &a.id, keys(5), t0).len(), 5);
        // Under another ID: nothing.
        assert!(
            s.accept_samples(policy, &a, &id(99), keys(5), t0)
                .is_empty()
        );
        // One /24 yields at most SAMPLES_PER_NETWORK per window, whatever the node.
        let mut total = 0;
        for i in 2..40u32 {
            let n = CompactNode {
                id: id(i),
                addr: SocketAddr::from(([8, 8, 8, i as u8], 6881)),
            };
            total += s.accept_samples(policy, &n, &n.id, keys(20), t0).len();
        }
        assert_eq!(total, SAMPLES_PER_NETWORK as usize);
        let other = CompactNode {
            id: id(50),
            addr: SocketAddr::from(([9, 9, 9, 9], 6881)),
        };
        assert_eq!(
            s.accept_samples(policy, &other, &other.id, keys(20), t0)
                .len(),
            20
        );
        let a_later = t0 + SAMPLE_QUOTA_WINDOW;
        assert_eq!(
            s.accept_samples(policy, &a, &a.id, keys(20), a_later).len(),
            20
        );
    }

    #[test]
    fn scheduling_skips_nodes_until_due() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 100, 100);
        let (a, b) = (node(1), node(2));
        assert!(f.offer(a, t0));
        let t = picked(&mut f, t0);
        f.finish(t, Some(a.id), t0 + Duration::from_millis(1500));
        assert!(!f.eligible(&a, t0));
        assert!(!f.offer(a, t0 + SEC));
        // Rounded up to whole seconds: never earlier than asked.
        assert!(!f.eligible(&a, t0 + Duration::from_millis(1999)));
        assert!(f.eligible(&a, t0 + 2 * SEC));
        // A queued node whose ID is being sampled is skipped when popped.
        let a2 = CompactNode {
            id: a.id,
            addr: addr(9),
        };
        assert!(f.offer(a, t0 + 2 * SEC));
        assert!(f.offer(a2, t0 + 2 * SEC));
        let ta = picked(&mut f, t0 + 2 * SEC);
        assert_eq!(ta.node, a);
        assert!(matches!(f.pick(t0 + 2 * SEC).0, Pick::Empty));
        // Skipped, not evicted: the not-due entry stays queued for a later pick.
        assert_eq!(f.len(), 1);
        f.finish(ta, Some(a.id), t0 + 60 * SEC);
        assert!(!f.offer(a2, t0 + 59 * SEC));
        // Other nodes are unaffected.
        assert!(f.offer(b, t0 + 2 * SEC));
        assert_eq!(picked(&mut f, t0 + 2 * SEC).node, b);
        check_bounds(&f);
    }

    #[test]
    fn answered_id_is_remembered() {
        let t0 = Instant::now();
        // The same node behind a new port waits as well.
        let mut f = Frontier::with_capacity(t0, 100, 100);
        let a = node(1);
        f.offer(a, t0);
        let t = picked(&mut f, t0);
        f.finish(t, Some(a.id), t0 + 300 * SEC);
        let moved = CompactNode {
            id: a.id,
            addr: addr(7),
        };
        assert!(!f.offer(moved, t0 + 299 * SEC));
        assert!(f.offer(moved, t0 + 300 * SEC));

        // A node that never answered is remembered only by its endpoint.
        let mut f = Frontier::with_capacity(t0, 100, 100);
        let b = node(2);
        f.offer(b, t0);
        let t = picked(&mut f, t0);
        f.finish(t, None, t0 + HOUR);
        assert_eq!(f.visited.len(), 1);
        assert!(!f.offer(b, t0 + 10 * SEC));
        assert!(f.offer(
            CompactNode {
                id: b.id,
                addr: addr(8)
            },
            t0 + 10 * SEC
        ));

        // A node answering under another ID has that ID remembered too.
        let mut f = Frontier::with_capacity(t0, 100, 100);
        let c = node(3);
        f.offer(c, t0);
        let t = picked(&mut f, t0);
        f.finish(t, Some(id(30)), t0 + HOUR);
        assert_eq!(f.visited.len(), 2);
        assert!(!f.offer(
            CompactNode {
                id: id(30),
                addr: addr(30)
            },
            t0 + 10 * SEC
        ));
        assert!(f.offer(
            CompactNode {
                id: c.id,
                addr: addr(31)
            },
            t0 + 10 * SEC
        ));
        // ...but only if there is room for it: here the map is full with c's
        // own (expired) entries, which a new answer does not replace.
        let mut f = Frontier::with_capacity(t0, 100, 2);
        f.offer(c, t0);
        let t = picked(&mut f, t0);
        f.finish(t, Some(c.id), t0 + 10 * SEC);
        f.offer(c, t0 + 20 * SEC);
        let t = picked(&mut f, t0 + 20 * SEC);
        f.finish(t, Some(id(30)), t0 + HOUR);
        assert_eq!(f.visited.len(), 2);
        assert!(!f.eligible(&c, t0 + 30 * SEC));
        assert!(f.offer(
            CompactNode {
                id: id(30),
                addr: addr(30)
            },
            t0 + 30 * SEC
        ));
        check_bounds(&f);
    }

    #[test]
    fn answers_do_not_move_in_flight_nodes() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 10, 100);
        let (a, b) = (node(1), node(2));
        assert!(f.offer(a, t0));
        assert!(f.offer(b, t0));
        let ta = picked(&mut f, t0);
        let tb = picked(&mut f, t0);
        // b answers with a's ID while a is in flight: a's time must not change.
        f.finish(tb, Some(a.id), t0 + 300 * SEC);
        assert!(f.send_allowed(&ta, t0));
        f.finish(ta, Some(a.id), t0 + 300 * SEC);
        assert!(!f.eligible(&a, t0 + 299 * SEC));
    }

    #[test]
    fn early_sends_are_caught() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 10, 100);
        assert!(f.offer(node(1), t0));
        let t = picked(&mut f, t0);
        assert!(f.send_allowed(&t, t0));
        // If anything recorded a later time for a node in flight, the send path refuses.
        let at = f.secs_ceil(t0 + 60 * SEC);
        f.set_next(t.endpoint_key, at);
        assert!(!f.send_allowed(&t, t0 + 59 * SEC));
        assert!(f.send_allowed(&t, t0 + 60 * SEC));
        let at = f.secs_ceil(t0 + 120 * SEC);
        f.set_next(t.id_key, at);
        assert!(!f.send_allowed(&t, t0 + 60 * SEC));
    }

    #[test]
    fn full_visited_map_evicts_farthest_first() {
        let t0 = Instant::now();
        // Room for three nodes (an endpoint and an ID each).
        let mut f = Frontier::with_capacity(t0, 100, 6);
        for (i, skip) in [(0, HOUR), (1, 2 * HOUR), (2, 6 * HOUR)] {
            assert!(f.offer(node(i), t0));
            let t = picked(&mut f, t0);
            f.finish(t, Some(id(i)), t0 + skip);
        }
        assert_eq!(f.visited.len(), 6);
        // A new node is admitted by evicting the farthest entries (node 2's
        // 6h pair), not by refusing.
        assert!(f.offer(node(10), t0));
        let (pick, refused) = f.pick(t0 + 60 * SEC);
        assert!(matches!(pick, Pick::Node(ref t) if t.node == node(10)));
        assert_eq!(refused, 0);
        assert_eq!(f.visited.len(), 4);
        // The evicted node is forgotten; the nearer ones are not.
        assert!(f.eligible(&node(2), t0 + 60 * SEC));
        assert!(!f.eligible(&node(0), t0 + 60 * SEC));
        assert!(!f.eligible(&node(1), t0 + 60 * SEC));
        check_bounds(&f);
        // Right after an eviction the map is full again, so the next new
        // node waits for the throttle instead of rescanning at once.
        assert!(f.offer(node(11), t0 + 60 * SEC));
        let (pick, refused) = f.pick(t0 + 61 * SEC);
        assert!(matches!(pick, Pick::Full));
        assert_eq!(refused, 1);
        assert_eq!(f.len(), 1);
        check_bounds(&f);
    }

    #[test]
    fn in_flight_entries_block_eviction() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 100, 2);
        assert!(f.offer(node(1), t0));
        let t = picked(&mut f, t0);
        f.finish(t, Some(id(1)), t0 + 10 * SEC);
        // Node 1 is due again and picked: its expired entries are in flight.
        assert!(f.offer(node(1), t0 + 20 * SEC));
        let t1 = picked(&mut f, t0 + 20 * SEC);
        // No room for node 2: the only entries are expired but in flight,
        // and there is nothing unexpired to evict.
        assert!(f.offer(node(2), t0 + 20 * SEC));
        let (pick, refused) = f.pick(t0 + 20 * SEC);
        assert!(matches!(pick, Pick::Full));
        assert_eq!(refused, 1);
        assert_eq!(f.len(), 1);
        assert_eq!(f.visited.len(), 2);
        check_bounds(&f);
        // Once node 1 is done, node 2 is admitted and node 1's expired
        // entries are pruned.
        f.finish(t1, Some(id(1)), t0 + 100 * SEC);
        let (pick, refused) = f.pick(t0 + 100 * SEC);
        assert!(matches!(pick, Pick::Node(ref t) if t.node == node(2)));
        assert_eq!(refused, 0);
        assert_eq!(f.visited.len(), 0);
        check_bounds(&f);
    }

    #[test]
    fn timeout_backoff_ladder() {
        let base = HOUR;
        let max = 6 * HOUR;
        assert_eq!(timeout_backoff(1, base, max), HOUR);
        assert_eq!(timeout_backoff(2, base, max), 2 * HOUR);
        assert_eq!(timeout_backoff(3, base, max), 4 * HOUR);
        assert_eq!(timeout_backoff(4, base, max), 6 * HOUR);
        assert_eq!(timeout_backoff(5, base, max), 6 * HOUR);
        assert_eq!(timeout_backoff(u8::MAX, base, max), 6 * HOUR);
        // Custom base/max respected.
        assert_eq!(timeout_backoff(1, SEC, 10 * SEC), SEC);
        assert_eq!(timeout_backoff(2, SEC, 10 * SEC), 2 * SEC);
        assert_eq!(timeout_backoff(3, SEC, 10 * SEC), 4 * SEC);
        assert_eq!(timeout_backoff(4, SEC, 10 * SEC), 8 * SEC);
        assert_eq!(timeout_backoff(5, SEC, 10 * SEC), 10 * SEC);
        // Saturates, never exceeds max.
        assert_eq!(timeout_backoff(u8::MAX, SEC, 10 * SEC), 10 * SEC);
        assert_eq!(
            timeout_backoff(3, Duration::MAX, Duration::MAX),
            Duration::MAX
        );
        assert_eq!(timeout_backoff(u8::MAX, HOUR, 6 * HOUR), 6 * HOUR);
    }

    #[test]
    fn timeout_strikes_increment_and_reset() {
        let t0 = Instant::now();
        let s = Sampler::new(t0);
        let (a, b) = (addr(1), addr(2));
        assert_eq!(s.timeout_strike(a), 1);
        assert_eq!(s.timeout_strike(a), 2);
        assert_eq!(s.timeout_strike(a), 3);
        // Another address is independent.
        assert_eq!(s.timeout_strike(b), 1);
        assert_eq!(s.timeout_strike(a), 4);
        // Any non-timeout outcome clears the strikes.
        s.clear_timeout_strike(a);
        assert_eq!(s.timeout_strike(a), 1);
        assert_eq!(s.timeout_strike(b), 2);
        s.clear_timeout_strike(b);
        // Clearing an unknown address is a no-op.
        s.clear_timeout_strike(addr(99));
        check_strike_bound(&s, 3);
    }

    #[test]
    fn timeout_strikes_are_bounded() {
        let t0 = Instant::now();
        let s = Sampler::new(t0);
        for i in 0..262_200u32 {
            s.timeout_strike(std::net::SocketAddr::from((
                std::net::Ipv4Addr::from(i),
                6881,
            )));
        }
        check_strike_bound(&s, 262_144);
    }

    fn check_strike_bound(s: &Sampler, max: usize) {
        assert!(lock(&s.timeouts).len() <= max);
    }

    #[test]
    fn in_flight_entries_survive_pruning() {
        let t0 = Instant::now();
        let mut f = Frontier::with_capacity(t0, 100, 4);
        f.offer(node(1), t0);
        let t = picked(&mut f, t0);
        f.finish(t, Some(id(1)), t0 + 10 * SEC);
        // Node 1 is due again and picked: its expired entries are in flight.
        f.offer(node(1), t0 + 20 * SEC);
        let t1 = picked(&mut f, t0 + 20 * SEC);
        f.offer(node(2), t0 + 20 * SEC);
        let t2 = picked(&mut f, t0 + 20 * SEC);
        check_bounds(&f);
        // No room for node 3, and pruning keeps node 1's entries.
        f.offer(node(3), t0 + 20 * SEC);
        assert!(matches!(f.pick(t0 + 20 * SEC).0, Pick::Full));
        assert_eq!(f.visited.len(), 2);
        f.finish(t1, Some(id(1)), t0 + 100 * SEC);
        f.finish(t2, Some(id(2)), t0 + 100 * SEC);
        assert_eq!(f.visited.len(), 4);
        check_bounds(&f);
    }

    /// Drives the frontier like the workers do, with a seeded random
    /// schedule, and checks every pick against a model of the recorded times.
    /// The visited map is big enough to never fill, so nothing is ever
    /// pruned or evicted and the model stays exact; capacity behavior has
    /// its own deterministic tests below.
    #[test]
    fn sends_are_never_early() {
        let mut rng = StdRng::seed_from_u64(51);
        let t0 = Instant::now();
        // 40 candidates over 35 endpoints and 30 IDs, in a map with room for all of them.
        let mut f = Frontier::with_capacity(t0, 64, 1000);
        let nodes: Vec<CompactNode> = (0..40)
            .map(|i| CompactNode {
                id: id(i % 30),
                addr: addr(i % 35),
            })
            .collect();
        let mut next_endpoint: HashMap<SocketAddr, Instant> = HashMap::new();
        let mut next_id: HashMap<NodeId, Instant> = HashMap::new();
        let mut outstanding: Vec<Ticket> = Vec::new();
        let mut now = t0;
        let (mut sent, mut early, mut refused) = (0u64, 0u64, 0u64);
        for _ in 0..20_000 {
            now += Duration::from_millis(rng.random_range(0..3000));
            for _ in 0..rng.random_range(0..6) {
                f.offer(nodes[rng.random_range(0..nodes.len())], now);
            }
            if outstanding.len() < 8 {
                let (pick, r) = f.pick(now);
                refused += r;
                if let Pick::Node(t) = pick {
                    assert!(
                        next_endpoint.get(&t.node.addr).is_none_or(|at| *at <= now),
                        "endpoint picked early"
                    );
                    assert!(
                        next_id.get(&t.node.id).is_none_or(|at| *at <= now),
                        "ID picked early"
                    );
                    // The send happens a little later, after the budget wait.
                    let send_at = now + Duration::from_millis(rng.random_range(0..4000));
                    if f.send_allowed(&t, send_at) {
                        sent += 1;
                    } else {
                        early += 1;
                    }
                    outstanding.push(t);
                }
            }
            if !outstanding.is_empty() && rng.random_bool(0.4) {
                let t = outstanding.swap_remove(rng.random_range(0..outstanding.len()));
                let answered_as = match rng.random_range(0..4) {
                    0 => None,
                    1 => Some(id(rng.random_range(0..30))),
                    _ => Some(t.node.id),
                };
                let next_at = now + Duration::from_millis(rng.random_range(0..300_000));
                let slot = next_endpoint.entry(t.node.addr).or_insert(next_at);
                *slot = (*slot).max(next_at);
                if answered_as == Some(t.node.id) {
                    let slot = next_id.entry(t.node.id).or_insert(next_at);
                    *slot = (*slot).max(next_at);
                }
                f.finish(t, answered_as, next_at);
            }
            check_bounds(&f);
        }
        assert_eq!(early, 0);
        assert!(sent > 1000, "only {sent} samples sent");
        assert_eq!(
            refused, 0,
            "the visited map filled up; the model is no longer exact"
        );
        eprintln!("sent {sent}, refused {refused}");
    }

    #[test]
    fn live_ring_offers_picks_and_evicts() {
        use std::net::SocketAddr;

        let mut ring = LiveRing::new();
        assert_eq!(ring.pick(Family::V4), None, "empty ring never panics");
        let a: SocketAddr = "1.1.1.1:6881".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:6881".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:6881".parse().unwrap();
        ring.offer(a);
        ring.offer(b);
        ring.offer(v6);
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pick(Family::V6), Some(v6), "family-filtered");
        for _ in 0..50 {
            let p = ring.pick(Family::V4).unwrap();
            assert!(p == a || p == b, "uniform over v4 entries");
        }
        // Re-offer resets the fail count.
        ring.note(a, Some(false));
        ring.note(a, Some(false));
        ring.offer(a);
        ring.note(a, Some(false));
        ring.note(a, Some(false));
        assert_eq!(ring.len(), 3, "reset strikes survive");
        ring.note(a, Some(false));
        assert_eq!(ring.len(), 2, "three consecutive strikes evict");
        // Non-verdicts leave the entry alone.
        ring.note(b, None);
        ring.note(b, None);
        assert_eq!(ring.len(), 2);
        // Success resets.
        ring.note(b, Some(false));
        ring.note(b, Some(true));
        ring.note(b, Some(false));
        ring.note(b, Some(false));
        assert_eq!(ring.len(), 2);
        // Unknown addresses are a no-op.
        assert!(!ring.note("3.3.3.3:6881".parse().unwrap(), Some(false)));
        // Bounded: oldest leaves at capacity.
        for i in 0..LIVE_RING_CAP + 10 {
            ring.offer(SocketAddr::from(([10, 0, 0, 1], 1024 + i as u16)));
        }
        assert_eq!(ring.len(), LIVE_RING_CAP);
    }

    #[test]
    fn live_probe_due_respects_share() {
        let mut tuning = DhtTuning::default();
        tuning.sampler_live_share = 0.0;
        assert!(!live_probe_due(&tuning));
        tuning.sampler_live_share = f64::NAN;
        assert!(!live_probe_due(&tuning), "NaN never probes");
        tuning.sampler_live_share = 1.0;
        assert!(live_probe_due(&tuning));
    }
}
