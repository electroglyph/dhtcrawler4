//! UDP tracker pool: connection-ID cache, scrape, one-shot announces.
//!
//! One socket per pool, replies demuxed by transaction ID. Trackers only
//! ever see `started` announces for keys the DHT already claimed —
//! post-claim, never speculative — capped to a random subset per key.
//!
//! Privacy/abuse: announces expose our IP per hash to tracker operators
//! (same exposure class as DHT participation); `started`-only one-shots,
//! a random subset of live trackers per key, per-(key,tracker) floors from
//! each tracker's announce `interval` (`max(interval, 60s)` — UDP has no
//! `min interval`), liveness probes ~1 packet/server/hour. Re-announce
//! only when a tracker returned zero peers and the cooldown elapsed.
//!
//! Selection uses one OS-seeded [`rand::rngs::StdRng`] per pool (not per
//! call, not per key). Per-tracker metric labels are bounded (<= 32
//! servers) — see [`METRIC_CONN_REFRESH`].

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use dc4_core::DhtKey;
use lru::LruCache;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::codec::{self, AnnounceReply, MAX_SCRAPE_HASHES, Reply};
use crate::list::{TrackerEntry, resolve};

/// Connection IDs are reused this long before a fresh handshake.
const CONN_TTL: Duration = Duration::from_secs(60);
/// Consecutive failed sweeps that mark a server dead.
const DEAD_AFTER: u8 = 2;
/// Per-(key,tracker) announce floor when a tracker gives no interval.
/// UDP has no `min interval` field (that is HTTP-tracker only); the floor
/// is `max(interval, 60s)` from the announce *response* (`scrape`
/// responses carry no interval).
const MIN_ANNOUNCE_FLOOR: u32 = 60;
/// Keys remembered for the re-announce floor (per-key aggregate).
const ANNOUNCE_MEMO_KEYS: usize = 16_384;
/// (key,tracker) pairs remembered for per-tracker floors.
const ANNOUNCE_DETAIL_KEYS: usize = 16_384;
/// Max concurrent announces the pool documents (~32 worker pool in the
/// spec; announces run inline on fetch workers, see the crawl-role docs).
pub const ANNOUNCE_CONCURRENCY: usize = 32;

/// `dc4_tracker_conn_refresh_total{tracker,reason}`: connection-ID
/// refreshes, `reason="expiry"|"invalid"`. Per-tracker labels are bounded
/// (config validates `trackers.len() <= 32`; the vendored list holds 17
/// usable UDP entries), so cardinality is acceptable — document the bound
/// wherever this metric is exported.
pub const METRIC_CONN_REFRESH: &str = "dc4_tracker_conn_refresh_total";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// True for tracker `error` replies about a stale connection ID
/// (BEP 15 action 3, e.g. "Invalid connection ID").
fn is_invalid_conn_id(text: &str) -> bool {
    text.to_ascii_lowercase().contains("invalid connection")
}

/// A live tracker: label for metrics, address for packets.
#[derive(Clone, Debug)]
pub struct LiveServer {
    pub label: String,
    pub addr: SocketAddr,
}

struct ResolvedServer {
    label: String,
    addrs: Vec<SocketAddr>,
}

struct ServerSet {
    servers: Vec<ResolvedServer>,
    live: HashSet<SocketAddr>,
    strikes: HashMap<SocketAddr, u8>,
}

impl ServerSet {
    fn label_of(&self, addr: &SocketAddr) -> String {
        self.servers
            .iter()
            .find(|s| s.addrs.contains(addr))
            .map(|s| s.label.clone())
            .unwrap_or_else(|| addr.to_string())
    }
}

/// Outcome of announcing one key: unioned peers plus the longest
/// re-announce floor any tracker asked for.
#[derive(Clone, Debug, Default)]
pub struct AnnounceOutcome {
    pub peers: Vec<SocketAddr>,
    pub interval_secs: u32,
    pub ok_servers: usize,
    /// Per server: label and whether it answered.
    pub server_ok: Vec<(String, bool)>,
    /// Per server: label and peer count (pre-dedupe).
    pub server_peers: Vec<(String, usize)>,
}

/// The pool. Passive: the crawl role drives refresh and sweeps.
/// Per-tracker metric labels are bounded (see [`METRIC_CONN_REFRESH`]).
pub struct TrackerPool {
    socket: UdpSocket,
    timeout: Duration,
    peer_id: [u8; 20],
    peer_port: u16,
    next_txn: AtomicU32,
    inflight: Mutex<HashMap<u32, oneshot::Sender<Reply>>>,
    conns: Mutex<HashMap<SocketAddr, (u64, Instant)>>,
    servers: Mutex<ServerSet>,
    /// Per-key re-announce aggregate: (announced-at, max floor, unioned
    /// peers). Fast gate for retries; bounded to [`ANNOUNCE_MEMO_KEYS`].
    announced: Mutex<LruCache<DhtKey, (Instant, u32, usize)>>,
    /// Per-(key,tracker) floor: ((key, tracker label), (announced-at,
    /// that tracker's floor, that tracker's peer count)). Honors each
    /// tracker's announce-response `interval` as its own floor; bounded
    /// to [`ANNOUNCE_DETAIL_KEYS`] like hints.
    announced_by_tracker: Mutex<LruCache<(DhtKey, String), (Instant, u32, usize)>>,
    /// Seeded once per pool from the OS (not per call, not per key — no
    /// correlation games). Tests pin it via `seed_rng` for determinism.
    rng: Mutex<StdRng>,
}

impl TrackerPool {
    /// Binds a socket and starts the reply demux loop. `peer_port` is the
    /// TCP port announced (the crawler is dial-out-only; it only affects
    /// inbound attempts toward us, which fail harmlessly).
    pub async fn start(
        entries: Vec<TrackerEntry>,
        peer_port: u16,
        timeout: Duration,
    ) -> std::io::Result<Arc<Self>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut peer_id = [0u8; 20];
        peer_id[..8].copy_from_slice(b"-DC0700-");
        peer_id[8..].copy_from_slice(&rand::random::<[u8; 12]>());
        let pool = Arc::new(Self {
            socket,
            timeout,
            peer_id,
            peer_port,
            next_txn: AtomicU32::new(rand::random()),
            inflight: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            servers: Mutex::new(ServerSet {
                servers: Vec::new(),
                live: HashSet::new(),
                strikes: HashMap::new(),
            }),
            announced: Mutex::new(LruCache::new(
                ANNOUNCE_MEMO_KEYS
                    .try_into()
                    .ok()
                    .unwrap_or(std::num::NonZeroUsize::new(1).expect("non-zero")),
            )),
            announced_by_tracker: Mutex::new(LruCache::new(
                ANNOUNCE_DETAIL_KEYS
                    .try_into()
                    .ok()
                    .unwrap_or(std::num::NonZeroUsize::new(1).expect("non-zero")),
            )),
            // Seeded once from the OS: `rand::random` draws from the
            // OS RNG, so each pool gets an unpredictable stream.
            rng: Mutex::new(StdRng::from_seed(rand::random::<[u8; 32]>())),
        });
        pool.set_servers(entries).await;
        let recv = Arc::clone(&pool);
        tokio::spawn(async move { recv.demux_loop().await });
        Ok(pool)
    }

    /// Replaces the server set (refresh): re-resolves, keeps liveness for
    /// still-known addresses, new addresses start live.
    pub async fn set_servers(&self, entries: Vec<TrackerEntry>) {
        let mut servers = Vec::with_capacity(entries.len());
        for e in &entries {
            let addrs = resolve(e).await;
            if addrs.is_empty() {
                tracing::warn!(tracker = %e.addr_string(), "tracker does not resolve; skipped");
                continue;
            }
            servers.push(ResolvedServer {
                label: e.addr_string(),
                addrs,
            });
        }
        let mut set = lock(&self.servers);
        let mut live = HashSet::new();
        let mut strikes = HashMap::new();
        for s in &servers {
            for a in &s.addrs {
                if set.live.contains(a) || !set.strikes.contains_key(a) {
                    live.insert(*a);
                } else {
                    strikes.insert(*a, set.strikes.get(a).copied().unwrap_or(0));
                }
            }
        }
        set.servers = servers;
        set.live = live;
        set.strikes = strikes;
        lock(&self.conns).retain(|a, _| set.live.contains(a));
    }

    /// Uniform random subset of the live set (seeded pool RNG).
    /// If the live set is smaller than `k`, returns what is live; if
    /// empty, returns empty (DHT-only fallback, counted upstream).
    pub fn pick_live(&self, k: usize) -> Vec<LiveServer> {
        if k == 0 {
            return Vec::new();
        }
        let set = lock(&self.servers);
        let mut rng = lock(&self.rng);
        let addrs: Vec<SocketAddr> = set.live.iter().copied().collect();
        addrs
            .choose_multiple(&mut *rng, k.min(addrs.len()))
            .map(|a| LiveServer {
                label: set.label_of(a),
                addr: *a,
            })
            .collect()
    }

    /// Pins the pool RNG (tests): deterministic selection afterwards.
    #[cfg(test)]
    fn seed_rng(&self, seed: u64) {
        *lock(&self.rng) = StdRng::seed_from_u64(seed);
    }

    /// Live server count (gauge).
    pub fn live_count(&self) -> usize {
        lock(&self.servers).live.len()
    }

    /// Known address count (gauge denominator, same units as live: socket
    /// addresses, not server entries — one entry can resolve to several).
    pub fn known_count(&self) -> usize {
        lock(&self.servers)
            .servers
            .iter()
            .map(|s| s.addrs.len())
            .sum()
    }

    /// Records one liveness verdict outside the sweep: success marks live
    /// and clears strikes, failure strikes (evicting at [`DEAD_AFTER`]).
    /// Scrape/announce traffic doubles as a probe so dead servers stop
    /// being selected long before the next hourly sweep.
    fn note_probe(&self, addr: SocketAddr, ok: bool) {
        let mut set = lock(&self.servers);
        if ok {
            // Only track known addresses: unknown addrs (e.g. test mocks
            // inserted directly into `live`) keep their existing state.
            if set.servers.iter().any(|s| s.addrs.contains(&addr)) {
                set.live.insert(addr);
                set.strikes.remove(&addr);
            }
            return;
        }
        if !set.servers.iter().any(|s| s.addrs.contains(&addr)) {
            return;
        }
        let n = set
            .strikes
            .get(&addr)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        set.strikes.insert(addr, n);
        if n >= DEAD_AFTER {
            set.live.remove(&addr);
        }
    }

    /// True when `key` was announced within its floor: retries skip it.
    /// The floor is the max announce-response `interval` over the
    /// servers tried (at least [`MIN_ANNOUNCE_FLOOR`]); see
    /// [`TrackerPool::tracker_floored`] for the per-tracker view and
    /// [`TrackerPool::last_had_peers`] for the zero-peers gate.
    pub fn announced_recently(&self, key: &DhtKey, now: Instant) -> bool {
        lock(&self.announced)
            .get(key)
            .is_some_and(|(at, floor, _)| {
                now.saturating_duration_since(*at) < Duration::from_secs(u64::from(*floor))
            })
    }

    /// True when the last announce for `key` returned peers: retries
    /// skip re-announcing (peers are already harvested into the dial
    /// queue). Re-announce is only for the zero-peers case once the
    /// per-(key,tracker) cooldown elapsed. Holds until LRU eviction.
    pub fn last_had_peers(&self, key: &DhtKey) -> bool {
        lock(&self.announced)
            .get(key)
            .is_some_and(|(_, _, n)| *n > 0)
    }

    /// True when `key` was announced to `label` within that tracker's
    /// own floor. Filters candidates so a retry can try unfloored
    /// trackers while floored ones cool down.
    pub fn tracker_floored(&self, key: &DhtKey, label: &str, now: Instant) -> bool {
        let probe = (*key, label.to_owned());
        lock(&self.announced_by_tracker)
            .get(&probe)
            .is_some_and(|(at, floor, _)| {
                now.saturating_duration_since(*at) < Duration::from_secs(u64::from(*floor))
            })
    }

    /// One `connect` probe: the liveness check and the handshake.
    pub async fn probe(&self, addr: SocketAddr) -> bool {
        self.connect(addr).await.is_some()
    }

    /// Full liveness sweep: every known address gets one `connect` probe.
    /// Success marks live; two consecutive failures mark dead. Probed with
    /// a short stagger (not a burst) so 17 servers do not hit the network
    /// at once; dead addresses are re-probed on the same sweep.
    pub async fn sweep(&self) {
        let addrs: Vec<SocketAddr> = {
            let set = lock(&self.servers);
            set.servers.iter().flat_map(|s| s.addrs.clone()).collect()
        };
        for (i, addr) in addrs.into_iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let ok = self.probe(addr).await;
            self.note_probe(addr, ok);
        }
    }

    /// Scrape `keys` at each server: per-key max seeders over the servers
    /// that answered, plus per-server success for metrics, plus per-server
    /// seed maps so callers can attribute seed hits per tracker.
    pub async fn scrape(
        &self,
        servers: &[LiveServer],
        keys: &[DhtKey],
    ) -> (
        HashMap<DhtKey, u32>,
        Vec<(String, bool)>,
        Vec<(String, HashMap<DhtKey, u32>)>,
    ) {
        let mut seeders: HashMap<DhtKey, u32> = HashMap::new();
        let mut outcomes = Vec::with_capacity(servers.len());
        let mut per_server = Vec::with_capacity(servers.len());
        for s in servers {
            let mut ok = false;
            let mut local: HashMap<DhtKey, u32> = HashMap::new();
            for chunk in keys.chunks(MAX_SCRAPE_HASHES) {
                if let Some(rows) = self.scrape_chunk(s.addr, chunk).await {
                    ok = true;
                    for (k, r) in chunk.iter().zip(rows.iter()) {
                        local.insert(*k, r.seeders);
                        seeders
                            .entry(*k)
                            .and_modify(|v| *v = (*v).max(r.seeders))
                            .or_insert(r.seeders);
                    }
                    self.note_probe(s.addr, true);
                } else {
                    self.note_probe(s.addr, false);
                }
            }
            outcomes.push((s.label.clone(), ok));
            per_server.push((s.label.clone(), local));
        }
        (seeders, outcomes, per_server)
    }

    /// One scrape chunk with a single reconnect-and-retry on failure.
    async fn scrape_chunk(
        &self,
        addr: SocketAddr,
        chunk: &[DhtKey],
    ) -> Option<Vec<crate::codec::ScrapeRow>> {
        let mut conn = self.connect(addr).await?;
        for _ in 0..2 {
            let txn = self.next_txn();
            let req = codec::encode_scrape(conn, txn, chunk);
            match self.exchange(addr, req, txn).await {
                Ok(Reply::Scrape(rows)) => return Some(rows),
                _ => {
                    self.drop_conn(addr);
                    conn = self.connect(addr).await?;
                }
            }
        }
        None
    }

    /// Announce `key` at each server: unioned peers, longest floor.
    /// Always records the attempt so retries honor the floor, per key
    /// and per (key,tracker). Failed servers memo a minimum-floor
    /// zero-peer entry so hammering a dead tracker is throttled too.
    pub async fn announce(&self, servers: &[LiveServer], key: &DhtKey) -> AnnounceOutcome {
        let now = Instant::now();
        let mut out = AnnounceOutcome::default();
        let mut seen = HashSet::new();
        for s in servers {
            let Some(conn) = self.connect(s.addr).await else {
                self.note_probe(s.addr, false);
                out.server_ok.push((s.label.clone(), false));
                lock(&self.announced_by_tracker)
                    .put((*key, s.label.clone()), (now, MIN_ANNOUNCE_FLOOR, 0));
                continue;
            };
            let txn = self.next_txn();
            let req = codec::encode_announce(conn, txn, key, &self.peer_id, self.peer_port);
            if let Ok(Reply::Announce(AnnounceReply {
                interval_secs,
                peers,
            })) = self.exchange(s.addr, req, txn).await
            {
                out.ok_servers += 1;
                out.server_ok.push((s.label.clone(), true));
                out.server_peers.push((s.label.clone(), peers.len()));
                out.interval_secs = out.interval_secs.max(interval_secs);
                self.note_probe(s.addr, true);
                let floor = interval_secs.max(MIN_ANNOUNCE_FLOOR);
                lock(&self.announced_by_tracker)
                    .put((*key, s.label.clone()), (now, floor, peers.len()));
                for p in peers {
                    if seen.insert(p) {
                        out.peers.push(p);
                    }
                }
            } else {
                // Failure (timeout or tracker `error`): drop the cached
                // ID so the next use re-handshakes. Invalid-ID errors
                // already dropped the cache + bumped the metric in the
                // demux loop; generic failures just drop.
                self.drop_conn(s.addr);
                self.note_probe(s.addr, false);
                out.server_ok.push((s.label.clone(), false));
                lock(&self.announced_by_tracker)
                    .put((*key, s.label.clone()), (now, MIN_ANNOUNCE_FLOOR, 0));
            }
        }
        let floor = out.interval_secs.max(MIN_ANNOUNCE_FLOOR);
        lock(&self.announced).put(*key, (now, floor, out.peers.len()));
        out
    }

    /// Cached connection ID, or a fresh handshake. `None` on failure.
    /// A successful refresh past [`CONN_TTL`] bumps
    /// [`METRIC_CONN_REFRESH`] with `reason="expiry"`.
    async fn connect(&self, addr: SocketAddr) -> Option<u64> {
        let expired = match lock(&self.conns).get(&addr).copied() {
            Some((id, at)) if at.elapsed() < CONN_TTL => return Some(id),
            Some(_) => true,
            None => false,
        };
        for _ in 0..2 {
            let txn = self.next_txn();
            let req = codec::encode_connect(txn).to_vec();
            if let Ok(Reply::Connect { connection_id }) = self.exchange(addr, req, txn).await {
                lock(&self.conns).insert(addr, (connection_id, Instant::now()));
                if expired {
                    let label = lock(&self.servers).label_of(&addr);
                    metrics::counter!(METRIC_CONN_REFRESH, "tracker" => label, "reason" => "expiry")
                        .increment(1);
                }
                return Some(connection_id);
            }
        }
        None
    }

    /// Records a re-announce floor entry (tests): per-key aggregate plus
    /// a zero-peer per-tracker entry is left to `announce` itself.
    #[cfg(test)]
    fn memo_announced(&self, key: &DhtKey) {
        lock(&self.announced).put(*key, (Instant::now(), MIN_ANNOUNCE_FLOOR, 0));
    }

    /// Backdates a cached connection ID (tests): forces expiry refresh.
    #[cfg(test)]
    fn backdate_conn_for_test(&self, addr: SocketAddr, at: Instant) {
        if let Some(entry) = lock(&self.conns).get_mut(&addr) {
            entry.1 = at;
        }
    }

    /// Drains the live set (test hook for simulating the live set
    /// emptying between triage entry and flush).
    pub fn clear_live_for_test(&self) {
        lock(&self.servers).live.clear();
    }

    /// Drops a cached connection ID (reconnect on next use).
    fn drop_conn(&self, addr: SocketAddr) {
        lock(&self.conns).remove(&addr);
    }

    fn next_txn(&self) -> u32 {
        self.next_txn.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends one request, awaits its reply with one retry on timeout.
    async fn exchange(&self, addr: SocketAddr, req: Vec<u8>, txn: u32) -> Result<Reply, ()> {
        for _ in 0..2 {
            let (tx, rx) = oneshot::channel();
            {
                let mut inflight = lock(&self.inflight);
                if inflight.contains_key(&txn) {
                    return Err(());
                }
                inflight.insert(txn, tx);
            }
            let sent = self.socket.send_to(&req, addr).await.is_ok();
            if !sent {
                lock(&self.inflight).remove(&txn);
                return Err(());
            }
            match tokio::time::timeout(self.timeout, rx).await {
                Ok(Ok(reply)) => {
                    lock(&self.inflight).remove(&txn);
                    return Ok(reply);
                }
                _ => {
                    lock(&self.inflight).remove(&txn);
                }
            }
        }
        Err(())
    }

    async fn demux_loop(&self) {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, from) = match self.socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let packet = &buf[..len];
            if packet.len() < 8 {
                continue;
            }
            let action = u32::from_be_bytes(packet[0..4].try_into().unwrap_or([0; 4]));
            let txn = u32::from_be_bytes(packet[4..8].try_into().unwrap_or([0; 4]));
            // Tracker `error` replies (action 3) previously vanished here
            // and waiters timed out. Now they wake the waiter as
            // `Reply::Error`, and an "invalid connection ID" text
            // immediately drops the cached ID for the replying tracker
            // plus bumps the refresh metric, so the caller's single
            // retry re-handshakes instead of reusing the dead ID.
            if action == 3 {
                let text = codec::error_text(packet).unwrap_or_default();
                tracing::debug!(txn, error = %text, "tracker error reply");
                if is_invalid_conn_id(&text) {
                    self.drop_conn(from);
                    let label = lock(&self.servers).label_of(&from);
                    metrics::counter!(METRIC_CONN_REFRESH, "tracker" => label, "reason" => "invalid")
                        .increment(1);
                }
                if let Some(tx) = lock(&self.inflight).remove(&txn) {
                    let _ = tx.send(Reply::Error(text));
                }
                continue;
            }
            let reply = match action {
                0 => codec::decode_connect(packet)
                    .map(|connection_id| Reply::Connect { connection_id }),
                1 => codec::decode_announce(packet).map(Reply::Announce),
                2 => codec::decode_scrape(packet, usize::MAX).map(Reply::Scrape),
                _ => None,
            };
            if let Some(reply) = reply
                && let Some(tx) = lock(&self.inflight).remove(&txn)
            {
                let _ = tx.send(reply);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::list::parse_list;

    #[tokio::test]
    async fn announce_floor_memo() {
        let pool = TrackerPool::start(Vec::new(), 6881, Duration::from_secs(1))
            .await
            .unwrap();
        let k = DhtKey([9; 20]);
        assert!(!pool.announced_recently(&k, Instant::now()));
        pool.memo_announced(&k);
        assert!(pool.announced_recently(&k, Instant::now()));
    }

    #[tokio::test]
    async fn scrape_and_announce_against_mock_tracker() {
        let (entries, _, _) = parse_list("udp://127.0.0.1:0/announce\n");
        assert!(entries.is_empty(), "port 0 rejected by the parser");
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut conn_id = 0x1111u64;
            loop {
                let (len, from) = sock.recv_from(&mut buf).await.unwrap();
                let pkt = &buf[..len];
                if len < 16 {
                    continue;
                }
                let action = u32::from_be_bytes(pkt[8..12].try_into().unwrap());
                let txn = u32::from_be_bytes(pkt[12..16].try_into().unwrap());
                match action {
                    0 => {
                        conn_id += 1;
                        let mut r = vec![0u8; 16];
                        r[0..4].copy_from_slice(&0u32.to_be_bytes());
                        r[4..8].copy_from_slice(&txn.to_be_bytes());
                        r[8..16].copy_from_slice(&conn_id.to_be_bytes());
                        sock.send_to(&r, from).await.unwrap();
                    }
                    2 => {
                        let n = (len - 16) / 20;
                        let mut r = vec![0u8; 8 + 12 * n];
                        r[0..4].copy_from_slice(&2u32.to_be_bytes());
                        r[4..8].copy_from_slice(&txn.to_be_bytes());
                        for i in 0..n {
                            r[8 + 12 * i..12 + 12 * i].copy_from_slice(&3u32.to_be_bytes());
                        }
                        sock.send_to(&r, from).await.unwrap();
                    }
                    1 => {
                        let mut r = vec![0u8; 20 + 6];
                        r[0..4].copy_from_slice(&1u32.to_be_bytes());
                        r[4..8].copy_from_slice(&txn.to_be_bytes());
                        r[8..12].copy_from_slice(&99u32.to_be_bytes());
                        r[20..24].copy_from_slice(&[10, 0, 0, 1]);
                        r[24..26].copy_from_slice(&6881u16.to_be_bytes());
                        sock.send_to(&r, from).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
        let pool = TrackerPool::start(Vec::new(), 6881, Duration::from_secs(2))
            .await
            .unwrap();
        {
            let mut set = lock(&pool.servers);
            set.servers.push(ResolvedServer {
                label: "mock".into(),
                addrs: vec![tracker_addr],
            });
            set.live.insert(tracker_addr);
        }
        let servers = pool.pick_live(3);
        assert_eq!(servers.len(), 1);
        let keys = vec![DhtKey([1; 20]), DhtKey([2; 20])];
        let (seeders, outcomes, _) = pool.scrape(&servers, &keys).await;
        assert_eq!(outcomes, vec![("mock".to_owned(), true)]);
        assert_eq!(seeders.get(&keys[0]), Some(&3));
        let out = pool.announce(&servers, &keys[0]).await;
        assert_eq!(out.ok_servers, 1);
        assert_eq!(out.interval_secs, 99);
        assert_eq!(out.peers, vec!["10.0.0.1:6881".parse().unwrap()]);
        assert!(pool.announced_recently(&keys[0], Instant::now()));
        // Connection ID cached: second scrape reuses it.
        assert_eq!(lock(&pool.conns).len(), 1);
        // Per-tracker floor + had-peers gate: the announcing tracker is
        // floored, an untried label is not, and the key counts as peerful.
        assert!(pool.tracker_floored(&keys[0], "mock", Instant::now()));
        assert!(!pool.tracker_floored(&keys[0], "other", Instant::now()));
        assert!(pool.last_had_peers(&keys[0]));
        assert!(!pool.last_had_peers(&keys[1]));
    }

    #[tokio::test]
    async fn selection_is_seeded_k_subset_and_empty() {
        let pool = TrackerPool::start(Vec::new(), 6881, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(pool.pick_live(3).is_empty(), "empty live set picks empty");
        assert!(pool.pick_live(0).is_empty(), "k=0 picks empty even when live");
        let addrs: Vec<SocketAddr> = (0..5)
            .map(|i| SocketAddr::from(([10, 0, 0, 1], 6900 + i)))
            .collect();
        {
            let mut set = lock(&pool.servers);
            set.servers.push(ResolvedServer {
                label: "five".into(),
                addrs: addrs.clone(),
            });
            for a in &addrs {
                set.live.insert(*a);
            }
        }
        assert!(pool.pick_live(0).is_empty(), "k=0 picks empty when live");
        pool.seed_rng(42);
        let first = pool.pick_live(3);
        assert_eq!(first.len(), 3, "k-subset of the 5 live addrs");
        pool.seed_rng(42);
        let second = pool.pick_live(3);
        assert_eq!(
            first.iter().map(|s| s.addr).collect::<Vec<_>>(),
            second.iter().map(|s| s.addr).collect::<Vec<_>>(),
            "seeded RNG is deterministic"
        );
        let all = pool.pick_live(99);
        assert_eq!(all.len(), 5, "k larger than live returns what is live");
    }

    #[test]
    fn invalid_conn_id_text_matches() {
        assert!(is_invalid_conn_id("Invalid connection ID"));
        assert!(is_invalid_conn_id("invalid connection id (timeout)"));
        assert!(!is_invalid_conn_id("failure reason"));
        assert!(!is_invalid_conn_id(""));
    }

    #[tokio::test]
    async fn conn_expiry_refreshes_the_handshake() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut conn_id = 0x2000u64;
            loop {
                let (len, from) = sock.recv_from(&mut buf).await.unwrap();
                if len < 16 {
                    continue;
                }
                let action = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                let txn = u32::from_be_bytes(buf[12..16].try_into().unwrap());
                if action != 0 {
                    continue;
                }
                conn_id += 1;
                let mut r = vec![0u8; 16];
                r[0..4].copy_from_slice(&0u32.to_be_bytes());
                r[4..8].copy_from_slice(&txn.to_be_bytes());
                r[8..16].copy_from_slice(&conn_id.to_be_bytes());
                sock.send_to(&r, from).await.unwrap();
            }
        });
        let pool = TrackerPool::start(Vec::new(), 6881, Duration::from_secs(2))
            .await
            .unwrap();
        {
            let mut set = lock(&pool.servers);
            set.servers.push(ResolvedServer {
                label: "mock".into(),
                addrs: vec![tracker_addr],
            });
            set.live.insert(tracker_addr);
        }
        let first = pool.connect(tracker_addr).await.expect("handshake");
        pool.backdate_conn_for_test(tracker_addr, Instant::now() - CONN_TTL - Duration::from_secs(1));
        let second = pool.connect(tracker_addr).await.expect("refresh");
        assert_ne!(first, second, "expired ID must re-handshake, not reuse");
    }

    #[tokio::test]
    async fn sweep_marks_dead_after_two_failures_and_live_on_success() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = sock.local_addr().unwrap();
        let serve = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (len, from) = sock.recv_from(&mut buf).await.unwrap();
                if len < 16 {
                    continue;
                }
                let txn = u32::from_be_bytes(buf[12..16].try_into().unwrap());
                let mut r = vec![0u8; 16];
                r[0..4].copy_from_slice(&0u32.to_be_bytes());
                r[4..8].copy_from_slice(&txn.to_be_bytes());
                r[8..16].copy_from_slice(&0x3333u64.to_be_bytes());
                sock.send_to(&r, from).await.unwrap();
            }
        });
        let pool = TrackerPool::start(Vec::new(), 6881, Duration::from_millis(150))
            .await
            .unwrap();
        {
            let mut set = lock(&pool.servers);
            set.servers.push(ResolvedServer {
                label: "flap".into(),
                addrs: vec![tracker_addr],
            });
            set.live.insert(tracker_addr);
        }
        pool.sweep().await;
        assert_eq!(pool.live_count(), 1, "answering tracker stays live");
        serve.abort();
        // Give the OS a moment to release the port so probes fail fast.
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The live sweep cached a connection ID: force expiry so the next
        // sweeps really probe the (now dead) port instead of reusing it.
        pool.backdate_conn_for_test(tracker_addr, Instant::now() - CONN_TTL - Duration::from_secs(1));
        pool.sweep().await;
        assert_eq!(pool.live_count(), 1, "one failure strikes but keeps live");
        pool.sweep().await;
        assert_eq!(pool.live_count(), 0, "two consecutive failures mark dead");
        assert_eq!(pool.known_count(), 1, "known denominator counts addrs");
    }

    #[tokio::test]
    async fn scrape_reports_per_server_seed_maps() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut conn_id = 0x4400u64;
            loop {
                let (len, from) = sock.recv_from(&mut buf).await.unwrap();
                if len < 16 {
                    continue;
                }
                let action = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                let txn = u32::from_be_bytes(buf[12..16].try_into().unwrap());
                match action {
                    0 => {
                        conn_id += 1;
                        let mut r = vec![0u8; 16];
                        r[0..4].copy_from_slice(&0u32.to_be_bytes());
                        r[4..8].copy_from_slice(&txn.to_be_bytes());
                        r[8..16].copy_from_slice(&conn_id.to_be_bytes());
                        sock.send_to(&r, from).await.unwrap();
                    }
                    2 => {
                        let n = (len - 16) / 20;
                        let mut r = vec![0u8; 8 + 12 * n];
                        r[0..4].copy_from_slice(&2u32.to_be_bytes());
                        r[4..8].copy_from_slice(&txn.to_be_bytes());
                        for i in 0..n {
                            // First key looks live (7 seeders), rest dead.
                            let s = if i == 0 { 7u32 } else { 0u32 };
                            r[8 + 12 * i..12 + 12 * i].copy_from_slice(&s.to_be_bytes());
                        }
                        sock.send_to(&r, from).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
        let pool = TrackerPool::start(Vec::new(), 6881, Duration::from_secs(2))
            .await
            .unwrap();
        {
            let mut set = lock(&pool.servers);
            set.servers.push(ResolvedServer {
                label: "mock".into(),
                addrs: vec![tracker_addr],
            });
            set.live.insert(tracker_addr);
        }
        let servers = pool.pick_live(2);
        let keys = vec![DhtKey([5; 20]), DhtKey([6; 20])];
        let (seeders, outcomes, per_server) = pool.scrape(&servers, &keys).await;
        assert_eq!(outcomes, vec![("mock".to_owned(), true)]);
        assert_eq!(seeders.get(&keys[0]), Some(&7));
        assert_eq!(seeders.get(&keys[1]), Some(&0));
        assert_eq!(per_server.len(), 1);
        assert_eq!(per_server[0].1.get(&keys[0]), Some(&7));
        assert_eq!(per_server[0].1.get(&keys[1]), Some(&0));
    }

    #[tokio::test]
    async fn invalid_conn_id_error_drops_the_cache() {
        // The tracker answers `connect` fine but every announce with an
        // action-3 "Invalid connection ID": the pool must surface the
        // failure and drop the cached ID so the next use re-handshakes.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tracker_addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (len, from) = sock.recv_from(&mut buf).await.unwrap();
                if len < 16 {
                    continue;
                }
                let action = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                let txn = u32::from_be_bytes(buf[12..16].try_into().unwrap());
                if action == 0 {
                    let mut r = vec![0u8; 16];
                    r[0..4].copy_from_slice(&0u32.to_be_bytes());
                    r[4..8].copy_from_slice(&txn.to_be_bytes());
                    r[8..16].copy_from_slice(&0x9900u64.to_be_bytes());
                    sock.send_to(&r, from).await.unwrap();
                } else if action == 1 {
                    let msg = b"Invalid connection ID";
                    let mut r = vec![0u8; 8 + msg.len()];
                    r[0..4].copy_from_slice(&3u32.to_be_bytes());
                    r[4..8].copy_from_slice(&txn.to_be_bytes());
                    r[8..].copy_from_slice(msg);
                    sock.send_to(&r, from).await.unwrap();
                }
            }
        });
        let pool = TrackerPool::start(Vec::new(), 6881, Duration::from_secs(2))
            .await
            .unwrap();
        {
            let mut set = lock(&pool.servers);
            set.servers.push(ResolvedServer {
                label: "strict".into(),
                addrs: vec![tracker_addr],
            });
            set.live.insert(tracker_addr);
        }
        let servers = pool.pick_live(2);
        let key = DhtKey([11; 20]);
        let out = pool.announce(&servers, &key).await;
        assert_eq!(out.ok_servers, 0, "invalid-ID announce must fail");
        assert!(out.peers.is_empty());
        assert!(
            lock(&pool.conns).is_empty(),
            "invalid ID is dropped, next use re-handshakes"
        );
    }
}
