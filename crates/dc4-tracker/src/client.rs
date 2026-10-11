//! UDP tracker pool: connection-ID cache, scrape, one-shot announces.
//!
//! One socket per pool, replies demuxed by transaction ID. Trackers only
//! ever see `started` announces for keys the DHT already claimed —
//! post-claim, never speculative — capped to a random subset per key.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use dc4_core::DhtKey;
use lru::LruCache;
use rand::seq::IndexedRandom;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::codec::{self, AnnounceReply, MAX_SCRAPE_HASHES, Reply};
use crate::list::{TrackerEntry, resolve};

/// Connection IDs are reused this long before a fresh handshake.
const CONN_TTL: Duration = Duration::from_secs(60);
/// Consecutive failed sweeps that mark a server dead.
const DEAD_AFTER: u8 = 2;
/// Per-(key) announce floor when a tracker gives no interval.
const MIN_ANNOUNCE_FLOOR: u32 = 60;
/// Keys remembered for the re-announce floor.
const ANNOUNCE_MEMO_KEYS: usize = 16_384;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
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
pub struct TrackerPool {
    socket: UdpSocket,
    timeout: Duration,
    peer_id: [u8; 20],
    peer_port: u16,
    next_txn: AtomicU32,
    inflight: Mutex<HashMap<u32, oneshot::Sender<Reply>>>,
    conns: Mutex<HashMap<SocketAddr, (u64, Instant)>>,
    servers: Mutex<ServerSet>,
    announced: Mutex<LruCache<DhtKey, (Instant, u32)>>,
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
                ANNOUNCE_MEMO_KEYS.try_into().ok().unwrap_or(
                    std::num::NonZeroUsize::new(1).expect("non-zero"),
                ),
            )),
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

    /// Uniform random subset of the live set (seeded per call from the OS).
    pub fn pick_live(&self, k: usize) -> Vec<LiveServer> {
        let set = lock(&self.servers);
        let mut rng = rand::rng();
        let addrs: Vec<SocketAddr> = set.live.iter().copied().collect();
        addrs
            .choose_multiple(&mut rng, k.max(1).min(addrs.len().max(1)))
            .map(|a| LiveServer {
                label: set.label_of(a),
                addr: *a,
            })
            .collect()
    }

    /// Live server count (gauge).
    pub fn live_count(&self) -> usize {
        lock(&self.servers).live.len()
    }

    /// Known server count (gauge denominator).
    pub fn known_count(&self) -> usize {
        lock(&self.servers).servers.len()
    }

    /// True when `key` was announced within its floor: retries skip it.
    pub fn announced_recently(&self, key: &DhtKey, now: Instant) -> bool {
        lock(&self.announced)
            .get(key)
            .is_some_and(|(at, floor)| now.saturating_duration_since(*at) < Duration::from_secs(u64::from(*floor)))
    }

    /// One `connect` probe: the liveness check and the handshake.
    pub async fn probe(&self, addr: SocketAddr) -> bool {
        self.connect(addr).await.is_some()
    }

    /// Full liveness sweep: every known address gets one `connect` probe.
    /// Success marks live; two consecutive failures mark dead. Callers
    /// stagger calls; dead addresses are re-probed on the same sweep.
    pub async fn sweep(&self) {
        let addrs: Vec<SocketAddr> = {
            let set = lock(&self.servers);
            set.servers.iter().flat_map(|s| s.addrs.clone()).collect()
        };
        for addr in addrs {
            let ok = self.probe(addr).await;
            let mut set = lock(&self.servers);
            if ok {
                set.live.insert(addr);
                set.strikes.remove(&addr);
            } else {
                let n = set.strikes.get(&addr).copied().unwrap_or(0).saturating_add(1);
                set.strikes.insert(addr, n);
                if n >= DEAD_AFTER {
                    set.live.remove(&addr);
                }
            }
        }
    }

    /// Scrape `keys` at each server: per-key max seeders over the servers
    /// that answered, plus per-server success for metrics.
    pub async fn scrape(
        &self,
        servers: &[LiveServer],
        keys: &[DhtKey],
    ) -> (HashMap<DhtKey, u32>, Vec<(String, bool)>) {
        let mut seeders: HashMap<DhtKey, u32> = HashMap::new();
        let mut outcomes = Vec::with_capacity(servers.len());
        for s in servers {
            let mut ok = false;
            for chunk in keys.chunks(MAX_SCRAPE_HASHES) {
                if let Some(rows) = self.scrape_chunk(s.addr, chunk).await {
                    ok = true;
                    for (k, r) in chunk.iter().zip(rows.iter()) {
                        seeders
                            .entry(*k)
                            .and_modify(|v| *v = (*v).max(r.seeders))
                            .or_insert(r.seeders);
                    }
                }
            }
            outcomes.push((s.label.clone(), ok));
        }
        (seeders, outcomes)
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
    /// Always records the attempt so retries honor the floor.
    pub async fn announce(&self, servers: &[LiveServer], key: &DhtKey) -> AnnounceOutcome {
        let mut out = AnnounceOutcome::default();
        let mut seen = HashSet::new();
        for s in servers {
            let Some(conn) = self.connect(s.addr).await else {
                out.server_ok.push((s.label.clone(), false));
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
                for p in peers {
                    if seen.insert(p) {
                        out.peers.push(p);
                    }
                }
            } else {
                out.server_ok.push((s.label.clone(), false));
            }
        }
        let floor = out.interval_secs.max(MIN_ANNOUNCE_FLOOR);
        lock(&self.announced).put(*key, (Instant::now(), floor));
        out
    }

    /// Cached connection ID, or a fresh handshake. `None` on failure.
    async fn connect(&self, addr: SocketAddr) -> Option<u64> {
        if let Some((id, at)) = lock(&self.conns).get(&addr).copied()
            && at.elapsed() < CONN_TTL
        {
            return Some(id);
        }
        for _ in 0..2 {
            let txn = self.next_txn();
            let req = codec::encode_connect(txn).to_vec();
            if let Ok(Reply::Connect { connection_id }) = self.exchange(addr, req, txn).await {
                lock(&self.conns).insert(addr, (connection_id, Instant::now()));
                return Some(connection_id);
            }
        }
        None
    }

    /// Records a re-announce floor entry (tests).
    #[cfg(test)]
    fn memo_announced(&self, key: &DhtKey) {
        lock(&self.announced).put(*key, (Instant::now(), MIN_ANNOUNCE_FLOOR));
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
            let (len, _from) = match self.socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let packet = &buf[..len];
            if packet.len() < 8 {
                continue;
            }
            let action = u32::from_be_bytes(packet[0..4].try_into().unwrap_or([0; 4]));
            let txn = u32::from_be_bytes(packet[4..8].try_into().unwrap_or([0; 4]));
            let reply = match action {
                0 => codec::decode_connect(packet).map(|connection_id| Reply::Connect { connection_id }),
                1 => codec::decode_announce(packet).map(Reply::Announce),
                2 => codec::decode_scrape(packet, usize::MAX).map(Reply::Scrape),
                3 => {
                    if let Some(text) = codec::error_text(packet) {
                        tracing::debug!(txn, error = %text, "tracker error reply");
                    }
                    None
                }
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
        let (seeders, outcomes) = pool.scrape(&servers, &keys).await;
        assert_eq!(outcomes, vec![("mock".to_owned(), true)]);
        assert_eq!(seeders.get(&keys[0]), Some(&3));
        let out = pool.announce(&servers, &keys[0]).await;
        assert_eq!(out.ok_servers, 1);
        assert_eq!(out.interval_secs, 99);
        assert_eq!(out.peers, vec!["10.0.0.1:6881".parse().unwrap()]);
        assert!(pool.announced_recently(&keys[0], Instant::now()));
        // Connection ID cached: second scrape reuses it.
        assert_eq!(lock(&pool.conns).len(), 1);
    }
}
