//! Tracker hybrid: scrape triage plus one-shot announces.
//!
//! Every claimed key joins one global scrape batcher (74 keys or 200 ms).
//! Each flush is scraped at a random subset of live trackers; keys with
//! seeders land in the announce stage, the rest stay DHT-only. Announce
//! results merge into the fetch dial queue like any other peers.
//!
//! Privacy/abuse: announces expose our IP per hash to tracker operators
//! (same exposure class as DHT participation). Good-citizen subset:
//! `started`-only one-shots, a random subset of live trackers per key
//! (never the whole list), per-(key,tracker) re-announce floors honoring
//! each tracker's announce-response `interval` (`max(interval, 60s)` —
//! UDP has no `min interval`, only `interval`; scrape responses carry
//! none), liveness probes ~1 packet/server/hour. Re-announce only when a
//! tracker returned zero peers and the cooldown elapsed: keys that
//! already yielded peers are not re-announced.
//!
//! Metric cardinality: per-tracker labels are bounded — explicit
//! `trackers` validate to <= 32 entries and the vendored list holds 17
//! usable UDP entries — so `tracker`-labeled series stay small. See
//! [`METRIC_CONN_REFRESH`].
//!
//! Deviations from the hybrid spec, documented not hidden:
//! - No dedicated 32-task announce pool: announces run inline on fetch
//!   workers, throttled by the shared [`PacketBudget`] plus a 32-permit
//!   semaphore ([`ANNOUNCE_CONCURRENCY`]), so at most 32 announces run
//!   at once without extra tasks.
//! - `tracker_list_url` defaults to `""` (refresh off): the tree has no
//!   TLS client (plain HTTP only), so the spec's `https://` default URL
//!   cannot be fetched — set an `http://` URL to enable refresh.
//! - Selection uses one OS-seeded RNG per pool (see `TrackerPool`), not
//!   per key.
//! - One socket per pool, not per tracker (fewer FDs, same pipelining).
//! - First-seen addresses start live optimistically (no blocking probe
//!   at startup); traffic verdicts + the hourly sweep evict the dead.
//! - Announce selection is filter-then-sample over unfloored servers, so
//!   one floored draw never blocks unfloored capacity.
//! - Scrape flushes charge 2 packets/server (connect + scrape floor;
//!   retries uncounted); announces charge 2/server.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use dc4_core::DhtKey;
use dc4_tracker::{LiveServer, TrackerPool, parse_list};
use tokio::sync::Semaphore;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::config::CrawlConfig;
use crate::stores::CrawlStore;

const BATCH_KEYS: usize = dc4_tracker::MAX_SCRAPE_HASHES;
const BATCH_WINDOW: Duration = Duration::from_millis(200);
const SWEEP_SECS: u64 = 3_600;
/// Max concurrent announces: the spec's ~32 worker pool, implemented as
/// a semaphore around inline announces (no dedicated tasks).
const ANNOUNCE_CONCURRENCY: usize = dc4_tracker::ANNOUNCE_CONCURRENCY;

pub const METRIC_ANNOUNCES: &str = "dc4_tracker_announces_total";
pub const METRIC_PEERS: &str = "dc4_tracker_peers_total";
pub const METRIC_TIMEOUTS: &str = "dc4_tracker_timeouts_total";
pub const METRIC_SCRAPES: &str = "dc4_tracker_scrapes_total";
pub const METRIC_SCRAPED_KEYS: &str = "dc4_tracker_scraped_keys_total";
pub const METRIC_SEED_HITS: &str = "dc4_tracker_seed_hits_total";
pub const METRIC_LIST_REFRESH: &str = "dc4_tracker_list_refresh_total";
pub const METRIC_LIST_SERVERS: &str = "dc4_tracker_list_servers";
/// Connection-ID refreshes by tracker and reason (`expiry`|`invalid`),
/// emitted by the pool. Per-tracker cardinality is bounded (<= 32
/// servers; see the module docs).
pub const METRIC_CONN_REFRESH: &str = dc4_tracker::METRIC_CONN_REFRESH;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Tracker knobs, copied out of [`CrawlConfig`] at startup. `Default` is
/// disabled, so test roles start no pool and open no sockets.
#[derive(Debug, Clone)]
pub struct TrackerConfig {
    pub enabled: bool,
    pub trackers: Vec<String>,
    pub list_url: String,
    pub list_refresh: Duration,
    pub announces_per_key: u32,
    pub scrape_fanout: u32,
    pub packets_per_sec: u32,
    pub timeout: Duration,
    pub peer_port: u16,
}

impl TrackerConfig {
    pub fn from_config(c: &CrawlConfig) -> Self {
        Self {
            enabled: c.tracker_enabled,
            trackers: c.trackers.clone(),
            list_url: c.tracker_list_url.clone(),
            list_refresh: Duration::from_secs(c.tracker_list_refresh_secs),
            announces_per_key: c.tracker_announces_per_key,
            scrape_fanout: c.tracker_scrape_fanout,
            packets_per_sec: c.tracker_packets_per_sec,
            timeout: Duration::from_secs(c.tracker_timeout_secs),
            peer_port: c.dht_port,
        }
    }
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            trackers: Vec::new(),
            list_url: String::new(),
            list_refresh: Duration::from_secs(86_400),
            announces_per_key: 5,
            scrape_fanout: 3,
            packets_per_sec: 200,
            timeout: Duration::from_secs(5),
            peer_port: 6881,
        }
    }
}

/// Token bucket for tracker packets (1 s burst), shared pool-wide.
struct PacketBudget {
    rate: f64,
    state: Mutex<(f64, Instant)>,
}

impl PacketBudget {
    fn new(packets_per_sec: u32) -> Self {
        Self {
            rate: packets_per_sec.max(1) as f64,
            state: Mutex::new((packets_per_sec.max(1) as f64, Instant::now())),
        }
    }

    async fn acquire(&self, n: usize) {
        let mut need = n as f64;
        while need > 0.0 {
            let wait = {
                let mut state = lock(&self.state);
                let now = Instant::now();
                let (tokens, last) = &mut *state;
                *tokens = (*tokens
                    + now.saturating_duration_since(*last).as_secs_f64() * self.rate)
                    .min(self.rate);
                *last = now;
                if *tokens >= need {
                    *tokens -= need;
                    need = 0.0;
                    Duration::ZERO
                } else {
                    need -= *tokens;
                    *tokens = 0.0;
                    Duration::from_secs_f64(need / self.rate)
                }
            };
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
    }
}

struct Pending {
    key: DhtKey,
    tx: oneshot::Sender<Option<u32>>,
}

/// Scrape batcher: collects claimed keys and flushes at 74 keys
/// ([`BATCH_KEYS`] = one datagram) or every ~200 ms ([`BATCH_WINDOW`]),
/// whichever comes first. Whoever fills the batch or times out flushes
/// it; every pending key gets its verdict, so no key is left behind.
struct ScrapeBatcher {
    pending: Vec<Pending>,
}

impl ScrapeBatcher {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }
}

/// The crawl role's handle: pool, batcher, budget, store. `None` in the
/// fetcher means trackers are off and fetch is DHT-only.
pub struct TrackerHandle<S> {
    pool: Arc<TrackerPool>,
    tuning: TrackerConfig,
    budget: PacketBudget,
    batch: Mutex<ScrapeBatcher>,
    announce_sem: Arc<Semaphore>,
    store: S,
}

impl<S: CrawlStore> TrackerHandle<S> {
    /// Starts the pool on the vendored snapshot plus any explicit `trackers`
    /// (which replace, not merge). Returns `None` when disabled.
    pub async fn start(c: &TrackerConfig, store: S) -> Option<Arc<Self>> {
        if !c.enabled {
            return None;
        }
        let tuning = c.clone();
        let (entries, http, bad) = if c.trackers.is_empty() {
            parse_list(dc4_tracker::VENDORED_LIST)
        } else {
            parse_list(&c.trackers.join("\n"))
        };
        if bad > 0 {
            tracing::warn!(bad, "tracker list lines failed to parse; skipped");
        }
        if http > 0 {
            tracing::info!(http, "non-UDP tracker lines skipped (UDP only)");
        }
        let pool = TrackerPool::start(entries, tuning.peer_port, tuning.timeout)
            .await
            .ok()?;
        tracing::info!(
            known = pool.known_count(),
            live = pool.live_count(),
            "tracker pool started"
        );
        metrics::gauge!(METRIC_LIST_SERVERS, "state" => "live").set(pool.live_count() as f64);
        metrics::gauge!(METRIC_LIST_SERVERS, "state" => "dead")
            .set(pool.known_count().saturating_sub(pool.live_count()) as f64);
        Some(Arc::new(Self {
            pool,
            tuning,
            budget: PacketBudget::new(c.packets_per_sec),
            batch: Mutex::new(ScrapeBatcher::new()),
            announce_sem: Arc::new(Semaphore::new(ANNOUNCE_CONCURRENCY)),
            store,
        }))
    }

    /// Triage verdict for `key`: seeders when scraped, `None` when unknown
    /// (DHT-only fallback). Joins the global batch: whoever fills it or
    /// times out flushes it.
    pub async fn triage(&self, key: DhtKey) -> Option<u32> {
        if self.pool.live_count() == 0 {
            metrics::counter!(METRIC_ANNOUNCES, "tracker" => "none", "outcome" => "no_live")
                .increment(1);
            return None;
        }
        let (tx, rx) = oneshot::channel();
        let mut rx = rx;
        let full = {
            let mut batch = lock(&self.batch);
            batch.pending.push(Pending { key, tx });
            batch.pending.len() >= BATCH_KEYS
        };
        if !full {
            // Someone else's flush usually resolves this first; on timeout
            // take the batch and flush it ourselves (or find it done).
            // Wait only the batch window: the flush itself (budget +
            // scrape) happens after, so a low-rate single key pays ~200ms,
            // not the scrape timeout on top.
            let wait = BATCH_WINDOW;
            tokio::select! {
                v = &mut rx => return v.unwrap_or(None),
                () = tokio::time::sleep(wait) => {}
            }
        }
        self.flush().await;
        rx.await.unwrap_or(None)
    }

    /// Flushes whatever is pending: scrape at a random subset, resolve
    /// every verdict, refresh estimates.
    async fn flush(&self) {
        let pending: Vec<Pending> = std::mem::take(&mut lock(&self.batch).pending);
        if pending.is_empty() {
            return;
        }
        let keys: Vec<DhtKey> = pending.iter().map(|p| p.key).collect();
        let servers: Vec<LiveServer> = self.pool.pick_live(self.tuning.scrape_fanout as usize);
        if servers.is_empty() {
            // Live set drained between triage entry and flush: resolve
            // every key DHT-only explicitly so no oneshot is left behind
            // and the fallback is counted like the triage-entry path.
            metrics::counter!(METRIC_ANNOUNCES, "tracker" => "none", "outcome" => "no_live")
                .increment(pending.len() as u64);
            for p in pending {
                let _ = p.tx.send(None);
            }
            return;
        }
        // One scrape costs (at least) a connect plus the scrape itself per
        // server; retries/re-handshakes cost more and are uncounted, so
        // charge 2/server as the floor rather than 1.
        self.budget.acquire(servers.len() * 2).await;
        let (seeders, outcomes, per_server) = self.pool.scrape(&servers, &keys).await;
        for (label, ok) in &outcomes {
            metrics::counter!(METRIC_SCRAPES, "tracker" => label.clone()).increment(1);
            if *ok {
                metrics::counter!(METRIC_SCRAPED_KEYS, "tracker" => label.clone())
                    .increment(keys.len() as u64);
            } else {
                metrics::counter!(METRIC_TIMEOUTS).increment(1);
            }
        }
        for (label, seeds) in &per_server {
            let hits = seeds.values().filter(|s| **s > 0).count() as u64;
            if hits > 0 {
                metrics::counter!(METRIC_SEED_HITS, "tracker" => label.clone()).increment(hits);
            }
        }
        for p in pending {
            let verdict = seeders.get(&p.key).copied();
            if let Some(s) = verdict
                && let Err(e) = self.store.note_fetch_estimate(&p.key, s).await
            {
                tracing::debug!(error = %e, "tracker triage note_fetch_estimate failed");
            }
            let _ = p.tx.send(verdict);
        }
    }

    /// Announces a triage-positive key: unioned tracker peers. Empty when
    /// floored, peerless, or unanswered. Skips keys that already yielded
    /// peers (harvested into the dial queue — re-announcing wastes
    /// packets) and filters per-tracker floored candidates so a retry can
    /// try unfloored trackers while floored ones cool down.
    pub async fn announce_peers(&self, key: DhtKey) -> Vec<SocketAddr> {
        let now = Instant::now();
        if self.pool.last_had_peers(&key) {
            metrics::counter!(METRIC_ANNOUNCES, "tracker" => "none", "outcome" => "floored")
                .increment(1);
            return Vec::new();
        }
        if self.pool.announced_recently(&key, now) {
            metrics::counter!(METRIC_ANNOUNCES, "tracker" => "none", "outcome" => "floored")
                .increment(1);
            return Vec::new();
        }
        let servers =
            self.pool
                .pick_live_unfloored(&key, self.tuning.announces_per_key as usize, now);
        if servers.is_empty() {
            // Either no live servers (DHT-only fallback) or every live
            // server is floored for this key (retry cooldown). Both are
            // counted `floored` except the truly-empty set below: keep
            // the distinction so `no_live` still means the pool is quiet.
            if self.pool.live_count() == 0 {
                metrics::counter!(METRIC_ANNOUNCES, "tracker" => "none", "outcome" => "no_live")
                    .increment(1);
            } else {
                metrics::counter!(METRIC_ANNOUNCES, "tracker" => "none", "outcome" => "floored")
                    .increment(1);
            }
            return Vec::new();
        }
        let live = servers;
        // Bound concurrent announces pool-wide (spec's ~32 worker pool).
        let sem = self.announce_sem.clone();
        let Ok(_permit) = sem.acquire_owned().await else {
            return Vec::new();
        };
        self.budget.acquire(live.len() * 2).await;
        let out = self.pool.announce(&live, &key).await;
        for (label, ok) in &out.server_ok {
            metrics::counter!(
                METRIC_ANNOUNCES,
                "tracker" => label.clone(),
                "outcome" => if *ok { "ok" } else { "error" }
            )
            .increment(1);
        }
        for (label, n) in &out.server_peers {
            metrics::counter!(METRIC_PEERS, "tracker" => label.clone()).increment(*n as u64);
        }
        if out.ok_servers == 0 {
            metrics::counter!(METRIC_TIMEOUTS).increment(1);
        }
        out.peers
    }

    /// Hourly liveness sweep driver.
    pub async fn run_sweep(self: Arc<Self>, stop: CancellationToken) {
        let mut ticker = tokio::time::interval(Duration::from_secs(SWEEP_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                _ = ticker.tick() => {
                    self.pool.sweep().await;
                    self.export_servers();
                }
            }
        }
    }

    /// Periodic list refresh driver. Empty URL disables.
    pub async fn run_refresh(
        self: Arc<Self>,
        url: String,
        every: Duration,
        stop: CancellationToken,
    ) {
        if url.trim().is_empty() {
            return;
        }
        let mut ticker = tokio::time::interval(every.max(Duration::from_secs(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                _ = ticker.tick() => {
                    match dc4_tracker::list::fetch_list(&url, Duration::from_secs(30)).await {
                        Ok(text) => {
                            let (entries, http, bad) = parse_list(&text);
                            if bad > 0 {
                                tracing::warn!(bad, "refreshed tracker list lines failed to parse");
                            }
                            if http > 0 {
                                tracing::info!(http, "refreshed non-UDP tracker lines skipped");
                            }
                            self.pool.set_servers(entries).await;
                            metrics::counter!(METRIC_LIST_REFRESH, "outcome" => "ok").increment(1);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "tracker list refresh failed; keeping the last set");
                            metrics::counter!(METRIC_LIST_REFRESH, "outcome" => "error")
                                .increment(1);
                        }
                    }
                    self.export_servers();
                }
            }
        }
    }

    fn export_servers(&self) {
        let live = self.pool.live_count() as f64;
        let known = self.pool.known_count() as f64;
        metrics::gauge!(METRIC_LIST_SERVERS, "state" => "live").set(live);
        metrics::gauge!(METRIC_LIST_SERVERS, "state" => "dead").set(known - live);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memstore::MemoryStore;

    /// Minimal UDP tracker: connect handshakes, scrape reports `seeders`
    /// for every key, announce returns one peer.
    async fn mock_tracker(seeders: u32, peer: SocketAddr) -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut conn_id = 0x5500u64;
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
                            r[8 + 12 * i..12 + 12 * i].copy_from_slice(&seeders.to_be_bytes());
                        }
                        sock.send_to(&r, from).await.unwrap();
                    }
                    1 => {
                        let mut r = vec![0u8; 20 + 6];
                        r[0..4].copy_from_slice(&1u32.to_be_bytes());
                        r[4..8].copy_from_slice(&txn.to_be_bytes());
                        r[8..12].copy_from_slice(&60u32.to_be_bytes());
                        match peer {
                            SocketAddr::V4(v4) => {
                                r[20..24].copy_from_slice(&v4.ip().octets());
                                r[24..26].copy_from_slice(&v4.port().to_be_bytes());
                            }
                            SocketAddr::V6(_) => continue,
                        }
                        sock.send_to(&r, from).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
        addr
    }

    fn handle_config(mock: SocketAddr) -> TrackerConfig {
        TrackerConfig {
            enabled: true,
            trackers: vec![format!("udp://{}:{}", mock.ip(), mock.port())],
            timeout: Duration::from_secs(2),
            ..TrackerConfig::default()
        }
    }

    #[tokio::test]
    async fn disabled_starts_no_pool() {
        let store = MemoryStore::new();
        let h = TrackerHandle::start(&TrackerConfig::default(), store).await;
        assert!(h.is_none(), "enabled=false must yield no pool/sockets");
    }

    #[tokio::test]
    async fn explicit_trackers_replace_the_vendored_list() {
        let store = MemoryStore::new();
        let cfg = TrackerConfig {
            enabled: true,
            trackers: vec!["udp://127.0.0.1:9".to_owned()],
            timeout: Duration::from_secs(2),
            ..TrackerConfig::default()
        };
        let h = TrackerHandle::start(&cfg, store).await.unwrap();
        assert_eq!(
            h.pool.known_count(),
            1,
            "one explicit entry replaces the 17-entry vendored list"
        );
    }

    #[tokio::test]
    async fn batcher_timeout_flushes_a_lonely_key() {
        let peer: SocketAddr = "10.9.0.1:6881".parse().unwrap();
        let mock = mock_tracker(4, peer).await;
        let h = TrackerHandle::start(&handle_config(mock), MemoryStore::new())
            .await
            .unwrap();
        let key = DhtKey([77; 20]);
        let verdict = tokio::time::timeout(Duration::from_secs(10), h.triage(key))
            .await
            .expect("single key must flush on timeout, not hang");
        assert_eq!(verdict, Some(4), "no key left behind on the timeout path");
    }

    #[tokio::test]
    async fn flush_with_drained_live_set_resolves_none() {
        let peer: SocketAddr = "10.9.0.2:6881".parse().unwrap();
        let mock = mock_tracker(4, peer).await;
        let h = TrackerHandle::start(&handle_config(mock), MemoryStore::new())
            .await
            .unwrap();
        // Drain the optimistic live set between triage entry and flush.
        h.pool.clear_live_for_test();
        let key = DhtKey([78; 20]);
        let verdict = tokio::time::timeout(Duration::from_secs(10), h.triage(key))
            .await
            .expect("drained live set must still resolve");
        assert_eq!(verdict, None, "empty-servers flush resolves DHT-only");
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_failure_keeps_last_set() {
        // WS5: a failing list refresh must keep serving the last known set,
        // never clear it. The driver only calls `set_servers` on `Ok`, so a
        // refused connection leaves the pool untouched across ticks.
        let peer: SocketAddr = "10.9.0.3:6881".parse().unwrap();
        let mock = mock_tracker(4, peer).await;
        let h = TrackerHandle::start(&handle_config(mock), MemoryStore::new())
            .await
            .unwrap();
        assert_eq!(h.pool.live_count(), 1, "mock starts optimistically live");
        let stop = CancellationToken::new();
        let driver = tokio::spawn(h.clone().run_refresh(
            "http://127.0.0.1:1/nonexistent.txt".to_string(),
            Duration::from_secs(1),
            stop.clone(),
        ));
        // Several ticks fire; every fetch fails fast (connection refused).
        tokio::time::sleep(Duration::from_secs(5)).await;
        stop.cancel();
        driver.await.unwrap();
        assert_eq!(
            h.pool.live_count(),
            1,
            "failed refreshes must keep the last set"
        );
    }

    #[tokio::test]
    async fn announce_skips_keys_that_already_yielded_peers() {
        let peer: SocketAddr = "10.9.0.3:6881".parse().unwrap();
        let mock = mock_tracker(4, peer).await;
        let h = TrackerHandle::start(&handle_config(mock), MemoryStore::new())
            .await
            .unwrap();
        let key = DhtKey([79; 20]);
        let first = h.announce_peers(key).await;
        assert_eq!(first, vec![peer]);
        let second = h.announce_peers(key).await;
        assert!(second.is_empty(), "peer-yielding keys are not re-announced");
    }

    #[tokio::test]
    async fn triage_zero_seeders_means_dht_only_but_still_a_verdict() {
        let peer: SocketAddr = "10.9.0.4:6881".parse().unwrap();
        let mock = mock_tracker(0, peer).await;
        let h = TrackerHandle::start(&handle_config(mock), MemoryStore::new())
            .await
            .unwrap();
        let verdict = tokio::time::timeout(Duration::from_secs(10), h.triage(DhtKey([80; 20])))
            .await
            .expect("zero-seeder batch must still resolve");
        assert_eq!(verdict, Some(0), "zero seeders is a verdict (DHT-only)");
    }

    #[tokio::test]
    async fn batcher_size_trigger_flushes_a_full_batch() {
        // 74 concurrent triage calls fill one datagram (BATCH_KEYS): every
        // key must resolve via the size trigger, so no key waits for the
        // 200 ms timeout path and none is left behind.
        let peer: SocketAddr = "10.9.0.5:6881".parse().unwrap();
        let mock = mock_tracker(6, peer).await;
        let h = TrackerHandle::start(&handle_config(mock), MemoryStore::new())
            .await
            .unwrap();
        let keys: Vec<DhtKey> = (0..BATCH_KEYS)
            .map(|i| {
                let mut b = [0xbu8; 20];
                b[..8].copy_from_slice(&(i as u64).to_be_bytes());
                DhtKey(b)
            })
            .collect();
        let futs: Vec<_> = keys.iter().map(|k| h.triage(*k)).collect();
        let verdicts =
            tokio::time::timeout(Duration::from_secs(20), futures::future::join_all(futs))
                .await
                .expect("a full batch must flush on size, not hang");
        assert_eq!(verdicts.len(), BATCH_KEYS);
        assert!(
            verdicts.iter().all(|v| *v == Some(6)),
            "every key in the full batch resolves, got {verdicts:?}"
        );
    }

    #[tokio::test]
    async fn triage_refreshes_seeders_est_for_retry_priority() {
        // Scrape-triage must write the verdict back via
        // `note_fetch_estimate`: the claim queue orders by
        // (attempts, seeders_est), so triage sharpens retry priority.
        use crate::stores::CrawlStore;
        use dc4_store::Observation;
        let peer: SocketAddr = "10.9.0.6:6881".parse().unwrap();
        let mock = mock_tracker(9, peer).await;
        let store = MemoryStore::new();
        let key = DhtKey([0xcc; 20]);
        store
            .observe(
                &[Observation {
                    key,
                    sightings: 1,
                    priority: false,
                }],
                10,
            )
            .await
            .unwrap();
        let h = TrackerHandle::start(&handle_config(mock), store.clone())
            .await
            .unwrap();
        let verdict = tokio::time::timeout(Duration::from_secs(10), h.triage(key))
            .await
            .expect("triage must resolve");
        assert_eq!(verdict, Some(9));
        let claimed = store.claim(10, Duration::from_secs(120)).await.unwrap();
        let got = claimed
            .iter()
            .find(|i| i.dht_key == key)
            .expect("key pending");
        assert_eq!(
            got.seeders_est,
            Some(9),
            "triage verdict must refresh the piggybacked estimate"
        );
    }
}
