//! Tracker hybrid: scrape triage plus one-shot announces.
//!
//! Every claimed key joins one global scrape batcher (74 keys or 200 ms).
//! Each flush is scraped at a random subset of live trackers; keys with
//! seeders land in the announce stage, the rest stay DHT-only. Announce
//! results merge into the fetch dial queue like any other peers.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use dc4_core::DhtKey;
use dc4_tracker::{LiveServer, TrackerPool, parse_list};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::config::CrawlConfig;
use crate::stores::CrawlStore;

const BATCH_KEYS: usize = dc4_tracker::MAX_SCRAPE_HASHES;
const BATCH_WINDOW: Duration = Duration::from_millis(200);
const SWEEP_SECS: u64 = 3_600;

pub const METRIC_ANNOUNCES: &str = "dc4_tracker_announces_total";
pub const METRIC_PEERS: &str = "dc4_tracker_peers_total";
pub const METRIC_TIMEOUTS: &str = "dc4_tracker_timeouts_total";
pub const METRIC_SCRAPES: &str = "dc4_tracker_scrapes_total";
pub const METRIC_SCRAPED_KEYS: &str = "dc4_tracker_scraped_keys_total";
pub const METRIC_SEED_HITS: &str = "dc4_tracker_seed_hits_total";
pub const METRIC_LIST_REFRESH: &str = "dc4_tracker_list_refresh_total";
pub const METRIC_LIST_SERVERS: &str = "dc4_tracker_list_servers";

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
            announces_per_key: 3,
            scrape_fanout: 2,
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
                *tokens = (*tokens + now.saturating_duration_since(*last).as_secs_f64() * self.rate)
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

struct BatchState {
    pending: Vec<Pending>,
}

/// The crawl role's handle: pool, batcher, budget, store. `None` in the
/// fetcher means trackers are off and fetch is DHT-only.
pub struct TrackerHandle<S> {
    pool: Arc<TrackerPool>,
    tuning: TrackerConfig,
    budget: PacketBudget,
    batch: Mutex<BatchState>,
    store: S,
}

impl<S: CrawlStore> TrackerHandle<S> {
    /// Starts the pool on the vendored snapshot plus any explicit `trackers`
    /// (which replace, not merge). Returns `None` when disabled.
    pub async fn start(
        c: &TrackerConfig,
        store: S,
    ) -> Option<Arc<Self>> {
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
        Some(Arc::new(Self {
            pool,
            tuning,
            budget: PacketBudget::new(c.packets_per_sec),
            batch: Mutex::new(BatchState {
                pending: Vec::new(),
            }),
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
            let wait = BATCH_WINDOW + self.tuning.timeout * 2 + Duration::from_secs(1);
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
            return;
        }
        self.budget.acquire(servers.len()).await;
        let (seeders, outcomes) = self.pool.scrape(&servers, &keys).await;
        for (label, ok) in &outcomes {
            metrics::counter!(METRIC_SCRAPES, "tracker" => label.clone()).increment(1);
            if *ok {
                metrics::counter!(METRIC_SCRAPED_KEYS, "tracker" => label.clone())
                    .increment(keys.len() as u64);
            } else {
                metrics::counter!(METRIC_TIMEOUTS).increment(1);
            }
        }
        for p in pending {
            let verdict = seeders.get(&p.key).copied();
            if verdict.is_some_and(|s| s > 0) {
                metrics::counter!(METRIC_SEED_HITS).increment(1);
            }
            if let Some(s) = verdict
                && let Err(e) = self.store.note_fetch_estimate(&p.key, s).await
            {
                tracing::debug!(error = %e, "tracker triage note_fetch_estimate failed");
            }
            let _ = p.tx.send(verdict);
        }
    }

    /// Announces a triage-positive key: unioned tracker peers. Empty when
    /// floored, peerless, or unanswered.
    pub async fn announce_peers(&self, key: DhtKey) -> Vec<SocketAddr> {
        if self.pool.announced_recently(&key, Instant::now()) {
            metrics::counter!(METRIC_ANNOUNCES, "tracker" => "none", "outcome" => "floored")
                .increment(1);
            return Vec::new();
        }
        let servers = self
            .pool
            .pick_live(self.tuning.announces_per_key as usize);
        if servers.is_empty() {
            metrics::counter!(METRIC_ANNOUNCES, "tracker" => "none", "outcome" => "no_live")
                .increment(1);
            return Vec::new();
        }
        self.budget.acquire(servers.len() * 2).await;
        let out = self.pool.announce(&servers, &key).await;
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
