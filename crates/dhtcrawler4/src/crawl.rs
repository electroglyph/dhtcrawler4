//! The crawl role (design §13): a DHT node, admission and fetch workers.
//!
//! Shutdown, when the token is cancelled:
//! 1. workers stop claiming new keys;
//! 2. fetches in progress get up to 30 s, then are abandoned (their leases
//!    expire and the keys are claimed again later);
//! 3. admission writes its last batch;
//! 4. the DHT node stops and saves its state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dc4_dht::{DhtConfig, DhtStatsSnapshot, DhtTuning, Family, MIN_GOOD_NODES};
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::admission::{Admission, AdmissionTuning, DISCOVERED_CHANNEL_CAPACITY, shared_hints};
use crate::config::{Config, ConfigError};
use crate::fetch::{FetchLimitsConfig, FetchTuning, Fetcher, claim_channel};
use crate::peers::PeerFilter;
use crate::scrape::{ScrapeTuning, Scraper};
use crate::stores::CrawlStore;

/// How often DHT counters are exported.
pub const DHT_STATS_INTERVAL: Duration = Duration::from_secs(5);
/// How often the queue depth is read.
pub const QUEUE_DEPTH_INTERVAL: Duration = Duration::from_secs(30);
/// How often readiness is re-checked.
pub const READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// Time allowed for the readiness database ping.
pub const READINESS_PING_TIMEOUT: Duration = Duration::from_secs(5);
/// How long shutdown waits for fetches in progress.
pub const SHUTDOWN_FETCH_WAIT: Duration = Duration::from_secs(30);

const METRIC_QUEUE_DEPTH: &str = "dc4_queue_depth";
const METRIC_DB_POOL_SIZE: &str = "dc4_db_pool_size";
const METRIC_DB_POOL_IDLE: &str = "dc4_db_pool_idle";

/// Everything the crawl role needs besides the store.
#[derive(Debug, Clone)]
pub struct CrawlOptions {
    /// The DHT node. Tests set `allow_private_addrs`, `tuning` (with
    /// `limits_by_endpoint`) and the bind addresses here.
    pub dht: DhtConfig,
    /// `crawl.max_pending`.
    pub max_pending: i64,
    /// `crawl.fetch_workers`.
    pub fetch_workers: usize,
    /// Connection and byte limits of the fetchers.
    pub limits: FetchLimitsConfig,
    /// The peer address filter; [`CrawlOptions::new`] derives it from the
    /// DHT's test switches.
    pub filter: PeerFilter,
    pub admission: AdmissionTuning,
    pub fetch: FetchTuning,
    /// BEP 33 scrape worker tunings; the worker count is `scrape_workers`.
    pub scrape: ScrapeTuning,
    /// Dedicated BEP 33 scrape workers (`crawl.scrape_workers`).
    pub scrape_workers: usize,
    pub stats_interval: Duration,
    pub queue_depth_interval: Duration,
    pub readiness_interval: Duration,
    /// Good routing nodes needed for readiness.
    pub min_good_nodes: usize,
    pub shutdown_wait: Duration,
}

impl CrawlOptions {
    /// Production timings around `dht`. The peer filter follows
    /// `dht.allow_private_addrs` and `dht.tuning.limits_by_endpoint`.
    pub fn new(
        dht: DhtConfig,
        max_pending: i64,
        fetch_workers: usize,
        limits: FetchLimitsConfig,
    ) -> Self {
        let filter = PeerFilter {
            allow_private: dht.allow_private_addrs,
            by_endpoint: dht.tuning.limits_by_endpoint,
        };
        Self {
            dht,
            max_pending,
            fetch_workers,
            limits,
            filter,
            admission: AdmissionTuning::default(),
            fetch: FetchTuning::default(),
            scrape: ScrapeTuning::default(),
            scrape_workers: 1,
            stats_interval: DHT_STATS_INTERVAL,
            queue_depth_interval: QUEUE_DEPTH_INTERVAL,
            readiness_interval: READINESS_INTERVAL,
            min_good_nodes: MIN_GOOD_NODES,
            shutdown_wait: SHUTDOWN_FETCH_WAIT,
        }
    }

    /// Options from `[crawl]`.
    pub fn from_config(cfg: &Config) -> Result<Self, ConfigError> {
        let c = &cfg.crawl;
        let (bind_v4, bind_v6) = cfg.dht_binds()?;
        let mut dht = DhtConfig {
            bind_v4,
            bind_v6,
            bootstrap: c.bootstrap.clone(),
            state_file: cfg.dht_state_file(),
            max_packets_per_sec: c.max_packets_per_sec,
            scrape_packets_per_sec: c.scrape_packets_per_sec,
            fetch_packets_per_sec: c.fetch_packets_per_sec,
            sampler: true,
            sampler_concurrency: c.sampler_concurrency,
            read_only: c.read_only,
            allow_private_addrs: false,
            client_version: dc4_dht::DEFAULT_CLIENT_VERSION,
            bep42_r: None,
            tuning: DhtTuning::default(),
        };
        dht.tuning.scrape_early_exit_quorum =
            usize::try_from(c.scrape_early_exit_quorum).unwrap_or(usize::MAX);
        dht.bep42_r = c.bep42_r;
        dht.tuning.scrape_query_timeout = Duration::from_secs(c.scrape_query_timeout_secs);
        dht.tuning.scrape_node_cache_keys = c.scrape_node_cache_keys;
        let mut opts = Self::new(
            dht,
            c.max_pending,
            c.fetch_workers,
            FetchLimitsConfig {
                max_connections: c.max_connections,
                max_metadata_bytes: c.max_metadata_bytes,
                max_inflight_metadata_bytes: c.max_inflight_metadata_bytes,
            },
        );
        opts.scrape = ScrapeTuning::from_config(c);
        opts.scrape_workers = c.scrape_workers;
        opts.admission.removal_cooldown_days = c.removal_cooldown_days;
        Ok(opts)
    }
}

/// Why the crawl role failed.
#[derive(Debug, thiserror::Error)]
pub enum CrawlError {
    #[error("cannot start the DHT node: {0}")]
    Dht(#[from] dc4_dht::Error),
    #[error("crawl task failed: {0}")]
    Task(String),
}

/// A running crawl role.
#[derive(Debug)]
pub struct Crawler {
    dht: dc4_dht::Dht,
    supervisor: JoinHandle<Result<(), CrawlError>>,
}

impl Crawler {
    /// Starts the DHT node, admission, the fetch workers and the exporters.
    /// Everything stops when `cancel` is cancelled; [`Crawler::join`]
    /// waits for that.
    pub async fn start<S: CrawlStore>(
        opts: CrawlOptions,
        store: S,
        ready: Arc<AtomicBool>,
        cancel: CancellationToken,
    ) -> Result<Crawler, CrawlError> {
        let (tx, rx) = mpsc::channel(DISCOVERED_CHANNEL_CAPACITY);
        let dht = dc4_dht::Dht::start(opts.dht.clone(), tx).await?;
        tracing::info!(
            sockets = dht.local_addrs().len(),
            sampler = opts.dht.sampler,
            read_only = opts.dht.read_only,
            workers = opts.fetch_workers,
            "DHT node started"
        );
        let stop = cancel.child_token();
        let hints = shared_hints(&opts.admission);

        let admission = Admission::new(
            store.clone(),
            opts.max_pending,
            opts.filter,
            opts.admission,
            Arc::clone(&hints),
            Instant::now(),
        );
        let admission_stop = CancellationToken::new();
        let admission_task = tokio::spawn(admission.run(rx, dht.clone(), admission_stop.clone()));

        let fetcher = Arc::new(Fetcher::new(
            store.clone(),
            dht.clone(),
            opts.filter,
            hints,
            opts.limits,
            opts.fetch,
        ));
        let mut workers = JoinSet::new();
        // One bulk claim per 512 keys instead of one 8-key scan per worker:
        // the claimer feeds batches over a bounded channel (256 batches =
        // 2048 keys) and a full channel backpressures it. The claimer joins
        // the same set, so its panic fails the role loudly like any worker's.
        let (claim_tx, claim_rx) = claim_channel();
        workers.spawn(Arc::clone(&fetcher).run_claimer(claim_tx, stop.clone()));
        for _ in 0..opts.fetch_workers {
            workers.spawn(Arc::clone(&fetcher).run_worker(Arc::clone(&claim_rx), stop.clone()));
        }
        let scraper = Arc::new(Scraper::new(
            store.clone(),
            dht.clone(),
            opts.scrape.clone(),
        ));
        for _ in 0..opts.scrape_workers {
            workers.spawn(Arc::clone(&scraper).run(stop.clone()));
        }

        let mut aux = JoinSet::new();
        aux.spawn(export_dht_stats(
            dht.clone(),
            opts.stats_interval,
            stop.clone(),
        ));
        aux.spawn(export_queue_depth(
            store.clone(),
            opts.queue_depth_interval,
            stop.clone(),
        ));
        aux.spawn(track_readiness(
            store,
            dht.clone(),
            opts.min_good_nodes,
            Arc::clone(&ready),
            opts.readiness_interval,
            stop.clone(),
        ));

        let supervisor = tokio::spawn(supervise(Supervised {
            dht: dht.clone(),
            stop,
            workers,
            admission_stop,
            admission_task,
            aux,
            shutdown_wait: opts.shutdown_wait,
            ready,
        }));
        Ok(Crawler { dht, supervisor })
    }

    /// The DHT node (it stops when the crawler stops).
    pub fn dht(&self) -> &dc4_dht::Dht {
        &self.dht
    }

    /// Waits until the crawler has stopped.
    pub async fn join(self) -> Result<(), CrawlError> {
        self.supervisor
            .await
            .map_err(|e| CrawlError::Task(e.to_string()))?
    }
}

/// Runs the crawl role until `cancel` is cancelled.
pub async fn run<S: CrawlStore>(
    opts: CrawlOptions,
    store: S,
    ready: Arc<AtomicBool>,
    cancel: CancellationToken,
) -> Result<(), CrawlError> {
    Crawler::start(opts, store, ready, cancel)
        .await?
        .join()
        .await
}

struct Supervised {
    dht: dc4_dht::Dht,
    stop: CancellationToken,
    workers: JoinSet<()>,
    admission_stop: CancellationToken,
    admission_task: JoinHandle<()>,
    aux: JoinSet<()>,
    shutdown_wait: Duration,
    ready: Arc<AtomicBool>,
}

async fn supervise(mut s: Supervised) -> Result<(), CrawlError> {
    let admission_join: Option<Result<(), JoinError>> = tokio::select! {
        () = s.stop.cancelled() => None,
        joined = &mut s.admission_task => Some(joined),
    };
    let admission_ended = admission_join.is_some();
    s.stop.cancel();
    s.ready.store(false, Ordering::Relaxed);
    tracing::info!("crawl role stopping");

    let deadline = Instant::now() + s.shutdown_wait;
    // A panicked worker must fail the role, not vanish into the log: fetch
    // capacity silently dropping to zero with an `Ok(())` shutdown has no
    // alerting signal.
    let mut worker_error: Option<String> = None;
    loop {
        match tokio::time::timeout_at(deadline, s.workers.join_next()).await {
            Ok(Some(Ok(()))) => {}
            Ok(Some(Err(e))) => {
                tracing::error!(error = %e, "a fetch worker failed");
                if worker_error.is_none() {
                    worker_error = Some(e.to_string());
                }
            }
            Ok(None) => break,
            Err(_) => {
                tracing::warn!(
                    workers = s.workers.len(),
                    "abandoning fetches still in progress"
                );
                s.workers.shutdown().await;
                break;
            }
        }
    }

    if !admission_ended {
        s.admission_stop.cancel();
        if let Err(e) = (&mut s.admission_task).await {
            tracing::error!(error = %e, "the admission task failed");
        }
    }
    s.aux.shutdown().await;
    // The readiness task may have been stopped between its checks.
    s.ready.store(false, Ordering::Relaxed);
    s.dht.shutdown().await;
    tracing::info!("crawl role stopped");
    if let Some(joined) = admission_join {
        return Err(admission_early_error(joined));
    }
    if let Some(msg) = worker_error {
        return Err(CrawlError::Task(format!("a fetch worker failed: {msg}")));
    }
    Ok(())
}

/// Builds the early-exit error when the admission task ends before `stop`,
/// preserving the panic/cancellation cause instead of discarding it.
fn admission_early_error(join: Result<(), JoinError>) -> CrawlError {
    match join {
        Ok(()) => CrawlError::Task("admission stopped unexpectedly".into()),
        Err(e) => {
            tracing::error!(error = %e, "the admission task failed");
            CrawlError::Task(format!("admission stopped unexpectedly: {e}"))
        }
    }
}

/// Exports one DHT snapshot as the metrics in `docs/04-operations.md` §6.
pub fn export_snapshot(s: &DhtStatsSnapshot) {
    for family in Family::ALL {
        let f = s.family(family);
        let label = family.as_str();
        metrics::counter!("dc4_dht_packets_in_total", "family" => label).absolute(f.packets_in);
        metrics::counter!("dc4_dht_packets_out_total", "family" => label).absolute(f.packets_out);
        for (reason, n) in f.dropped.iter() {
            metrics::counter!(
                "dc4_dht_packets_dropped_total",
                "family" => label,
                "reason" => reason.as_str()
            )
            .absolute(n);
        }
        metrics::counter!("dc4_dht_samples_total", "family" => label).absolute(f.samples);
        metrics::counter!("dc4_dht_recv_errors_total", "family" => label).absolute(f.recv_errors);
        metrics::gauge!("dc4_dht_routing_nodes", "family" => label).set(f.routing_nodes as f64);
        metrics::gauge!("dc4_dht_good_nodes", "family" => label).set(f.good_nodes as f64);
        metrics::gauge!("dc4_dht_sampler_frontier", "family" => label)
            .set(f.sampler_frontier as f64);
        metrics::gauge!("dc4_dht_sampler_visited", "family" => label).set(f.sampler_visited as f64);
    }
    for (method, n) in s.queries_received.iter() {
        metrics::counter!("dc4_dht_queries_received_total", "method" => method).absolute(n);
    }
    metrics::counter!("dc4_dht_timeouts_total").absolute(s.timeouts);
    metrics::counter!("dc4_dht_sampler_early_total").absolute(s.sampler_early);
    metrics::counter!("dc4_dht_sampler_visited_full_total").absolute(s.sampler_visited_full);
    metrics::counter!("dc4_dht_sampler_pick_empty_total").absolute(s.sampler_pick_empty);
    metrics::counter!("dc4_dht_responder_dropped_total").absolute(s.responder_dropped);
    metrics::counter!("dc4_dht_discovered_dropped_total").absolute(s.discovered_dropped);
    metrics::gauge!("dc4_dht_peer_store_keys").set(s.peer_store_keys as f64);
}

async fn export_dht_stats(dht: dc4_dht::Dht, every: Duration, stop: CancellationToken) {
    let mut ticker = tokio::time::interval(every.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.cancelled() => break,
            _ = ticker.tick() => export_snapshot(&dht.stats()),
        }
    }
}

/// One export tick: the queue depth (`None` when unreadable) and the pool
/// use. Split out for tests; [`export_queue_depth`] only moves these into
/// gauges.
async fn snapshot_queue_depth<S: CrawlStore>(store: &S) -> (Option<i64>, Option<(u32, usize)>) {
    let depth = match store.pending_depth().await {
        Ok(depth) => Some(depth),
        Err(e) => {
            tracing::warn!(error = %e, "reading the queue depth failed");
            None
        }
    };
    (depth, store.pool_status())
}

async fn export_queue_depth<S: CrawlStore>(store: S, every: Duration, stop: CancellationToken) {
    let mut ticker = tokio::time::interval(every.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.cancelled() => break,
            _ = ticker.tick() => {
                let (depth, pool) = snapshot_queue_depth(&store).await;
                if let Some(depth) = depth {
                    metrics::gauge!(METRIC_QUEUE_DEPTH).set(depth as f64);
                }
                if let Some((size, idle)) = pool {
                    metrics::gauge!(METRIC_DB_POOL_SIZE).set(f64::from(size));
                    metrics::gauge!(METRIC_DB_POOL_IDLE).set(idle as f64);
                }
            }
        }
    }
}

async fn track_readiness<S: CrawlStore>(
    store: S,
    dht: dc4_dht::Dht,
    min_good_nodes: usize,
    ready: Arc<AtomicBool>,
    every: Duration,
    stop: CancellationToken,
) {
    loop {
        let database = matches!(
            tokio::time::timeout(READINESS_PING_TIMEOUT, store.ping()).await,
            Ok(Ok(()))
        );
        let routing = dht.good_nodes() >= min_good_nodes;
        ready.store(
            database && routing && !stop.is_cancelled(),
            Ordering::Relaxed,
        );
        tokio::select! {
            () = stop.cancelled() => break,
            () = tokio::time::sleep(every) => {}
        }
    }
    ready.store(false, Ordering::Relaxed);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use dc4_dht::FamilyStats;

    #[tokio::test]
    async fn admission_early_exit_keeps_the_cause() {
        let ok = tokio::spawn(async {}).await;
        let err = admission_early_error(ok);
        let CrawlError::Task(msg) = err else {
            panic!("expected a Task error");
        };
        assert_eq!(msg, "admission stopped unexpectedly");

        let panicked = tokio::spawn(async {
            panic!("admission exploded");
        })
        .await;
        assert!(panicked.is_err());
        let err = admission_early_error(panicked);
        let CrawlError::Task(msg) = err else {
            panic!("expected a Task error");
        };
        assert!(
            msg.starts_with("admission stopped unexpectedly: "),
            "cause discarded: {msg}"
        );
        assert!(msg.contains("panicked"), "panic cause missing: {msg}");

        let handle = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        handle.abort();
        let cancelled = handle.await;
        assert!(cancelled.is_err());
        let err = admission_early_error(cancelled);
        let CrawlError::Task(msg) = err else {
            panic!("expected a Task error");
        };
        assert!(
            msg.starts_with("admission stopped unexpectedly: "),
            "cause discarded: {msg}"
        );
    }
    #[test]
    fn options_from_config() {
        let cfg = Config::default();
        let o = CrawlOptions::from_config(&cfg).unwrap();
        assert_eq!(o.dht.bind_v4, Some("0.0.0.0:6881".parse().unwrap()));
        assert_eq!(o.dht.bind_v6, Some("[::]:6881".parse().unwrap()));
        assert_eq!(
            o.dht.state_file,
            Some("/var/lib/dhtcrawler4/dht-state.json".into())
        );
        assert_eq!(o.dht.bootstrap.len(), 4);
        assert!(o.dht.sampler);
        assert_eq!(o.dht.sampler_concurrency, 1024);
        assert!(!o.dht.allow_private_addrs);
        assert_eq!(o.dht.tuning, DhtTuning::default());
        assert!(o.dht.validate().is_ok());
        assert_eq!(o.filter, PeerFilter::PRODUCTION);
        assert_eq!(o.fetch_workers, 3072);
        assert_eq!(o.dht.scrape_packets_per_sec, 100);
        assert_eq!(
            o.dht.fetch_packets_per_sec,
            dc4_dht::DEFAULT_FETCH_PACKETS_PER_SEC
        );
        assert_eq!(o.dht.tuning.scrape_early_exit_quorum, 3);
        assert_eq!(o.dht.tuning.scrape_query_timeout, Duration::from_secs(10));
        assert_eq!(o.dht.tuning.scrape_node_cache_keys, 4096);
        assert_eq!(o.dht.bep42_r, None);
        assert_eq!(o.admission.removal_cooldown_days, 7);
        assert_eq!(o.scrape_workers, 1);
        assert_eq!(o.scrape.threshold, 0);
        assert_eq!(o.max_pending, 5_000_000);
        assert_eq!(o.limits.max_connections, 12288);
        assert_eq!(o.limits.max_inflight_metadata_bytes, 1_073_741_824);
        assert_eq!(o.min_good_nodes, MIN_GOOD_NODES);
        let mut cfg = Config::default();
        cfg.crawl.bep42_r = Some(3);
        assert_eq!(
            CrawlOptions::from_config(&cfg).unwrap().dht.bep42_r,
            Some(3)
        );

        let mut cfg = Config::default();
        cfg.crawl.bind_v6 = String::new();
        cfg.crawl.read_only = true;
        cfg.crawl.state_dir = std::path::PathBuf::new();
        let o = CrawlOptions::from_config(&cfg).unwrap();
        assert_eq!(o.dht.bind_v6, None);
        assert!(o.dht.read_only);
        assert_eq!(o.dht.state_file, None);

        let test_dht = DhtConfig {
            allow_private_addrs: true,
            tuning: DhtTuning {
                limits_by_endpoint: true,
                ..DhtTuning::default()
            },
            ..DhtConfig::default()
        };
        let o = CrawlOptions::new(test_dht, 10, 1, o.limits);
        assert!(o.filter.allow_private && o.filter.by_endpoint);
    }

    #[test]
    fn options_propagate_scrape_knobs() {
        // Every previously-dead knob reaches its consumer: the per-RPC
        // scrape timeout and the node-cache size land in the DHT tuning,
        // the removal base in the admission tuning.
        let mut cfg = Config::default();
        cfg.crawl.scrape_query_timeout_secs = 15;
        cfg.crawl.scrape_lookup_timeout_secs = 30;
        cfg.crawl.scrape_node_cache_keys = 128;
        cfg.crawl.removal_cooldown_days = 14;
        let o = CrawlOptions::from_config(&cfg).unwrap();
        assert_eq!(o.dht.tuning.scrape_query_timeout, Duration::from_secs(15));
        assert_eq!(o.dht.tuning.scrape_node_cache_keys, 128);
        assert_eq!(o.admission.removal_cooldown_days, 14);
        assert_eq!(o.scrape.lookup_timeout, Duration::from_secs(30));
        assert!(o.dht.validate().is_ok());
    }

    #[test]
    fn snapshot_export_does_not_need_a_recorder() {
        export_snapshot(&DhtStatsSnapshot::default());
        let s = DhtStatsSnapshot {
            sampler_pick_empty: 3,
            v4: FamilyStats {
                recv_errors: 1,
                sampler_frontier: 7,
                ..FamilyStats::default()
            },
            v6: FamilyStats {
                sampler_visited: 9,
                ..FamilyStats::default()
            },
            ..DhtStatsSnapshot::default()
        };
        export_snapshot(&s);
    }

    #[tokio::test]
    async fn queue_snapshot_reports_depth_without_pool() {
        use crate::memstore::MemoryStore;

        let store = MemoryStore::new();
        assert_eq!(snapshot_queue_depth(&store).await, (Some(0), None));
        store.enqueue(dc4_core::DhtKey([21; 20]));
        store.enqueue(dc4_core::DhtKey([22; 20]));
        assert_eq!(snapshot_queue_depth(&store).await, (Some(2), None));
    }

    /// A pool that never connected: size/idle are observable with no
    /// database, and depth reads fail deterministically (the pool is
    /// closed, so nothing is even dialled).
    async fn dead_store() -> dc4_store::Store {
        let pool =
            dc4_store::sqlx::PgPool::connect_lazy("postgres://dc4:secret@127.0.0.1:1/unused")
                .unwrap();
        pool.close().await;
        dc4_store::Store::from_pool(pool)
    }

    #[tokio::test]
    async fn store_pool_status_reports_pool_size() {
        let pool =
            dc4_store::sqlx::PgPool::connect_lazy("postgres://dc4:secret@127.0.0.1:1/unused")
                .unwrap();
        let store = dc4_store::Store::from_pool(pool);
        assert_eq!(store.pool_status(), Some((0, 0)));
    }

    #[tokio::test]
    async fn queue_snapshot_survives_a_dead_database() {
        let store = dead_store().await;
        // The depth error degrades to None (and a warning) instead of taking
        // down the exporter; the pool gauges still report.
        assert_eq!(snapshot_queue_depth(&store).await, (None, Some((0, 0))));
    }

    #[tokio::test]
    async fn export_queue_depth_ticks_then_exits_on_cancel() {
        use crate::memstore::MemoryStore;

        // Both pool branches of the loop: the stand-in (no pool) and a dead
        // pool (pool gauges, failing depth reads).
        let stop = CancellationToken::new();
        let run = tokio::spawn(export_queue_depth(
            MemoryStore::new(),
            Duration::from_millis(10),
            stop.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();

        let stop = CancellationToken::new();
        let run = tokio::spawn(export_queue_depth(
            dead_store().await,
            Duration::from_millis(10),
            stop.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
    }
}
