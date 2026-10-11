//! Fetch workers (design §13): claim a key, find peers, fetch its metadata
//! over BEP 9, verify and parse it, and store the result.
//!
//! One claimer bulk-claims up to 512 due keys per scan, slices each scan
//! into batches of up to 8, and feeds the workers over a bounded channel
//! (256 batches = 2048 keys); a full channel backpressures the claimer, so
//! there is one bound and no outstanding counter to drift. Each worker:
//! 1. receives one batch (keys carry a 120 s lease, renewed in the background
//!    while the batch is worked — a full batch can outlive the lease);
//! 2. collects peers from the hint map and `get_peers` (6 s), each passing
//!    the address chokepoint and the per-destination limits;
//! 3. tries up to 8 peers (3 for unscraped or measured-dead keys), 3 at a
//!    time, inside the global connection limit and the metadata byte
//!    budget, all within 45 s — high-estimate keys get one second lookup
//!    when the first drains before giving up;
//! 4. verifies and parses the metadata;
//! 5. records successes in one transaction and failures and give-ups in one
//!    each (`complete_batch`, `fail_batch`, `give_up_batch`), falling back
//!    to one key at a time when a batch is rejected.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use dc4_core::DhtKey;
use dc4_dht::compact::canonical_addr;
use dc4_peer::{BYTE_BUDGET_UNIT, FetchError, FetchLimits};
use dc4_store::{FileRow, NewTorrent, PendingItem, StoreError};
use dc4_torrent::TorrentMeta;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::admission::{METRIC_HINT_USED, SharedHints, add_hint, take_hints};
use crate::peers::{OwnAddrs, PeerFilter, PeerSource};
use crate::stores::CrawlStore;

/// Queue items claimed at a time by one worker.
pub const CLAIM_BATCH: i64 = 8;
/// Keys per bulk scan by the single claimer. One scan per 512 keys replaces
/// 64 per-worker scans, so the ~47k-tuple prefix walk runs ~1.5/s instead of
/// ~95/s. Within `MAX_CLAIM`, so no store change is needed.
pub const CLAIM_BULK: i64 = 512;
/// Claim-channel capacity in batches (`CLAIM_CHAN_BATCHES` × `CLAIM_BATCH`
/// = 2048 keys). The only bound in the design: a full channel backpressures
/// the claimer via `send`. Worst-case buffer dwell is 2048 keys of work
/// (~2.7 s at 758 keys/s, ~3.4 s counting the in-hand bulk), two orders of
/// magnitude inside the 120 s lease — and a full drain fits the 30 s
/// shutdown wait the same way.
pub const CLAIM_CHAN_BATCHES: usize = 256;
/// Lease on a claimed key.
pub const CLAIM_LEASE: Duration = Duration::from_secs(120);
/// How often a lease is renewed while its key is being worked on.
pub const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(90);
/// Shortest pause of an idle worker.
pub const IDLE_SLEEP_MIN: Duration = Duration::from_secs(1);
/// Longest pause of an idle worker.
pub const IDLE_SLEEP_MAX: Duration = Duration::from_secs(3);
/// Time allowed for the `get_peers` lookup of one key.
pub const GET_PEERS_TIMEOUT: Duration = Duration::from_secs(6);
/// Time allowed for all fetch attempts of one key.
pub const KEY_DEADLINE: Duration = Duration::from_secs(45);
/// Peers tried per key.
pub const MAX_PEER_ATTEMPTS: usize = 8;
/// Peers tried at the same time per key.
pub const PARALLEL_ATTEMPTS: usize = 3;
/// Peers tried per key with no live evidence: unscraped (`None`) or
/// measured-dead (`Some(0)`) estimates (update.md step 4). Must stay below
/// [`MAX_PEER_ATTEMPTS`]; the saving lands on keys with peers, since
/// peerless keys start no dials either way.
pub const LOW_EFFORT_MAX_ATTEMPTS: usize = 3;
/// Smallest estimate that earns the second lookup. A starting value, not
/// derived — no estimate-split outcome data exists yet; move it on the gate.
pub const HIGH_EST_MIN: u32 = 5;
/// Lookups per key with `seeders_est >= HIGH_EST_MIN`.
pub const HIGH_EST_MAX_LOOKUPS: u8 = 2;
/// TCP connect timeout per peer.
pub const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Handshake timeout per peer.
pub const PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
/// Whole-fetch timeout per peer.
pub const PEER_FETCH_TIMEOUT: Duration = Duration::from_secs(20);
/// Concurrent connections to one destination IP.
pub const DEST_MAX_CONCURRENT: u32 = 2;
/// Connection attempts to one destination IP per window.
pub const DEST_MAX_ATTEMPTS: usize = 10;
/// The attempt-counting window.
pub const DEST_WINDOW: Duration = Duration::from_secs(60);
/// How long a refused or timed-out destination is skipped.
pub const DEST_NEGATIVE_TTL_SHORT: Duration = Duration::from_secs(3 * 60);
/// How long a destination with other connect errors is skipped.
pub const DEST_NEGATIVE_TTL: Duration = Duration::from_secs(10 * 60);
/// Destination IPs tracked; new ones are refused when full.
pub const DEST_CAPACITY: usize = 100_000;
/// Least time between two sweeps of a full destination map.
pub const DEST_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// First retry delay after a failed claim.
pub const STORE_RETRY_BASE: Duration = Duration::from_secs(1);
/// Longest retry delay after failed claims.
pub const STORE_RETRY_MAX: Duration = Duration::from_secs(30);
/// Shortest lease renewal period accepted (guards against a zero period).
const MIN_RENEW_INTERVAL: Duration = Duration::from_millis(10);

const METRIC_FETCH: &str = "dc4_fetch_total";
const METRIC_DESTINATION_SKIPPED: &str = "dc4_destination_skipped_total";
const METRIC_CLAIM_CHAN_DEPTH: &str = "dc4_claim_chan_depth";
/// Claimed keys per scan, by liveness (`live=true` for `seeders_est > 0`,
/// `false` for unscraped NULL and measured-dead 0). The step-2 gate reads
/// `live` up / `false` down vs the pre-change hour. In-memory only,
/// permanent, two series.
const METRIC_CLAIMED: &str = "dc4_claimed_total";
/// Started peer dials, by claim-time estimate bucket (`null`/`dead`/`low`/
/// `high`, see [`est_bucket`]). Read against [`METRIC_FETCH`] with the same
/// label as ok per 10k dials per bucket — the step-4 gate. In-memory only,
/// permanent, four series.
const METRIC_DIALS: &str = "dc4_fetch_dials_total";

/// Per-key fetch effort derived from the claim-time estimate (update.md
/// step 4): junk gets a small dial budget and one lookup, proven swarms
/// get today's budget plus one second lookup when the first drains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEffort {
    /// Peers tried at most (hints and lookup peers share this budget).
    pub max_attempts: usize,
    /// Lookups issued at most.
    pub max_lookups: u8,
}

/// Effort for one key from its claim-time `seeders_est`: `None` (unscraped)
/// and `Some(0)` (measured dead, never live) get the floor, `1..HIGH_EST_MIN`
/// gets today's effort, `>= HIGH_EST_MIN` gets today's effort plus a second
/// lookup on drain.
pub fn effort_for(est: Option<u32>) -> KeyEffort {
    match est {
        None | Some(0) => KeyEffort {
            max_attempts: LOW_EFFORT_MAX_ATTEMPTS,
            max_lookups: 1,
        },
        Some(e) if e < HIGH_EST_MIN => KeyEffort {
            max_attempts: MAX_PEER_ATTEMPTS,
            max_lookups: 1,
        },
        Some(_) => KeyEffort {
            max_attempts: MAX_PEER_ATTEMPTS,
            max_lookups: HIGH_EST_MAX_LOOKUPS,
        },
    }
}

/// Metric bucket for one key's claim-time estimate. The mid-fetch piggyback
/// writes the DB row, never the in-hand item, so claim-time keeps dials and
/// outcomes joinable.
pub fn est_bucket(est: Option<u32>) -> &'static str {
    match est {
        None => "null",
        Some(0) => "dead",
        Some(e) if e < HIGH_EST_MIN => "low",
        Some(_) => "high",
    }
}

/// The claim channel's receiving end, shared by every fetch worker. The
/// mutex serialises only the handoff: a worker holds it while waiting for
/// the next batch, never while fetching or storing.
pub type ClaimRx = std::sync::Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<PendingItem>>>>;

/// The claim channel from the single claimer to the workers
/// ([`CLAIM_CHAN_BATCHES`] batches). Senders backpressure when it is full;
/// receivers see `None` once the claimer is gone and it is drained.
pub fn claim_channel() -> (mpsc::Sender<Vec<PendingItem>>, ClaimRx) {
    let (tx, rx) = mpsc::channel(CLAIM_CHAN_BATCHES);
    (tx, std::sync::Arc::new(tokio::sync::Mutex::new(rx)))
}

/// Batches waiting in the claim channel, read sender-side. `Sender` has no
/// `len()` (only the receiver does), but `max_capacity() - capacity()` is
/// the same number; a racing `send` moves it by ±1 at most, immaterial for
/// a depth gauge.
fn claim_chan_depth(tx: &mpsc::Sender<Vec<PendingItem>>) -> usize {
    tx.max_capacity().saturating_sub(tx.capacity())
}

/// One bulk scan for the single claimer (update.md step 2): leases up to
/// `n` live keys (`seeders_est > 0`) first, then tops up with the
/// unfiltered claim so workers never idle. The live leases exclude those
/// keys from the top-up, so the pair never double-leases; when the live
/// pool is dry the top-up is the whole bulk (today's behavior exactly).
/// A failed top-up does not waste the live leases already held: they are
/// fed to the workers with a warning, and only an empty live pool still
/// errors the scan (the claimer backs off).
/// Counts both halves into [`METRIC_CLAIMED`] by liveness.
pub async fn claim_bulk<S: CrawlStore>(
    store: &S,
    n: i64,
    lease: Duration,
) -> Result<Vec<PendingItem>, StoreError> {
    let mut items = store.claim_live(n, lease).await?;
    if (items.len() as i64) < n {
        let rest = n.saturating_sub(items.len() as i64);
        match store.claim(rest, lease).await {
            Ok(topup) => items.extend(topup),
            Err(e) if items.is_empty() => return Err(e),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    live = items.len(),
                    "claim top-up failed; feeding live leases"
                );
            }
        }
    }
    // Liveness is read off the items, so a concurrent piggyback write
    // between the two phases still counts exactly.
    let live_now = items
        .iter()
        .filter(|i| i.seeders_est.is_some_and(|e| e > 0))
        .count();
    let unproven = items.len().saturating_sub(live_now);
    if live_now > 0 {
        metrics::counter!(METRIC_CLAIMED, "live" => "true").increment(live_now as u64);
    }
    if unproven > 0 {
        metrics::counter!(METRIC_CLAIMED, "live" => "false").increment(unproven as u64);
    }
    Ok(items)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `now + d`, or `now` if that would overflow (it never does in practice).
fn after(now: Instant, d: Duration) -> Instant {
    now.checked_add(d).unwrap_or(now)
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Timings and limits of the fetch workers. `Default` gives the production
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchTuning {
    pub lease: Duration,
    pub renew_every: Duration,
    pub idle_min: Duration,
    pub idle_max: Duration,
    pub get_peers_timeout: Duration,
    pub key_deadline: Duration,
    /// Global dial ceiling per key. The estimate bucket (`effort_for`) sets
    /// the per-key budget below it; the effective budget is the minimum of
    /// the two, so lowering this in tests still binds.
    pub max_attempts: usize,
    pub parallel_attempts: usize,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub peer_timeout: Duration,
    pub store_retry_base: Duration,
    pub store_retry_max: Duration,
    pub destinations: DestLimits,
}

impl Default for FetchTuning {
    fn default() -> Self {
        Self {
            lease: CLAIM_LEASE,
            renew_every: LEASE_RENEW_INTERVAL,
            idle_min: IDLE_SLEEP_MIN,
            idle_max: IDLE_SLEEP_MAX,
            get_peers_timeout: GET_PEERS_TIMEOUT,
            key_deadline: KEY_DEADLINE,
            max_attempts: MAX_PEER_ATTEMPTS,
            parallel_attempts: PARALLEL_ATTEMPTS,
            connect_timeout: PEER_CONNECT_TIMEOUT,
            handshake_timeout: PEER_HANDSHAKE_TIMEOUT,
            peer_timeout: PEER_FETCH_TIMEOUT,
            store_retry_base: STORE_RETRY_BASE,
            store_retry_max: STORE_RETRY_MAX,
            destinations: DestLimits::default(),
        }
    }
}

/// How one key ended (the `outcome` label of `dc4_fetch_total`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchOutcome {
    /// Stored.
    Ok,
    /// No usable peer was found.
    NoPeers,
    /// Peers were found, but no fetch succeeded in time.
    FetchFailed,
    /// The metadata was verified but could not be parsed.
    ParseError,
    /// A BEP 27 private torrent; the key is given up.
    Private,
    /// The final database operation failed.
    StoreError,
}

impl FetchOutcome {
    /// Every outcome.
    pub const ALL: [FetchOutcome; 6] = [
        FetchOutcome::Ok,
        FetchOutcome::NoPeers,
        FetchOutcome::FetchFailed,
        FetchOutcome::ParseError,
        FetchOutcome::Private,
        FetchOutcome::StoreError,
    ];

    /// The metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            FetchOutcome::Ok => "ok",
            FetchOutcome::NoPeers => "no_peers",
            FetchOutcome::FetchFailed => "fetch_failed",
            FetchOutcome::ParseError => "parse_error",
            FetchOutcome::Private => "private",
            FetchOutcome::StoreError => "store_error",
        }
    }
}

// ---------------------------------------------------------------------------
// Destination limiter
// ---------------------------------------------------------------------------

/// Per-destination limits. `Default` gives the production values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestLimits {
    pub max_concurrent: u32,
    pub max_attempts: usize,
    pub window: Duration,
    pub negative_ttl: Duration,
    pub negative_ttl_short: Duration,
    pub capacity: usize,
    pub sweep_interval: Duration,
    /// TEST ONLY: count each IP:port as its own destination, like
    /// `DhtTuning::limits_by_endpoint`. Production counts per IP.
    pub by_endpoint: bool,
}

impl Default for DestLimits {
    fn default() -> Self {
        Self {
            max_concurrent: DEST_MAX_CONCURRENT,
            max_attempts: DEST_MAX_ATTEMPTS,
            window: DEST_WINDOW,
            negative_ttl: DEST_NEGATIVE_TTL,
            negative_ttl_short: DEST_NEGATIVE_TTL_SHORT,
            capacity: DEST_CAPACITY,
            sweep_interval: DEST_SWEEP_INTERVAL,
            by_endpoint: false,
        }
    }
}

/// Why a destination was skipped (the `reason` label of
/// `dc4_destination_skipped_total`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestDenied {
    /// Already at the concurrent-connection limit.
    Busy,
    /// Already at the attempts-per-minute limit.
    RateLimited,
    /// Recently refused or timed out.
    NegativeCache,
    /// The map is full of active destinations.
    Full,
}

impl DestDenied {
    /// The metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            DestDenied::Busy => "busy",
            DestDenied::RateLimited => "rate_limited",
            DestDenied::NegativeCache => "negative_cache",
            DestDenied::Full => "map_full",
        }
    }

    /// Whether the peer deserves another chance later in the same obtain.
    /// `Busy`, `RateLimited` and `Full` are momentary (budget frees up as
    /// attempts finish); a live negative-cache entry stays failed until it
    /// expires, so requeueing it could only spin.
    fn retryable(self) -> bool {
        !matches!(self, DestDenied::NegativeCache)
    }
}

/// Peers the destination limiter refused, held for one retry per progress
/// step within the same obtain instead of being dropped for the key.
///
/// `progress` counts completed work (finished attempts, finished lookups);
/// requeueing only when it advanced guarantees a permanently-refused peer
/// waits for real time to pass instead of spinning, and terminates because
/// progress steps are bounded by the attempt budget plus two lookups.
#[derive(Debug, Default)]
struct Deferred {
    peers: Vec<SocketAddr>,
    requeued_at: usize,
}

impl Deferred {
    fn push(&mut self, peer: SocketAddr) {
        self.peers.push(peer);
    }

    fn requeue(&mut self, queue: &mut VecDeque<SocketAddr>, progress: usize) {
        if !self.peers.is_empty() && progress != self.requeued_at {
            queue.extend(self.peers.drain(..));
            self.requeued_at = progress;
        }
    }
}

#[derive(Debug)]
struct Destination {
    active: u32,
    attempts: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl Destination {
    fn idle(&self, now: Instant, window: Duration) -> bool {
        self.active == 0
            && self.blocked_until.is_none_or(|until| until <= now)
            && self
                .attempts
                .back()
                .is_none_or(|at| now.saturating_duration_since(*at) >= window)
    }
}

#[derive(Debug, Default)]
struct LimiterState {
    /// Keyed by IP (with port 0), or by endpoint with `by_endpoint`.
    map: HashMap<SocketAddr, Destination>,
    last_sweep: Option<Instant>,
}

/// Limits connections per destination IP: concurrency, attempts per
/// minute, and a negative cache. The map is bounded; when it is full of
/// destinations that are still in use, new ones are refused rather than
/// evicting live entries.
#[derive(Debug)]
pub struct DestinationLimiter {
    limits: DestLimits,
    state: Mutex<LimiterState>,
}

impl DestinationLimiter {
    /// A new limiter.
    pub fn new(limits: DestLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            state: Mutex::new(LimiterState::default()),
        })
    }

    fn key(&self, peer: SocketAddr) -> SocketAddr {
        let peer = canonical_addr(peer);
        if self.limits.by_endpoint {
            peer
        } else {
            SocketAddr::new(peer.ip(), 0)
        }
    }

    /// Starts an attempt to `peer`, or says why not.
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: SocketAddr,
        now: Instant,
    ) -> Result<DestPermit, DestDenied> {
        let ip = self.key(peer);
        let limits = self.limits;
        let mut state = lock(&self.state);
        if !state.map.contains_key(&ip) && state.map.len() >= limits.capacity {
            let sweep_due = state
                .last_sweep
                .is_none_or(|at| now.saturating_duration_since(at) >= limits.sweep_interval);
            if sweep_due {
                state.map.retain(|_, d| !d.idle(now, limits.window));
                state.last_sweep = Some(now);
            }
            if state.map.len() >= limits.capacity {
                return Err(DestDenied::Full);
            }
        }
        let dest = state.map.entry(ip).or_insert_with(|| Destination {
            active: 0,
            attempts: VecDeque::new(),
            blocked_until: None,
        });
        if let Some(until) = dest.blocked_until {
            if now < until {
                return Err(DestDenied::NegativeCache);
            }
            dest.blocked_until = None;
        }
        while dest
            .attempts
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= limits.window)
        {
            dest.attempts.pop_front();
        }
        if dest.active >= limits.max_concurrent {
            return Err(DestDenied::Busy);
        }
        if dest.attempts.len() >= limits.max_attempts {
            return Err(DestDenied::RateLimited);
        }
        dest.active = dest.active.saturating_add(1);
        dest.attempts.push_back(now);
        Ok(DestPermit {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// Destinations tracked.
    pub fn len(&self) -> usize {
        lock(&self.state).map.len()
    }

    /// True when no destination is tracked.
    pub fn is_empty(&self) -> bool {
        lock(&self.state).map.is_empty()
    }
}

/// One attempt in progress; dropping it frees the slot.
#[derive(Debug)]
pub struct DestPermit {
    limiter: Arc<DestinationLimiter>,
    ip: SocketAddr,
}

impl DestPermit {
    /// Ends the attempt. A `negative` attempt (a non-refused connect error)
    /// makes the destination skipped for the long negative-cache time;
    /// refused and timed-out errors use the short one (see
    /// [`negative_ttl_for`]).
    pub fn finish(self, negative: bool, now: Instant) {
        let long = self.limiter.limits.negative_ttl;
        self.finish_with_ttl(negative.then_some(long), now);
    }

    /// Ends the attempt, skipping the destination until `now + ttl`.
    pub fn finish_with_ttl(self, ttl: Option<Duration>, now: Instant) {
        if let Some(ttl) = ttl {
            let until = after(now, ttl);
            if let Some(dest) = lock(&self.limiter.state).map.get_mut(&self.ip) {
                dest.blocked_until = Some(until);
            }
        }
    }
}

/// Negative-cache TTL for a fetch failure, if any: refused and timed-out
/// destinations rest briefly, other connect errors rest longer, and
/// post-connect failures are not cached.
fn negative_ttl_for(err: &FetchError, limits: &DestLimits) -> Option<Duration> {
    match err {
        FetchError::Timeout => Some(limits.negative_ttl_short),
        FetchError::Connect(kind)
            if *kind == std::io::ErrorKind::ConnectionRefused
                || *kind == std::io::ErrorKind::TimedOut =>
        {
            Some(limits.negative_ttl_short)
        }
        FetchError::Connect(_) => Some(limits.negative_ttl),
        _ => None,
    }
}

impl Drop for DestPermit {
    fn drop(&mut self) {
        if let Some(dest) = lock(&self.limiter.state).map.get_mut(&self.ip) {
            dest.active = dest.active.saturating_sub(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

/// What fetched metadata turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inspection {
    /// It does not hash to the key.
    Mismatch,
    /// It could not be parsed.
    Invalid,
    /// A BEP 27 private torrent.
    Private,
    /// A torrent that may be stored.
    Valid(TorrentMeta),
}

/// Verifies `info` against `key` and parses it. CPU-bound; run it off the
/// async threads.
pub fn inspect(key: &DhtKey, info: &[u8]) -> Inspection {
    if dc4_torrent::verify(key, info).is_none() {
        return Inspection::Mismatch;
    }
    let parsed = dc4_torrent::parse_info_visit(info, &mut |_| {});
    match parsed {
        Err(_) => Inspection::Invalid,
        Ok(meta) if meta.private => Inspection::Private,
        Ok(meta) => Inspection::Valid(meta),
    }
}

/// The store record for a parsed torrent.
pub fn new_torrent(key: DhtKey, meta: TorrentMeta) -> NewTorrent {
    NewTorrent {
        dht_key: key,
        info_hash_v1: meta.info_hash_v1,
        info_hash_v2: meta.info_hash_v2,
        name: meta.name,
        total_size: meta.total_size,
        file_count: meta.file_count,
        files: meta
            .files
            .into_iter()
            .map(|f| FileRow {
                path: f.path,
                size: f.size,
            })
            .collect(),
        files_truncated: meta.files_truncated,
        piece_length: meta.piece_length,
    }
}

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

/// Renews a lease in the background until dropped.
struct RenewalGuard(tokio::task::JoinHandle<()>);

/// True when a background lease renewal could act before the fetch's own
/// deadline: the first tick fires at `renew_every`, and past `key_deadline`
/// the fetch is already timed out. With default tuning (90 s vs 45 s) the
/// tick never fires, so spawning the guard is pure overhead (a task plus a
/// timer per key across all workers).
fn renewal_before_deadline(renew_every: Duration, key_deadline: Duration) -> bool {
    renew_every.max(MIN_RENEW_INTERVAL) < key_deadline
}

impl RenewalGuard {
    fn spawn<S: CrawlStore>(store: S, key: DhtKey, lease: Duration, every: Duration) -> Self {
        let every = every.max(MIN_RENEW_INTERVAL);
        Self(tokio::spawn(async move {
            let mut ticker = tokio::time::interval_at(after(Instant::now(), every), every);
            loop {
                ticker.tick().await;
                match store.renew(&key, lease).await {
                    Ok(true) => {}
                    Ok(false) => tracing::debug!("a queue lease was lost during a fetch"),
                    Err(e) => tracing::warn!(error = %e, "renewing a queue lease failed"),
                }
            }
        }))
    }

    /// Renews every key of a claimed batch until dropped. A batch holds its
    /// leases for the whole sequential fetch run plus the batched store: up
    /// to `CLAIM_BATCH` × `key_deadline` (8 × 45 s = 360 s by default), far
    /// past the 120 s lease — even though one key alone (45 s) never needs
    /// renewal. Without this, early keys' leases expire mid-batch and another
    /// worker can claim and re-fetch them (wasted work, double attempts).
    /// Returns `None` when renewal cannot help (no keys, or the first tick
    /// would fire after the lease already expired).
    fn spawn_all<S: CrawlStore>(
        store: S,
        keys: &[DhtKey],
        lease: Duration,
        every: Duration,
    ) -> Option<Self> {
        if keys.is_empty() {
            return None;
        }
        let every = every.max(MIN_RENEW_INTERVAL);
        if every >= lease {
            return None;
        }
        let keys = keys.to_vec();
        Some(Self(tokio::spawn(async move {
            let mut ticker = tokio::time::interval_at(after(Instant::now(), every), every);
            loop {
                ticker.tick().await;
                for key in &keys {
                    match store.renew(key, lease).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::debug!("a queue lease was lost during a fetch");
                        }
                        Err(e) => tracing::warn!(error = %e, "renewing a queue lease failed"),
                    }
                }
            }
        })))
    }
}

impl Drop for RenewalGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Obtained {
    Metadata(Vec<u8>),
    NoPeers,
    Failed,
}

/// Everything the fetch workers share.
pub struct Fetcher<S, P> {
    store: S,
    peers: P,
    filter: PeerFilter,
    hints: SharedHints,
    limiter: Arc<DestinationLimiter>,
    connections: Semaphore,
    byte_budget: Arc<Semaphore>,
    max_metadata: usize,
    tuning: FetchTuning,
}

impl<S, P> std::fmt::Debug for Fetcher<S, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetcher")
            .field("tuning", &self.tuning)
            .finish_non_exhaustive()
    }
}

/// Sizes of the shared fetch resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchLimitsConfig {
    /// Concurrent peer connections in total (`crawl.max_connections`).
    pub max_connections: usize,
    /// Largest accepted `metadata_size` (`crawl.max_metadata_bytes`).
    pub max_metadata_bytes: usize,
    /// Metadata bytes held by all fetches (`crawl.max_inflight_metadata_bytes`).
    pub max_inflight_metadata_bytes: usize,
}

/// What one claimed key needs from the database, decided without any store
/// access.
#[derive(Debug)]
enum Staged {
    /// No usable peer was found.
    Missing,
    /// Peers were found, but no fetch succeeded in time.
    Failed,
    /// Verified metadata that can never be stored, with its outcome.
    Doomed(FetchOutcome),
    /// A torrent ready to store.
    Ready(NewTorrent),
}

impl<S: CrawlStore, P: PeerSource> Fetcher<S, P> {
    /// Shared state for the workers.
    pub fn new(
        store: S,
        peers: P,
        filter: PeerFilter,
        hints: SharedHints,
        limits: FetchLimitsConfig,
        tuning: FetchTuning,
    ) -> Self {
        let budget_permits = (limits.max_inflight_metadata_bytes / BYTE_BUDGET_UNIT)
            .clamp(1, Semaphore::MAX_PERMITS);
        // The test switch applies to every per-address rule.
        let destinations = DestLimits {
            by_endpoint: tuning.destinations.by_endpoint || filter.by_endpoint,
            ..tuning.destinations
        };
        Self {
            store,
            peers,
            filter,
            hints,
            limiter: DestinationLimiter::new(destinations),
            connections: Semaphore::new(limits.max_connections.clamp(1, Semaphore::MAX_PERMITS)),
            byte_budget: Arc::new(Semaphore::new(budget_permits)),
            max_metadata: limits.max_metadata_bytes,
            tuning,
        }
    }

    /// The destination limiter.
    pub fn limiter(&self) -> &Arc<DestinationLimiter> {
        &self.limiter
    }

    /// Fetches, verifies and parses one claimed key: the network half of
    /// [`Fetcher::process`], with no store access and no metrics.
    async fn fetch_item(&self, item: &PendingItem) -> Staged {
        self.fetch_item_inner(item, true).await
    }

    /// [`Fetcher::fetch_item`], with the per-key renewal guard optional.
    /// [`Fetcher::process_batch`] disables it: the batch guard (one task for
    /// all keys, held for the whole batch) covers every key, so per-key
    /// tasks would only duplicate renewals.
    async fn fetch_item_inner(&self, item: &PendingItem, renew: bool) -> Staged {
        let key = item.dht_key;
        let renewal = (renew
            && renewal_before_deadline(self.tuning.renew_every, self.tuning.key_deadline))
        .then(|| {
            RenewalGuard::spawn(
                self.store.clone(),
                key,
                self.tuning.lease,
                self.tuning.renew_every,
            )
        });
        let obtained =
            tokio::time::timeout(self.tuning.key_deadline, self.obtain(key, item.seeders_est))
                .await
                .unwrap_or(Obtained::Failed);
        drop(renewal);
        match obtained {
            Obtained::NoPeers => Staged::Missing,
            Obtained::Failed => Staged::Failed,
            Obtained::Metadata(info) => {
                let key = item.dht_key;
                let inspection = tokio::task::spawn_blocking(move || inspect(&key, &info))
                    .await
                    .unwrap_or(Inspection::Invalid);
                match inspection {
                    Inspection::Mismatch => Staged::Failed,
                    Inspection::Invalid => Staged::Doomed(FetchOutcome::ParseError),
                    Inspection::Private => Staged::Doomed(FetchOutcome::Private),
                    Inspection::Valid(meta) => Staged::Ready(new_torrent(key, meta)),
                }
            }
        }
    }

    /// Records one fetched item.
    async fn store_one(&self, item: &PendingItem, staged: Staged) -> FetchOutcome {
        let outcome = match staged {
            Staged::Missing => self.give_back(item.dht_key, FetchOutcome::NoPeers).await,
            Staged::Failed => {
                self.give_back(item.dht_key, FetchOutcome::FetchFailed)
                    .await
            }
            Staged::Doomed(outcome) => self.give_up(item.dht_key, outcome).await,
            Staged::Ready(t) => self.store_ready(item.dht_key, t).await,
        };
        self.emit(item, outcome);
        outcome
    }

    /// The outcome counter and debug log, identical for every store path.
    /// Both counters carry the claim-time estimate bucket (see
    /// [`est_bucket`]), so ok per dial is readable per bucket.
    fn emit(&self, item: &PendingItem, outcome: FetchOutcome) {
        metrics::counter!(
            METRIC_FETCH,
            "outcome" => outcome.as_str(),
            "est" => est_bucket(item.seeders_est)
        )
        .increment(1);
        tracing::debug!(
            outcome = outcome.as_str(),
            earlier_attempts = item.attempts,
            "fetch finished"
        );
    }

    /// Fetches, checks and stores one claimed key.
    pub async fn process(&self, item: &PendingItem) -> FetchOutcome {
        let staged = self.fetch_item(item).await;
        self.store_one(item, staged).await
    }

    async fn obtain(&self, key: DhtKey, est: Option<u32>) -> Obtained {
        let effort = effort_for(est);
        let bucket = est_bucket(est);
        // The estimate bucket sets the per-key budget; tuning stays a
        // global ceiling so a lowered test knob still binds.
        let max_attempts = effort.max_attempts.min(self.tuning.max_attempts);
        let mut own = OwnAddrs::of(&self.peers);
        let mut queue: VecDeque<SocketAddr> = VecDeque::new();
        let mut seen: HashSet<SocketAddr> = HashSet::new();
        let hinted = take_hints(&self.hints, &key, Instant::now());
        if hinted.is_empty() {
            metrics::counter!(METRIC_HINT_USED, "outcome" => "empty").increment(1);
        }
        for peer in hinted {
            match self.filter.accept(peer, &own) {
                Some(peer) if seen.insert(peer) => {
                    metrics::counter!(METRIC_HINT_USED, "outcome" => "dialed").increment(1);
                    queue.push_back(peer);
                }
                _ => {
                    metrics::counter!(METRIC_HINT_USED, "outcome" => "filtered").increment(1);
                }
            }
        }
        // Boxed so a high-estimate key can run a second lookup after the
        // first drains (update.md step 4); `scrape_peers` takes `&self`, so
        // every call is a fresh future. The caller's key deadline bounds the
        // pair — no new timeout knob.
        let mut lookup: Option<Pin<Box<dyn Future<Output = dc4_dht::ScrapeReport> + Send>>> = Some(
            Box::pin(self.peers.scrape_peers(key, self.tuning.get_peers_timeout)),
        );
        let mut lookups_done: u8 = 0;
        let mut attempts = 0usize;
        let mut running = FuturesUnordered::new();
        let mut deferred = Deferred::default();
        let mut progress = 0usize;
        loop {
            if queue.is_empty() {
                deferred.requeue(&mut queue, progress);
            }
            while running.len() < self.tuning.parallel_attempts && attempts < max_attempts {
                let Some(peer) = queue.pop_front() else { break };
                match self.limiter.try_acquire(peer, Instant::now()) {
                    Ok(permit) => {
                        attempts = attempts.saturating_add(1);
                        metrics::counter!(METRIC_DIALS, "est" => bucket).increment(1);
                        running.push(self.attempt(peer, key, permit));
                    }
                    Err(denied) => {
                        metrics::counter!(METRIC_DESTINATION_SKIPPED, "reason" => denied.as_str())
                            .increment(1);
                        if denied.retryable() {
                            deferred.push(peer);
                        }
                    }
                }
            }
            // A proven swarm earns one more lookup when stalled drained:
            // nothing running, nothing queued, dial budget left. This also
            // un-sticks limiter-deferred peers: the completing lookup counts
            // as progress, so they requeue on the next pass. Capped at
            // `max_lookups`, so the loop still terminates.
            if lookup.is_none()
                && lookups_done < effort.max_lookups
                && running.is_empty()
                && queue.is_empty()
                && attempts < max_attempts
            {
                lookup = Some(Box::pin(
                    self.peers.scrape_peers(key, self.tuning.get_peers_timeout),
                ));
            }
            if running.is_empty() && (lookup.is_none() || attempts >= max_attempts) {
                break;
            }
            tokio::select! {
                report = async {
                    if let Some(lookup) = lookup.as_mut() {
                        lookup.await
                    } else {
                        std::future::pending().await
                    }
                }, if lookup.is_some() => {
                    lookups_done = lookups_done.saturating_add(1);
                    lookup = None;
                    progress = progress.saturating_add(1);
                    own = OwnAddrs::of(&self.peers);
                    // §8 piggyback: the traversal was already paid for, so
                    // its estimate is free liveness data for the queue's
                    // ordering. Unaware (None) leaves NULL, never 0.
                    // Best-effort: a lost write only costs ordering.
                    if let Some(est) = report.seeders_est()
                        && let Ok(est) = u32::try_from(est)
                        && let Err(e) = self.store.note_fetch_estimate(&key, est).await
                    {
                        tracing::debug!(error = %e, "note_fetch_estimate failed");
                    }
                    for peer in report.peers {
                        if let Some(peer) = self.filter.accept(peer, &own)
                            && seen.insert(peer)
                        {
                            // traversal-found peers become retry
                            // hints (bounded 8/key by `HintMap::add`), so a
                            // failed attempt's retry dials known-good peers
                            // first instead of re-traversing from scratch.
                            // `take` is destructive, so these survive only
                            // for the NEXT `obtain()` — this one already
                            // holds them in `seen`, no double-dial.
                            add_hint(&self.hints, key, peer, Instant::now());
                            queue.push_back(peer);
                        }
                    }
                }
                Some(result) = running.next(), if !running.is_empty() => {
                    progress = progress.saturating_add(1);
                    match result {
                        Ok(info) => return Obtained::Metadata(info),
                        Err(e) => tracing::debug!(reason = e.label(), "peer fetch failed"),
                    }
                }
                // Unreachable: the checks above keep one branch enabled.
                else => break,
            }
        }
        if seen.is_empty() {
            Obtained::NoPeers
        } else {
            Obtained::Failed
        }
    }

    async fn attempt(
        &self,
        peer: SocketAddr,
        key: DhtKey,
        permit: DestPermit,
    ) -> Result<Vec<u8>, FetchError> {
        let Ok(_slot) = self.connections.acquire().await else {
            return Err(FetchError::BudgetClosed);
        };
        let limits = FetchLimits {
            connect: self.tuning.connect_timeout,
            handshake: self.tuning.handshake_timeout,
            total: self.tuning.peer_timeout,
            max_metadata: self.max_metadata,
            byte_budget: Some(Arc::clone(&self.byte_budget)),
        };
        let result = dc4_peer::fetch_metadata(peer, key, &limits).await;
        let ttl = match &result {
            Err(e) => negative_ttl_for(e, &self.tuning.destinations),
            Ok(_) => None,
        };
        permit.finish_with_ttl(ttl, Instant::now());
        result
    }

    /// Stores one parsed torrent: the transaction half of the old
    /// `store_metadata`.
    async fn store_ready(&self, key: DhtKey, t: NewTorrent) -> FetchOutcome {
        match self.store.complete(&key, &t).await {
            Ok(_) => FetchOutcome::Ok,
            // The store can never accept this torrent (e.g. a size
            // above i64::MAX); retrying would loop on it forever.
            Err(e @ StoreError::Invalid(_)) => {
                tracing::warn!(error = %e, "fetched torrent cannot be stored; giving up");
                self.give_up(key, FetchOutcome::StoreError).await
            }
            Err(e) => {
                tracing::warn!(error = %e, "storing a fetched torrent failed");
                self.give_back(key, FetchOutcome::StoreError).await
            }
        }
    }

    async fn give_back(&self, key: DhtKey, outcome: FetchOutcome) -> FetchOutcome {
        match self.store.fail(&key).await {
            Ok(_) => outcome,
            Err(e) => {
                tracing::warn!(error = %e, "recording a failed fetch failed");
                FetchOutcome::StoreError
            }
        }
    }

    async fn give_up(&self, key: DhtKey, outcome: FetchOutcome) -> FetchOutcome {
        match self.store.give_up(&key).await {
            Ok(_) => outcome,
            Err(e) => {
                tracing::warn!(error = %e, "recording a failed fetch failed");
                FetchOutcome::StoreError
            }
        }
    }

    /// The single claimer: bulk-claims [`CLAIM_BULK`] keys per scan, slices
    /// each scan into [`CLAIM_BATCH`] batches, and feeds the workers. A full
    /// channel blocks `send`, which is the backpressure — there is no
    /// separate outstanding counter to drift. Each bulk scan is
    /// attempts-first ordered and the channel is FIFO, so order holds within
    /// a scan; across scans, keys that become due while the buffer is full
    /// wait behind at most 2048 already-claimed keys (~2.7 s of work).
    ///
    /// Stopping drops `tx`: workers drain what is buffered, then exit.
    /// Scans already claimed but never sent keep their leases, which expire
    /// in at most the lease — identical to crash semantics today. There is
    /// deliberately no renewal guard here: the worst-case dwell (~2.7 s,
    /// ~3.4 s counting the in-hand bulk) never reaches the first 90 s
    /// renewal tick, so it could never fire. Batch guards cover keys from
    /// dispense onward, unchanged.
    pub async fn run_claimer(
        self: Arc<Self>,
        tx: mpsc::Sender<Vec<PendingItem>>,
        stop: CancellationToken,
    ) {
        let base = self.tuning.store_retry_base;
        let mut backoff = base;
        metrics::gauge!(METRIC_CLAIM_CHAN_DEPTH).set(0.0);
        'outer: loop {
            if stop.is_cancelled() {
                break;
            }
            metrics::gauge!(METRIC_CLAIM_CHAN_DEPTH).set(claim_chan_depth(&tx) as f64);
            match claim_bulk(&self.store, CLAIM_BULK, self.tuning.lease).await {
                Ok(items) if items.is_empty() => {
                    backoff = base;
                    let pause = self.idle_pause();
                    tokio::select! {
                        () = stop.cancelled() => break 'outer,
                        () = tokio::time::sleep(pause) => {}
                    }
                }
                Ok(items) => {
                    backoff = base;
                    let batch_size = usize::try_from(CLAIM_BATCH).unwrap_or(usize::MAX).max(1);
                    for chunk in items.chunks(batch_size) {
                        let batch = chunk.to_vec();
                        tokio::select! {
                            () = stop.cancelled() => break 'outer,
                            res = tx.send(batch) => {
                                if res.is_err() {
                                    // Every worker is gone; nothing will ever
                                    // drain the channel again.
                                    break 'outer;
                                }
                            }
                        }
                        metrics::gauge!(METRIC_CLAIM_CHAN_DEPTH).set(claim_chan_depth(&tx) as f64);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "claiming queue items failed");
                    let pause = backoff;
                    backoff = backoff.saturating_mul(2).min(self.tuning.store_retry_max);
                    tokio::select! {
                        () = stop.cancelled() => break 'outer,
                        () = tokio::time::sleep(pause) => {}
                    }
                }
            }
        }
    }

    /// One worker: processes batches from the claim channel until `stop`
    /// fires and the channel is drained. A batch already received is
    /// finished first. When the claimer is gone and the channel is empty,
    /// the worker exits — the claimer only exits on `stop` (or when no
    /// worker can receive), so this is the shutdown path, and a panicked
    /// claimer still fails the role through the shared `JoinSet`.
    pub async fn run_worker(self: Arc<Self>, rx: ClaimRx, stop: CancellationToken) {
        loop {
            let batch = tokio::select! {
                biased;
                () = stop.cancelled() => {
                    // Drain-then-break: what is left buffered is seconds of
                    // work, far inside the shutdown wait, and every batch
                    // taken here is finished first below.
                    rx.lock().await.try_recv().ok()
                }
                batch = async { rx.lock().await.recv().await } => batch,
            };
            match batch {
                Some(batch) => {
                    self.process_batch(&batch).await;
                }
                None => break,
            }
        }
    }

    /// Fetches a claimed batch, then records it in as few transactions as
    /// the store allows. Outcomes and metrics match one-by-one `process()`.
    /// One renewal task covers all keys for the whole batch (sequential
    /// fetches plus the batched store can outlive the lease).
    async fn process_batch(&self, items: &[PendingItem]) {
        let keys: Vec<DhtKey> = items.iter().map(|item| item.dht_key).collect();
        let _batch_renewals = RenewalGuard::spawn_all(
            self.store.clone(),
            &keys,
            self.tuning.lease,
            self.tuning.renew_every,
        );
        let mut staged = Vec::with_capacity(items.len());
        for item in items {
            staged.push(self.fetch_item_inner(item, false).await);
        }
        let mut readies: Vec<(&PendingItem, NewTorrent)> = Vec::new();
        let mut faileds: Vec<(&PendingItem, FetchOutcome)> = Vec::new();
        let mut doomeds: Vec<(&PendingItem, FetchOutcome)> = Vec::new();
        for (item, stage) in items.iter().zip(staged) {
            match stage {
                Staged::Ready(t) => readies.push((item, t)),
                Staged::Missing => faileds.push((item, FetchOutcome::NoPeers)),
                Staged::Failed => faileds.push((item, FetchOutcome::FetchFailed)),
                Staged::Doomed(outcome) => doomeds.push((item, outcome)),
            }
        }
        // Successes share one transaction; a rejected batch falls back to
        // one key at a time, exactly as `process()` would.
        if !readies.is_empty() {
            let pairs: Vec<(DhtKey, NewTorrent)> = readies
                .iter()
                .map(|(item, t)| (item.dht_key, t.clone()))
                .collect();
            match self.store.complete_batch(&pairs).await {
                Ok(ids) => {
                    debug_assert_eq!(ids.len(), readies.len());
                    for (item, _) in &readies {
                        self.emit(item, FetchOutcome::Ok);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "batched completion failed; storing one key at a time");
                    for (item, t) in readies {
                        let outcome = self.store_ready(item.dht_key, t).await;
                        self.emit(item, outcome);
                    }
                }
            }
        }
        if !faileds.is_empty() {
            let keys: Vec<DhtKey> = faileds.iter().map(|(item, _)| item.dht_key).collect();
            match self.store.fail_batch(&keys).await {
                Ok(()) => {
                    for (item, outcome) in &faileds {
                        self.emit(item, *outcome);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "batched failure recording failed; recording one key at a time");
                    for (item, outcome) in faileds {
                        let stored = self.give_back(item.dht_key, outcome).await;
                        self.emit(item, stored);
                    }
                }
            }
        }
        if !doomeds.is_empty() {
            let keys: Vec<DhtKey> = doomeds.iter().map(|(item, _)| item.dht_key).collect();
            match self.store.give_up_batch(&keys).await {
                Ok(()) => {
                    for (item, outcome) in &doomeds {
                        self.emit(item, *outcome);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "batched give-up failed; recording one key at a time");
                    for (item, outcome) in doomeds {
                        let stored = self.give_up(item.dht_key, outcome).await;
                        self.emit(item, stored);
                    }
                }
            }
        }
    }

    fn idle_pause(&self) -> Duration {
        let a = millis(self.tuning.idle_min);
        let b = millis(self.tuning.idle_max);
        Duration::from_millis(rand::random_range(a.min(b)..=a.max(b)))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::collections::BTreeMap;

    use dc4_bencode::OwnedValue;
    use tokio::net::TcpListener;

    use std::net::IpAddr;

    use super::*;
    use crate::admission::{AdmissionTuning, shared_hints};
    use crate::memstore::MemoryStore;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A destination on port 6881.
    fn dest(s: &str) -> SocketAddr {
        SocketAddr::new(ip(s), 6881)
    }

    fn limits(capacity: usize) -> DestLimits {
        DestLimits {
            capacity,
            ..DestLimits::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn destination_concurrency() {
        let l = DestinationLimiter::new(limits(10));
        let now = Instant::now();
        let a = l.try_acquire(dest("1.1.1.1"), now).unwrap();
        let b = l.try_acquire(dest("::ffff:1.1.1.1"), now).unwrap();
        assert_eq!(
            l.try_acquire(dest("1.1.1.1"), now).unwrap_err(),
            DestDenied::Busy
        );
        // Another destination is independent.
        let _c = l.try_acquire(dest("1.1.1.2"), now).unwrap();
        drop(a);
        let _d = l.try_acquire(dest("1.1.1.1"), now).unwrap();
        b.finish(false, now);
        let _e = l.try_acquire(dest("1.1.1.1"), now).unwrap();
        assert_eq!(l.len(), 2);

        // In production any port of one IP is the same destination.
        let at = |port| SocketAddr::new(ip("5.5.5.5"), port);
        let _x = l.try_acquire(at(1), now).unwrap();
        let _y = l.try_acquire(at(2), now).unwrap();
        assert_eq!(l.try_acquire(at(3), now).unwrap_err(), DestDenied::Busy);
        // With the test switch each endpoint is its own destination.
        let t = DestinationLimiter::new(DestLimits {
            by_endpoint: true,
            ..limits(10)
        });
        let held: Vec<DestPermit> = (1..=3)
            .map(|port| t.try_acquire(at(port), now).unwrap())
            .collect();
        assert_eq!(held.len(), 3);
        assert_eq!(t.len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn destination_attempts_per_minute() {
        let l = DestinationLimiter::new(limits(10));
        let t0 = Instant::now();
        for i in 0..DEST_MAX_ATTEMPTS {
            let at = t0 + Duration::from_secs(u64::try_from(i).unwrap());
            l.try_acquire(dest("2.2.2.2"), at)
                .unwrap()
                .finish(false, at);
        }
        let t = t0 + Duration::from_secs(30);
        assert_eq!(
            l.try_acquire(dest("2.2.2.2"), t).unwrap_err(),
            DestDenied::RateLimited
        );
        // The first attempt leaves the window after a minute.
        let t = t0 + DEST_WINDOW;
        l.try_acquire(dest("2.2.2.2"), t).unwrap();
        assert_eq!(
            l.try_acquire(dest("2.2.2.2"), t).unwrap_err(),
            DestDenied::RateLimited
        );
    }

    #[tokio::test(start_paused = true)]
    async fn destination_negative_cache() {
        let l = DestinationLimiter::new(limits(10));
        let t0 = Instant::now();
        l.try_acquire(dest("3.3.3.3"), t0).unwrap().finish(true, t0);
        let t = t0 + DEST_NEGATIVE_TTL - Duration::from_secs(1);
        assert_eq!(
            l.try_acquire(dest("3.3.3.3"), t).unwrap_err(),
            DestDenied::NegativeCache
        );
        l.try_acquire(dest("3.3.3.3"), t0 + DEST_NEGATIVE_TTL)
            .unwrap();
    }

    #[test]
    fn negative_ttl_classifier_splits_refused_and_timeout() {
        use std::io::ErrorKind;
        let limits = DestLimits::default();
        assert_eq!(
            negative_ttl_for(&FetchError::Timeout, &limits),
            Some(DEST_NEGATIVE_TTL_SHORT)
        );
        assert_eq!(
            negative_ttl_for(&FetchError::Connect(ErrorKind::ConnectionRefused), &limits),
            Some(DEST_NEGATIVE_TTL_SHORT)
        );
        assert_eq!(
            negative_ttl_for(&FetchError::Connect(ErrorKind::TimedOut), &limits),
            Some(DEST_NEGATIVE_TTL_SHORT)
        );
        assert_eq!(
            negative_ttl_for(&FetchError::Connect(ErrorKind::AddrInUse), &limits),
            Some(DEST_NEGATIVE_TTL)
        );
        assert_eq!(
            negative_ttl_for(&FetchError::Io(ErrorKind::ConnectionReset), &limits),
            None
        );
        assert_eq!(negative_ttl_for(&FetchError::Rejected, &limits), None);
        assert_eq!(negative_ttl_for(&FetchError::BadHandshake, &limits), None);
    }

    #[tokio::test(start_paused = true)]
    async fn destination_negative_ttl_split() {
        let l = DestinationLimiter::new(limits(10));
        let t0 = Instant::now();
        l.try_acquire(dest("1.2.3.4"), t0)
            .unwrap()
            .finish_with_ttl(Some(DEST_NEGATIVE_TTL_SHORT), t0);
        l.try_acquire(dest("5.6.7.8"), t0).unwrap().finish(true, t0);
        // After the short TTL the refused destination is back, while the
        // long-blocked one is still denied.
        let t = t0 + DEST_NEGATIVE_TTL_SHORT;
        l.try_acquire(dest("1.2.3.4"), t).unwrap().finish(false, t);
        assert_eq!(
            l.try_acquire(dest("5.6.7.8"), t).unwrap_err(),
            DestDenied::NegativeCache
        );
        l.try_acquire(dest("5.6.7.8"), t0 + DEST_NEGATIVE_TTL)
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn full_destination_map_refuses_instead_of_evicting() {
        let l = DestinationLimiter::new(limits(2));
        let t0 = Instant::now();
        let held = l.try_acquire(dest("4.4.4.1"), t0).unwrap();
        l.try_acquire(dest("4.4.4.2"), t0).unwrap().finish(true, t0);
        assert_eq!(
            l.try_acquire(dest("4.4.4.3"), t0).unwrap_err(),
            DestDenied::Full
        );
        // Known destinations are still served.
        assert!(l.try_acquire(dest("4.4.4.1"), t0).is_ok());
        // Once entries go idle, a sweep makes room; the one in use stays.
        let t = t0 + DEST_NEGATIVE_TTL;
        l.try_acquire(dest("4.4.4.3"), t).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(
            l.try_acquire(dest("4.4.4.1"), t).map(|_| ()),
            Ok(()),
            "an active destination is never evicted"
        );
        drop(held);
    }

    #[test]
    fn outcome_labels() {
        let labels: Vec<&str> = FetchOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(
            labels,
            [
                "ok",
                "no_peers",
                "fetch_failed",
                "parse_error",
                "private",
                "store_error"
            ]
        );
    }

    #[test]
    fn only_momentary_denials_are_retried() {
        assert!(DestDenied::Busy.retryable());
        assert!(DestDenied::RateLimited.retryable());
        assert!(DestDenied::Full.retryable());
        assert!(!DestDenied::NegativeCache.retryable());
    }

    #[test]
    fn deferred_peers_retry_once_per_progress_step() {
        let mut queue = VecDeque::from([dest("9.9.9.9")]);
        let mut deferred = Deferred::default();
        deferred.push(queue.pop_front().unwrap());
        assert!(queue.is_empty());
        // No progress yet: no requeue, so a still-busy peer cannot spin.
        deferred.requeue(&mut queue, 0);
        assert!(queue.is_empty());
        // After other work finished, the peer gets another chance.
        deferred.requeue(&mut queue, 1);
        assert_eq!(queue.len(), 1);
        // ...but only one chance per progress step: a repeat denial waits.
        deferred.push(queue.pop_front().unwrap());
        deferred.requeue(&mut queue, 1);
        assert!(queue.is_empty());
        deferred.requeue(&mut queue, 2);
        assert_eq!(queue.len(), 1);
    }

    /// SHA-1 (FIPS 180-4), to key test data that does not parse.
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [
            0x6745_2301,
            0xEFCD_AB89,
            0x98BA_DCFE,
            0x1032_5476,
            0xC3D2_E1F0,
        ];
        let bit_len = u64::try_from(data.len()).unwrap().wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());
        for chunk in msg.chunks(64) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let [mut a, mut b, mut c, mut d, mut e] = h;
            for (i, wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                    20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                    _ => (b ^ c ^ d, 0xCA62_C1D6),
                };
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(*wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = t;
            }
            for (hv, v) in h.iter_mut().zip([a, b, c, d, e]) {
                *hv = hv.wrapping_add(v);
            }
        }
        let mut out = [0u8; 20];
        for (i, v) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    /// A v1 multi-file info dictionary whose files are 1 000 bytes each.
    pub(crate) fn info_dict(name: &str, files: &[&str], private: bool) -> Vec<u8> {
        let sized: Vec<(&str, i64)> = files.iter().map(|f| (*f, 1000)).collect();
        info_dict_sized(name, &sized, private)
    }

    /// A v1 multi-file info dictionary with the given file sizes.
    fn info_dict_sized(name: &str, files: &[(&str, i64)], private: bool) -> Vec<u8> {
        let mut d = BTreeMap::new();
        d.insert(b"name".to_vec(), OwnedValue::from(name));
        d.insert(b"piece length".to_vec(), OwnedValue::Int(16384));
        d.insert(b"pieces".to_vec(), OwnedValue::Bytes(vec![7u8; 20]));
        let list = files
            .iter()
            .map(|(path, length)| {
                let mut f = BTreeMap::new();
                f.insert(b"length".to_vec(), OwnedValue::Int(*length));
                f.insert(
                    b"path".to_vec(),
                    OwnedValue::List(path.split('/').map(OwnedValue::from).collect()),
                );
                OwnedValue::Dict(f)
            })
            .collect();
        d.insert(b"files".to_vec(), OwnedValue::List(list));
        if private {
            d.insert(b"private".to_vec(), OwnedValue::Int(1));
        }
        dc4_bencode::encode(&OwnedValue::Dict(d))
    }

    fn key_of(info: &[u8]) -> DhtKey {
        dc4_torrent::parse_info(info).unwrap().info_hash_v1.unwrap()
    }

    #[test]
    fn inspection() {
        let good = info_dict("ubuntu images", &["a/one.iso", "b/two.iso"], false);
        let k = key_of(&good);
        match inspect(&k, &good) {
            Inspection::Valid(meta) => {
                assert_eq!(meta.name, "ubuntu images");
                let t = new_torrent(k, meta);
                assert_eq!(t.files.len(), 2);
                assert_eq!(t.total_size, 2000);
                assert_eq!(t.info_hash_v1, Some(k));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(inspect(&DhtKey([0; 20]), &good), Inspection::Mismatch);
        let private = info_dict("tracker only", &["x.txt"], true);
        assert_eq!(inspect(&key_of(&private), &private), Inspection::Private);
        // The test SHA-1 agrees with dc4-torrent.
        assert_eq!(DhtKey(sha1(&good)), k);
        assert_eq!(
            DhtKey(sha1(b"abc")).to_hex(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        // Verified but unparseable: not a torrent, or a negative length.
        let junk = dc4_bencode::encode(&OwnedValue::Dict(BTreeMap::new()));
        assert_eq!(inspect(&DhtKey(sha1(&junk)), &junk), Inspection::Invalid);
        let negative = info_dict_sized("clean name", &[("a.txt", 5), ("b.txt", -1)], false);
        assert_eq!(
            inspect(&DhtKey(sha1(&negative)), &negative),
            Inspection::Invalid
        );
    }

    #[derive(Clone)]
    struct FixedPeers(Vec<SocketAddr>);

    impl PeerSource for FixedPeers {
        async fn get_peers(&self, _: DhtKey, _: Duration) -> Vec<SocketAddr> {
            self.0.clone()
        }
        async fn scrape_peers(&self, _: DhtKey, _: Duration) -> dc4_dht::ScrapeReport {
            dc4_dht::ScrapeReport {
                peers: self.0.clone(),
                ..dc4_dht::ScrapeReport::default()
            }
        }
        fn own_ips(&self) -> Vec<IpAddr> {
            vec![ip("127.0.0.1")]
        }
        fn own_endpoints(&self) -> Vec<SocketAddr> {
            Vec::new()
        }
    }

    fn test_tuning() -> FetchTuning {
        FetchTuning {
            connect_timeout: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
            peer_timeout: Duration::from_secs(3),
            key_deadline: Duration::from_secs(10),
            idle_min: Duration::from_millis(20),
            idle_max: Duration::from_millis(40),
            ..FetchTuning::default()
        }
    }

    fn fetcher<P: PeerSource>(store: &MemoryStore, peers: P) -> Arc<Fetcher<MemoryStore, P>> {
        fetcher_with(store, peers, test_tuning())
    }

    /// [`fetcher_with`], but the fetch reads `hints` first — for proving
    /// hint peers share the one dial budget.
    fn fetcher_with_hints<P: PeerSource>(
        store: &MemoryStore,
        peers: P,
        tuning: FetchTuning,
        hints: SharedHints,
    ) -> Arc<Fetcher<MemoryStore, P>> {
        let filter = PeerFilter {
            allow_private: true,
            by_endpoint: true,
        };
        Arc::new(Fetcher::new(
            store.clone(),
            peers,
            filter,
            hints,
            FetchLimitsConfig {
                max_connections: 8,
                max_metadata_bytes: 1024 * 1024,
                max_inflight_metadata_bytes: 1024 * 1024,
            },
            tuning,
        ))
    }

    fn fetcher_with<P: PeerSource>(
        store: &MemoryStore,
        peers: P,
        tuning: FetchTuning,
    ) -> Arc<Fetcher<MemoryStore, P>> {
        let filter = PeerFilter {
            allow_private: true,
            by_endpoint: true,
        };
        Arc::new(Fetcher::new(
            store.clone(),
            peers,
            filter,
            shared_hints(&AdmissionTuning::default()),
            FetchLimitsConfig {
                max_connections: 8,
                max_metadata_bytes: 1024 * 1024,
                max_inflight_metadata_bytes: 1024 * 1024,
            },
            tuning,
        ))
    }

    async fn seeder(info: &[u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(dc4_peer::seeder::serve(
            listener,
            key_of(info),
            info.to_vec(),
        ));
        addr
    }

    fn item(key: DhtKey) -> PendingItem {
        PendingItem {
            dht_key: key,
            attempts: 0,
            seen_count: 1,
            seeders_est: None,
        }
    }

    fn item_with(key: DhtKey, est: Option<u32>) -> PendingItem {
        PendingItem {
            seeders_est: est,
            ..item(key)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn claim_bulk_puts_live_keys_first_and_tops_up() {
        let store = MemoryStore::new();
        let live_lo = DhtKey([21; 20]);
        let live_hi = DhtKey([22; 20]);
        let dead = DhtKey([23; 20]);
        let fresh = DhtKey([24; 20]);
        for k in [live_lo, live_hi, dead, fresh] {
            store.enqueue(k);
        }
        store.note_fetch_estimate(&live_lo, 5).await.unwrap();
        store.note_fetch_estimate(&live_hi, 50).await.unwrap();
        // Measured dead: aware lookup, no seeds — never live.
        store.note_fetch_estimate(&dead, 0).await.unwrap();
        // Bulk of 3: both live keys first (higher estimate first), then
        // one top-up. The dead key flows via the top-up, never jumping
        // the queue (`NULLS LAST` puts `Some(0)` before `None`).
        let bulk = claim_bulk(&store, 3, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(bulk.len(), 3);
        assert_eq!(bulk[0].dht_key, live_hi);
        assert_eq!(bulk[1].dht_key, live_lo);
        assert_eq!(bulk[2].dht_key, dead);
        // No double-lease across the two phases.
        let mut keys: Vec<DhtKey> = bulk.iter().map(|i| i.dht_key).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 3);
        // Two store round trips while the live pool was short.
        assert_eq!(store.live_claim_calls(), 1);
        assert_eq!(store.claim_calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn claim_bulk_without_live_keys_is_one_unfiltered_bulk() {
        let store = MemoryStore::new();
        let a = DhtKey([31; 20]);
        let b = DhtKey([32; 20]);
        store.enqueue(a);
        store.enqueue(b);
        // No estimates anywhere: the live phase is empty and the top-up
        // is the whole bulk — today's behavior exactly, workers never idle.
        let bulk = claim_bulk(&store, 8, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(bulk.len(), 2);
        assert!(bulk.iter().all(|i| i.seeders_est.is_none()));
    }

    #[tokio::test(start_paused = true)]
    async fn claim_bulk_full_live_pool_skips_the_top_up() {
        let store = MemoryStore::new();
        for n in 0..4u8 {
            let k = DhtKey([40 + n; 20]);
            store.enqueue(k);
            store
                .note_fetch_estimate(&k, u32::from(n) + 1)
                .await
                .unwrap();
        }
        let bulk = claim_bulk(&store, 3, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(bulk.len(), 3);
        assert!(bulk.iter().all(|i| i.seeders_est.is_some_and(|e| e > 0)));
        // The live phase covered the bulk: no second round trip.
        assert_eq!(store.live_claim_calls(), 1);
        assert_eq!(store.claim_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn claim_bulk_propagates_store_errors_without_leasing() {
        let store = MemoryStore::new();
        store.enqueue(DhtKey([51; 20]));
        store.fail_next_claims(1);
        assert!(
            claim_bulk(&store, 8, Duration::from_secs(120))
                .await
                .is_err()
        );
        // The failed live phase leased nothing: the retry claims the key.
        let bulk = claim_bulk(&store, 8, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(bulk.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn claim_bulk_empty_or_nonpositive_is_empty() {
        let store = MemoryStore::new();
        assert!(
            claim_bulk(&store, 8, Duration::from_secs(120))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            claim_bulk(&store, 0, Duration::from_secs(120))
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A scripted claim backend for `claim_bulk`: the live phase returns
    /// canned items, the top-up is recorded and scripted. Everything else
    /// is unimplemented (these tests never touch it).
    #[derive(Clone)]
    struct ScriptedClaims {
        live: Vec<PendingItem>,
        topup: Vec<PendingItem>,
        fail_topup: bool,
        calls: Arc<Mutex<Vec<(&'static str, i64)>>>,
    }

    impl CrawlStore for ScriptedClaims {
        async fn observe(
            &self,
            _batch: &[dc4_store::Observation],
            _max_pending: i64,
        ) -> dc4_store::Result<dc4_store::ObserveOutcome> {
            unimplemented!()
        }
        async fn claim(&self, n: i64, _lease: Duration) -> dc4_store::Result<Vec<PendingItem>> {
            self.calls.lock().unwrap().push(("claim", n));
            if self.fail_topup {
                return Err(StoreError::Invalid("injected top-up failure".into()));
            }
            Ok(self.topup.clone())
        }
        async fn claim_live(
            &self,
            n: i64,
            _lease: Duration,
        ) -> dc4_store::Result<Vec<PendingItem>> {
            self.calls.lock().unwrap().push(("claim_live", n));
            Ok(self.live.clone())
        }
        async fn renew(&self, _key: &DhtKey, _lease: Duration) -> dc4_store::Result<bool> {
            unimplemented!()
        }
        async fn complete(&self, _key: &DhtKey, _t: &NewTorrent) -> dc4_store::Result<i64> {
            unimplemented!()
        }
        async fn fail(&self, _key: &DhtKey) -> dc4_store::Result<bool> {
            unimplemented!()
        }
        async fn give_up(&self, _key: &DhtKey) -> dc4_store::Result<bool> {
            unimplemented!()
        }
        async fn pending_depth(&self) -> dc4_store::Result<i64> {
            unimplemented!()
        }
        async fn claim_scrape_due(
            &self,
            _limit: i64,
            _live_interval: Duration,
            _unknown_interval: Duration,
        ) -> dc4_store::Result<Vec<dc4_store::ScrapeItem>> {
            unimplemented!()
        }
        async fn record_scrape(
            &self,
            _id: i64,
            _seeders_est: Option<u32>,
            _scrape_failures: u32,
        ) -> dc4_store::Result<bool> {
            unimplemented!()
        }
        async fn record_scrapes(
            &self,
            _rows: &[(i64, Option<u32>, u32)],
        ) -> dc4_store::Result<u64> {
            unimplemented!()
        }
        async fn tombstone_dead(
            &self,
            _id: i64,
            _old_last_seen_at: chrono::DateTime<chrono::Utc>,
            _old_change_seq: i64,
        ) -> dc4_store::Result<bool> {
            unimplemented!()
        }
        async fn purge_tombstoned(&self, _grace: Duration, _limit: i64) -> dc4_store::Result<u64> {
            unimplemented!()
        }
        async fn purge_gave_up(&self, _older_than: Duration) -> dc4_store::Result<u64> {
            unimplemented!()
        }
        async fn note_fetch_estimate(
            &self,
            _key: &DhtKey,
            _seeders_est: u32,
        ) -> dc4_store::Result<()> {
            unimplemented!()
        }
        async fn trim_removed_keys(&self, _cap: i64) -> dc4_store::Result<u64> {
            unimplemented!()
        }
        async fn removed_keys_count(&self) -> dc4_store::Result<i64> {
            unimplemented!()
        }
        async fn removal_cooldowns(
            &self,
            _keys: &[DhtKey],
            _base_days: u64,
            _strong_evidence: &[DhtKey],
        ) -> dc4_store::Result<Vec<dc4_store::RemovalCooldown>> {
            unimplemented!()
        }
        async fn note_removed_sightings(&self, _keys: &[DhtKey]) -> dc4_store::Result<u64> {
            unimplemented!()
        }
        async fn refresh_scraped(&self, _keys: &[DhtKey]) -> dc4_store::Result<u64> {
            unimplemented!()
        }
        async fn ping(&self) -> dc4_store::Result<()> {
            unimplemented!()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn claim_bulk_top_up_is_sized_to_fill_n() {
        let live_key = DhtKey([61; 20]);
        let store = ScriptedClaims {
            live: vec![PendingItem {
                dht_key: live_key,
                attempts: 1,
                seen_count: 2,
                seeders_est: Some(9),
            }],
            topup: vec![item(DhtKey([62; 20])), item(DhtKey([63; 20]))],
            fail_topup: false,
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let bulk = claim_bulk(&store, 8, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(bulk.len(), 3);
        assert_eq!(bulk[0].dht_key, live_key);
        // The top-up is asked for exactly the shortfall, not a full bulk.
        assert_eq!(
            store.calls.lock().unwrap().clone(),
            vec![("claim_live", 8), ("claim", 7)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn claim_bulk_top_up_failure_feeds_live_leases() {
        let live_key = DhtKey([64; 20]);
        let store = ScriptedClaims {
            live: vec![PendingItem {
                dht_key: live_key,
                attempts: 1,
                seen_count: 2,
                seeders_est: Some(9),
            }],
            topup: Vec::new(),
            fail_topup: true,
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        // A failed top-up feeds the live leases already held (with a
        // warning) instead of erroring the scan and idling the workers
        // while the leases tick down in the database.
        let bulk = claim_bulk(&store, 8, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(bulk.len(), 1);
        assert_eq!(bulk[0].dht_key, live_key);
        assert_eq!(
            store.calls.lock().unwrap().clone(),
            vec![("claim_live", 8), ("claim", 7)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn claim_bulk_empty_live_top_up_failure_still_errors() {
        let store = ScriptedClaims {
            live: Vec::new(),
            topup: Vec::new(),
            fail_topup: true,
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        // Nothing leased and nothing to top up with: the scan still errors
        // so the claimer backs off.
        assert!(
            claim_bulk(&store, 8, Duration::from_secs(120))
                .await
                .is_err()
        );
    }

    #[test]
    fn effort_buckets_match_the_plan() {
        assert_eq!(LOW_EFFORT_MAX_ATTEMPTS, 3);
        assert_eq!(HIGH_EST_MIN, 5);
        assert_eq!(HIGH_EST_MAX_LOOKUPS, 2);
        const {
            assert!(LOW_EFFORT_MAX_ATTEMPTS < MAX_PEER_ATTEMPTS);
        }
        assert_eq!(
            effort_for(None),
            KeyEffort {
                max_attempts: 3,
                max_lookups: 1
            }
        );
        assert_eq!(
            effort_for(Some(0)),
            KeyEffort {
                max_attempts: 3,
                max_lookups: 1
            }
        );
        assert_eq!(
            effort_for(Some(1)),
            KeyEffort {
                max_attempts: MAX_PEER_ATTEMPTS,
                max_lookups: 1
            }
        );
        assert_eq!(
            effort_for(Some(4)),
            KeyEffort {
                max_attempts: MAX_PEER_ATTEMPTS,
                max_lookups: 1
            }
        );
        assert_eq!(
            effort_for(Some(5)),
            KeyEffort {
                max_attempts: MAX_PEER_ATTEMPTS,
                max_lookups: 2
            }
        );
        assert_eq!(
            effort_for(Some(u32::MAX)),
            KeyEffort {
                max_attempts: MAX_PEER_ATTEMPTS,
                max_lookups: 2
            }
        );
        assert_eq!(est_bucket(None), "null");
        assert_eq!(est_bucket(Some(0)), "dead");
        assert_eq!(est_bucket(Some(4)), "low");
        assert_eq!(est_bucket(Some(5)), "high");
    }

    /// Scripted lookups for the effort tests: each `scrape_peers` call pops
    /// the next peer list and counts the call, so tests pin both the dial
    /// budget and the lookup count. Timeouts are recorded to prove both
    /// lookups share the one 6 s knob (no new timeout).
    #[derive(Clone)]
    struct ScriptedLookups {
        scripts: Arc<Mutex<std::collections::VecDeque<Vec<SocketAddr>>>>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        timeouts: Arc<Mutex<Vec<Duration>>>,
    }

    impl ScriptedLookups {
        fn new(scripts: Vec<Vec<SocketAddr>>) -> Self {
            Self {
                scripts: Arc::new(Mutex::new(scripts.into_iter().collect())),
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                timeouts: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn timeouts(&self) -> Vec<Duration> {
            lock(&self.timeouts).clone()
        }
    }

    impl PeerSource for ScriptedLookups {
        async fn get_peers(&self, _: DhtKey, _: Duration) -> Vec<SocketAddr> {
            Vec::new()
        }
        async fn scrape_peers(&self, _: DhtKey, timeout: Duration) -> dc4_dht::ScrapeReport {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            lock(&self.timeouts).push(timeout);
            let peers = lock(&self.scripts).pop_front().unwrap_or_default();
            dc4_dht::ScrapeReport {
                peers,
                ..dc4_dht::ScrapeReport::default()
            }
        }
        fn own_ips(&self) -> Vec<IpAddr> {
            vec![ip("127.0.0.1")]
        }
        fn own_endpoints(&self) -> Vec<SocketAddr> {
            Vec::new()
        }
    }

    /// An open port that accepts and drops: every inbound connection is one
    /// counted dial that then fails fast at the handshake.
    async fn counting_listener() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&dials);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(socket);
            }
        });
        (addr, dials)
    }

    async fn counting_pool(
        n: usize,
    ) -> (Vec<SocketAddr>, Vec<Arc<std::sync::atomic::AtomicUsize>>) {
        let mut addrs = Vec::with_capacity(n);
        let mut counters = Vec::with_capacity(n);
        for _ in 0..n {
            let (addr, dials) = counting_listener().await;
            addrs.push(addr);
            counters.push(dials);
        }
        (addrs, counters)
    }

    fn dial_count(counters: &[Arc<std::sync::atomic::AtomicUsize>]) -> usize {
        counters
            .iter()
            .map(|c| c.load(std::sync::atomic::Ordering::SeqCst))
            .sum()
    }

    #[tokio::test(start_paused = true)]
    async fn null_and_dead_estimates_cap_dials_at_three() {
        for est in [None, Some(0)] {
            let store = MemoryStore::new();
            let (addrs, counters) = counting_pool(10).await;
            let peers = ScriptedLookups::new(vec![addrs]);
            let f = fetcher(&store, peers.clone());
            let k = DhtKey([91; 20]);
            assert!(matches!(f.obtain(k, est).await, Obtained::Failed));
            assert_eq!(peers.calls(), 1, "est {est:?}: one lookup");
            assert_eq!(dial_count(&counters), 3, "est {est:?}: three dials");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn traversal_peers_become_retry_hints() {
        // lookup-found peers are recorded into the HintMap, so
        // a retry dials known-good peers first. The counting listener
        // accepts then drops: every dial fails fast at the handshake.
        let store = MemoryStore::new();
        let hints = shared_hints(&AdmissionTuning::default());
        let (addr, dials) = counting_listener().await;
        let peers = ScriptedLookups::new(vec![vec![addr]]);
        let f = fetcher_with_hints(&store, peers, test_tuning(), hints.clone());
        let k = DhtKey([77; 20]);
        assert!(matches!(f.obtain(k, None).await, Obtained::Failed));
        let before = dials.load(std::sync::atomic::Ordering::SeqCst);
        assert!(before > 0, "first obtain dials the found peer");
        // The found peer survived as a retry hint despite dial failure
        // (non-destructive check: `take_hints` drains).
        assert_eq!(hints.lock().unwrap().len(), 1);
        // Second obtain: the (script-exhausted, peerless) lookup returns
        // nothing, but the hint seeds the queue — dials happen anyway, and
        // the `seen` dedupe in `obtain()` still holds (no double queueing).
        assert!(matches!(f.obtain(k, None).await, Obtained::Failed));
        assert!(
            dials.load(std::sync::atomic::Ordering::SeqCst) > before,
            "retry dials the hinted peer without traversal peers"
        );
        // The retry consumed the hint (destructive take).
        assert!(hints.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn low_estimate_keeps_today_effort() {
        let store = MemoryStore::new();
        let (addrs, counters) = counting_pool(10).await;
        let peers = ScriptedLookups::new(vec![addrs]);
        let f = fetcher(&store, peers.clone());
        assert!(matches!(
            f.obtain(DhtKey([92; 20]), Some(4)).await,
            Obtained::Failed
        ));
        assert_eq!(peers.calls(), 1);
        assert_eq!(dial_count(&counters), MAX_PEER_ATTEMPTS);
    }

    #[tokio::test(start_paused = true)]
    async fn high_estimate_reruns_a_drained_lookup() {
        let store = MemoryStore::new();
        let (addrs, counters) = counting_pool(10).await;
        let peers = ScriptedLookups::new(vec![Vec::new(), addrs]);
        let f = fetcher(&store, peers.clone());
        assert!(matches!(
            f.obtain(DhtKey([93; 20]), Some(50)).await,
            Obtained::Failed
        ));
        assert_eq!(peers.calls(), 2);
        assert_eq!(dial_count(&counters), MAX_PEER_ATTEMPTS);
        // Both rounds share the one 6 s knob — no new timeout.
        assert_eq!(peers.timeouts(), vec![GET_PEERS_TIMEOUT, GET_PEERS_TIMEOUT]);
    }

    #[tokio::test(start_paused = true)]
    async fn high_estimate_skips_the_second_lookup_when_spent() {
        // The first lookup alone exhausts the dial budget: no budget is left
        // for a second round's peers, so no second lookup issues.
        let store = MemoryStore::new();
        let (addrs, counters) = counting_pool(20).await;
        let peers = ScriptedLookups::new(vec![addrs]);
        let f = fetcher(&store, peers.clone());
        assert!(matches!(
            f.obtain(DhtKey([94; 20]), Some(50)).await,
            Obtained::Failed
        ));
        assert_eq!(peers.calls(), 1);
        assert_eq!(dial_count(&counters), MAX_PEER_ATTEMPTS);
    }

    #[tokio::test(start_paused = true)]
    async fn high_estimate_skips_the_second_lookup_on_success() {
        let info = info_dict("second lookup skipped", &["a.txt"], false);
        let addr = seeder(&info).await;
        let store = MemoryStore::new();
        let peers = ScriptedLookups::new(vec![vec![addr], vec![addr]]);
        let f = fetcher(&store, peers.clone());
        assert!(matches!(
            f.obtain(key_of(&info), Some(50)).await,
            Obtained::Metadata(_)
        ));
        assert_eq!(peers.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn drained_second_lookup_can_still_win() {
        let info = info_dict("second lookup wins", &["a.txt"], false);
        let addr = seeder(&info).await;
        let store = MemoryStore::new();
        let peers = ScriptedLookups::new(vec![Vec::new(), vec![addr]]);
        let f = fetcher(&store, peers.clone());
        assert!(matches!(
            f.obtain(key_of(&info), Some(50)).await,
            Obtained::Metadata(_)
        ));
        assert_eq!(peers.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn non_high_estimates_never_rerun_a_drained_lookup() {
        // A drained first lookup with dial budget still left: only `high`
        // earns the second round. The queued second script must stay
        // untouched (one lookup, zero dials, peerless `NoPeers`).
        for (est, key) in [
            (None, DhtKey([96; 20])),
            (Some(0), DhtKey([97; 20])),
            (Some(4), DhtKey([98; 20])),
        ] {
            let store = MemoryStore::new();
            let (addrs, counters) = counting_pool(4).await;
            let peers = ScriptedLookups::new(vec![Vec::new(), addrs]);
            let f = fetcher(&store, peers.clone());
            assert!(
                matches!(f.obtain(key, est).await, Obtained::NoPeers),
                "est {est:?}: drained and peerless"
            );
            assert_eq!(peers.calls(), 1, "est {est:?}: one lookup");
            assert_eq!(dial_count(&counters), 0, "est {est:?}: no dials");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn high_estimate_caps_lookups_at_two() {
        // Two drained lookups with budget left: the third script stays
        // queued forever — the cap holds even when peers would exist.
        let store = MemoryStore::new();
        let (addrs, counters) = counting_pool(4).await;
        let peers = ScriptedLookups::new(vec![Vec::new(), Vec::new(), addrs]);
        let f = fetcher(&store, peers.clone());
        assert!(matches!(
            f.obtain(DhtKey([99; 20]), Some(50)).await,
            Obtained::NoPeers
        ));
        assert_eq!(peers.calls(), 2);
        assert_eq!(dial_count(&counters), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn hints_share_the_dial_budget() {
        // Two hint peers plus four lookup peers against the 3-dial floor:
        // the hints go first (queue order) and the lookup gets the
        // remainder — 2 + 1, not 2 + 3.
        let store = MemoryStore::new();
        let (hint_addrs, hint_counters) = counting_pool(2).await;
        let (lookup_addrs, lookup_counters) = counting_pool(4).await;
        let peers = ScriptedLookups::new(vec![lookup_addrs]);
        let hints = shared_hints(&AdmissionTuning::default());
        let k = DhtKey([100; 20]);
        for peer in &hint_addrs {
            lock(&hints).add(k, *peer, Instant::now());
        }
        let tuning = test_tuning();
        let f = fetcher_with_hints(&store, peers.clone(), tuning, hints);
        assert!(matches!(f.obtain(k, None).await, Obtained::Failed));
        assert_eq!(peers.calls(), 1);
        assert_eq!(dial_count(&hint_counters), 2, "both hints dialed");
        assert_eq!(dial_count(&lookup_counters), 1, "one lookup peer left");
    }

    #[tokio::test(start_paused = true)]
    async fn high_estimate_with_refused_peers_still_terminates() {
        // Every peer refused by the destination limiter (`Full` is
        // retryable, so they defer): the second lookup still issues once
        // progress advances it, then the cap stops the loop — no spin,
        // no dials, lookup count pinned at two.
        let store = MemoryStore::new();
        let (addrs, counters) = counting_pool(1).await;
        let peers = ScriptedLookups::new(vec![addrs.clone(), addrs]);
        let tuning = FetchTuning {
            destinations: DestLimits {
                capacity: 0,
                ..test_tuning().destinations
            },
            ..test_tuning()
        };
        let f = fetcher_with(&store, peers.clone(), tuning);
        assert!(matches!(
            f.obtain(DhtKey([101; 20]), Some(50)).await,
            Obtained::Failed
        ));
        assert_eq!(peers.calls(), 2);
        assert_eq!(dial_count(&counters), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn tuning_max_attempts_still_caps_as_a_ceiling() {
        // The estimate bucket sets the per-key budget; a lowered tuning
        // knob still binds below it.
        let store = MemoryStore::new();
        let (addrs, counters) = counting_pool(10).await;
        let peers = ScriptedLookups::new(vec![addrs]);
        let tuning = FetchTuning {
            max_attempts: 2,
            ..test_tuning()
        };
        let f = fetcher_with(&store, peers.clone(), tuning);
        assert!(matches!(
            f.obtain(DhtKey([102; 20]), Some(50)).await,
            Obtained::Failed
        ));
        assert_eq!(peers.calls(), 1, "spent budget skips the rerun");
        assert_eq!(dial_count(&counters), 2);
    }

    #[test]
    fn fetch_and_dial_metrics_carry_the_claim_time_bucket() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // A manual current-thread runtime inside the local recorder: the
        // fetch runs on this thread, so its counters land in `recorder`.
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let store = MemoryStore::new();
                    // One dead port per fetch: a refused dial negative-caches
                    // its destination, so sharing one port would make the
                    // second fetch skip (correctly) with zero dials.
                    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let dead_addr = dead.local_addr().unwrap();
                    drop(dead);
                    let dead2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let dead_addr2 = dead2.local_addr().unwrap();
                    drop(dead2);
                    let k = DhtKey([95; 20]);
                    store.enqueue(k);
                    let f = fetcher(&store, FixedPeers(vec![dead_addr]));
                    assert_eq!(
                        f.process(&item_with(k, Some(50))).await,
                        FetchOutcome::FetchFailed
                    );
                    // Same shape, unscraped bucket: one dial, `null` labels.
                    let k2 = DhtKey([103; 20]);
                    store.enqueue(k2);
                    let f2 = fetcher(&store, FixedPeers(vec![dead_addr2]));
                    assert_eq!(
                        f2.process(&item_with(k2, None)).await,
                        FetchOutcome::FetchFailed
                    );
                });
        });
        let text = handle.render();
        assert!(
            text.contains("dc4_fetch_dials_total{est=\"high\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("dc4_fetch_dials_total{est=\"null\"} 1"),
            "{text}"
        );
        let fetch_line = text
            .lines()
            .find(|l| l.starts_with("dc4_fetch_total{") && l.contains("est=\"high\""))
            .unwrap_or_else(|| panic!("no high-bucket fetch_total:\n{text}"));
        assert!(fetch_line.contains("outcome=\"fetch_failed\""), "{text}");
        let null_line = text
            .lines()
            .find(|l| l.starts_with("dc4_fetch_total{") && l.contains("est=\"null\""))
            .unwrap_or_else(|| panic!("no null-bucket fetch_total:\n{text}"));
        assert!(null_line.contains("outcome=\"fetch_failed\""), "{text}");
    }

    #[test]
    fn renewal_guard_spawns_only_before_the_deadline() {
        // Production tuning: the first tick (90 s) never fires before the
        // fetch times out (45 s).
        assert!(!renewal_before_deadline(LEASE_RENEW_INTERVAL, KEY_DEADLINE));
        assert!(!renewal_before_deadline(
            Duration::from_secs(90),
            Duration::from_secs(60)
        ));
        assert!(renewal_before_deadline(
            Duration::from_millis(50),
            Duration::from_secs(10)
        ));
        // A tick exactly at the deadline races the timeout: useless too.
        assert!(!renewal_before_deadline(
            Duration::from_secs(10),
            Duration::from_secs(10)
        ));
        // A zero interval is clamped to MIN_RENEW_INTERVAL, still useful.
        assert!(renewal_before_deadline(
            Duration::ZERO,
            Duration::from_secs(10)
        ));
    }

    #[tokio::test]
    async fn batch_renewals_spawn_only_when_useful() {
        let store = MemoryStore::new();
        let one = [DhtKey([1; 20])];
        // Production tuning: a full batch (8 x 45 s) far outlives the lease.
        assert!(
            RenewalGuard::spawn_all(store.clone(), &one, CLAIM_LEASE, LEASE_RENEW_INTERVAL)
                .is_some()
        );
        // Nothing to renew, or the first tick would fire after expiry.
        assert!(
            RenewalGuard::spawn_all(store.clone(), &[], CLAIM_LEASE, LEASE_RENEW_INTERVAL)
                .is_none()
        );
        assert!(
            RenewalGuard::spawn_all(
                store.clone(),
                &one,
                Duration::from_secs(120),
                Duration::from_secs(120)
            )
            .is_none()
        );
        assert!(
            RenewalGuard::spawn_all(
                store.clone(),
                &one,
                Duration::from_secs(120),
                Duration::from_secs(300)
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn batch_renewals_cover_slow_batches() {
        // Per-key renewal is off here (the first tick would race the key
        // deadline), so any renewal must come from the batch guard.
        let tuning = FetchTuning {
            key_deadline: Duration::from_millis(200),
            renew_every: Duration::from_millis(200),
            ..test_tuning()
        };
        assert!(!renewal_before_deadline(
            tuning.renew_every,
            tuning.key_deadline
        ));
        let store = MemoryStore::new();
        let slow = holding_listener().await;
        let keys = [DhtKey([11; 20]), DhtKey([12; 20])];
        for k in &keys {
            store.enqueue(*k);
        }
        // Leases must exist for renewals to count.
        let claimed = store.claim(2, Duration::from_secs(120)).await.unwrap();
        assert_eq!(claimed.len(), 2);
        let f = fetcher_with(&store, FixedPeers(vec![slow]), tuning);
        let items: Vec<PendingItem> = keys.iter().map(|k| item(*k)).collect();
        // Each fetch runs the 200 ms key deadline; the batch guard ticks at
        // 200 ms and renews both leases mid-batch.
        f.process_batch(&items).await;
        assert!(
            store.renewals() >= 1,
            "the batch guard should have renewed, got {}",
            store.renewals()
        );
        for k in &keys {
            assert_eq!(store.failures(k), 1);
        }

        // Contrast: one key at a time spawns no guard under this tuning.
        let before = store.renewals();
        let k = DhtKey([13; 20]);
        store.enqueue(k);
        let claimed = store.claim(1, Duration::from_secs(120)).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(f.process(&item(k)).await, FetchOutcome::FetchFailed);
        assert_eq!(store.renewals(), before);
    }

    #[tokio::test]
    async fn process_batch_falls_back_to_one_key_at_a_time() {
        let first = info_dict("fallback one", &["a.txt"], false);
        let second = info_dict("fallback two", &["b.txt"], false);
        let good = seeder(&first).await;
        let good2 = seeder(&second).await;
        let store = MemoryStore::new();
        let k1 = key_of(&first);
        let k2 = key_of(&second);
        let missing = DhtKey([77; 20]);
        for k in [k1, k2, missing] {
            store.enqueue(k);
        }
        // Both batched writes fail atomically; the per-key fallbacks still
        // succeed, with the same outcomes as one-by-one process().
        store.fail_next_batches(2);
        let f = fetcher(&store, FixedPeers(vec![good, good2]));
        let items: Vec<PendingItem> = [k1, k2, missing].iter().map(|k| item(*k)).collect();
        f.process_batch(&items).await;
        assert_eq!(store.torrent(&k1).unwrap().name, "fallback one");
        assert_eq!(store.torrent(&k2).unwrap().name, "fallback two");
        assert_eq!(store.failures(&missing), 1);
        // The failed key stays queued for retry; the rest are done.
        assert_eq!(store.pending_keys(), vec![missing]);
    }

    /// A peer that accepts connections and then never speaks, so the
    /// handshake runs its full timeout.
    async fn holding_listener() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(sock);
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn slow_fetch_renews_its_lease() {
        let store = MemoryStore::new();
        let k = DhtKey([7; 20]);
        store.enqueue(k);
        // Renewals only count against a claimed lease.
        let claimed = store.claim(1, Duration::from_secs(120)).await.unwrap();
        assert_eq!(claimed.len(), 1);
        let tuning = FetchTuning {
            renew_every: Duration::from_millis(50),
            ..test_tuning()
        };
        let f = fetcher_with(&store, FixedPeers(vec![holding_listener().await]), tuning);
        // The handshake runs its 1 s timeout, far past the 50 ms renewal
        // interval, so the guard must have been spawned and must have
        // renewed the still-queued key.
        assert_eq!(f.process(&claimed[0]).await, FetchOutcome::FetchFailed);
        assert!(store.renewals() >= 1);
    }

    #[tokio::test]
    async fn process_stores_and_fails() {
        let first = info_dict("fetch test", &["a.txt", "b/c.txt"], false);
        let second = info_dict("fetch test second", &["x.txt"], false);
        let private = info_dict("private test", &["a.txt"], true);
        let seeders = [
            seeder(&first).await,
            seeder(&second).await,
            seeder(&private).await,
        ];
        let store = MemoryStore::new();
        for (info, addr, expected) in [
            (&first, seeders[0], FetchOutcome::Ok),
            (&second, seeders[1], FetchOutcome::Ok),
            (&private, seeders[2], FetchOutcome::Private),
        ] {
            let k = key_of(info);
            store.enqueue(k);
            // An unreachable peer first; the right one is still found.
            let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dead_addr = dead.local_addr().unwrap();
            drop(dead);
            let f = fetcher(&store, FixedPeers(vec![dead_addr, addr]));
            assert_eq!(f.process(&item(k)).await, expected);
        }
        let first_key = key_of(&first);
        let stored = store.torrent(&first_key).unwrap();
        assert_eq!(stored.name, "fetch test");
        assert_eq!(stored.files.len(), 2);
        assert!(store.torrent(&key_of(&second)).is_some());
        // A private torrent is given up at once: not stored, never claimed.
        assert!(store.torrent(&key_of(&private)).is_none());
        assert!(store.pending_keys().is_empty());

        // No peers at all.
        let k = DhtKey([9; 20]);
        store.enqueue(k);
        let f = fetcher(&store, FixedPeers(Vec::new()));
        assert_eq!(f.process(&item(k)).await, FetchOutcome::NoPeers);
        assert_eq!(store.failures(&k), 1);

        // Only our own address and non-dialable ones: no peers either.
        let own = "127.0.0.1:1".parse().unwrap();
        let zero = "0.0.0.0:6881".parse().unwrap();
        let f = Arc::new(Fetcher::new(
            store.clone(),
            FixedPeers(vec![own, zero]),
            PeerFilter {
                allow_private: true,
                by_endpoint: false,
            },
            shared_hints(&AdmissionTuning::default()),
            FetchLimitsConfig {
                max_connections: 8,
                max_metadata_bytes: 1024 * 1024,
                max_inflight_metadata_bytes: 1024 * 1024,
            },
            test_tuning(),
        ));
        assert_eq!(f.process(&item(k)).await, FetchOutcome::NoPeers);

        // A peer that serves the wrong data: the fetch fails.
        let wrong = seeder(&first).await;
        let other = DhtKey([8; 20]);
        store.enqueue(other);
        let f = fetcher(&store, FixedPeers(vec![wrong]));
        assert_eq!(f.process(&item(other)).await, FetchOutcome::FetchFailed);
        assert_eq!(store.failures(&other), 1);
        // The refused address is now in the negative cache for this fetcher.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let f = fetcher(&store, FixedPeers(vec![dead_addr]));
        assert_eq!(f.process(&item(other)).await, FetchOutcome::FetchFailed);
        assert_eq!(
            f.limiter()
                .try_acquire(dead_addr, Instant::now())
                .unwrap_err(),
            DestDenied::NegativeCache
        );
    }

    #[tokio::test]
    async fn process_batch_matches_process() {
        let first = info_dict("batch one", &["a.txt"], false);
        let second = info_dict("batch two", &["b.txt"], false);
        let private = info_dict("batch private", &["c.txt"], true);
        let seeders = [
            seeder(&first).await,
            seeder(&second).await,
            seeder(&private).await,
        ];
        // Every key sees the same peers, in order: each key skips the
        // seeders holding other torrents (mismatch) until its own. The last
        // key matches nothing and fails.
        let peers = FixedPeers(seeders.to_vec());
        let keys = [
            key_of(&first),
            key_of(&second),
            key_of(&private),
            DhtKey([77; 20]),
        ];
        let expected = [
            FetchOutcome::Ok,
            FetchOutcome::Ok,
            FetchOutcome::Private,
            FetchOutcome::FetchFailed,
        ];
        let store = MemoryStore::new();
        for k in &keys {
            store.enqueue(*k);
        }
        let f = fetcher(&store, peers);
        let items: Vec<PendingItem> = keys.iter().map(|k| item(*k)).collect();
        f.process_batch(&items).await;
        for (k, name) in [(keys[0], "batch one"), (keys[1], "batch two")] {
            let stored = store.torrent(&k).unwrap();
            assert_eq!(stored.name, name);
        }
        assert!(store.torrent(&keys[2]).is_none());
        assert_eq!(store.failures(&keys[3]), 1);
        // The failed key stays queued for retry; the rest are done.
        assert_eq!(store.pending_keys(), vec![keys[3]]);

        // One key at a time gives the same outcomes on the same setup.
        let store = MemoryStore::new();
        for k in &keys {
            store.enqueue(*k);
        }
        let f = fetcher(&store, FixedPeers(seeders.to_vec()));
        for (k, outcome) in keys.iter().zip(expected) {
            assert_eq!(f.process(&item(*k)).await, outcome);
        }
    }

    #[test]
    fn claim_channel_sizing() {
        // The single bound: 256 batches of up to 8 keys = 2048 keys, and a
        // bulk scan of 512 fits the store's 10 000-claim ceiling.
        assert_eq!(CLAIM_BULK, 512);
        const {
            assert!(CLAIM_BULK < dc4_store::MAX_CLAIM);
        }
        assert_eq!(CLAIM_CHAN_BATCHES, 256);
        assert_eq!(CLAIM_CHAN_BATCHES as i64 * CLAIM_BATCH, 2048);
    }

    #[tokio::test]
    async fn claim_channel_depth_reports_buffered_batches() {
        let (tx, rx) = claim_channel();
        assert_eq!(claim_chan_depth(&tx), 0);
        for _ in 0..3 {
            tx.send(vec![item(DhtKey([1; 20]))]).await.unwrap();
        }
        assert_eq!(claim_chan_depth(&tx), 3);
        rx.lock().await.recv().await.unwrap();
        assert_eq!(claim_chan_depth(&tx), 2);
    }

    /// Distinct keys `0..n` packed into 20 bytes.
    fn many_keys(n: u16) -> Vec<DhtKey> {
        (0..n)
            .map(|i| {
                let mut b = [9u8; 20];
                b[0] = (i & 0xff) as u8;
                b[1] = (i >> 8) as u8;
                DhtKey(b)
            })
            .collect()
    }

    #[tokio::test]
    async fn claimer_feeds_every_key_exactly_once() {
        // 1200 keys over an 8-batch channel: several bulk scans under real
        // backpressure, 8 recorders racing the handoff. Delivery must be a
        // permutation of the queue: no loss, no duplicate.
        let keys = many_keys(1200);
        let store = MemoryStore::new();
        for k in &keys {
            store.enqueue(*k);
        }
        let f = fetcher(&store, FixedPeers(Vec::new()));
        let (tx, rx) = {
            let (tx, raw) = mpsc::channel(8);
            (tx, Arc::new(tokio::sync::Mutex::new(raw)))
        };
        let stop = CancellationToken::new();
        let claimer = tokio::spawn(Arc::clone(&f).run_claimer(tx, stop.clone()));
        let seen: Arc<Mutex<Vec<DhtKey>>> = Arc::default();
        let mut recorders = Vec::new();
        for _ in 0..8 {
            let rx = Arc::clone(&rx);
            let seen = Arc::clone(&seen);
            recorders.push(tokio::spawn(async move {
                while let Some(batch) = rx.lock().await.recv().await {
                    lock(&seen).extend(batch.iter().map(|p| p.dht_key));
                }
            }));
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if lock(&seen).len() >= keys.len() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "only {} of {} keys delivered",
                lock(&seen).len(),
                keys.len()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), claimer)
            .await
            .unwrap()
            .unwrap();
        for r in recorders {
            tokio::time::timeout(Duration::from_secs(5), r)
                .await
                .unwrap()
                .unwrap();
        }
        let mut got = lock(&seen).clone();
        got.sort();
        let mut want = keys.clone();
        want.sort();
        assert_eq!(got, want, "every queued key delivered exactly once");
        // Three bulk scans cover 1200 keys; anything more is idle re-scans
        // of an empty (all leased) queue, never duplicate delivery.
        assert!(store.claim_calls() >= 3, "claims: {}", store.claim_calls());
    }

    #[tokio::test]
    async fn claimer_workers_match_one_by_one_outcomes() {
        // The same 4-key setup as `process_batch_matches_process`, driven
        // through the claim channel instead of direct calls: the end state
        // must match one-by-one `process()`.
        let first = info_dict("batch one", &["a.txt"], false);
        let second = info_dict("batch two", &["b.txt"], false);
        let private = info_dict("batch private", &["c.txt"], true);
        let seeders = [
            seeder(&first).await,
            seeder(&second).await,
            seeder(&private).await,
        ];
        let peers = FixedPeers(seeders.to_vec());
        let keys = [
            key_of(&first),
            key_of(&second),
            key_of(&private),
            DhtKey([77; 20]),
        ];
        let store = MemoryStore::new();
        for k in &keys {
            store.enqueue(*k);
        }
        let f = fetcher(&store, peers);
        let stop = CancellationToken::new();
        let (tx, rx) = claim_channel();
        let claimer = tokio::spawn(Arc::clone(&f).run_claimer(tx, stop.clone()));
        let mut workers = Vec::new();
        for _ in 0..2 {
            workers.push(tokio::spawn(
                Arc::clone(&f).run_worker(Arc::clone(&rx), stop.clone()),
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let done = store.torrent(&keys[0]).is_some()
                && store.torrent(&keys[1]).is_some()
                && store.pending_keys() == vec![keys[3]];
            if done {
                break;
            }
            assert!(Instant::now() < deadline, "workers did not finish");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for (k, name) in [(keys[0], "batch one"), (keys[1], "batch two")] {
            let stored = store.torrent(&k).unwrap();
            assert_eq!(stored.name, name);
        }
        assert!(store.torrent(&keys[2]).is_none());
        assert_eq!(store.failures(&keys[3]), 1);
        stop.cancel();
        for w in workers {
            tokio::time::timeout(Duration::from_secs(5), w)
                .await
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), claimer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn stop_mid_run_leaves_no_stuck_keys() {
        // 48 keys, a 4-batch channel, no workers: the claimer parks on send
        // backpressure with an in-hand bulk, then `stop` drops everything
        // buffered — like a crash. After the 2 s leases expire every key
        // must be reclaimable: nothing is stuck.
        let keys: Vec<DhtKey> = (0..48u8).map(|i| DhtKey([i; 20])).collect();
        let store = MemoryStore::new();
        for k in &keys {
            store.enqueue(*k);
        }
        let tuning = FetchTuning {
            lease: Duration::from_secs(2),
            idle_min: Duration::from_millis(1),
            idle_max: Duration::from_millis(2),
            ..test_tuning()
        };
        let f = fetcher_with(&store, FixedPeers(Vec::new()), tuning);
        let (tx, rx) = {
            let (tx, raw) = mpsc::channel(4);
            (tx, Arc::new(tokio::sync::Mutex::new(raw)))
        };
        let stop = CancellationToken::new();
        let claimer = tokio::spawn(Arc::clone(&f).run_claimer(tx, stop.clone()));
        // One scan of 48 keys, then parked on the full channel: no second
        // scan, no spin. One scan is two store round trips (live phase +
        // top-up, the live pool being empty).
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), claimer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(store.live_claim_calls(), 1);
        assert_eq!(store.claim_calls(), 2);
        drop(rx);
        tokio::time::sleep(Duration::from_secs(3)).await;
        let again = store.claim(48, Duration::from_secs(60)).await.unwrap();
        assert_eq!(again.len(), 48, "every key reclaimable after expiry");
        let mut got: Vec<DhtKey> = again.iter().map(|p| p.dht_key).collect();
        got.sort();
        let mut want = keys.clone();
        want.sort();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn empty_queue_bounds_claim_rate_and_parks_workers() {
        // No keys: the claimer's idle cadence (20–40 ms) is the only claim
        // rate, and the workers sit in `recv` making no progress.
        let store = MemoryStore::new();
        let f = fetcher(&store, FixedPeers(Vec::new()));
        let stop = CancellationToken::new();
        let (tx, rx) = claim_channel();
        let claimer = tokio::spawn(Arc::clone(&f).run_claimer(tx, stop.clone()));
        let mut workers = Vec::new();
        for _ in 0..2 {
            workers.push(tokio::spawn(
                Arc::clone(&f).run_worker(Arc::clone(&rx), stop.clone()),
            ));
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        // A spinning claimer would scan thousands of times; the idle cadence
        // gives a handful (first scan immediate, then one per 20–40 ms).
        // Scans are counted off the live phase (one per scan); each scan is
        // two store calls while the live pool is dry (live + top-up).
        let scans = store.live_claim_calls();
        assert!(scans >= 1, "the claimer never scanned");
        assert!(scans <= 10, "claim storm on an empty queue: {scans} scans");
        assert_eq!(store.claim_calls(), scans * 2);
        assert_eq!(store.torrent_count(), 0);
        assert!(!claimer.is_finished(), "the claimer must park, not exit");
        for w in &workers {
            assert!(!w.is_finished(), "a worker must park, not exit");
        }
        stop.cancel();
        for w in workers {
            tokio::time::timeout(Duration::from_secs(5), w)
                .await
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), claimer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn unusable_verified_metadata_gives_up_at_once() {
        let store = MemoryStore::new();
        // Parses to a total size above i64::MAX: the store refuses it.
        let huge = info_dict_sized("huge", &[("a", i64::MAX), ("b", i64::MAX)], false);
        // Does not parse (a negative length).
        let broken = info_dict_sized("broken", &[("a", 5), ("b", -1)], false);
        for (info, expected) in [
            (&huge, FetchOutcome::StoreError),
            (&broken, FetchOutcome::ParseError),
        ] {
            let k = DhtKey(sha1(info));
            store.enqueue(k);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(dc4_peer::seeder::serve(listener, k, info.clone()));
            let f = fetcher(&store, FixedPeers(vec![addr]));
            assert_eq!(f.process(&item(k)).await, expected);
            assert!(store.torrent(&k).is_none());
            assert_eq!(store.failures(&k), 1);
            // Given up: never claimed again.
            assert!(!store.pending_keys().contains(&k), "{expected:?}");
        }
    }

    #[tokio::test]
    async fn transient_store_error_records_a_failure() {
        let store = MemoryStore::new();
        let good = info_dict("transient test", &["a.txt"], false);
        let k = key_of(&good);
        store.enqueue(k);
        // The database hiccups mid-write: `complete` fails transiently.
        store.fail_next_completes(1);
        let f = fetcher(&store, FixedPeers(vec![seeder(&good).await]));
        assert_eq!(f.process(&item(k)).await, FetchOutcome::StoreError);
        assert!(store.torrent(&k).is_none());
        // The failure went through `fail`, so `attempts` advances toward
        // `MAX_FETCH_ATTEMPTS` instead of stalling until lease expiry.
        assert_eq!(store.failures(&k), 1);
        // Still queued for retry, not given up.
        assert!(store.pending_keys().contains(&k));
    }

    #[tokio::test]
    async fn hints_are_tried_and_workers_drain_the_queue() {
        let info = info_dict("hinted", &["a.txt", "b.txt"], false);
        let k = key_of(&info);
        let addr = seeder(&info).await;
        let store = MemoryStore::new();
        let f = fetcher(&store, FixedPeers(Vec::new()));
        lock(&f.hints).add(k, addr, Instant::now());
        store.enqueue(k);
        let stop = CancellationToken::new();
        let (tx, rx) = claim_channel();
        let claimer = tokio::spawn(Arc::clone(&f).run_claimer(tx, stop.clone()));
        let worker = tokio::spawn(Arc::clone(&f).run_worker(rx, stop.clone()));
        let deadline = Instant::now() + Duration::from_secs(10);
        while store.torrent(&k).is_none() {
            assert!(
                Instant::now() < deadline,
                "the worker did not store the torrent"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), claimer)
            .await
            .unwrap()
            .unwrap();
    }

    /// A lookup that finds no peers but carries one seed's filter (§8: the
    /// traversal was paid for, the estimate is free).
    #[derive(Clone)]
    struct FilteredPeers;

    impl PeerSource for FilteredPeers {
        async fn get_peers(&self, _: DhtKey, _: Duration) -> Vec<SocketAddr> {
            Vec::new()
        }
        fn own_ips(&self) -> Vec<IpAddr> {
            Vec::new()
        }
        fn own_endpoints(&self) -> Vec<SocketAddr> {
            Vec::new()
        }
        async fn scrape_peers(&self, _: DhtKey, _: Duration) -> dc4_dht::ScrapeReport {
            let mut sd = dc4_dht::bloom::ScrapeBloom::empty();
            sd.insert_ip(&"127.0.0.1".parse().unwrap());
            dc4_dht::ScrapeReport {
                peers: Vec::new(),
                seed_filters: vec![sd.0],
                peer_filters: vec![[0u8; dc4_dht::bloom::BLOOM_LEN]],
                aware: 1,
                unaware: 0,
                families_attempted: 2,
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fetch_piggyback_records_the_free_estimate() {
        let store = MemoryStore::new();
        let k = DhtKey([7; 20]);
        store.enqueue(k);
        let f = fetcher(&store, FilteredPeers);
        // No peers, so the fetch fails — but the free estimate is kept for
        // the retry's liveness ordering.
        assert_eq!(f.process(&item(k)).await, FetchOutcome::NoPeers);
        assert_eq!(store.pending_seeders(&k), Some(1));
    }

    /// Deterministic xorshift: random peers without a new dependency.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            let mut x = self.0 | 1;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// The DHT as the server sees it: every key draws fresh random peers
    /// every round — correct seeders, wrong-data seeders, a private
    /// torrent, dead ports, empty lookups — routed per key.
    #[derive(Clone)]
    struct ChaosPeers {
        table: Arc<std::sync::Mutex<BTreeMap<DhtKey, Vec<SocketAddr>>>>,
    }

    impl ChaosPeers {
        fn set(&self, key: DhtKey, peers: Vec<SocketAddr>) {
            self.table.lock().unwrap().insert(key, peers);
        }
    }

    impl PeerSource for ChaosPeers {
        async fn get_peers(&self, _: DhtKey, _: Duration) -> Vec<SocketAddr> {
            Vec::new()
        }
        async fn scrape_peers(&self, key: DhtKey, _: Duration) -> dc4_dht::ScrapeReport {
            let peers = self
                .table
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default();
            dc4_dht::ScrapeReport {
                peers,
                ..dc4_dht::ScrapeReport::default()
            }
        }
        fn own_ips(&self) -> Vec<IpAddr> {
            vec![ip("127.0.0.1")]
        }
        fn own_endpoints(&self) -> Vec<SocketAddr> {
            Vec::new()
        }
    }

    /// A dialable-nothing address: refused instantly, like a dead peer.
    async fn dead_addr() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    }

    fn chaos_key(seed: u64, i: usize) -> DhtKey {
        let mut b = [0xABu8; 20];
        b[0..8].copy_from_slice(&seed.to_le_bytes());
        b[8..16].copy_from_slice(&(i as u64).to_le_bytes());
        DhtKey(b)
    }

    /// One drain of everything due, over 4 concurrent claim→process
    /// workers (the claimer/worker split, minus the channel): three run
    /// the batch path, one the single-key path. Returns every key
    /// claimed this drain, so the caller can check none was terminal.
    async fn drain(store: &MemoryStore, f: &Arc<Fetcher<MemoryStore, ChaosPeers>>) -> Vec<DhtKey> {
        let claimed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut js = tokio::task::JoinSet::new();
        for w in 0..4 {
            let (store, f, claimed) = (store.clone(), Arc::clone(f), Arc::clone(&claimed));
            js.spawn(async move {
                loop {
                    let items = store
                        .claim(CLAIM_BATCH, Duration::from_secs(120))
                        .await
                        .unwrap();
                    if items.is_empty() {
                        break;
                    }
                    claimed
                        .lock()
                        .unwrap()
                        .extend(items.iter().map(|i| i.dht_key));
                    if w == 3 {
                        for it in &items {
                            f.process(it).await;
                        }
                    } else {
                        f.process_batch(&items).await;
                    }
                }
            });
        }
        while js.join_next().await.is_some() {}
        Arc::try_unwrap(claimed).unwrap().into_inner().unwrap()
    }

    /// Mimics the server against the real pipeline: random DHT behavior
    /// redrawn every round, concurrent workers, transient store faults
    /// forcing the one-key-at-a-time fallbacks. After every round it
    /// asserts the two invariants the server diag put in doubt: no live
    /// row at or past the give-up count, and no terminal key re-claimed.
    /// A failure here names the mechanism behind live attempts-2..5
    /// rows; staying green says the pipeline cannot mint them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn chaos_pipeline_preserves_queue_invariants() {
        for seed in [11u64, 0x9e3779b97f4a7c15, 0xd1ab011c] {
            chaos_once(seed).await;
        }
    }

    async fn chaos_once(seed: u64) {
        const GOOD: usize = 5;
        const CHAOS: usize = 34;
        const ROUNDS: usize = 5;
        // Short backoff so retries come due between rounds; the 1.5 s
        // sleeps below hold 3x margin.
        let store = MemoryStore::with_fail_backoff(Duration::from_millis(500));
        let peers = ChaosPeers {
            table: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        };
        let f = fetcher_with(&store, peers.clone(), test_tuning());

        // Fixed identities: good keys own a correct seeder each, one key
        // owns a private torrent; the rest draw chaos every round.
        let mut keys = Vec::new();
        let mut good_addrs = Vec::new();
        for i in 0..GOOD {
            let info = info_dict(&format!("chaos good {seed}-{i}"), &["f.bin"], false);
            good_addrs.push((key_of(&info), seeder(&info).await));
            keys.push(key_of(&info));
        }
        let private_info = info_dict("chaos private", &["p.bin"], true);
        let private_key = key_of(&private_info);
        let private_addr = seeder(&private_info).await;
        keys.push(private_key);
        let wrong_info = info_dict("chaos wrong", &["w.bin"], false);
        let wrong_addr = seeder(&wrong_info).await;
        for i in 0..CHAOS {
            keys.push(chaos_key(seed, i));
        }
        {
            let mut seen = std::collections::HashSet::new();
            for k in &keys {
                assert!(seen.insert(*k), "duplicate test key");
            }
        }
        for k in &keys {
            store.enqueue(*k);
        }

        let max_live = u32::try_from(dc4_store::MAX_FETCH_ATTEMPTS).unwrap_or(u32::MAX) - 1;
        let mut rng = Lcg(seed);
        let mut completed = std::collections::HashSet::new();
        let mut gave_up = std::collections::HashSet::new();
        // Non-vacuity: the draws must actually produce retries, stores
        // and give-ups, or the invariant asserts prove nothing.
        let mut saw_retry = false;

        for round in 0..ROUNDS {
            // Redraw the DHT: sticky outcomes for the fixed identities,
            // fresh chaos for the rest.
            let mut dead = Vec::new();
            for _ in 0..CHAOS {
                dead.push(dead_addr().await);
            }
            let mut di = 0;
            for k in &keys {
                if let Some((_, a)) = good_addrs.iter().find(|(g, _)| g == k) {
                    peers.set(*k, vec![*a]);
                } else if *k == private_key {
                    peers.set(*k, vec![private_addr]);
                } else {
                    let roll = rng.below(100);
                    peers.set(
                        *k,
                        match roll {
                            0..30 => Vec::new(),
                            30..60 => vec![dead[di % dead.len()]],
                            60..75 => vec![wrong_addr],
                            75..85 => vec![dead[di % dead.len()], wrong_addr],
                            85..95 => vec![private_addr],
                            _ => Vec::new(),
                        },
                    );
                    di += 1;
                }
            }
            // Transient store faults force the batch fallbacks (same
            // semantics, one key at a time) on some rounds.
            if round >= 1 && rng.below(2) == 0 {
                store.fail_next_batches(1 + rng.below(2) as usize);
            }

            let claimed = drain(&store, &f).await;
            for k in &claimed {
                assert!(
                    !completed.contains(k) && !gave_up.contains(k),
                    "seed {seed} round {round}: terminal key re-claimed: {k:?}"
                );
            }
            // THE server anomaly, checked every round: the fail paths
            // flip `gave_up` on the final attempt, so a live row must
            // never reach the give-up count.
            for (k, a) in store.live_attempts() {
                assert!(
                    a <= max_live,
                    "seed {seed} round {round}: live {k:?} at attempts {a}"
                );
                saw_retry |= a == max_live;
            }
            for k in &keys {
                if completed.contains(k) || gave_up.contains(k) {
                    continue;
                }
                if store.live_attempts().iter().any(|(l, _)| l == k) {
                    continue;
                }
                if store.torrent(k).is_some() {
                    completed.insert(*k);
                } else {
                    gave_up.insert(*k);
                }
            }
            // Round 0 settles the fixed identities: good keys stored,
            // the private key gave up at once.
            if round == 0 {
                for (g, _) in &good_addrs {
                    assert!(
                        completed.contains(g),
                        "seed {seed}: good key not stored: {g:?}"
                    );
                }
                assert!(
                    gave_up.contains(&private_key),
                    "seed {seed}: private key live"
                );
            }
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }

        // One last drain with faults off: everything must be terminal,
        // nothing live, nothing stuck.
        let claimed = drain(&store, &f).await;
        for k in &claimed {
            assert!(
                !completed.contains(k) && !gave_up.contains(k),
                "seed {seed} final: terminal key re-claimed: {k:?}"
            );
        }
        assert!(
            store.live_attempts().is_empty(),
            "seed {seed} final: stuck live rows: {:?}",
            store.live_attempts()
        );
        for k in &keys {
            if completed.contains(k) || gave_up.contains(k) {
                continue;
            }
            if store.torrent(k).is_some() {
                completed.insert(*k);
            } else {
                gave_up.insert(*k);
            }
        }
        assert_eq!(completed.len() + gave_up.len(), keys.len());
        assert!(
            saw_retry,
            "seed {seed}: never observed a live retry — chaos draws are vacuous"
        );
        assert!(
            !completed.is_empty() && !gave_up.is_empty(),
            "seed {seed}: one terminal path never fired"
        );
    }
}
