//! Admission (design §13): turns DHT discoveries into queue entries.
//!
//! 1. A discovered `peer` passes the address chokepoint and goes into the
//!    [`HintMap`].
//! 2. A key already in the [`DedupSet`] is skipped.
//! 3. A key seen only through `get_peers` is admitted once sightings came
//!    from at least two /24 (IPv4) or /48 (IPv6) networks within the current
//!    dedup generation ([`SourceTracker`]), or on its first sighting as a
//!    non-priority key subject to a per-flush-cycle cap
//!    ([`GET_PEERS_SINGLE_CAP`], 20% of [`BATCH_MAX_KEYS`]). Sampled keys
//!    are admitted at once as non-priority keys (the sighting is our own
//!    sampler's, not a stranger's claim needing corroboration); only
//!    announced keys are admitted at once as priority keys. While the queue is under pressure
//!    (the last flush saw depth at or above the cap), sampled discoveries
//!    shed before the batch without entering the dedup set.
//! 4. Admitted keys are merged into a batch that is written with
//!    `observe` every second or every 1 000 keys, retrying with backoff.
//! 5. A key enters the dedup set only after the `observe` call that
//!    included it succeeded.

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use dc4_core::DhtKey;
use dc4_dht::compact::canonical_ip;
use dc4_dht::{Discovered, Family, Source};
use dc4_store::{Observation, ObserveOutcome};
use lru::LruCache;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::peers::{OwnAddrs, PeerFilter, PeerSource};
use crate::stores::CrawlStore;

/// Capacity of the channel from the DHT node to admission.
pub const DISCOVERED_CHANNEL_CAPACITY: usize = 65_536;
/// Keys per dedup generation.
pub const DEDUP_GENERATION_KEYS: usize = 2_000_000;
/// Age at which the dedup set starts a new generation.
pub const DEDUP_ROTATION: Duration = Duration::from_secs(30 * 60);
/// Distinct source networks a `get_peers`-only key needs.
pub const GET_PEERS_MIN_SOURCES: usize = 2;
/// First-sighting `get_peers` keys admitted per flush cycle (20% of
/// [`BATCH_MAX_KEYS`]).
pub const GET_PEERS_SINGLE_CAP: usize = 200;
/// Keys the source tracker remembers.
pub const SOURCE_TRACKER_KEYS: usize = 200_000;
/// Source networks remembered per key.
pub const SOURCE_PREFIXES_PER_KEY: usize = 4;
/// IPv4 source network size (bits).
pub const SOURCE_PREFIX_V4: u32 = 24;
/// IPv6 source network size (bits).
pub const SOURCE_PREFIX_V6: u32 = 48;
/// Keys the hint map remembers.
pub const HINT_KEYS: usize = 100_000;
/// Peers remembered per key in the hint map.
pub const HINT_PEERS_PER_KEY: usize = 8;
/// Lifetime of a hint.
pub const HINT_TTL: Duration = Duration::from_secs(5 * 60);
/// Keys the removal-memory cache holds; beyond this it is cleared and
/// rebuilt from the database (a documented heuristic: cooldowns only
/// grow the cache under flap).
pub const REMOVAL_CACHE_KEYS: usize = 100_000;
/// How long a "not removed" answer is trusted without re-checking.
pub const REMOVAL_CACHE_CLEAR_TTL: Duration = Duration::from_secs(60 * 60);
/// Keys that trigger an immediate batch write.
pub const BATCH_MAX_KEYS: usize = 1_000;
/// Longest time a batch waits before it is written.
pub const BATCH_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
/// First retry delay after a failed batch write.
pub const FLUSH_RETRY_BASE: Duration = Duration::from_millis(500);
/// Longest retry delay after failed batch writes.
pub const FLUSH_RETRY_MAX: Duration = Duration::from_secs(30);
/// How long the final flush may keep retrying at shutdown.
pub const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);
/// How often our own addresses are re-read from the node.
pub const OWN_ADDRS_REFRESH: Duration = Duration::from_secs(5);
/// Shortest flush period accepted (a zero period would spin).
const MIN_FLUSH_INTERVAL: Duration = Duration::from_millis(1);

const METRIC_DISCOVERED: &str = "dc4_discovered_total";
const METRIC_ADMITTED: &str = "dc4_admitted_total";
/// Pipeline blocks, by reason (also used by `fetch`).
pub const METRIC_BLOCKED: &str = "dc4_blocked_total";
/// Hint peers recorded, by discovery source (answers whether
/// hints carry yield or are vestigial).
pub const METRIC_HINT_ADDED: &str = "dc4_hint_added_total";
/// Hint peers consumed by fetch, by outcome: `dialed` (queued), `filtered`
/// (re-filter/repeat dropped), `empty` (no hints for the key).
pub const METRIC_HINT_USED: &str = "dc4_hint_used_total";

/// Capacities of zero are rejected loudly: a zero-capacity LRU cannot exist,
/// so silently running with room for one key would be a worse surprise.
#[allow(clippy::panic)] // fail-fast on a programming error, like `expect`
const fn non_zero(n: usize) -> NonZeroUsize {
    match NonZeroUsize::new(n) {
        Some(n) => n,
        None => panic!("admission cache capacity must be non-zero"),
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Timings and sizes of admission. `Default` gives the production values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionTuning {
    pub dedup_keys: usize,
    pub dedup_rotation: Duration,
    pub source_keys: usize,
    pub hint_keys: usize,
    pub hint_ttl: Duration,
    pub batch_max_keys: usize,
    pub flush_interval: Duration,
    pub retry_base: Duration,
    pub retry_max: Duration,
    pub shutdown_flush_timeout: Duration,
    /// First-sighting `get_peers` keys admitted per flush cycle.
    pub get_peers_single_cap: usize,
    /// Base admission cooldown of a removed key, in days (bep33.md §4a/§6:
    /// base, escalating ×4 per repeat to the 90d cap).
    pub removal_cooldown_days: u64,
}

impl Default for AdmissionTuning {
    fn default() -> Self {
        Self {
            dedup_keys: DEDUP_GENERATION_KEYS,
            dedup_rotation: DEDUP_ROTATION,
            source_keys: SOURCE_TRACKER_KEYS,
            hint_keys: HINT_KEYS,
            hint_ttl: HINT_TTL,
            batch_max_keys: BATCH_MAX_KEYS,
            flush_interval: BATCH_FLUSH_INTERVAL,
            retry_base: FLUSH_RETRY_BASE,
            retry_max: FLUSH_RETRY_MAX,
            shutdown_flush_timeout: SHUTDOWN_FLUSH_TIMEOUT,
            get_peers_single_cap: GET_PEERS_SINGLE_CAP,
            removal_cooldown_days: 7,
        }
    }
}

// ---------------------------------------------------------------------------
// Dedup set
// ---------------------------------------------------------------------------

/// A hasher for values that are already uniformly distributed `u64`s.
#[derive(Default)]
struct PassThroughHasher(u64);

impl Hasher for PassThroughHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*b);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

type FingerprintSet = HashSet<u64, BuildHasherDefault<PassThroughHasher>>;

/// Keys observed recently, in two generations.
///
/// Keys are kept as 64-bit fingerprints under a per-process random key, so a
/// generation of 2 000 000 keys takes tens of megabytes, and nobody can
/// choose keys that collide with a given one. A collision only delays a
/// key until the next rotation.
pub struct DedupSet {
    fingerprint: RandomState,
    current: FingerprintSet,
    previous: FingerprintSet,
    capacity: usize,
    rotate_every: Duration,
    rotated_at: Instant,
}

impl std::fmt::Debug for DedupSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupSet")
            .field("current", &self.current.len())
            .field("previous", &self.previous.len())
            .finish_non_exhaustive()
    }
}

impl DedupSet {
    /// An empty set whose first generation starts at `now`.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero: a zero-capacity dedup set cannot exist,
    /// so silently running with room for one key would be a worse surprise.
    pub fn new(capacity: usize, rotate_every: Duration, now: Instant) -> Self {
        assert!(capacity > 0, "dedup set capacity must be non-zero");
        Self {
            fingerprint: RandomState::new(),
            current: FingerprintSet::default(),
            previous: FingerprintSet::default(),
            capacity,
            rotate_every,
            rotated_at: now,
        }
    }

    fn fingerprint(&self, key: &DhtKey) -> u64 {
        self.fingerprint.hash_one(key.0)
    }

    /// Whether `key` is in either generation.
    pub fn contains(&self, key: &DhtKey) -> bool {
        let fp = self.fingerprint(key);
        self.current.contains(&fp) || self.previous.contains(&fp)
    }

    /// Adds `key`. Returns true if a new generation started because the
    /// current one was full. Keys already present in either generation are
    /// not re-added (a previous-generation key re-added to current would
    /// occupy a slot in both generations and halve the dedup window).
    pub fn insert(&mut self, key: &DhtKey, now: Instant) -> bool {
        let fp = self.fingerprint(key);
        if self.current.contains(&fp) || self.previous.contains(&fp) {
            return false;
        }
        let rotated = self.current.len() >= self.capacity;
        if rotated {
            self.rotate(now);
        }
        self.current.insert(fp);
        rotated
    }

    /// Starts a new generation if the current one is old enough. Returns
    /// true if it did.
    pub fn maybe_rotate(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.rotated_at) < self.rotate_every {
            return false;
        }
        self.rotate(now);
        true
    }

    fn rotate(&mut self, now: Instant) {
        self.previous = std::mem::take(&mut self.current);
        self.rotated_at = now;
    }

    /// Keys in the current and previous generations.
    pub fn len(&self) -> (usize, usize) {
        (self.current.len(), self.previous.len())
    }

    /// True when both generations are empty.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty() && self.previous.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Source tracker
// ---------------------------------------------------------------------------

/// The network a source address belongs to, as one number: /24 for IPv4,
/// /48 for IPv6 (IPv4-mapped addresses count as IPv4).
pub fn source_network(ip: IpAddr) -> u64 {
    const V6_SHIFT: u32 = 128 - SOURCE_PREFIX_V6;
    const V4_SHIFT: u32 = 32 - SOURCE_PREFIX_V4;
    const V4_TAG: u64 = 1 << SOURCE_PREFIX_V6;
    match canonical_ip(ip) {
        // An IPv4 network is at least V4_TAG; an IPv6 one (48 bits) is below it.
        IpAddr::V4(v4) => V4_TAG | u64::from(u32::from(v4) >> V4_SHIFT),
        IpAddr::V6(v6) => u64::try_from(u128::from(v6) >> V6_SHIFT).unwrap_or(u64::MAX),
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Networks {
    seen: [u64; SOURCE_PREFIXES_PER_KEY],
    len: usize,
}

impl Networks {
    fn add(&mut self, network: u64) -> usize {
        let known = self.seen.iter().take(self.len).any(|n| *n == network);
        if !known && let Some(slot) = self.seen.get_mut(self.len) {
            *slot = network;
            self.len = self.len.saturating_add(1);
        }
        self.len
    }
}

/// For keys seen only through `get_peers`, the distinct source networks
/// seen so far (bounded LRU).
pub struct SourceTracker {
    map: LruCache<DhtKey, Networks>,
}

impl std::fmt::Debug for SourceTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceTracker")
            .field("keys", &self.map.len())
            .finish()
    }
}

impl SourceTracker {
    /// A tracker for at most `keys` keys.
    pub fn new(keys: usize) -> Self {
        Self {
            map: LruCache::new(non_zero(keys)),
        }
    }

    /// Records a sighting of `key` from `from`; returns the number of
    /// distinct networks seen for it.
    pub fn record(&mut self, key: DhtKey, from: IpAddr) -> usize {
        let network = source_network(from);
        self.map
            .get_or_insert_mut(key, Networks::default)
            .add(network)
    }

    /// Forgets `key`.
    pub fn remove(&mut self, key: &DhtKey) {
        self.map.pop(key);
    }

    /// Forgets everything (a new dedup generation began).
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Keys tracked.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no key is tracked.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Hint map
// ---------------------------------------------------------------------------

/// Peers that announced a key, kept briefly so a fetch can try them before
/// (and besides) a `get_peers` lookup. Memory only (R11).
pub struct HintMap {
    map: LruCache<DhtKey, Vec<(SocketAddr, Instant)>>,
    ttl: Duration,
}

impl std::fmt::Debug for HintMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HintMap")
            .field("keys", &self.map.len())
            .finish_non_exhaustive()
    }
}

impl HintMap {
    /// A map for at most `keys` keys whose hints expire after `ttl`.
    pub fn new(keys: usize, ttl: Duration) -> Self {
        Self {
            map: LruCache::new(non_zero(keys)),
            ttl,
        }
    }

    /// Remembers `peer` for `key`. The caller has already filtered it.
    pub fn add(&mut self, key: DhtKey, peer: SocketAddr, now: Instant) {
        let ttl = self.ttl;
        let peers = self.map.get_or_insert_mut(key, Vec::new);
        peers.retain(|(p, at)| *p != peer && now.saturating_duration_since(*at) < ttl);
        // `retain` above removed any older entry for this peer; drop the
        // oldest others until there is room (the vector is non-empty here).
        while peers.len() >= HINT_PEERS_PER_KEY {
            peers.remove(0);
        }
        peers.push((peer, now));
    }

    /// Removes and returns the unexpired hints for `key`, newest first.
    pub fn take(&mut self, key: &DhtKey, now: Instant) -> Vec<SocketAddr> {
        let ttl = self.ttl;
        self.map
            .pop(key)
            .unwrap_or_default()
            .into_iter()
            .rev()
            .filter(|(_, at)| now.saturating_duration_since(*at) < ttl)
            .map(|(p, _)| p)
            .collect()
    }

    /// Keys with hints.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when there are no hints.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// The hint map shared by admission and the fetch workers.
pub type SharedHints = Arc<Mutex<HintMap>>;

/// A new shared hint map.
pub fn shared_hints(tuning: &AdmissionTuning) -> SharedHints {
    Arc::new(Mutex::new(HintMap::new(tuning.hint_keys, tuning.hint_ttl)))
}

/// Takes the hints for `key` from a shared map.
pub fn take_hints(hints: &SharedHints, key: &DhtKey, now: Instant) -> Vec<SocketAddr> {
    lock(hints).take(key, now)
}

/// Records one hint on a shared map (traversal-found peers
/// become retry hints). Bounded by the same per-key cap as the add path;
/// `get_peers`-sourced peers are deliberately NOT added at the admission
/// add-path: producers set `peer: None` for `GetPeers`/`Sample` (only
/// `Announce` carries `Some`), so `handle()` structurally never sees one —
/// and traversal peers would double-dial if re-added there. Only
/// lookup-success peers are recorded here, for the *next* `obtain()`.
/// The map itself does not count: callers emit
/// `dc4_hint_added_total{source="traversal"}` (fetch traversal peers) or
/// `{source="tracker"}` (tracker announce peers) alongside the add, so adds
/// join with `dc4_hint_used_total{outcome="dialed"}` on the retry.
pub fn add_hint(hints: &SharedHints, key: DhtKey, peer: SocketAddr, now: Instant) {
    lock(hints).add(key, peer, now);
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Pending {
    sightings: u32,
    priority: bool,
}

/// Why a batch was not written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushStopped {
    /// Shutdown was requested while retrying.
    Cancelled,
    /// The deadline passed while retrying.
    Deadline,
}

/// The admission state: dedup set, source tracker, hints and the batch.
pub struct Admission<S> {
    store: S,
    max_pending: i64,
    filter: PeerFilter,
    tuning: AdmissionTuning,
    dedup: DedupSet,
    sources: SourceTracker,
    hints: SharedHints,
    batch: HashMap<DhtKey, Pending>,
    /// First-sighting `get_peers` admits this flush cycle (capped by
    /// `get_peers_single_cap`).
    single_sighting_admits: usize,
    /// Keys announced with `seed=1` since the last flush: live seeders that
    /// short-circuit their next scrape (bep33.md §4b win 6).
    seed_announced: HashSet<DhtKey>,
    /// Removal-memory verdicts by key (bep33.md §4a): a synchronous PK
    /// lookup per discovery would kill throughput, so verdicts are cached
    /// here and refreshed in batch by [`Admission::flush`].
    removal_cache: HashMap<DhtKey, RemovalVerdict>,
    /// Early-shed flag for sampled discoveries, refreshed by
    /// [`Admission::flush`] from `pending_depth` (set at or above
    /// `max_pending`, mirroring the store's priority-only gate). Read by the
    /// sync [`Admission::handle`]; both run on the same task (`run` owns
    /// `self`), so no synchronisation is needed. Shed keys skip the dedup
    /// set, so clearing the flag admits them immediately again.
    shed_sampler: bool,
}

/// A cached removal-memory verdict.
#[derive(Debug, Clone, Copy)]
enum RemovalVerdict {
    /// In cooldown until the instant.
    Blocked(Instant),
    /// Known-clear when checked at the instant.
    Clear(Instant),
}

impl<S> std::fmt::Debug for Admission<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission")
            .field("batch", &self.batch.len())
            .field("dedup", &self.dedup)
            .finish_non_exhaustive()
    }
}

/// Evicts removal-memory verdicts down to [`REMOVAL_CACHE_KEYS`].
///
/// Live cooldowns are the load-bearing entries: dropping a `Blocked`
/// verdict lets the next flush admit the key if the re-query fails, so
/// stale and negative verdicts (cheap to re-query on a miss) go first.
/// Only a pathological over-cap of live cooldowns sheds the
/// soonest-expiring ones, never the whole map.
fn evict_removal_cache(cache: &mut HashMap<DhtKey, RemovalVerdict>, now: Instant) {
    if cache.len() <= REMOVAL_CACHE_KEYS {
        return;
    }
    cache.retain(|_, v| matches!(v, RemovalVerdict::Blocked(until) if *until > now));
    if cache.len() <= REMOVAL_CACHE_KEYS {
        return;
    }
    let mut expiries: Vec<(DhtKey, Instant)> = cache
        .iter()
        .filter_map(|(key, verdict)| match *verdict {
            RemovalVerdict::Blocked(until) => Some((*key, until)),
            RemovalVerdict::Clear(_) => None,
        })
        .collect();
    expiries.sort_by_key(|(_, until)| *until);
    let shed = cache.len().saturating_sub(REMOVAL_CACHE_KEYS);
    for (key, _) in expiries.iter().take(shed) {
        cache.remove(key);
    }
}

impl<S: CrawlStore> Admission<S> {
    /// New admission state writing to `store`.
    pub fn new(
        store: S,
        max_pending: i64,
        filter: PeerFilter,
        tuning: AdmissionTuning,
        hints: SharedHints,
        now: Instant,
    ) -> Self {
        Self {
            store,
            max_pending,
            filter,
            tuning,
            dedup: DedupSet::new(tuning.dedup_keys, tuning.dedup_rotation, now),
            sources: SourceTracker::new(tuning.source_keys),
            hints,
            batch: HashMap::new(),
            single_sighting_admits: 0,
            seed_announced: HashSet::new(),
            removal_cache: HashMap::new(),
            shed_sampler: false,
        }
    }

    /// Keys waiting in the batch.
    pub fn batch_len(&self) -> usize {
        self.batch.len()
    }

    /// The dedup set.
    pub fn dedup(&self) -> &DedupSet {
        &self.dedup
    }

    /// The source tracker.
    pub fn sources(&self) -> &SourceTracker {
        &self.sources
    }

    /// Handles one discovery.
    pub fn handle(&mut self, event: Discovered, own: &OwnAddrs, now: Instant) {
        let source = event.source;
        metrics::counter!(
            METRIC_DISCOVERED,
            "source" => source.as_str(),
            "family" => Family::of_ip(&canonical_ip(event.from)).as_str()
        )
        .increment(1);

        if let Some(peer) = event.peer {
            match self.filter.accept(peer, own) {
                Some(peer) => {
                    lock(&self.hints).add(event.key, peer, now);
                    metrics::counter!(METRIC_HINT_ADDED, "source" => source.as_str()).increment(1);
                }
                None => {
                    metrics::counter!(METRIC_BLOCKED, "reason" => "peer_address").increment(1);
                }
            }
        }

        if self.dedup.maybe_rotate(now) {
            self.sources.clear();
        }
        if event.seed {
            // A live seeder just proved itself: refresh its scrape clock
            // at flush time (announce short-circuit, §4b win 6). The key
            // still flows through the normal batch path below (its peer
            // is a hint like any other).
            self.seed_announced.insert(event.key);
        }
        if self.dedup.contains(&event.key) {
            return;
        }
        // Only announces are priority: sampled keys join get_peers keys as
        // non-priority, so sampler volume no longer crowds announces out of
        // the queue under pressure.
        let priority = source == Source::Announce;
        if let Some(pending) = self.batch.get_mut(&event.key) {
            pending.sightings = pending.sightings.saturating_add(1);
            pending.priority |= priority;
            return;
        }
        // Depth-gated early shed: while the flag is set these keys would be
        // dropped by the store's priority-only gate anyway, so shedding them
        // here skips the batch write. Shed keys stay out of the dedup set so
        // recovery is instant; get_peers keys keep flowing through their
        // two-network tracker (their volume is ~1% of the sampler's).
        if source == Source::Sample && self.shed_sampler {
            metrics::counter!(METRIC_BLOCKED, "reason" => "shed_sampler").increment(1);
            return;
        }
        if priority {
            self.sources.remove(&event.key);
        } else if source == Source::GetPeers {
            let count = self.sources.record(event.key, event.from);
            if count >= GET_PEERS_MIN_SOURCES {
                self.sources.remove(&event.key);
            } else if self.single_sighting_admits < self.tuning.get_peers_single_cap {
                // First sighting: admit at once as non-priority.
                self.single_sighting_admits = self.single_sighting_admits.saturating_add(1);
                self.sources.remove(&event.key);
            } else {
                metrics::counter!(METRIC_BLOCKED, "reason" => "get_peers_single_capped")
                    .increment(1);
                return;
            }
        } else {
            // A sampled sighting is our own sampler's, not a stranger's
            // claim: admit at once as non-priority, dropping any get_peers
            // tracking for the key.
            self.sources.remove(&event.key);
        }
        self.batch.insert(
            event.key,
            Pending {
                sightings: 1,
                priority,
            },
        );
        metrics::counter!(METRIC_ADMITTED, "source" => source.as_str()).increment(1);
    }

    fn observations(&self) -> Vec<Observation> {
        self.batch
            .iter()
            .map(|(key, p)| Observation {
                key: *key,
                sightings: p.sightings,
                priority: p.priority,
            })
            .collect()
    }

    /// Drops batch keys still in removal cooldown (§4a) and counts a
    /// post-removal sighting for every batch key the memory still knows.
    /// Verdicts come from the bounded [`REMOVAL_CACHE_KEYS`] cache (live
    /// cooldowns survive eviction); misses are
    /// checked in one batched query. Keys with strong evidence (seed
    /// announces in `strong_evidence`, or enough post-removal sightings)
    /// get the ÷4 shortening from the store — shortening, never bypassing.
    async fn gate_removals(&mut self, strong_evidence: &[DhtKey]) {
        let now = Instant::now();
        let strong: HashSet<&DhtKey> = strong_evidence.iter().collect();
        let mut misses = Vec::new();
        let mut blocked_keys = Vec::new();
        let mut remembered = Vec::new();
        for key in self.batch.keys().copied().collect::<Vec<_>>() {
            // Seed announces are fresh evidence: always re-check them, so a
            // cached verdict never masks the ÷4 shortening.
            if strong.contains(&key) {
                misses.push(key);
                continue;
            }
            match self.removal_cache.get(&key) {
                Some(RemovalVerdict::Blocked(until)) if *until > now => {
                    blocked_keys.push(key);
                    remembered.push(key);
                }
                Some(RemovalVerdict::Clear(at)) if now < *at + REMOVAL_CACHE_CLEAR_TTL => {}
                _ => misses.push(key),
            }
        }
        if !misses.is_empty() {
            match self
                .store
                .removal_cooldowns(&misses, self.tuning.removal_cooldown_days, strong_evidence)
                .await
            {
                Ok(rows) => {
                    for rc in rows {
                        if rc.remaining > Duration::ZERO {
                            self.removal_cache
                                .insert(rc.key, RemovalVerdict::Blocked(now + rc.remaining));
                            blocked_keys.push(rc.key);
                            remembered.push(rc.key);
                        } else {
                            self.removal_cache
                                .insert(rc.key, RemovalVerdict::Clear(now));
                        }
                    }
                    for key in misses {
                        self.removal_cache
                            .entry(key)
                            .or_insert(RemovalVerdict::Clear(now));
                    }
                }
                Err(e) => {
                    // Fail closed: the cooldowns are unknown, so the misses
                    // leave the batch for recheck on re-announce instead of
                    // being admitted unchecked. No verdict is cached and no
                    // sighting is recorded — nothing is known about them.
                    tracing::warn!(
                        error = %e,
                        keys = misses.len(),
                        "removal_cooldowns failed; dropping the batch keys for recheck"
                    );
                    blocked_keys.extend(misses);
                }
            }
            evict_removal_cache(&mut self.removal_cache, now);
        }
        if !remembered.is_empty()
            && let Err(e) = self.store.note_removed_sightings(&remembered).await
        {
            tracing::warn!(
                error = %e,
                "note_removed_sightings failed; continuing with the batch"
            );
        }
        if !blocked_keys.is_empty() {
            metrics::counter!(METRIC_BLOCKED, "reason" => "removal_cooldown")
                .increment(u64::try_from(blocked_keys.len()).unwrap_or(u64::MAX));
            for key in blocked_keys {
                self.batch.remove(&key);
            }
        }
    }

    /// Writes the batch, retrying with exponential backoff until it
    /// succeeds, `cancel` fires or `deadline` passes. Keys enter the dedup
    /// set only after a successful write.
    ///
    /// Before writing, the batch passes the removal-memory gate (§4a):
    /// keys still in cooldown are dropped (counted as
    /// `dc4_blocked_total{reason="removal_cooldown"}`) and counted as
    /// post-removal sightings; keys announced with `seed=1` refresh their
    /// scrape clock first (§4b win 6). A failed removal-memory query drops
    /// the batch keys for recheck on re-announce (fail closed: unknown
    /// cooldowns are never admitted unchecked); only the scrape-clock
    /// refresh stays best-effort.
    pub async fn flush(
        &mut self,
        cancel: Option<&CancellationToken>,
        deadline: Option<Instant>,
    ) -> Result<ObserveOutcome, FlushStopped> {
        // Refresh the early-shed flag even for empty batches: an engaged
        // shed starves the batch, so gating the poll on batch work would
        // latch the shed on forever. The flag mirrors the store's
        // priority-only gate (`depth >= max_pending`, corpses included).
        match self.store.pending_depth().await {
            Ok(depth) => self.shed_sampler = depth >= self.max_pending,
            Err(e) => tracing::warn!(
                error = %e,
                "reading queue depth failed; keeping the shed flag"
            ),
        }
        let seeds: Vec<DhtKey> = self.seed_announced.iter().copied().collect();
        self.seed_announced.clear();
        if !seeds.is_empty()
            && let Err(e) = self.store.refresh_scraped(&seeds).await
        {
            tracing::warn!(
                error = %e,
                keys = seeds.len(),
                "refresh_scraped failed; continuing with the batch"
            );
        }
        if self.batch.is_empty() {
            self.single_sighting_admits = 0;
            return Ok(ObserveOutcome::default());
        }
        // Seed announces are strong evidence (§4a): they shorten (never
        // bypass) the removal cooldown of the same keys in the gate below.
        self.gate_removals(&seeds).await;
        if self.batch.is_empty() {
            self.single_sighting_admits = 0;
            return Ok(ObserveOutcome::default());
        }
        let batch = self.observations();
        let mut delay = self.tuning.retry_base;
        loop {
            match self.store.observe(&batch, self.max_pending).await {
                Ok(outcome) => {
                    let now = Instant::now();
                    let mut rotated = false;
                    for o in &batch {
                        rotated |= self.dedup.insert(&o.key, now);
                    }
                    if rotated {
                        self.sources.clear();
                    }
                    self.batch.clear();
                    self.single_sighting_admits = 0;
                    if outcome.dropped > 0 {
                        metrics::counter!(METRIC_BLOCKED, "reason" => "queue_full")
                            .increment(outcome.dropped);
                    }
                    return Ok(outcome);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        keys = batch.len(),
                        retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        "writing discovered keys failed; retrying"
                    );
                }
            }
            let wake = Instant::now() + delay;
            if let Some(deadline) = deadline
                && wake > deadline
            {
                return Err(FlushStopped::Deadline);
            }
            match cancel {
                Some(token) => {
                    tokio::select! {
                        () = token.cancelled() => return Err(FlushStopped::Cancelled),
                        () = tokio::time::sleep_until(wake) => {}
                    }
                }
                None => tokio::time::sleep_until(wake).await,
            }
            delay = delay.saturating_mul(2).min(self.tuning.retry_max);
        }
    }

    /// Runs until `stop` fires or the channel closes, then drains the
    /// channel and writes the last batch (retrying for at most
    /// `shutdown_flush_timeout`).
    pub async fn run<P: PeerSource>(
        mut self,
        mut rx: mpsc::Receiver<Discovered>,
        peers: P,
        stop: CancellationToken,
    ) {
        let mut ticker = tokio::time::interval(self.tuning.flush_interval.max(MIN_FLUSH_INTERVAL));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut own = OwnAddrs::of(&peers);
        let mut own_read_at = Instant::now();
        loop {
            tokio::select! {
                biased;
                () = stop.cancelled() => break,
                event = rx.recv() => {
                    let Some(event) = event else { break };
                    let now = Instant::now();
                    if now.saturating_duration_since(own_read_at) >= OWN_ADDRS_REFRESH {
                        own = OwnAddrs::of(&peers);
                        own_read_at = now;
                    }
                    self.handle(event, &own, now);
                    if self.batch.len() >= self.tuning.batch_max_keys {
                        // A cancelled flush keeps its batch for the final flush.
                        let _ = self.flush(Some(&stop), None).await;
                    }
                }
                _ = ticker.tick() => {
                    let _ = self.flush(Some(&stop), None).await;
                }
            }
        }
        let now = Instant::now();
        while let Ok(event) = rx.try_recv() {
            self.handle(event, &own, now);
        }
        let deadline = Instant::now() + self.tuning.shutdown_flush_timeout;
        match self.flush(None, Some(deadline)).await {
            Ok(_) => tracing::debug!("admission stopped"),
            Err(_) => tracing::warn!(
                keys = self.batch.len(),
                "admission stopped without writing its last batch"
            ),
        }
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
    use super::*;
    use crate::memstore::MemoryStore;

    fn key(n: u8) -> DhtKey {
        DhtKey([n; 20])
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn event(k: DhtKey, source: Source, from: &str, peer: Option<&str>) -> Discovered {
        Discovered {
            key: k,
            source,
            peer: peer.map(sa),
            seed: false,
            from: ip(from),
        }
    }

    fn seed_event(k: DhtKey) -> Discovered {
        Discovered {
            key: k,
            source: Source::Announce,
            peer: None,
            seed: true,
            from: ip("8.8.8.8"),
        }
    }

    fn stored_torrent(k: DhtKey) -> dc4_store::NewTorrent {
        dc4_store::NewTorrent {
            dht_key: k,
            info_hash_v1: Some(k),
            info_hash_v2: None,
            name: "x".into(),
            total_size: 1,
            file_count: 0,
            files: Vec::new(),
            files_truncated: false,
            piece_length: None,
        }
    }

    fn admission(store: &MemoryStore, filter: PeerFilter) -> Admission<MemoryStore> {
        let tuning = AdmissionTuning::default();
        Admission::new(
            store.clone(),
            i64::MAX,
            filter,
            tuning,
            shared_hints(&tuning),
            Instant::now(),
        )
    }

    fn admission_with_single_cap(
        store: &MemoryStore,
        filter: PeerFilter,
        cap: usize,
    ) -> Admission<MemoryStore> {
        let tuning = AdmissionTuning {
            get_peers_single_cap: cap,
            ..AdmissionTuning::default()
        };
        Admission::new(
            store.clone(),
            i64::MAX,
            filter,
            tuning,
            shared_hints(&tuning),
            Instant::now(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn dedup_generations_rotate() {
        let t0 = Instant::now();
        let mut d = DedupSet::new(3, Duration::from_secs(60), t0);
        assert!(d.is_empty());
        for n in 0..3 {
            assert!(!d.insert(&key(n), t0));
        }
        assert!(d.contains(&key(0)));
        // A full generation rotates on the next new key.
        assert!(d.insert(&key(3), t0));
        assert_eq!(d.len(), (1, 3));
        assert!(d.contains(&key(0)) && d.contains(&key(3)));
        // Re-inserting a present key never rotates.
        assert!(!d.insert(&key(3), t0));
        // Time-based rotation: the oldest generation is forgotten.
        assert!(!d.maybe_rotate(t0 + Duration::from_secs(59)));
        assert!(d.maybe_rotate(t0 + Duration::from_secs(60)));
        assert!(!d.contains(&key(0)));
        assert!(d.contains(&key(3)));
        assert!(d.maybe_rotate(t0 + Duration::from_secs(120)));
        assert!(d.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn dedup_insert_ignores_previous_generation() {
        // A previous-only key must not be re-added to current.
        let t0 = Instant::now();
        let mut d = DedupSet::new(3, Duration::from_secs(60), t0);
        for n in 0..3 {
            assert!(!d.insert(&key(n), t0));
        }
        assert!(d.insert(&key(3), t0));
        assert_eq!(d.len(), (1, 3));
        // key(0) lives only in previous now; re-insert must be a no-op.
        assert!(!d.insert(&key(0), t0));
        assert_eq!(d.len(), (1, 3));
        assert!(d.contains(&key(0)));
    }

    #[test]
    fn source_networks() {
        assert_eq!(
            source_network(ip("1.2.3.4")),
            source_network(ip("1.2.3.200"))
        );
        assert_ne!(source_network(ip("1.2.3.4")), source_network(ip("1.2.4.4")));
        assert_eq!(
            source_network(ip("::ffff:1.2.3.4")),
            source_network(ip("1.2.3.9"))
        );
        assert_eq!(
            source_network(ip("2001:db8:1:ffff::1")),
            source_network(ip("2001:db8:1::2"))
        );
        assert_ne!(
            source_network(ip("2001:db8:1::1")),
            source_network(ip("2001:db8:2::1"))
        );
        // IPv4 and IPv6 networks never collide.
        assert_ne!(source_network(ip("0.0.0.1")), source_network(ip("::")));
        assert_ne!(
            source_network(ip("0.1.0.0")),
            source_network(ip("0:0:0:0:0:0:0:1"))
        );
        let mut t = SourceTracker::new(2);
        assert_eq!(t.record(key(1), ip("1.2.3.4")), 1);
        assert_eq!(t.record(key(1), ip("1.2.3.5")), 1);
        assert_eq!(t.record(key(1), ip("5.6.7.8")), 2);
        for n in 10..20 {
            t.record(key(1), ip(&format!("{n}.0.0.1")));
        }
        assert_eq!(t.record(key(1), ip("99.0.0.1")), SOURCE_PREFIXES_PER_KEY);
        t.record(key(2), ip("1.1.1.1"));
        t.record(key(3), ip("1.1.1.1"));
        assert_eq!(t.len(), 2, "bounded LRU");
        assert_eq!(t.record(key(1), ip("5.6.7.8")), 1, "key 1 was evicted");
    }

    #[test]
    #[should_panic(expected = "must be non-zero")]
    fn zero_capacity_is_rejected_not_silently_one() {
        let _ = SourceTracker::new(0);
    }

    #[tokio::test(start_paused = true)]
    async fn removal_gate_fails_closed_on_store_error() {
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::default();
        a.handle(
            event(key(1), Source::Sample, "1.2.3.4", None),
            &own,
            Instant::now(),
        );
        // The removal-memory query fails: the key must not be admitted.
        store.fail_next_removals(1);
        let outcome = a.flush(None, None).await.unwrap();
        assert_eq!(outcome.queued, 0);
        assert_eq!(a.batch_len(), 0);
        assert_eq!(store.observe_calls(), 0);
        // Nothing was cached about the key, so the next sighting rechecks
        // against a healthy store and is admitted.
        a.handle(
            event(key(1), Source::Sample, "1.2.3.4", None),
            &own,
            Instant::now(),
        );
        let outcome = a.flush(None, None).await.unwrap();
        assert_eq!(outcome.queued, 1);
        assert_eq!(store.observe_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn removal_cache_eviction_keeps_live_cooldowns() {
        fn wide_key(i: u32) -> DhtKey {
            let mut b = [0u8; 20];
            b[..4].copy_from_slice(&i.to_be_bytes());
            DhtKey(b)
        }
        let cap = u32::try_from(REMOVAL_CACHE_KEYS).unwrap();
        let now = Instant::now();
        let mut cache = HashMap::new();
        for i in 0..cap {
            cache.insert(wide_key(i), RemovalVerdict::Clear(now));
        }
        let mut live = Vec::new();
        for i in 0..5u32 {
            let k = wide_key(cap + i);
            cache.insert(k, RemovalVerdict::Blocked(now + Duration::from_secs(3600)));
            live.push(k);
        }
        for i in 0..3u32 {
            cache.insert(
                wide_key(cap + 100 + i),
                RemovalVerdict::Blocked(now - Duration::from_secs(1)),
            );
        }
        evict_removal_cache(&mut cache, now);
        assert_eq!(cache.len(), 5);
        for k in &live {
            assert!(matches!(cache.get(k), Some(RemovalVerdict::Blocked(_))));
        }
        // Pathological: live cooldowns alone exceed the cap — the
        // soonest-expiring shed, the rest survive.
        let mut cache = HashMap::new();
        for i in 0..cap + 5 {
            cache.insert(
                wide_key(i),
                RemovalVerdict::Blocked(now + Duration::from_secs(u64::from(i) + 1)),
            );
        }
        evict_removal_cache(&mut cache, now);
        assert_eq!(cache.len(), REMOVAL_CACHE_KEYS);
        for i in 0..5u32 {
            assert!(!cache.contains_key(&wide_key(i)), "soonest-expiring shed");
        }
        assert!(cache.contains_key(&wide_key(cap + 4)));
    }

    #[tokio::test(start_paused = true)]
    async fn get_peers_needs_two_networks() {
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::default();
        let now = Instant::now();
        // A first get_peers sighting admits at once as non-priority.
        let k = key(7);
        a.handle(event(k, Source::GetPeers, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        assert!(a.sources().is_empty());
        // More sightings merge into the batch.
        a.handle(event(k, Source::GetPeers, "1.2.3.99", None), &own, now);
        a.handle(event(k, Source::GetPeers, "9.9.9.9", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        // Announce is admitted at once with priority; sample is admitted at
        // once without it (only announces are priority now).
        a.handle(event(key(8), Source::Sample, "1.2.3.4", None), &own, now);
        a.handle(event(key(9), Source::Announce, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 3);
        a.flush(None, None).await.unwrap();
        let observed = store.observed();
        let find = |k: DhtKey| observed.iter().find(|o| o.key == k).copied().unwrap();
        assert_eq!(find(key(7)).sightings, 3);
        assert!(!find(key(7)).priority);
        assert!(!find(key(8)).priority);
        assert!(find(key(9)).priority);
        assert_eq!(store.pending_keys().len(), 3);
        // Keys now in the dedup set are skipped.
        a.handle(event(key(8), Source::Sample, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 0);
        // IPv6 sightings admit at once too.
        let k6 = key(10);
        a.handle(
            event(k6, Source::GetPeers, "2001:db8:1:2::1", None),
            &own,
            now,
        );
        assert_eq!(a.batch_len(), 1);
        a.handle(
            event(k6, Source::GetPeers, "2001:db8:1:3::1", None),
            &own,
            now,
        );
        a.handle(
            event(k6, Source::GetPeers, "2001:db8:2::1", None),
            &own,
            now,
        );
        assert_eq!(a.batch_len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn get_peers_single_sighting_admitted_non_priority() {
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::default();
        let now = Instant::now();
        a.handle(event(key(1), Source::GetPeers, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        assert!(a.sources().is_empty());
        a.flush(None, None).await.unwrap();
        let observed = store.observed();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].sightings, 1);
        assert!(!observed[0].priority);
    }

    #[tokio::test(start_paused = true)]
    async fn get_peers_single_cap_enforced_and_reset() {
        let store = MemoryStore::new();
        let mut a = admission_with_single_cap(&store, PeerFilter::PRODUCTION, 1);
        let own = OwnAddrs::default();
        let now = Instant::now();
        a.handle(event(key(1), Source::GetPeers, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        // Cap exhausted: the next first sighting is blocked, not batched.
        a.handle(event(key(2), Source::GetPeers, "5.6.7.8", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        assert!(!a.dedup().contains(&key(2)));
        // The flush ends the cycle, so new keys flow again.
        a.flush(None, None).await.unwrap();
        a.handle(event(key(2), Source::GetPeers, "5.6.7.8", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        a.flush(None, None).await.unwrap();
        assert_eq!(store.pending_keys().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn get_peers_two_networks_admit_past_exhausted_single_cap() {
        let store = MemoryStore::new();
        let mut a = admission_with_single_cap(&store, PeerFilter::PRODUCTION, 1);
        let own = OwnAddrs::default();
        let now = Instant::now();
        // Exhaust the single-sighting cap with one key.
        a.handle(event(key(1), Source::GetPeers, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        // A first sighting of another key is blocked ...
        a.handle(event(key(2), Source::GetPeers, "5.6.7.8", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        // ... but its second network admits without consuming the cap.
        a.handle(event(key(2), Source::GetPeers, "9.9.9.9", None), &own, now);
        assert_eq!(a.batch_len(), 2);
        assert!(a.sources().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn sample_admitted_at_once_without_priority() {
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::default();
        let now = Instant::now();
        // One sighting is enough (no two-network rule for our own sampler),
        // but the key is non-priority: only announces are priority.
        a.handle(event(key(1), Source::Sample, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        a.flush(None, None).await.unwrap();
        let observed = store.observed();
        assert_eq!(observed.len(), 1);
        assert!(!observed[0].priority);
        assert_eq!(store.pending_keys(), vec![key(1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn sample_clears_get_peers_tracking() {
        let store = MemoryStore::new();
        // Single-sighting admits disabled: one get_peers sighting tracks.
        let mut a = admission_with_single_cap(&store, PeerFilter::PRODUCTION, 0);
        let own = OwnAddrs::default();
        let now = Instant::now();
        // One get_peers sighting only tracks the key ...
        a.handle(event(key(1), Source::GetPeers, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 0);
        assert_eq!(a.sources().len(), 1);
        // ... then our own sampler sees it: admitted at once, non-priority,
        // tracking dropped.
        a.handle(event(key(1), Source::Sample, "9.9.9.9", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        assert!(a.sources().is_empty());
        a.flush(None, None).await.unwrap();
        let observed = store.observed();
        assert_eq!(observed.len(), 1);
        assert!(!observed[0].priority);
    }

    #[tokio::test(start_paused = true)]
    async fn announce_merges_priority_into_a_sampled_batch_entry() {
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::default();
        let now = Instant::now();
        a.handle(event(key(1), Source::Sample, "1.2.3.4", None), &own, now);
        a.handle(event(key(1), Source::Announce, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        a.flush(None, None).await.unwrap();
        let observed = store.observed();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].sightings, 2);
        assert!(observed[0].priority);
    }

    #[tokio::test(start_paused = true)]
    async fn shed_drops_only_samples_while_set() {
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::default();
        let now = Instant::now();
        a.shed_sampler = true;
        // Samples shed before the batch and stay out of the dedup set ...
        a.handle(event(key(1), Source::Sample, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 0);
        assert!(!a.dedup().contains(&key(1)));
        // ... announces still flow ...
        a.handle(event(key(2), Source::Announce, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        // ... and get_peers first sightings admit at once (non-priority).
        a.handle(event(key(3), Source::GetPeers, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 2);
        a.handle(event(key(3), Source::GetPeers, "9.9.9.9", None), &own, now);
        assert_eq!(a.batch_len(), 2);
        // A re-sighted shed key sheds again instead of hiding in dedup.
        a.handle(event(key(1), Source::Sample, "5.6.7.8", None), &own, now);
        assert_eq!(a.batch_len(), 2);
        assert!(!a.dedup().contains(&key(1)));
        let out = a.flush(None, None).await.unwrap();
        assert_eq!(out.queued, 2);
        assert_eq!(store.pending_keys().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn shed_merges_into_an_existing_batch_entry() {
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::default();
        let now = Instant::now();
        a.handle(event(key(1), Source::Announce, "1.2.3.4", None), &own, now);
        a.shed_sampler = true;
        // Already batched: the re-sighting merges (sightings grow, priority
        // kept) instead of shedding — the batch write was already paid for.
        a.handle(event(key(1), Source::Sample, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
        a.flush(None, None).await.unwrap();
        let observed = store.observed();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].sightings, 2);
        assert!(observed[0].priority);
    }

    #[tokio::test(start_paused = true)]
    async fn shed_flag_tracks_depth_across_flushes() {
        use crate::stores::CrawlStore;

        let store = MemoryStore::new();
        let tuning = AdmissionTuning::default();
        let mut a = Admission::new(
            store.clone(),
            2,
            PeerFilter::PRODUCTION,
            tuning,
            shared_hints(&tuning),
            Instant::now(),
        );
        let own = OwnAddrs::default();
        let now = Instant::now();
        assert!(!a.shed_sampler);
        // Fill to the cap: the flag is polled before the observe, so it
        // engages on the following flush, not this one.
        a.handle(event(key(1), Source::Announce, "1.2.3.4", None), &own, now);
        a.handle(event(key(2), Source::Announce, "1.2.3.4", None), &own, now);
        a.flush(None, None).await.unwrap();
        assert_eq!(store.pending_keys().len(), 2);
        assert!(!a.shed_sampler);
        // An empty flush still polls: without this an engaged shed would
        // starve the batch and latch on forever.
        a.flush(None, None).await.unwrap();
        assert!(a.shed_sampler);
        // Samples shed while the flag is set ...
        a.handle(event(key(3), Source::Sample, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 0);
        // ... and flow again once depth falls below the cap. Draining via
        // completion removes the rows (a claim would only lease them).
        for key in [key(1), key(2)] {
            store.complete(&key, &stored_torrent(key)).await.unwrap();
        }
        a.flush(None, None).await.unwrap();
        assert!(!a.shed_sampler);
        a.handle(event(key(3), Source::Sample, "1.2.3.4", None), &own, now);
        assert_eq!(a.batch_len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn shed_flag_keeps_prior_value_when_depth_poll_fails() {
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::default();
        let now = Instant::now();
        // A failed poll keeps the flag either way and never fails the flush:
        // the batch still writes.
        a.shed_sampler = true;
        store.fail_next_depths(1);
        a.handle(event(key(1), Source::Announce, "1.2.3.4", None), &own, now);
        a.flush(None, None).await.unwrap();
        assert!(a.shed_sampler);
        assert_eq!(store.pending_keys(), vec![key(1)]);
        a.shed_sampler = false;
        store.fail_next_depths(1);
        a.flush(None, None).await.unwrap();
        assert!(!a.shed_sampler);
    }

    #[tokio::test(start_paused = true)]
    async fn source_counts_reset_with_the_generation() {
        let store = MemoryStore::new();
        // Single-sighting admits disabled so the two-network rule applies.
        let mut a = admission_with_single_cap(&store, PeerFilter::PRODUCTION, 0);
        let own = OwnAddrs::default();
        let t0 = Instant::now();
        a.handle(event(key(1), Source::GetPeers, "1.2.3.4", None), &own, t0);
        let later = t0 + DEDUP_ROTATION;
        a.handle(
            event(key(1), Source::GetPeers, "5.6.7.8", None),
            &own,
            later,
        );
        assert_eq!(a.batch_len(), 0, "the first sighting was forgotten");
        a.handle(
            event(key(1), Source::GetPeers, "9.9.9.9", None),
            &own,
            later,
        );
        assert_eq!(a.batch_len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn keys_enter_dedup_only_after_a_successful_write() {
        let store = MemoryStore::new();
        let tuning = AdmissionTuning {
            retry_base: Duration::from_millis(100),
            ..AdmissionTuning::default()
        };
        let mut a = Admission::new(
            store.clone(),
            i64::MAX,
            PeerFilter::PRODUCTION,
            tuning,
            shared_hints(&tuning),
            Instant::now(),
        );
        let own = OwnAddrs::default();
        a.handle(
            event(key(1), Source::Sample, "1.2.3.4", None),
            &own,
            Instant::now(),
        );
        // Two failures before the deadline, one when cancelled, and one more
        // before the final write succeeds.
        store.fail_next_observes(4);
        // A deadline shorter than the retries gives up and keeps the batch.
        let deadline = Instant::now() + Duration::from_millis(150);
        assert_eq!(
            a.flush(None, Some(deadline)).await,
            Err(FlushStopped::Deadline)
        );
        assert_eq!(a.batch_len(), 1);
        assert!(!a.dedup().contains(&key(1)));
        // A cancelled flush keeps it too.
        let token = CancellationToken::new();
        token.cancel();
        assert_eq!(
            a.flush(Some(&token), None).await,
            Err(FlushStopped::Cancelled)
        );
        assert!(!a.dedup().contains(&key(1)));
        let before = Instant::now();
        let outcome = a.flush(None, None).await.unwrap();
        assert_eq!(outcome.queued, 1);
        assert!(Instant::now() - before >= Duration::from_millis(100));
        assert!(a.dedup().contains(&key(1)));
        assert_eq!(a.batch_len(), 0);
        assert_eq!(store.observe_calls(), 5);
        // Sightings of a key waiting in a failed batch are merged, not lost.
        store.fail_next_observes(1);
        a.handle(
            event(key(2), Source::Sample, "1.2.3.4", None),
            &own,
            Instant::now(),
        );
        let token = CancellationToken::new();
        token.cancel();
        assert!(a.flush(Some(&token), None).await.is_err());
        a.handle(
            event(key(2), Source::Sample, "1.2.3.4", None),
            &own,
            Instant::now(),
        );
        a.flush(None, None).await.unwrap();
        let last = store
            .observed()
            .into_iter()
            .rfind(|o| o.key == key(2))
            .unwrap();
        assert_eq!(last.sightings, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn hints_are_filtered_and_expire() {
        let store = MemoryStore::new();
        let filter = PeerFilter::PRODUCTION;
        let mut a = admission(&store, filter);
        let own = OwnAddrs::new(vec![ip("8.8.4.4")], vec![]);
        let t0 = Instant::now();
        let k = key(3);
        // Only the first is kept: then ours, private, loopback and port 0.
        for peer in [
            "8.8.8.8:6881",
            "8.8.4.4:6881",
            "10.0.0.1:6881",
            "127.0.0.1:6881",
            "1.1.1.1:0",
        ] {
            a.handle(event(k, Source::Announce, "8.8.8.8", Some(peer)), &own, t0);
        }
        let hints = a.hints.clone();
        assert_eq!(take_hints(&hints, &k, t0), vec![sa("8.8.8.8:6881")]);
        assert!(take_hints(&hints, &k, t0).is_empty(), "taking removes");

        // Expiry, newest first, and at most eight per key.
        let mut map = HintMap::new(10, HINT_TTL);
        map.add(k, sa("1.1.1.1:1"), t0);
        for port in 2..=10u16 {
            map.add(k, SocketAddr::new(ip("1.1.1.1"), port), t0 + HINT_TTL / 2);
        }
        let got = map.take(&k, t0 + HINT_TTL);
        assert_eq!(got.len(), HINT_PEERS_PER_KEY);
        assert_eq!(got[0], sa("1.1.1.1:10"));
        assert!(!got.contains(&sa("1.1.1.1:1")));
        map.add(k, sa("1.1.1.1:1"), t0);
        assert!(map.take(&k, t0 + HINT_TTL).is_empty(), "expired");
        // The map is a bounded LRU.
        let mut small = HintMap::new(2, HINT_TTL);
        for n in 0..5 {
            small.add(key(n), sa("1.1.1.1:1"), t0);
        }
        assert_eq!(small.len(), 2);
        assert!(small.take(&key(0), t0).is_empty());
        assert_eq!(small.take(&key(4), t0).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn get_peers_events_add_no_retry_hints() {
        // WS2: `get_peers`-sourced sightings must not become retry hints —
        // traversal already queues those peers, so re-adding would
        // double-dial. Producers emit `peer: None` for `GetPeers` (only
        // `Announce` carries a peer); the admission add-path therefore
        // records nothing for them while announce peers land in the map.
        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::new(vec![ip("8.8.4.4")], vec![]);
        let t0 = Instant::now();
        let k = key(9);
        a.handle(event(k, Source::GetPeers, "8.8.8.8", None), &own, t0);
        a.handle(event(k, Source::Sample, "8.8.8.8", None), &own, t0);
        assert!(
            take_hints(&a.hints, &k, t0).is_empty(),
            "peerless get_peers/sample events add no hints"
        );
        a.handle(
            event(k, Source::Announce, "8.8.8.8", Some("8.8.8.8:6881")),
            &own,
            t0,
        );
        assert_eq!(take_hints(&a.hints, &k, t0), vec![sa("8.8.8.8:6881")]);
    }

    #[tokio::test(start_paused = true)]
    async fn run_flushes_on_interval_and_at_shutdown() {
        #[derive(Clone)]
        struct NoPeers;
        impl PeerSource for NoPeers {
            async fn get_peers(&self, _: DhtKey, _: Duration) -> Vec<SocketAddr> {
                Vec::new()
            }
            async fn scrape_peers(&self, _: DhtKey, _: Duration) -> dc4_dht::ScrapeReport {
                dc4_dht::ScrapeReport::default()
            }
            fn own_ips(&self) -> Vec<IpAddr> {
                Vec::new()
            }
            fn own_endpoints(&self) -> Vec<SocketAddr> {
                Vec::new()
            }
        }

        let store = MemoryStore::new();
        let a = admission(&store, PeerFilter::PRODUCTION);
        let (tx, rx) = mpsc::channel(16);
        let stop = CancellationToken::new();
        let task = tokio::spawn(a.run(rx, NoPeers, stop.clone()));
        tx.send(event(key(1), Source::Sample, "1.2.3.4", None))
            .await
            .unwrap();
        tokio::time::sleep(BATCH_FLUSH_INTERVAL * 2).await;
        assert_eq!(store.pending_keys(), vec![key(1)]);
        // Events still queued at shutdown are written too.
        tx.send(event(key(2), Source::Sample, "1.2.3.4", None))
            .await
            .unwrap();
        stop.cancel();
        task.await.unwrap();
        assert_eq!(store.pending_keys(), vec![key(1), key(2)]);
    }

    #[tokio::test(start_paused = true)]
    async fn flush_skips_keys_in_removal_cooldown() {
        use crate::stores::CrawlStore;

        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::new(vec![ip("8.8.4.4")], vec![]);
        let t0 = Instant::now();
        // Key 1 was scrape-tombstoned, so its removal is remembered.
        let dead = key(1);
        let id = store.complete(&dead, &stored_torrent(dead)).await.unwrap();
        let items = store
            .claim_scrape_due(10, Duration::ZERO, Duration::ZERO)
            .await
            .unwrap();
        let snap = items.iter().find(|c| c.id == id).unwrap().clone();
        assert!(
            store
                .tombstone_dead(id, snap.last_seen_at, snap.change_seq)
                .await
                .unwrap()
        );
        // Key 2 is fresh.
        let live = key(2);
        a.handle(event(dead, Source::Announce, "1.2.3.4", None), &own, t0);
        a.handle(event(live, Source::Announce, "1.2.3.4", None), &own, t0);
        let out = a.flush(None, None).await.unwrap();
        assert_eq!(out.queued, 1);
        assert_eq!(store.pending_keys(), vec![live]);
        // Still blocked on the next flush (cached verdict): no re-fetch
        // storm while the cooldown runs.
        a.handle(event(dead, Source::Announce, "5.6.7.8", None), &own, t0);
        let out = a.flush(None, None).await.unwrap();
        assert_eq!(out.queued, 0);
        assert_eq!(store.pending_keys(), vec![live]);
    }

    #[tokio::test(start_paused = true)]
    async fn flush_shortens_cooldown_on_seed_evidence_but_never_bypasses() {
        use crate::stores::CrawlStore;

        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::new(vec![ip("8.8.4.4")], vec![]);
        let dead = key(1);
        let id = store.complete(&dead, &stored_torrent(dead)).await.unwrap();
        let items = store
            .claim_scrape_due(10, Duration::ZERO, Duration::ZERO)
            .await
            .unwrap();
        let snap = items.iter().find(|c| c.id == id).unwrap().clone();
        assert!(
            store
                .tombstone_dead(id, snap.last_seen_at, snap.change_seq)
                .await
                .unwrap()
        );
        // Two days into the 7d cooldown a plain announce is still blocked
        // (5d left), while a seed announce is admitted (7/4 = 1.75d < 2d):
        // shortening, never bypassing — a fresh removal still blocks.
        tokio::time::advance(Duration::from_secs(2 * 24 * 60 * 60)).await;
        let t0 = Instant::now();
        a.handle(event(dead, Source::Announce, "1.2.3.4", None), &own, t0);
        let out = a.flush(None, None).await.unwrap();
        assert_eq!(out.queued, 0);
        assert!(store.pending_keys().is_empty());
        a.handle(seed_event(dead), &own, Instant::now());
        let out = a.flush(None, None).await.unwrap();
        assert_eq!(out.queued, 1);
        assert_eq!(store.pending_keys(), vec![dead]);
    }

    #[tokio::test(start_paused = true)]
    async fn flush_rescans_cached_keys_carrying_seed_evidence() {
        use crate::stores::CrawlStore;

        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::new(vec![ip("8.8.4.4")], vec![]);
        // 32 tombstoned keys: even-indexed ones will carry seed evidence.
        let all: Vec<DhtKey> = (0..32u8).map(|n| key(10 + n)).collect();
        for k in &all {
            let id = store.complete(k, &stored_torrent(*k)).await.unwrap();
            let items = store
                .claim_scrape_due(100, Duration::ZERO, Duration::ZERO)
                .await
                .unwrap();
            let snap = items.iter().find(|c| c.id == id).unwrap().clone();
            assert!(
                store
                    .tombstone_dead(id, snap.last_seen_at, snap.change_seq)
                    .await
                    .unwrap()
            );
        }
        // Two days into the 7d cooldown a first flush blocks everything
        // and caches the verdicts.
        tokio::time::advance(Duration::from_secs(2 * 24 * 60 * 60)).await;
        let t0 = Instant::now();
        for k in &all {
            a.handle(event(*k, Source::Announce, "1.2.3.4", None), &own, t0);
        }
        let out = a.flush(None, None).await.unwrap();
        assert_eq!(out.queued, 0);
        assert!(store.pending_keys().is_empty());
        // Seed announces for the even half (plus evidence for unknown keys,
        // which must not error or admit anything): the evidence half must
        // skip the cached Blocked verdicts, re-check the store, and land
        // inside the ÷4 shortening window (admitted), while the odd half
        // stays on its cached verdict (blocked).
        for k in all.iter().step_by(2) {
            a.handle(seed_event(*k), &own, Instant::now());
        }
        a.handle(seed_event(key(200)), &own, Instant::now());
        a.handle(seed_event(key(201)), &own, Instant::now());
        for k in all.iter().skip(1).step_by(2) {
            a.handle(
                event(*k, Source::Announce, "5.6.7.8", None),
                &own,
                Instant::now(),
            );
        }
        let out = a.flush(None, None).await.unwrap();
        let mut pending = store.pending_keys();
        pending.sort();
        let mut expected: Vec<DhtKey> = all.iter().step_by(2).copied().collect();
        // The unknown evidence keys are fresh (no removal on record), so
        // they pass the gate and are admitted like any new key.
        expected.push(key(200));
        expected.push(key(201));
        expected.sort();
        assert_eq!(out.queued, expected.len() as u64);
        assert_eq!(pending, expected);
    }

    #[tokio::test(start_paused = true)]
    async fn flush_refreshes_seed_announced_scrapes() {
        use crate::stores::CrawlStore;

        let store = MemoryStore::new();
        let mut a = admission(&store, PeerFilter::PRODUCTION);
        let own = OwnAddrs::new(vec![ip("8.8.4.4")], vec![]);
        let k = key(5);
        let id = store.complete(&k, &stored_torrent(k)).await.unwrap();
        store.record_scrape(id, Some(3), 1).await.unwrap();
        // A seed announce is also a discovery (its peer is a hint), and it
        // refreshes the scrape clock without a lookup.
        a.handle(seed_event(k), &own, Instant::now());
        a.flush(None, None).await.unwrap();
        let items = store
            .claim_scrape_due(10, Duration::ZERO, Duration::ZERO)
            .await
            .unwrap();
        let item = items.iter().find(|c| c.id == id).unwrap();
        assert_eq!(item.scrape_failures, 0);
        assert_eq!(item.seeders_est, Some(3));
    }
}
