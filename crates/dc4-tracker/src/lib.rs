//! BEP 15 UDP tracker client: multi-hash scrape triage and one-shot announces.
//!
//! Only what finding peers needs: `connect` (cached IDs), batched `scrape`
//! (up to 74 hashes per datagram) for triage, and single `started`
//! announces that harvest peer lists. No TCP trackers, no announce loop,
//! no stats reporting. Trackers only see keys the DHT already claimed.
//!
//! Privacy/abuse: announces expose our IP per hash to tracker operators
//! (same exposure class as DHT participation). Good-citizen subset:
//! `started`-only one-shots, a random subset of live trackers per key
//! (never the whole list), per-(key,tracker) re-announce floors honoring
//! each tracker's announce-response `interval` (UDP has no `min interval`;
//! floor is `max(interval, 60s)`), liveness probes at ~1 packet/server/hour.
//! Re-announce is only for the zero-peers case once the cooldown elapsed:
//! keys that already yielded peers are not re-announced.
//!
//! Metric cardinality: per-tracker labels are bounded (explicit
//! `trackers` validate to <= 32 entries; the vendored list holds 17
//! usable UDP entries) — see [`client::METRIC_CONN_REFRESH`].
//!
//! Deviations from the hybrid spec, documented not hidden: the list
//! refresh speaks plain HTTP only (no TLS client, so the spec's `https://`
//! default URL is off by default — set an `http://` URL to enable);
//! announces run inline on fetch workers throttled by the packet budget
//! plus a 32-permit semaphore, not on a dedicated 32-task pool; one
//! socket per pool (fewer FDs than one-per-tracker, same pipelining);
//! first-seen addresses start live optimistically — no blocking connect
//! probe at startup — and scrape/announce verdicts plus the hourly sweep
//! evict the dead; announces carry `left=1` (leecher, never seeder `0`);
//! announce selection is filter-then-sample over unfloored servers.

pub mod client;
pub mod codec;
pub mod list;

pub use client::{
    ANNOUNCE_CONCURRENCY, AnnounceOutcome, LiveServer, METRIC_CONN_REFRESH, TrackerPool,
};
pub use codec::{MAX_SCRAPE_HASHES, ScrapeRow};
pub use list::{TrackerEntry, VENDORED_LIST, parse_list};
