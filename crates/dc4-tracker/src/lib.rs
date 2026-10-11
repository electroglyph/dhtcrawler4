//! BEP 15 UDP tracker client: multi-hash scrape triage and one-shot announces.
//!
//! Only what finding peers needs: `connect` (cached IDs), batched `scrape`
//! (up to 74 hashes per datagram) for triage, and single `started`
//! announces that harvest peer lists. No TCP trackers, no announce loop,
//! no stats reporting. Trackers only see keys the DHT already claimed.

pub mod client;
pub mod codec;
pub mod list;

pub use client::{AnnounceOutcome, LiveServer, TrackerPool};
pub use codec::{MAX_SCRAPE_HASHES, ScrapeRow};
pub use list::{TrackerEntry, VENDORED_LIST, parse_list};
