//! A Mainline DHT node for dhtcrawler4 (BEP 5, 32, 42, 43, 51).
//!
//! [`Dht::start`] binds one UDP socket per address family and runs:
//! * a compliant responder (`ping`, `find_node`, `get_peers`,
//!   `announce_peer`, `sample_infohashes`) with real tokens, KRPC errors and
//!   its own reply budget;
//! * a routing table per family with BEP 42 node IDs, chosen after an
//!   external-IP vote;
//! * a BEP 51 sampler that emits [`Discovered`] keys and never samples a
//!   node before its `interval` has passed;
//! * iterative lookups for [`Dht::get_peers`] and [`Dht::announce`].
//!
//! Every input is bounded (datagram size, bencode depth and item count, list
//! lengths) and every map and queue has a fixed capacity. Outgoing queries
//! and replies have separate global budgets, and traffic is also limited per
//! address. Every address the node sends to, stores or hands out passes
//! [`is_dialable`]. Discoveries go to a bounded channel; when it is full they
//! are dropped and counted, never buffered.
//!
//! Protocol building blocks are public for tests and tools: [`krpc`]
//! (message codec), [`compact`] (compact encodings, the address chokepoint)
//! and [`node_id`] (XOR metric, BEP 42).
#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects)]
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

pub mod bloom;
pub mod compact;
mod config;
pub mod krpc;
mod lookup;
mod net;
mod node;
pub mod node_id;
mod peer_store;
mod ratelimit;
mod responder;
mod routing;
mod sampler;
mod state;
mod stats;
mod token;
mod util;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dc4_core::DhtKey;
use futures::future::join_all;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::DropGuard;

pub use compact::{Family, is_dialable};
pub use config::{
    DEFAULT_BOOTSTRAP, DEFAULT_CLIENT_VERSION, DEFAULT_FETCH_PACKETS_PER_SEC,
    DEFAULT_MAX_PACKETS_PER_SEC, DEFAULT_PORT, DEFAULT_RESPONDER_BYTES_PER_SEC,
    DEFAULT_RESPONDER_REPLIES_PER_SEC, DEFAULT_SAMPLER_CONCURRENCY,
    DEFAULT_SCRAPE_PACKETS_PER_SEC, DhtConfig, DhtTuning, MAX_SAMPLER_CONCURRENCY,
};
pub use node::MIN_GOOD_NODES;
pub use node_id::NodeId;
pub use stats::{DhtStatsSnapshot, DropCounts, DropReason, FamilyStats, QueryCounts};

use crate::node::Inner;
use crate::util::{after, lock};

/// Errors from [`Dht::start`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration cannot be used.
    #[error("invalid DHT configuration: {0}")]
    Config(String),
    /// A socket could not be bound, and the node cannot run without it.
    #[error("cannot bind DHT socket {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    /// IPv4 is disabled and IPv6 cannot be used: the host has no global
    /// IPv6 address.
    #[error("no DHT socket: IPv4 is disabled and the host has no global IPv6 address")]
    NoSocket,
}

/// How a key was discovered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// A BEP 51 `sample_infohashes` answer.
    Sample,
    /// An `announce_peer` query with a valid token.
    Announce,
    /// A `get_peers` query.
    GetPeers,
}

impl Source {
    /// The metric label: `"sample"`, `"announce"` or `"get_peers"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Sample => "sample",
            Source::Announce => "announce",
            Source::GetPeers => "get_peers",
        }
    }
}

/// A DHT key seen by the node. Addresses in it stay in memory only (R11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Discovered {
    pub key: DhtKey,
    pub source: Source,
    /// The announcing peer, for `Source::Announce`. It passed [`is_dialable`].
    pub peer: Option<SocketAddr>,
    /// True when an `announce_peer` arrived with `seed=1` (BEP 33): a live
    /// seeder just proved itself. Always false for other sources.
    pub seed: bool,
    /// The source IP of the packet behind the discovery: the querying node
    /// for `Announce` and `GetPeers`, the answering node for `Sample`.
    /// IPv4-mapped addresses are given as IPv4.
    pub from: IpAddr,
}

/// A BEP 33 scrape result for one infohash, merged over the node's
/// address families.
#[derive(Clone, Debug, Default)]
pub struct ScrapeReport {
    /// Distinct dialable peers found (as in [`Dht::get_peers`]).
    pub peers: Vec<std::net::SocketAddr>,
    /// `BFsd` (seed) filters, one per aware response.
    pub seed_filters: Vec<[u8; crate::bloom::BLOOM_LEN]>,
    /// `BFpe` (peer) filters, one per aware response (sanity/dedup only,
    /// never stored).
    pub peer_filters: Vec<[u8; crate::bloom::BLOOM_LEN]>,
    /// Responses that carried filter keys.
    pub aware: usize,
    /// Responses without filter keys.
    pub unaware: usize,
    /// Address families actually scraped (one pass per bound socket).
    /// A dead verdict is only valid when both families were attempted.
    pub families_attempted: usize,
}

impl ScrapeReport {
    /// Estimated seeders: the BEP counting formula over the OR-union of
    /// all aware `BFsd` filters. `None` means UNKNOWN — zero aware
    /// responses, or a saturated union. An empty union (aware responses,
    /// no seeds) estimates to `Some(0)`.
    pub fn seeders_est(&self) -> Option<u64> {
        crate::bloom::estimate_or(&self.seed_filters)
    }

    /// True when the report already proves a live swarm: an aware estimate
    /// above `threshold`. Only a live report may skip the second family
    /// (win 3); anything else needs the full traversal, and death always
    /// needs both families attempted (see the scrape worker).
    pub fn is_live(&self, threshold: u64) -> bool {
        self.seeders_est().is_some_and(|est| est > threshold)
    }

    /// Merges one per-socket traversal outcome, counting the family as
    /// attempted and deduplicating peers across families.
    fn merge_outcome(&mut self, outcome: lookup::ScrapeOutcome) {
        self.families_attempted = self.families_attempted.saturating_add(1);
        let mut seen: HashSet<SocketAddr> = self.peers.iter().copied().collect();
        for peer in outcome.peers {
            if seen.insert(peer) {
                self.peers.push(peer);
            }
        }
        self.seed_filters.extend(outcome.seed_filters);
        self.peer_filters.extend(outcome.peer_filters);
        self.aware = self.aware.saturating_add(outcome.aware);
        self.unaware = self.unaware.saturating_add(outcome.unaware);
    }
}

/// A running DHT node. Cheap to clone; the node stops when
/// [`shutdown`](Dht::shutdown) is called or the last handle is dropped.
#[derive(Clone)]
pub struct Dht {
    inner: Arc<Inner>,
    _stop_on_drop: Arc<DropGuard>,
}

impl std::fmt::Debug for Dht {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dht")
            .field("local_addrs", &self.local_addrs())
            .finish_non_exhaustive()
    }
}

impl Dht {
    /// Binds the sockets and starts the node. Discoveries are sent to `sink`
    /// with `try_send`: when it is full they are dropped and counted.
    pub async fn start(cfg: DhtConfig, sink: mpsc::Sender<Discovered>) -> Result<Dht, Error> {
        let inner = Arc::new(Inner::new(cfg, sink).await?);
        inner.spawn_tasks();
        let guard = Arc::new(inner.cancel.clone().drop_guard());
        Ok(Dht {
            inner,
            _stop_on_drop: guard,
        })
    }

    /// Looks up peers for `key` on every address family (iterative
    /// `get_peers`). Returns the distinct dialable peers found before
    /// `timeout`; IPv4-mapped peers are returned as IPv4. Callers still
    /// reject our own addresses ([`own_addrs`](Dht::own_addrs)).
    pub async fn get_peers(&self, key: DhtKey, timeout: Duration) -> Vec<SocketAddr> {
        let deadline = after(Instant::now(), timeout);
        let lookups = self
            .inner
            .sockets
            .iter()
            .map(|sock| lookup::get_peers(&self.inner, sock, key, deadline));
        let mut seen = HashSet::new();
        join_all(lookups)
            .await
            .into_iter()
            .flat_map(|outcome| outcome.peers)
            .filter(|peer| seen.insert(*peer))
            .collect()
    }

    /// Announces that we are a peer for `key` on `port` (TCP), on every
    /// address family. Returns the number of nodes that accepted it.
    pub async fn announce(&self, key: DhtKey, port: u16) -> usize {
        if port == 0 {
            return 0;
        }
        let deadline = after(Instant::now(), self.inner.cfg.tuning.lookup_timeout);
        let announces = self
            .inner
            .sockets
            .iter()
            .map(|sock| lookup::announce(&self.inner, sock, key, port, deadline));
        join_all(announces)
            .await
            .into_iter()
            .fold(0, usize::saturating_add)
    }

    /// BEP 33 scrape for `key` on every address family: iterative
    /// `get_peers` traversals with `scrape=1` on the dedicated scrape
    /// budget. Filters from all aware responses (both families) are kept
    /// for OR-union by the caller; see [`ScrapeReport::seeders_est`].
    ///
    /// The sibling of [`get_peers`](Dht::get_peers): `get_peers` keeps its
    /// signature so existing callers are untouched.
    pub async fn scrape(&self, key: DhtKey, timeout: Duration) -> ScrapeReport {
        let deadline = after(Instant::now(), timeout);
        let lookups = self
            .inner
            .sockets
            .iter()
            .map(|sock| lookup::scrape(&self.inner, sock, key, deadline));
        let mut report = ScrapeReport::default();
        for outcome in join_all(lookups).await {
            report.merge_outcome(outcome);
        }
        report
    }

    /// Fetch traversal for `key` on every address family:
    /// like [`scrape`](Dht::scrape) — iterative `get_peers` with `scrape=1`
    /// and the same filter union — but on the dedicated fetch budget instead
    /// of the scrape budget. The scrape role keeps `scrape` (now
    /// uncontended); the fetch role uses this.
    pub async fn scrape_fetch(&self, key: DhtKey, timeout: Duration) -> ScrapeReport {
        let deadline = after(Instant::now(), timeout);
        let lookups = self
            .inner
            .sockets
            .iter()
            .map(|sock| lookup::scrape_fetch(&self.inner, sock, key, deadline));
        let mut report = ScrapeReport::default();
        for outcome in join_all(lookups).await {
            report.merge_outcome(outcome);
        }
        report
    }
    /// BEP 33 scrape trying IPv4 first (win 3, bep33.md §12): runs the v4
    /// pass and skips the v6 pass only when v4 already proves live
    /// ([`ScrapeReport::is_live`]). Death always requires both families
    /// actually attempted in this round — a v4-only zero classifies as
    /// unknown, never dead, so v6-live swarms are never killed by the
    /// shortcut. Both passes share one overall `timeout` deadline; a pass
    /// that cannot start before the deadline is skipped and not counted
    /// (also unknown, never dead).
    pub async fn scrape_v4_first(
        &self,
        key: DhtKey,
        timeout: Duration,
        threshold: u64,
    ) -> ScrapeReport {
        let deadline = after(Instant::now(), timeout);
        let mut report = ScrapeReport::default();
        for sock in self.inner.sockets.iter().filter(|s| s.family == Family::V4) {
            if Instant::now() >= deadline || self.inner.cancel.is_cancelled() {
                break;
            }
            report.merge_outcome(lookup::scrape(&self.inner, sock, key, deadline).await);
        }
        if report.is_live(threshold) {
            return report;
        }
        for sock in self.inner.sockets.iter().filter(|s| s.family == Family::V6) {
            if Instant::now() >= deadline || self.inner.cancel.is_cancelled() {
                break;
            }
            report.merge_outcome(lookup::scrape(&self.inner, sock, key, deadline).await);
        }
        report
    }

    /// Current counters and sizes.
    pub fn stats(&self) -> DhtStatsSnapshot {
        self.inner.stats()
    }

    /// The bound socket addresses (with the actual ports).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.inner.sockets.iter().map(|s| s.local_addr).collect()
    }

    /// Our own IPs: the bound addresses that are not unspecified, plus the
    /// external IPs chosen by vote (or saved in the state file). The
    /// crawler rejects these as peers.
    pub fn own_addrs(&self) -> Vec<IpAddr> {
        self.inner.own().ips.clone()
    }

    /// Good routing-table nodes, summed over the address families. The
    /// crawl role is ready at [`MIN_GOOD_NODES`] or more.
    pub fn good_nodes(&self) -> usize {
        self.inner.good_nodes()
    }

    /// The current node ID of each socket, in the order of [`local_addrs`](Dht::local_addrs).
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.inner.own_ids()
    }

    /// Endpoints currently in the routing tables (diagnostics; memory only).
    pub fn routing_nodes(&self) -> Vec<SocketAddr> {
        self.inner
            .sockets
            .iter()
            .flat_map(|s| {
                lock(&s.state)
                    .table
                    .members()
                    .map(|e| e.addr)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Stops all tasks, waits for them and writes the state file. Other
    /// clones of this handle stop working too.
    pub async fn shutdown(self) {
        self.inner.shutdown().await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod scrape_tests {
    use super::*;
    use crate::bloom::{BLOOM_LEN, ScrapeBloom};
    use std::net::IpAddr;

    fn filter_with(ips: &[&str]) -> [u8; BLOOM_LEN] {
        let mut f = ScrapeBloom::empty();
        for ip in ips {
            f.insert_ip(&ip.parse::<IpAddr>().unwrap());
        }
        f.0
    }

    fn outcome(peers: Vec<SocketAddr>, seeds: &[&str], aware: usize) -> lookup::ScrapeOutcome {
        lookup::ScrapeOutcome {
            peers,
            seed_filters: if aware > 0 {
                vec![filter_with(seeds)]
            } else {
                Vec::new()
            },
            peer_filters: if aware > 0 {
                vec![[0u8; BLOOM_LEN]]
            } else {
                Vec::new()
            },
            aware,
            unaware: 1,
        }
    }

    #[test]
    fn merge_counts_families_and_dedups_peers() {
        let mut report = ScrapeReport::default();
        let shared: SocketAddr = "9.9.9.9:6881".parse().unwrap();
        let v4only: SocketAddr = "8.8.8.8:6881".parse().unwrap();
        report.merge_outcome(outcome(vec![shared, v4only], &["1.1.1.1"], 1));
        report.merge_outcome(outcome(vec![shared], &["2.2.2.2"], 1));
        assert_eq!(report.families_attempted, 2);
        assert_eq!(report.peers, vec![shared, v4only]);
        assert_eq!(report.aware, 2);
        assert_eq!(report.unaware, 2);
        assert_eq!(report.seed_filters.len(), 2);
        // The union of two distinct one-seed filters estimates to 2.
        assert_eq!(report.seeders_est(), Some(2));
    }

    #[test]
    fn is_live_needs_an_aware_estimate_above_threshold() {
        // Unaware-only: never live, so v4-first falls through to v6.
        let mut report = ScrapeReport::default();
        report.merge_outcome(outcome(Vec::new(), &[], 0));
        assert!(!report.is_live(0));
        // Aware zero at threshold 0: dead, not live — v6 still runs.
        let mut report = ScrapeReport::default();
        report.merge_outcome(outcome(Vec::new(), &[], 1));
        assert_eq!(report.seeders_est(), Some(0));
        assert!(!report.is_live(0));
        // Aware nonzero above the threshold: live, v6 is skipped.
        let mut report = ScrapeReport::default();
        report.merge_outcome(outcome(Vec::new(), &["1.1.1.1"], 1));
        assert_eq!(report.seeders_est(), Some(1));
        assert!(report.is_live(0));
        assert!(!report.is_live(1), "equal-to-threshold is dead, not live");
    }
}
