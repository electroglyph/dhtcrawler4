//! Counters for metrics (`docs/04-operations.md` §6).

use std::sync::atomic::{AtomicU64, Ordering};

use crate::compact::Family;
use crate::krpc::Method;

/// Per-method query counts (`dc4_dht_queries_received_total{method}`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryCounts {
    pub ping: u64,
    pub find_node: u64,
    pub get_peers: u64,
    pub announce_peer: u64,
    pub sample_infohashes: u64,
    /// Unknown methods (answered like `find_node` or with error 204) and
    /// queries too malformed to name a method.
    pub other: u64,
}

impl QueryCounts {
    /// `(method label, count)` pairs, in a fixed order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> {
        [
            ("ping", self.ping),
            ("find_node", self.find_node),
            ("get_peers", self.get_peers),
            ("announce_peer", self.announce_peer),
            ("sample_infohashes", self.sample_infohashes),
            ("other", self.other),
        ]
        .into_iter()
    }

    /// The sum over all methods.
    pub fn total(&self) -> u64 {
        self.iter().fold(0, |sum, (_, n)| sum.saturating_add(n))
    }
}

/// Why a datagram was dropped (`dc4_dht_packets_dropped_total{reason}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// Inbound: over the per-IP rate limit.
    RateLimited,
    /// Inbound: it filled the 2 048-byte receive buffer.
    Oversized,
    /// Inbound: not usable KRPC.
    Malformed,
    /// Inbound: a query beyond the responder budget, dropped unanswered.
    ResponderBudget,
    /// Inbound: a reply that matches no outstanding query (late or forged).
    Unsolicited,
    /// Inbound: from an address that fails the address chokepoint.
    Filtered,
    /// Outbound: a query not sent because the per-IP spacing did not
    /// allow it in time (split from the old single
    /// `throttled` label so budget pressure is answerable from metrics).
    ThrottledSpacing,
    /// Outbound: a query not sent because the main send budget did not
    /// allow it in time.
    ThrottledBudgetMain,
    /// Outbound: a query not sent because the scrape budget did not allow
    /// it in time.
    ThrottledBudgetScrape,
    /// Outbound: a query not sent because the fetch budget did not allow
    /// it in time.
    ThrottledBudgetFetch,
    /// Outbound: a query not sent because the transaction table was full
    /// (reports `QueryError::Busy`).
    ThrottledTxnFull,
    /// Outbound: the datagram could not be encoded or the socket refused it.
    SendError,
}

impl DropReason {
    /// Every reason, in a fixed order.
    pub const ALL: [DropReason; 12] = [
        DropReason::RateLimited,
        DropReason::Oversized,
        DropReason::Malformed,
        DropReason::ResponderBudget,
        DropReason::Unsolicited,
        DropReason::Filtered,
        DropReason::ThrottledSpacing,
        DropReason::ThrottledBudgetMain,
        DropReason::ThrottledBudgetScrape,
        DropReason::ThrottledBudgetFetch,
        DropReason::ThrottledTxnFull,
        DropReason::SendError,
    ];

    /// The metric label, e.g. `"rate_limited"`.
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::RateLimited => "rate_limited",
            DropReason::Oversized => "oversized",
            DropReason::Malformed => "malformed",
            DropReason::ResponderBudget => "responder_budget",
            DropReason::Unsolicited => "unsolicited",
            DropReason::Filtered => "filtered",
            DropReason::ThrottledSpacing => "throttled_spacing",
            DropReason::ThrottledBudgetMain => "throttled_budget_main",
            DropReason::ThrottledBudgetScrape => "throttled_budget_scrape",
            DropReason::ThrottledBudgetFetch => "throttled_budget_fetch",
            DropReason::ThrottledTxnFull => "throttled_txn_full",
            DropReason::SendError => "send_error",
        }
    }
}

/// Dropped datagrams by reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DropCounts {
    pub rate_limited: u64,
    pub oversized: u64,
    pub malformed: u64,
    pub responder_budget: u64,
    pub unsolicited: u64,
    pub filtered: u64,
    pub throttled_spacing: u64,
    pub throttled_budget_main: u64,
    pub throttled_budget_scrape: u64,
    pub throttled_budget_fetch: u64,
    pub throttled_txn_full: u64,
    pub send_error: u64,
}

impl DropCounts {
    /// The count for one reason.
    pub fn get(&self, reason: DropReason) -> u64 {
        match reason {
            DropReason::RateLimited => self.rate_limited,
            DropReason::Oversized => self.oversized,
            DropReason::Malformed => self.malformed,
            DropReason::ResponderBudget => self.responder_budget,
            DropReason::Unsolicited => self.unsolicited,
            DropReason::Filtered => self.filtered,
            DropReason::ThrottledSpacing => self.throttled_spacing,
            DropReason::ThrottledBudgetMain => self.throttled_budget_main,
            DropReason::ThrottledBudgetScrape => self.throttled_budget_scrape,
            DropReason::ThrottledBudgetFetch => self.throttled_budget_fetch,
            DropReason::ThrottledTxnFull => self.throttled_txn_full,
            DropReason::SendError => self.send_error,
        }
    }

    /// `(reason, count)` pairs in the order of [`DropReason::ALL`].
    pub fn iter(&self) -> impl Iterator<Item = (DropReason, u64)> {
        DropReason::ALL.map(|r| (r, self.get(r))).into_iter()
    }

    /// The sum over all reasons.
    pub fn total(&self) -> u64 {
        self.iter().fold(0, |sum, (_, n)| sum.saturating_add(n))
    }
}

/// Counters and sizes of one address family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FamilyStats {
    /// Whether a socket of this family is bound.
    pub enabled: bool,
    /// Datagrams received (`dc4_dht_packets_in_total`).
    pub packets_in: u64,
    /// Datagrams sent (`dc4_dht_packets_out_total`).
    pub packets_out: u64,
    /// Datagrams dropped, by reason (`dc4_dht_packets_dropped_total`).
    pub dropped: DropCounts,
    /// Keys received in BEP 51 samples (`dc4_dht_samples_total`).
    pub samples: u64,
    /// Routing-table members (`dc4_dht_routing_nodes`).
    pub routing_nodes: usize,
    /// Routing-table members in good state.
    pub good_nodes: usize,
    /// Queries waiting for a reply.
    pub pending_queries: usize,
    /// Nodes waiting in the sampler frontier.
    pub sampler_frontier: usize,
    /// Entries in the sampler's visited map.
    pub sampler_visited: usize,
    /// Receive-loop errors (`dc4_dht_recv_errors_total`).
    pub recv_errors: u64,
}

/// A snapshot of the node's counters and sizes. Counters only grow.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DhtStatsSnapshot {
    pub v4: FamilyStats,
    pub v6: FamilyStats,
    /// Queries received, including those dropped by the responder budget.
    pub queries_received: QueryCounts,
    /// Queries handed to the socket.
    pub queries_sent: QueryCounts,
    /// Matched responses to our queries.
    pub responses_received: u64,
    /// Matched KRPC errors (and malformed replies) to our queries.
    pub errors_received: u64,
    /// Queries that got no reply in time (`dc4_dht_timeouts_total`).
    pub timeouts: u64,
    /// KRPC errors we sent.
    pub errors_sent: u64,
    /// `Discovered` events delivered to the sink.
    pub discovered_emitted: u64,
    /// `Discovered` events dropped because the sink was full or closed.
    pub discovered_dropped: u64,
    /// Node-ID changes after an external-IP vote.
    pub node_id_changes: u64,
    /// `sample_infohashes` queries stopped because the node's next sample
    /// time had not come (`dc4_dht_sampler_early_total`). Must stay 0.
    pub sampler_early: u64,
    /// Nodes not sampled because the visited map was full of unexpired
    /// entries (`dc4_dht_sampler_visited_full_total`).
    pub sampler_visited_full: u64,
    /// Sampler picks that found nothing to sample
    /// (`dc4_dht_sampler_pick_empty_total`).
    pub sampler_pick_empty: u64,
    /// Live sampler addresses evicted after consecutive failures
    /// (`dc4_dht_sampler_live_evicted_total`).
    pub sampler_live_evicted: u64,
    /// Queries dropped unanswered by the responder budget, both families
    /// (`dc4_dht_responder_dropped_total`).
    pub responder_dropped: u64,
    /// Keys held in the announce store.
    pub peer_store_keys: usize,
}

impl DhtStatsSnapshot {
    /// The counters of one family.
    pub fn family(&self, family: Family) -> &FamilyStats {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }

    pub(crate) fn family_mut(&mut self, family: Family) -> &mut FamilyStats {
        match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        }
    }

    fn sum(&self, f: impl Fn(&FamilyStats) -> u64) -> u64 {
        f(&self.v4).saturating_add(f(&self.v6))
    }

    /// Datagrams received, both families.
    pub fn packets_in(&self) -> u64 {
        self.sum(|s| s.packets_in)
    }

    /// Datagrams sent, both families.
    pub fn packets_out(&self) -> u64 {
        self.sum(|s| s.packets_out)
    }

    /// Datagrams dropped for any reason, both families.
    pub fn packets_dropped(&self) -> u64 {
        self.sum(|s| s.dropped.total())
    }

    /// Keys received in BEP 51 samples, both families.
    pub fn samples(&self) -> u64 {
        self.sum(|s| s.samples)
    }

    /// Routing-table members, both families.
    pub fn routing_nodes(&self) -> usize {
        self.v4.routing_nodes.saturating_add(self.v6.routing_nodes)
    }

    /// Good routing-table members, both families.
    pub fn good_nodes(&self) -> usize {
        self.v4.good_nodes.saturating_add(self.v6.good_nodes)
    }
}

#[derive(Default)]
pub(crate) struct MethodCounters {
    ping: AtomicU64,
    find_node: AtomicU64,
    get_peers: AtomicU64,
    announce_peer: AtomicU64,
    sample_infohashes: AtomicU64,
    other: AtomicU64,
}

impl MethodCounters {
    pub(crate) fn count(&self, method: &Method) {
        let counter = match method {
            Method::Ping => &self.ping,
            Method::FindNode { .. } => &self.find_node,
            Method::GetPeers { .. } => &self.get_peers,
            Method::AnnouncePeer { .. } => &self.announce_peer,
            Method::SampleInfohashes { .. } => &self.sample_infohashes,
            Method::Other { .. } => &self.other,
        };
        incr(counter);
    }

    pub(crate) fn count_other(&self) {
        incr(&self.other);
    }

    fn snapshot(&self) -> QueryCounts {
        QueryCounts {
            ping: get(&self.ping),
            find_node: get(&self.find_node),
            get_peers: get(&self.get_peers),
            announce_peer: get(&self.announce_peer),
            sample_infohashes: get(&self.sample_infohashes),
            other: get(&self.other),
        }
    }
}

#[derive(Default)]
struct DropCounters {
    rate_limited: AtomicU64,
    oversized: AtomicU64,
    malformed: AtomicU64,
    responder_budget: AtomicU64,
    unsolicited: AtomicU64,
    filtered: AtomicU64,
    throttled_spacing: AtomicU64,
    throttled_budget_main: AtomicU64,
    throttled_budget_scrape: AtomicU64,
    throttled_budget_fetch: AtomicU64,
    throttled_txn_full: AtomicU64,
    send_error: AtomicU64,
}

impl DropCounters {
    fn counter(&self, reason: DropReason) -> &AtomicU64 {
        match reason {
            DropReason::RateLimited => &self.rate_limited,
            DropReason::Oversized => &self.oversized,
            DropReason::Malformed => &self.malformed,
            DropReason::ResponderBudget => &self.responder_budget,
            DropReason::Unsolicited => &self.unsolicited,
            DropReason::Filtered => &self.filtered,
            DropReason::ThrottledSpacing => &self.throttled_spacing,
            DropReason::ThrottledBudgetMain => &self.throttled_budget_main,
            DropReason::ThrottledBudgetScrape => &self.throttled_budget_scrape,
            DropReason::ThrottledBudgetFetch => &self.throttled_budget_fetch,
            DropReason::ThrottledTxnFull => &self.throttled_txn_full,
            DropReason::SendError => &self.send_error,
        }
    }

    fn snapshot(&self) -> DropCounts {
        let g = |r| get(self.counter(r));
        DropCounts {
            rate_limited: g(DropReason::RateLimited),
            oversized: g(DropReason::Oversized),
            malformed: g(DropReason::Malformed),
            responder_budget: g(DropReason::ResponderBudget),
            unsolicited: g(DropReason::Unsolicited),
            filtered: g(DropReason::Filtered),
            throttled_spacing: g(DropReason::ThrottledSpacing),
            throttled_budget_main: g(DropReason::ThrottledBudgetMain),
            throttled_budget_scrape: g(DropReason::ThrottledBudgetScrape),
            throttled_budget_fetch: g(DropReason::ThrottledBudgetFetch),
            throttled_txn_full: g(DropReason::ThrottledTxnFull),
            send_error: g(DropReason::SendError),
        }
    }
}

/// Counters of one address family.
#[derive(Default)]
pub(crate) struct FamilyCounters {
    pub(crate) packets_in: AtomicU64,
    pub(crate) packets_out: AtomicU64,
    pub(crate) samples: AtomicU64,
    pub(crate) recv_errors: AtomicU64,
    dropped: DropCounters,
}

impl FamilyCounters {
    /// Counts one dropped datagram.
    pub(crate) fn drop_packet(&self, reason: DropReason) {
        incr(self.dropped.counter(reason));
    }

    fn snapshot(&self) -> FamilyStats {
        FamilyStats {
            packets_in: get(&self.packets_in),
            packets_out: get(&self.packets_out),
            dropped: self.dropped.snapshot(),
            samples: get(&self.samples),
            recv_errors: get(&self.recv_errors),
            ..FamilyStats::default()
        }
    }
}

/// Lock-free counters shared by all tasks.
#[derive(Default)]
pub(crate) struct Counters {
    v4: FamilyCounters,
    v6: FamilyCounters,
    pub(crate) queries_received: MethodCounters,
    pub(crate) queries_sent: MethodCounters,
    pub(crate) responses_received: AtomicU64,
    pub(crate) errors_received: AtomicU64,
    pub(crate) timeouts: AtomicU64,
    pub(crate) errors_sent: AtomicU64,
    pub(crate) discovered_emitted: AtomicU64,
    pub(crate) discovered_dropped: AtomicU64,
    pub(crate) node_id_changes: AtomicU64,
    pub(crate) sampler_early: AtomicU64,
    pub(crate) sampler_visited_full: AtomicU64,
    pub(crate) sampler_pick_empty: AtomicU64,
    pub(crate) sampler_live_evicted: AtomicU64,
}

/// Adds one (wrapping, never panicking).
pub(crate) fn incr(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Adds `n` (wrapping, never panicking).
pub(crate) fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

fn get(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

impl Counters {
    /// The counters of one family.
    pub(crate) fn family(&self, family: Family) -> &FamilyCounters {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }

    /// Counter values; the caller fills in the sizes.
    pub(crate) fn snapshot(&self) -> DhtStatsSnapshot {
        let v4 = self.v4.snapshot();
        let v6 = self.v6.snapshot();
        DhtStatsSnapshot {
            responder_dropped: v4
                .dropped
                .responder_budget
                .wrapping_add(v6.dropped.responder_budget),
            v4,
            v6,
            queries_received: self.queries_received.snapshot(),
            queries_sent: self.queries_sent.snapshot(),
            responses_received: get(&self.responses_received),
            errors_received: get(&self.errors_received),
            timeouts: get(&self.timeouts),
            errors_sent: get(&self.errors_sent),
            discovered_emitted: get(&self.discovered_emitted),
            discovered_dropped: get(&self.discovered_dropped),
            node_id_changes: get(&self.node_id_changes),
            sampler_early: get(&self.sampler_early),
            sampler_visited_full: get(&self.sampler_visited_full),
            sampler_pick_empty: get(&self.sampler_pick_empty),
            sampler_live_evicted: get(&self.sampler_live_evicted),
            peer_store_keys: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_are_counted_per_family_and_reason() {
        let c = Counters::default();
        assert_eq!(c.snapshot().sampler_pick_empty, 0);
        assert_eq!(c.snapshot().v4.recv_errors, 0);
        incr(&c.sampler_pick_empty);
        incr(&c.sampler_pick_empty);
        incr(&c.family(Family::V4).recv_errors);
        c.family(Family::V4).drop_packet(DropReason::RateLimited);
        c.family(Family::V4)
            .drop_packet(DropReason::ResponderBudget);
        c.family(Family::V6)
            .drop_packet(DropReason::ResponderBudget);
        c.family(Family::V6).drop_packet(DropReason::SendError);
        incr(&c.family(Family::V6).packets_in);
        add(&c.family(Family::V4).samples, 20);
        let s = c.snapshot();
        assert_eq!(s.v4.dropped.rate_limited, 1);
        assert_eq!(s.v4.dropped.total(), 2);
        assert_eq!(s.v6.dropped.get(DropReason::SendError), 1);
        assert_eq!(s.responder_dropped, 2);
        assert_eq!(s.packets_dropped(), 4);
        assert_eq!(s.family(Family::V6).packets_in, 1);
        assert_eq!(s.packets_in(), 1);
        assert_eq!(s.samples(), 20);
        assert_eq!(s.sampler_pick_empty, 2);
        assert_eq!(s.v4.recv_errors, 1);
        assert_eq!(s.v6.recv_errors, 0);
        let labels: Vec<_> = s.v4.dropped.iter().map(|(r, n)| (r.as_str(), n)).collect();
        assert_eq!(labels[0], ("rate_limited", 1));
        assert_eq!(labels[3], ("responder_budget", 1));
        assert_eq!(labels.len(), DropReason::ALL.len());
    }

    #[test]
    fn throttled_split_labels_are_distinct_per_site() {
        // WS1: the old single `throttled` label is split per drop site so
        // dashboards can tell spacing/budget-main/budget-scrape/
        // budget-fetch/txn-full apart.
        assert_eq!(DropReason::ThrottledSpacing.as_str(), "throttled_spacing");
        assert_eq!(
            DropReason::ThrottledBudgetMain.as_str(),
            "throttled_budget_main"
        );
        assert_eq!(
            DropReason::ThrottledBudgetScrape.as_str(),
            "throttled_budget_scrape"
        );
        assert_eq!(
            DropReason::ThrottledBudgetFetch.as_str(),
            "throttled_budget_fetch"
        );
        assert_eq!(DropReason::ThrottledTxnFull.as_str(), "throttled_txn_full");
        let c = Counters::default();
        c.family(Family::V4)
            .drop_packet(DropReason::ThrottledBudgetFetch);
        c.family(Family::V4)
            .drop_packet(DropReason::ThrottledBudgetScrape);
        c.family(Family::V4).drop_packet(DropReason::ThrottledBudgetMain);
        let s = c.snapshot();
        assert_eq!(s.v4.dropped.throttled_budget_fetch, 1);
        assert_eq!(s.v4.dropped.throttled_budget_scrape, 1);
        assert_eq!(s.v4.dropped.throttled_budget_main, 1);
        assert_eq!(s.v4.dropped.throttled_spacing, 0);
        assert_eq!(s.v4.dropped.throttled_txn_full, 0);
    }

    #[test]
    fn method_labels() {        let c = MethodCounters::default();
        c.count(&Method::Ping);
        c.count(&Method::GetPeers {
            info_hash: dc4_core::DhtKey([0; 20]),
            scrape: false,
        });
        c.count_other();
        let q = c.snapshot();
        let labels: Vec<_> = q.iter().collect();
        assert_eq!(labels[0], ("ping", 1));
        assert_eq!(labels[2], ("get_peers", 1));
        assert_eq!(labels[5], ("other", 1));
        assert_eq!(q.total(), 3);
    }
}
