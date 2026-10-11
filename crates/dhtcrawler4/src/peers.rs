//! The crawler's view of the DHT node, and the address chokepoint for peers
//! (design §7, "Address chokepoint"; §13).
//!
//! Every peer the crawler would dial, from an announce (the hint map) or a
//! `get_peers` lookup, passes [`PeerFilter::accept`]: it must pass
//! [`dc4_dht::is_dialable`] and must not be one of our own addresses.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use dc4_core::DhtKey;
use dc4_dht::ScrapeReport;
use dc4_dht::compact::canonical_addr;

/// Lookup latency in seconds, labeled by traversal kind (`fetch` for the
/// fetch role, `scrape` for the scrape role; item 6). The gate
/// is fetch p99 down after the budget split.
pub const METRIC_LOOKUP_DURATION: &str = "dc4_lookup_duration_seconds";

/// What the crawler needs from a DHT node. Implemented by [`dc4_dht::Dht`];
/// tests may substitute their own.
pub trait PeerSource: Clone + Send + Sync + 'static {
    /// Peers for `key`, found within `timeout`.
    fn get_peers(
        &self,
        key: DhtKey,
        timeout: Duration,
    ) -> impl Future<Output = Vec<SocketAddr>> + Send;
    /// Peers for `key` plus the BEP 33 scrape filters the traversal saw
    /// (§8 piggyback: the traversal is already paid for by the fetch, so
    /// the filters are free liveness data for the queue's ordering).
    fn scrape_peers(
        &self,
        key: DhtKey,
        timeout: Duration,
    ) -> impl Future<Output = ScrapeReport> + Send;
    /// Our own IP addresses (bound and externally voted).
    fn own_ips(&self) -> Vec<IpAddr>;
    /// Our own bound socket addresses.
    fn own_endpoints(&self) -> Vec<SocketAddr>;
    /// Records a sighting of life for sampler live-probing:
    /// the sampler spends `sampler_live_share` of picks querying these
    /// addrs directly. Default is a no-op so test doubles are unaffected.
    fn note_live_addr(&self, _addr: SocketAddr) {}
}

impl PeerSource for dc4_dht::Dht {
    fn get_peers(
        &self,
        key: DhtKey,
        timeout: Duration,
    ) -> impl Future<Output = Vec<SocketAddr>> + Send {
        dc4_dht::Dht::get_peers(self, key, timeout)
    }

    fn scrape_peers(
        &self,
        key: DhtKey,
        timeout: Duration,
    ) -> impl Future<Output = ScrapeReport> + Send {
        async move {
            let start = std::time::Instant::now();
            let report = dc4_dht::Dht::scrape_fetch(self, key, timeout).await;
            metrics::histogram!(METRIC_LOOKUP_DURATION, "kind" => "fetch")
                .record(start.elapsed());
            report
        }
    }

    fn own_ips(&self) -> Vec<IpAddr> {
        self.own_addrs()
    }

    fn own_endpoints(&self) -> Vec<SocketAddr> {
        self.local_addrs()
    }

    fn note_live_addr(&self, addr: SocketAddr) {
        dc4_dht::Dht::note_live_addr(self, addr);
    }
}

/// A snapshot of our own addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnAddrs {
    ips: Vec<IpAddr>,
    endpoints: Vec<SocketAddr>,
}

impl OwnAddrs {
    /// Takes a snapshot from `source`.
    pub fn of<P: PeerSource>(source: &P) -> Self {
        Self::new(source.own_ips(), source.own_endpoints())
    }

    /// A snapshot of the given addresses (canonicalised).
    pub fn new(ips: Vec<IpAddr>, endpoints: Vec<SocketAddr>) -> Self {
        Self {
            ips: ips
                .into_iter()
                .map(dc4_dht::compact::canonical_ip)
                .collect(),
            endpoints: endpoints.into_iter().map(canonical_addr).collect(),
        }
    }
}

/// The address chokepoint for peers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerFilter {
    /// Accept private and loopback addresses. Tests only.
    pub allow_private: bool,
    /// Treat only our exact endpoints as ours, instead of any port on our
    /// IPs, so that tests can run many nodes and peers on 127.0.0.1. Tests
    /// only; mirrors `DhtTuning::limits_by_endpoint`.
    pub by_endpoint: bool,
}

impl PeerFilter {
    /// The production filter.
    pub const PRODUCTION: PeerFilter = PeerFilter {
        allow_private: false,
        by_endpoint: false,
    };

    /// `peer` in canonical form if the crawler may dial it.
    pub fn accept(&self, peer: SocketAddr, own: &OwnAddrs) -> Option<SocketAddr> {
        let peer = canonical_addr(peer);
        if !dc4_dht::is_dialable(peer, self.allow_private) {
            return None;
        }
        let ours = if self.by_endpoint {
            own.endpoints.contains(&peer)
        } else {
            own.ips.contains(&peer.ip())
        };
        (!ours).then_some(peer)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn production_filter() {
        let own = OwnAddrs::new(vec!["203.0.113.9".parse().unwrap()], vec![]);
        let f = PeerFilter::PRODUCTION;
        assert_eq!(f.accept(sa("8.8.8.8:6881"), &own), Some(sa("8.8.8.8:6881")));
        // IPv4-mapped addresses are canonicalised first.
        assert_eq!(
            f.accept(sa("[::ffff:8.8.8.8]:6881"), &own),
            Some(sa("8.8.8.8:6881"))
        );
        for bad in [
            "127.0.0.1:6881",
            "10.1.2.3:6881",
            "192.168.1.1:6881",
            "8.8.8.8:0",
            "0.0.0.0:6881",
            "[::1]:6881",
            "[fe80::1]:6881",
            "[::ffff:10.0.0.1]:6881",
        ] {
            assert_eq!(f.accept(sa(bad), &own), None, "{bad}");
        }
        // Our own (public) IP is refused on any port.
        let own = OwnAddrs::new(vec!["8.8.4.4".parse().unwrap()], vec![]);
        assert_eq!(f.accept(sa("8.8.4.4:51413"), &own), None);
        assert!(f.accept(sa("8.8.8.8:51413"), &own).is_some());
    }

    #[test]
    fn test_filter_keys_on_endpoints() {
        let f = PeerFilter {
            allow_private: true,
            by_endpoint: true,
        };
        let own = OwnAddrs::new(
            vec!["127.0.0.1".parse().unwrap()],
            vec![sa("127.0.0.1:40000")],
        );
        assert_eq!(f.accept(sa("127.0.0.1:40000"), &own), None);
        assert_eq!(
            f.accept(sa("127.0.0.1:40001"), &own),
            Some(sa("127.0.0.1:40001"))
        );
        assert_eq!(f.accept(sa("0.0.0.0:40001"), &own), None);
        assert_eq!(f.accept(sa("127.0.0.1:0"), &own), None);
    }
}
