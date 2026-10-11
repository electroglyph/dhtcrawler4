//! Node configuration.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::Error;
use crate::krpc::MAX_DATAGRAM_OUT;

/// Default DHT port.
pub const DEFAULT_PORT: u16 = 6881;
/// Default global send budget in packets per second (design §3): politeness
/// toward any single node comes from the 1 s per-address spacing, not this
/// aggregate (~6 MB/s total at full reply rate: ~1.2 out + ~4.8 in at
/// typical response sizes).
pub const DEFAULT_MAX_PACKETS_PER_SEC: u32 = 12_000;
/// Default number of concurrent `sample_infohashes` queries.
pub const DEFAULT_SAMPLER_CONCURRENCY: usize = 1024;
/// Default client version sent in `v`: "DC" plus version 0.1.
pub const DEFAULT_CLIENT_VERSION: [u8; 4] = *b"DC\x00\x01";
/// Default bootstrap routers (checked live on 2026-09-16; see `docs/00-horismos.md`).
pub const DEFAULT_BOOTSTRAP: [&str; 4] = [
    "dht.libtorrent.org:25401",
    "dht.transmissionbt.com:6881",
    "router.bt.ouinet.work:6881",
    "router.bittorrent.com:6881",
];
/// Default BEP 33 scrape budget in packets per second, kept much smaller
/// than the crawl bucket so scrapes never starve discovery.
pub const DEFAULT_SCRAPE_PACKETS_PER_SEC: u32 = 100;
/// Upper bound on `identities`: 8 matches the 8-way split in the
/// multi-replica runbook.
pub const MAX_IDENTITIES: u32 = 8;
/// Default dedicated fetch budget in packets per second:
/// fetch traversals are multi-packet lookups running at ~2,000+/s measured,
/// so 6,000 gives ~3x headroom — fetch alone can never be the binding
/// constraint while staying near the historic total egress envelope
/// (6k main + 6k fetch + 100 scrape ≈ old 12k default).
pub const DEFAULT_FETCH_PACKETS_PER_SEC: u32 = 6_000;
/// Upper bound on `sampler_concurrency`.
pub const MAX_SAMPLER_CONCURRENCY: usize = 1024;
/// Default responder budget in replies per second (design §3).
pub const DEFAULT_RESPONDER_REPLIES_PER_SEC: u32 = 1500;
/// Default responder budget in reply bytes per second (design §3).
pub const DEFAULT_RESPONDER_BYTES_PER_SEC: u32 = 192_000;

/// Configuration of a [`Dht`](crate::Dht) node.
#[derive(Clone, Debug)]
pub struct DhtConfig {
    /// IPv4 socket address; `None` disables IPv4. A bind failure is an error.
    pub bind_v4: Option<SocketAddr>,
    /// IPv6 socket address (bound with `IPV6_V6ONLY`); `None` disables IPv6.
    /// With an unspecified address (`[::]`) the socket is skipped, with a
    /// warning, when the host has no global IPv6 address. A bind failure is
    /// only a warning, unless no socket is left.
    pub bind_v6: Option<SocketAddr>,
    /// Bootstrap routers as "host:port". Every A/AAAA record is used and
    /// resolution failures are tolerated. Routers are never added to the
    /// routing table.
    pub bootstrap: Vec<String>,
    /// Where node IDs, external IPs and up to 300 contacts per family are
    /// kept between runs (JSON, written atomically). `None` keeps nothing.
    pub state_file: Option<PathBuf>,
    /// Global budget for outgoing queries per second.
    pub max_packets_per_sec: u32,
    /// Dedicated BEP 33 scrape budget in packets per second: scrape
    /// traversals charge this bucket, never the crawl bucket above.
    pub scrape_packets_per_sec: u32,
    /// Dedicated fetch budget in packets per second: fetch
    /// `get_peers` traversals charge this bucket, never the scrape bucket.
    pub fetch_packets_per_sec: u32,
    /// In-process DHT identities. Each binds its own UDP port per family
    /// (`dht_port + i`), with its own node ID and routing table. 1 is
    /// today's behavior. Ports are derived from `dht_port`, no extra knob.
    pub identities: u32,
    /// Run the BEP 51 sampler, which emits `Discovered { source: Sample }`.
    pub sampler: bool,
    /// Number of concurrent `sample_infohashes` queries.
    pub sampler_concurrency: usize,
    /// BEP 43 read-only mode: answer no queries and mark ours with `ro` = 1.
    pub read_only: bool,
    /// Accept private, loopback and other non-global addresses. Tests only:
    /// then only port 0 and unspecified addresses are rejected.
    pub allow_private_addrs: bool,
    /// Client version sent as `v` in every message.
    pub client_version: [u8; 4],
    /// Pins the BEP 42 `r` value 0-7 for multi-replica deployments, None = random.
    pub bep42_r: Option<u8>,
    /// Timers and protocol limits; the defaults are the production values.
    pub tuning: DhtTuning,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bind_v4: Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))),
            bind_v6: Some(SocketAddr::from((Ipv6Addr::UNSPECIFIED, DEFAULT_PORT))),
            bootstrap: DEFAULT_BOOTSTRAP.iter().map(|s| (*s).to_owned()).collect(),
            state_file: None,
            max_packets_per_sec: DEFAULT_MAX_PACKETS_PER_SEC,
            scrape_packets_per_sec: DEFAULT_SCRAPE_PACKETS_PER_SEC,
            fetch_packets_per_sec: DEFAULT_FETCH_PACKETS_PER_SEC,
            identities: 1,
            sampler: true,
            sampler_concurrency: DEFAULT_SAMPLER_CONCURRENCY,
            read_only: false,
            allow_private_addrs: false,
            client_version: DEFAULT_CLIENT_VERSION,
            bep42_r: None,
            tuning: DhtTuning::default(),
        }
    }
}

impl DhtConfig {
    /// Checks the configuration for values the node cannot run with.
    pub fn validate(&self) -> Result<(), Error> {
        if self.bind_v4.is_none() && self.bind_v6.is_none() {
            return Err(Error::Config(
                "at least one of bind_v4 and bind_v6 is required".into(),
            ));
        }
        if self.bind_v4.is_some_and(|a| !a.is_ipv4()) {
            return Err(Error::Config("bind_v4 must be an IPv4 address".into()));
        }
        if self.bind_v6.is_some_and(|a| !a.is_ipv6()) {
            return Err(Error::Config("bind_v6 must be an IPv6 address".into()));
        }
        if self.max_packets_per_sec == 0 {
            return Err(Error::Config(
                "max_packets_per_sec must be at least 1".into(),
            ));
        }
        if self.scrape_packets_per_sec == 0 {
            return Err(Error::Config(
                "scrape_packets_per_sec must be at least 1".into(),
            ));
        }
        if self.fetch_packets_per_sec == 0 {
            return Err(Error::Config(
                "fetch_packets_per_sec must be at least 1".into(),
            ));
        }
        if self.identities == 0 || self.identities > MAX_IDENTITIES {
            return Err(Error::Config(format!(
                "identities must be between 1 and {MAX_IDENTITIES}"
            )));
        }
        if self.sampler_concurrency == 0 || self.sampler_concurrency > MAX_SAMPLER_CONCURRENCY {
            return Err(Error::Config(format!(
                "sampler_concurrency must be between 1 and {MAX_SAMPLER_CONCURRENCY}"
            )));
        }
        if self.bep42_r.is_some_and(|r| r > 7) {
            return Err(Error::Config("bep42_r must be between 0 and 7".into()));
        }
        self.tuning.validate()
    }
}

/// Timers and limits. `Default` gives the production values; tests shorten
/// the timers so a private network converges in seconds.
//
// No `Eq`: `sampler_live_share: f64` cannot be `Eq`, and NaN
// must be rejectable — not silently unequal.
#[derive(Clone, Debug, PartialEq)]
pub struct DhtTuning {
    /// How long to wait for the reply to one query. There are no retries (BEP 5). Production: 4 s.
    pub query_timeout: Duration,
    /// How long to wait for the reply to one BEP 33 scrape query: the more
    /// lenient per-RPC direction from the BEP's 10 s guidance. Production: 10 s.
    pub scrape_query_timeout: Duration,
    /// After this long a lookup stops waiting for a query and moves on; a
    /// later reply is still used. Production: 2 s.
    pub query_slow_after: Duration,
    /// Time limit for lookups the node starts itself (bootstrap, refresh,
    /// sampler refill, announce). Production: 30 s.
    pub lookup_timeout: Duration,
    /// Longest a query may wait combined for per-address spacing and the
    /// send budget before it is dropped. Production: 4 s.
    pub max_send_wait: Duration,
    /// Minimum time between two queries to one IP. Production: 1 s.
    pub per_address_query_spacing: Duration,
    /// Inbound packets per second accepted from one host (IPv4 address or IPv6 /48). Production: 4.
    pub inbound_rate: u32,
    /// Inbound burst accepted from one host. Production: 8.
    pub inbound_burst: u32,
    /// Replies per second the responder may send, over all addresses; a
    /// query beyond it is dropped unanswered. Production: 1500.
    pub responder_replies_per_sec: u32,
    /// Reply bytes per second the responder may send, over all addresses.
    /// At least 1 024 (one full datagram). Production: 192 000.
    pub responder_bytes_per_sec: u32,
    /// Period of the maintenance task. Production: 5 s.
    pub maintenance_interval: Duration,
    /// A routing-table node idle this long is questionable (BEP 5). Production: 15 min.
    pub node_questionable_after: Duration,
    /// A bucket unchanged this long is refreshed (BEP 5). Production: 15 min.
    pub bucket_refresh_interval: Duration,
    /// Minimum time between liveness pings to one routing-table node. Production: 5 min.
    pub ping_interval: Duration,
    /// Liveness pings sent per maintenance round, at most. Production: 8.
    pub max_pings_per_round: usize,
    /// Token secret rotation period; tokens stay valid for one to two periods. Production: 5 min.
    pub token_rotation: Duration,
    /// Lifetime of an announce in the peer store. Production: 45 min.
    pub peer_ttl: Duration,
    /// How often the state file is written. Production: 5 min.
    pub state_save_interval: Duration,
    /// First bootstrap retry delay; it doubles up to `bootstrap_retry_max`. Production: 1 s.
    pub bootstrap_retry_base: Duration,
    /// Longest bootstrap retry delay. Production: 5 min.
    pub bootstrap_retry_max: Duration,
    /// Current votes an external IP needs to win; it also needs more than
    /// two-thirds of them. Each /24 (IPv4) or /48 (IPv6) has one vote. Production: 10.
    pub external_ip_votes: usize,
    /// Lifetime of an external-IP vote. Production: 30 min.
    pub external_ip_vote_ttl: Duration,
    /// Minimum time between two node-ID changes (and re-bootstraps) caused
    /// by a new external IP. Production: 1 h.
    pub id_change_min_interval: Duration,
    /// `interval` sent in `sample_infohashes` responses (BEP 51 maximum). Production: 21 600 s.
    pub sample_interval_sent: Duration,
    /// Minimum time before sampling one node again, whatever its `interval`. Production: 300 s.
    pub sample_min_resample: Duration,
    /// Skip time for a node that does not support BEP 51. Production: 6 h.
    pub sample_unsupported_skip: Duration,
    /// Skip time for a node that did not answer `sample_infohashes`. Production: 1 h.
    pub sample_timeout_skip: Duration,
    /// How long a BEP 51 sampler query waits for a reply. Shorter than
    /// `query_timeout` so slow nodes fail fast. Production: 2 s.
    pub sampler_query_timeout: Duration,
    /// Pause of a sampler worker that found nothing to sample. Production: 1 s.
    pub sampler_idle_wait: Duration,
    /// Agreeing nonzero scrape responses that end the traversal early
    /// (live-only, bep33.md §4b win 2; 0 disables). A dead verdict always
    /// needs the full both-families traversal. Production: 3.
    pub scrape_early_exit_quorum: usize,
    /// Most DHT keys whose closest-node lists are cached for reuse as the
    /// start set of repeat scrapes (bep33.md §2/§12 win 2). 0 disables the
    /// cache. Production: 4096.
    pub scrape_node_cache_keys: usize,
    /// TEST ONLY. Key the per-IP rules on IP:port instead of IP: one routing
    /// entry per IP, the /24 and /64 bucket rule, the inbound and outbound
    /// per-IP rate limits, external-IP vote diversity and the "our own
    /// address" rule. This lets many nodes share 127.0.0.1. Production: false.
    pub limits_by_endpoint: bool,
    /// Fraction of sampler picks that probe a live address directly instead
    /// of traversing the frontier. Live addresses hold stores
    /// biased toward live swarms; uniform-node samples are mostly dead.
    /// Validated manually to 0.0..=1.0 (NaN rejected). Production: 0.10.
    pub sampler_live_share: f64,
}

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);

impl Default for DhtTuning {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(4),
            scrape_query_timeout: Duration::from_secs(10),
            query_slow_after: Duration::from_secs(2),
            lookup_timeout: Duration::from_secs(30),
            max_send_wait: Duration::from_secs(4),
            per_address_query_spacing: Duration::from_secs(1),
            // 4/s with a burst of 8 keeps our replies to any one host at or
            // below 4.8 packets/s over any 10 s window, under libtorrent's ban
            // threshold of 5 packets/s averaged over 10 s.
            inbound_rate: 4,
            inbound_burst: 8,
            responder_replies_per_sec: DEFAULT_RESPONDER_REPLIES_PER_SEC,
            responder_bytes_per_sec: DEFAULT_RESPONDER_BYTES_PER_SEC,
            maintenance_interval: Duration::from_secs(5),
            node_questionable_after: MINUTE.saturating_mul(15),
            bucket_refresh_interval: MINUTE.saturating_mul(15),
            ping_interval: MINUTE.saturating_mul(5),
            max_pings_per_round: 8,
            token_rotation: MINUTE.saturating_mul(5),
            peer_ttl: MINUTE.saturating_mul(45),
            state_save_interval: MINUTE.saturating_mul(5),
            bootstrap_retry_base: Duration::from_secs(1),
            bootstrap_retry_max: MINUTE.saturating_mul(5),
            external_ip_votes: 10,
            external_ip_vote_ttl: MINUTE.saturating_mul(30),
            id_change_min_interval: HOUR,
            sample_interval_sent: Duration::from_secs(21_600),
            sample_min_resample: Duration::from_secs(300),
            sample_unsupported_skip: HOUR.saturating_mul(6),
            sample_timeout_skip: HOUR,
            sampler_query_timeout: Duration::from_secs(2),
            sampler_idle_wait: Duration::from_secs(1),
            scrape_early_exit_quorum: 3,
            scrape_node_cache_keys: 4096,
            limits_by_endpoint: false,
            sampler_live_share: 0.10,
        }
    }
}

impl DhtTuning {
    fn validate(&self) -> Result<(), Error> {
        let positive = [
            ("query_timeout", self.query_timeout),
            ("scrape_query_timeout", self.scrape_query_timeout),
            ("query_slow_after", self.query_slow_after),
            ("lookup_timeout", self.lookup_timeout),
            ("max_send_wait", self.max_send_wait),
            ("per_address_query_spacing", self.per_address_query_spacing),
            ("maintenance_interval", self.maintenance_interval),
            ("node_questionable_after", self.node_questionable_after),
            ("bucket_refresh_interval", self.bucket_refresh_interval),
            ("ping_interval", self.ping_interval),
            ("token_rotation", self.token_rotation),
            ("peer_ttl", self.peer_ttl),
            ("state_save_interval", self.state_save_interval),
            ("bootstrap_retry_base", self.bootstrap_retry_base),
            ("external_ip_vote_ttl", self.external_ip_vote_ttl),
            ("id_change_min_interval", self.id_change_min_interval),
            ("sample_interval_sent", self.sample_interval_sent),
            ("sample_min_resample", self.sample_min_resample),
            ("sample_unsupported_skip", self.sample_unsupported_skip),
            ("sample_timeout_skip", self.sample_timeout_skip),
            ("sampler_query_timeout", self.sampler_query_timeout),
            ("sampler_idle_wait", self.sampler_idle_wait),
        ];
        for (name, value) in positive {
            if value.is_zero() {
                return Err(Error::Config(format!(
                    "tuning.{name} must be greater than zero"
                )));
            }
        }
        if self.bootstrap_retry_max < self.bootstrap_retry_base {
            return Err(Error::Config(
                "tuning.bootstrap_retry_max must be at least bootstrap_retry_base".into(),
            ));
        }
        // Manual, not a generic range check: NaN must be rejected, and NaN
        // slips through `<`/`>` comparisons. `contains` fails NaN.
        if !(0.0..=1.0).contains(&self.sampler_live_share) {
            return Err(Error::Config(
                "tuning.sampler_live_share must be between 0.0 and 1.0".into(),
            ));
        }
        if self.sample_interval_sent
            > Duration::from_secs(crate::responder::MAX_SAMPLE_INTERVAL_SECS)
        {
            return Err(Error::Config(format!(
                "tuning.sample_interval_sent must be at most {}s (BEP 51)",
                crate::responder::MAX_SAMPLE_INTERVAL_SECS
            )));
        }
        if self.inbound_rate == 0 || self.inbound_burst == 0 {
            return Err(Error::Config(
                "tuning.inbound_rate and inbound_burst must be at least 1".into(),
            ));
        }
        if self.responder_replies_per_sec == 0 {
            return Err(Error::Config(
                "tuning.responder_replies_per_sec must be at least 1".into(),
            ));
        }
        let min_bytes = u32::try_from(MAX_DATAGRAM_OUT).unwrap_or(u32::MAX);
        if self.responder_bytes_per_sec < min_bytes {
            return Err(Error::Config(format!(
                "tuning.responder_bytes_per_sec must be at least {MAX_DATAGRAM_OUT}"
            )));
        }
        if self.external_ip_votes == 0 {
            return Err(Error::Config(
                "tuning.external_ip_votes must be at least 1".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_defaults() {
        let c = DhtConfig::default();
        assert_eq!(c.bind_v4, Some("0.0.0.0:6881".parse().unwrap()));
        assert_eq!(c.bind_v6, Some("[::]:6881".parse().unwrap()));
        assert_eq!(
            c.bootstrap,
            [
                "dht.libtorrent.org:25401",
                "dht.transmissionbt.com:6881",
                "router.bt.ouinet.work:6881",
                "router.bittorrent.com:6881"
            ]
        );
        assert_eq!(c.state_file, None);
        assert_eq!(c.max_packets_per_sec, DEFAULT_MAX_PACKETS_PER_SEC);
        assert_eq!(c.scrape_packets_per_sec, 100);
        assert!(c.sampler);
        assert_eq!(c.sampler_concurrency, DEFAULT_SAMPLER_CONCURRENCY);
        assert!(!c.read_only);
        assert!(!c.allow_private_addrs);
        assert_eq!(&c.client_version, b"DC\x00\x01");
        assert_eq!(c.bep42_r, None);
        let t = &c.tuning;
        assert_eq!(t.query_timeout, Duration::from_secs(4));
        assert_eq!(t.scrape_query_timeout, Duration::from_secs(10));
        assert_eq!(t.per_address_query_spacing, Duration::from_secs(1));
        assert_eq!((t.inbound_rate, t.inbound_burst), (4, 8));
        assert_eq!(
            t.responder_replies_per_sec,
            DEFAULT_RESPONDER_REPLIES_PER_SEC
        );
        assert_eq!(t.responder_bytes_per_sec, DEFAULT_RESPONDER_BYTES_PER_SEC);
        assert_eq!(t.peer_ttl, Duration::from_secs(45 * 60));
        assert_eq!(t.external_ip_votes, 10);
        assert_eq!(t.external_ip_vote_ttl, Duration::from_secs(30 * 60));
        assert_eq!(t.id_change_min_interval, Duration::from_secs(3600));
        assert_eq!(t.sample_interval_sent, Duration::from_secs(21_600));
        assert_eq!(t.sample_min_resample, Duration::from_secs(300));
        assert_eq!(t.sample_unsupported_skip, Duration::from_secs(6 * 3600));
        assert_eq!(t.sample_timeout_skip, Duration::from_secs(3600));
        assert_eq!(t.sampler_query_timeout, Duration::from_secs(2));
        assert_eq!(t.scrape_early_exit_quorum, 3);
        assert_eq!(t.scrape_node_cache_keys, 4096);
        assert!(!t.limits_by_endpoint);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn sample_interval_sent_capped_at_bep51_max() {
        let ok = DhtConfig::default();
        assert!(ok.validate().is_ok());
        let bad = DhtConfig {
            tuning: DhtTuning {
                sample_interval_sent: Duration::from_secs(
                    crate::responder::MAX_SAMPLE_INTERVAL_SECS + 1,
                ),
                ..DhtTuning::default()
            },
            ..DhtConfig::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn scrape_budget_is_dedicated() {
        // BEP 33 §2 LB-2: the scrape bucket is dedicated and much smaller
        // than the crawl bucket, so scrape traversals never starve the
        // crawl and crawl bursts never starve scrapes (node.rs:
        // `query_scrape` charges `scrape_budget`, `query_gated` charges
        // `budget`; both share per-address spacing).
        assert_eq!(DEFAULT_SCRAPE_PACKETS_PER_SEC, 100);
        assert_eq!(DEFAULT_MAX_PACKETS_PER_SEC, 12_000);
        let c = DhtConfig::default();
        assert!(c.scrape_packets_per_sec < c.max_packets_per_sec);
        assert!(c.validate().is_ok());
        let bad = DhtConfig {
            scrape_packets_per_sec: 0,
            ..DhtConfig::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn fetch_budget_is_dedicated() {
        // fetch traversals run on their own generous bucket, not
        // the 100/s scrape bucket (node.rs: `query_fetch` charges
        // `fetch_budget`, `query_scrape` charges `scrape_budget`; both share
        // per-address spacing).
        assert_eq!(DEFAULT_FETCH_PACKETS_PER_SEC, 6_000);
        let c = DhtConfig::default();
        assert!(c.fetch_packets_per_sec > c.scrape_packets_per_sec);
        assert!(c.validate().is_ok());
        let bad = DhtConfig {
            fetch_packets_per_sec: 0,
            ..DhtConfig::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn sampler_live_share_defaults_and_rejects_nan() {
        // 10% of sampler picks probe live addrs; NaN would
        // silently disable or misbehave, so it is rejected explicitly.
        assert_eq!(DhtTuning::default().sampler_live_share, 0.10);
        let mut tuning = DhtTuning::default();
        tuning.sampler_live_share = f64::NAN;
        let bad = DhtConfig {
            tuning: tuning.clone(),
            ..DhtConfig::default()
        };
        assert!(bad.validate().is_err());
        tuning.sampler_live_share = 1.01;
        let bad = DhtConfig {
            tuning: tuning.clone(),
            ..DhtConfig::default()
        };
        assert!(bad.validate().is_err());
        tuning.sampler_live_share = -0.5;
        let bad = DhtConfig {
            tuning,
            ..DhtConfig::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn validation() {
        let tuned = |tuning: DhtTuning| DhtConfig {
            tuning,
            ..DhtConfig::default()
        };
        let bad = [
            DhtConfig {
                bind_v4: None,
                bind_v6: None,
                ..DhtConfig::default()
            },
            DhtConfig {
                bind_v4: Some("[::]:1".parse().unwrap()),
                ..DhtConfig::default()
            },
            DhtConfig {
                bind_v6: Some("0.0.0.0:1".parse().unwrap()),
                ..DhtConfig::default()
            },
            DhtConfig {
                max_packets_per_sec: 0,
                ..DhtConfig::default()
            },
            DhtConfig {
                sampler_concurrency: MAX_SAMPLER_CONCURRENCY + 1,
                ..DhtConfig::default()
            },
            DhtConfig {
                sampler_concurrency: 0,
                ..DhtConfig::default()
            },
            DhtConfig {
                bep42_r: Some(8),
                ..DhtConfig::default()
            },
            tuned(DhtTuning {
                query_timeout: Duration::ZERO,
                ..DhtTuning::default()
            }),
            tuned(DhtTuning {
                sampler_query_timeout: Duration::ZERO,
                ..DhtTuning::default()
            }),
            tuned(DhtTuning {
                external_ip_vote_ttl: Duration::ZERO,
                ..DhtTuning::default()
            }),
            tuned(DhtTuning {
                inbound_rate: 0,
                ..DhtTuning::default()
            }),
            tuned(DhtTuning {
                external_ip_votes: 0,
                ..DhtTuning::default()
            }),
            tuned(DhtTuning {
                responder_replies_per_sec: 0,
                ..DhtTuning::default()
            }),
            tuned(DhtTuning {
                responder_bytes_per_sec: 1023,
                ..DhtTuning::default()
            }),
            tuned(DhtTuning {
                bootstrap_retry_max: Duration::from_millis(1),
                ..DhtTuning::default()
            }),
        ];
        for c in bad {
            assert!(matches!(c.validate(), Err(Error::Config(_))), "{c:?}");
        }
        let v6_only = DhtConfig {
            bind_v4: None,
            ..DhtConfig::default()
        };
        assert!(v6_only.validate().is_ok());
        let smallest = tuned(DhtTuning {
            responder_bytes_per_sec: 1024,
            ..DhtTuning::default()
        });
        assert!(smallest.validate().is_ok());
    }
}
