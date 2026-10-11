//! Live-network tests against the public BitTorrent DHT.
//!
//! These are opt-in and never run in CI:
//!
//! ```sh
//! DHTCRAWLER_LIVE=1 cargo test -p dhtcrawler4 --test live -- --ignored --test-threads=1
//! ```
//!
//! Rules the suite enforces on itself:
//!
//! - Every test is `#[ignore]`d and additionally requires `DHTCRAWLER_LIVE=1`,
//!   so a plain `cargo test` never sends a packet off-host.
//! - Tests run serially (`--test-threads=1`) and each bootstraps its own
//!   node, so one failure never cascades into the next test.
//! - The suite is read-only: it never calls `announce`, runs the sampler at
//!   the node's own production budgets, fetches from one peer at a time with
//!   small per-peer timeouts, and every test has an outer timeout.
//! - No infohash is pinned: fixtures are sampled live from the network
//!   (`sample_infohashes`), so the suite cannot rot and never targets a
//!   specific torrent. Assertions check protocol behaviour, structure and
//!   hash integrity, never content.
// Helpers outside #[test] functions are not covered by clippy.toml's test
// exemptions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use common::{note, wait_until};
use dc4_core::DhtKey;
use dc4_dht::{DEFAULT_BOOTSTRAP, Dht, DhtConfig, Discovered, MIN_GOOD_NODES, Source};
use dc4_peer::{FetchLimits, fetch_metadata};
use dc4_search::{IndexDoc, SearchIndex, SearchQuery};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Live tests only run with this set: a plain `cargo test` (and CI) must
/// never touch the public network.
fn require_live_env() {
    assert!(
        std::env::var_os("DHTCRAWLER_LIVE").is_some_and(|v| v == "1"),
        "live tests need DHTCRAWLER_LIVE=1; refusing to touch the public DHT"
    );
}

/// Always-on progress line: unlike [`note`](common::note) this prints
/// whether or not `DC4_E2E_VERBOSE` is set, so a pasted log from a failing
/// run tells the story on its own. Per-peer chatter stays behind `note`.
fn announce(started: Instant, what: &str) {
    eprintln!("[{:>6.2}s] {what}", started.elapsed().as_secs_f64());
}

/// One line of node state for progress logs and failure messages.
fn stats_line(dht: &Dht) -> String {
    let s = dht.stats();
    format!(
        "good={} routing={} out={} in={} responses={} timeouts={} find_node={} get_peers={} samples={} addrs={:?}",
        s.good_nodes(),
        s.routing_nodes(),
        s.packets_out(),
        s.packets_in(),
        s.responses_received,
        s.timeouts,
        s.queries_sent.find_node,
        s.queries_sent.get_peers,
        s.samples(),
        dht.own_addrs(),
    )
}
/// A production-shaped node on ephemeral ports: default bootstrap routers,
/// default budgets, default (production) tuning. Only the sampler is
/// switched per test.
fn live_config(sampler: bool) -> DhtConfig {
    DhtConfig {
        identities: 1,
        bind_v4: Some("0.0.0.0:0".parse().unwrap()),
        bind_v6: Some("[::]:0".parse().unwrap()),
        bootstrap: DEFAULT_BOOTSTRAP.iter().map(|s| (*s).to_owned()).collect(),
        state_file: None,
        sampler,
        ..DhtConfig::default()
    }
}

/// A running live node plus its discovery channel.
struct LiveNode {
    dht: Dht,
    rx: mpsc::Receiver<Discovered>,
    started: Instant,
}

impl LiveNode {
    async fn start(sampler: bool) -> LiveNode {
        let started = Instant::now();
        let (tx, rx) = mpsc::channel(4096);
        let dht = Dht::start(live_config(sampler), tx)
            .await
            .expect("bind sockets for the live node");
        announce(
            started,
            &format!(
                "node up on {:?}, sampler={sampler}, bootstrap={DEFAULT_BOOTSTRAP:?}",
                dht.local_addrs(),
            ),
        );
        LiveNode { dht, rx, started }
    }

    /// Waits for a ready routing table: the same threshold the crawl role
    /// uses. Tolerates dead bootstrap routers (2 of 4 were silent when the
    /// suite was written) since the node tries them all. Progress prints
    /// unconditionally so a stuck bootstrap leaves a trail.
    async fn wait_for_table(&self) {
        let limit = Duration::from_secs(6 * 60);
        let deadline = Instant::now() + limit;
        // None prints immediately, so a bootstrap stuck at zero still leaves
        // a first line; afterwards progress repeats every 15 seconds.
        let mut last_progress: Option<Instant> = None;
        loop {
            if self.dht.good_nodes() >= MIN_GOOD_NODES {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "live routing table did not fill in {limit:?}: {}",
                stats_line(&self.dht),
            );
            let due = last_progress.is_none_or(|t| t.elapsed() >= Duration::from_secs(15));
            if due {
                last_progress = Some(Instant::now());
                announce(
                    self.started,
                    &format!("bootstrapping: {}", stats_line(&self.dht)),
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        announce(
            self.started,
            &format!("table ready: {}", stats_line(&self.dht)),
        );
    }

    async fn shutdown(self) {
        self.dht.shutdown().await;
    }
}

/// Test 1: bootstrapping the public DHT fills the routing table and learns
/// our external address through other nodes' responses.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_bootstrap_fills_routing_table() {
    require_live_env();
    tokio::time::timeout(Duration::from_secs(8 * 60), async {
        let node = LiveNode::start(false).await;
        node.wait_for_table().await;

        // External-IP voting: routers see our source address, so our own
        // addresses must gain a non-loopback entry.
        wait_until(
            "external-IP voting to report our address",
            Duration::from_secs(60),
            || {
                let dht = node.dht.clone();
                async move {
                    dht.own_addrs()
                        .iter()
                        .any(|ip| !ip.is_loopback() && !ip.is_unspecified() && !is_unique_local(ip))
                }
            },
        )
        .await;

        let stats = node.dht.stats();
        assert!(
            stats.packets_out() > 0 && stats.responses_received > 0,
            "no two-way traffic with the live network: {stats:?}"
        );
        announce(
            node.started,
            &format!("voted external identity: {}", stats_line(&node.dht)),
        );
        node.shutdown().await;
    })
    .await
    .expect("the live bootstrap test timed out");
}

/// Test 2: iterative lookups of random targets actually traverse the live
/// network — `find_node` queries go out and responses come back — instead
/// of stalling or short-circuiting locally.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_lookup_traverses_the_network() {
    require_live_env();
    tokio::time::timeout(Duration::from_secs(10 * 60), async {
        let node = LiveNode::start(false).await;
        node.wait_for_table().await;

        let before = node.dht.stats();
        for round in 0..5 {
            let target = DhtKey(rand::random::<[u8; 20]>());
            // The timeout bounds the call; the assertions below prove the
            // lookup did real iterative work rather than giving up.
            let _ = node.dht.get_peers(target, Duration::from_secs(45)).await;
            announce(
                node.started,
                &format!("random lookup {round}: {}", stats_line(&node.dht)),
            );
        }
        let after = node.dht.stats();
        assert!(
            after.queries_sent.find_node > before.queries_sent.find_node,
            "lookups sent no find_node queries: {after:?}"
        );
        assert!(
            after.responses_received > before.responses_received,
            "lookups got no responses: {after:?}"
        );
        announce(
            node.started,
            &format!("lookup test done: {}", stats_line(&node.dht)),
        );
        node.shutdown().await;
    })
    .await
    .expect("the live lookup test timed out");
}

/// Collects up to `want` distinct BEP 51 sample keys, ignoring announces
/// and get_peers discoveries from the same channel.
async fn collect_samples(
    rx: &mut mpsc::Receiver<Discovered>,
    started: Instant,
    want: usize,
    limit: Duration,
) -> Vec<DhtKey> {
    let deadline = Instant::now() + limit;
    let mut keys = Vec::new();
    let mut seen = HashSet::new();
    while keys.len() < want && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(d)) if d.source == Source::Sample && seen.insert(d.key) => {
                keys.push(d.key);
                if keys.len() % 5 == 0 {
                    announce(started, &format!("{} live samples", keys.len()));
                }
            }
            // Closed sink, lagged receiver, or deadline elapsed: stop.
            _ => break,
        }
    }
    keys
}

/// Test 3: keys sampled live from the network resolve through `get_peers`.
/// Every response is protocol-valid by construction; the test passes when at
/// least one sampled key still has live peers (churn kills most).
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_get_peers_finds_real_peers() {
    require_live_env();
    tokio::time::timeout(Duration::from_secs(14 * 60), async {
        let mut node = LiveNode::start(true).await;
        node.wait_for_table().await;

        let keys =
            collect_samples(&mut node.rx, node.started, 10, Duration::from_secs(8 * 60)).await;
        assert!(
            !keys.is_empty(),
            "the live sampler produced no keys in 8 minutes: {}",
            stats_line(&node.dht),
        );

        let mut with_peers = 0;
        for key in &keys {
            let peers = node.dht.get_peers(*key, Duration::from_secs(30)).await;
            // Every key logs its count, including zeros: a wall of zeros
            // means dead swarms, silence would mean stuck lookups.
            announce(node.started, &format!("{key}: {} peers", peers.len()));
            if !peers.is_empty() {
                with_peers += 1;
            }
        }
        assert!(
            with_peers >= 1,
            "none of {} sampled keys had live peers: {}",
            keys.len(),
            stats_line(&node.dht),
        );
        announce(
            node.started,
            &format!("get_peers done: {}", stats_line(&node.dht)),
        );
        node.shutdown().await;
    })
    .await
    .expect("the live get_peers test timed out");
}

/// Limits for fetching from strangers: short enough that dead peers do not
/// eat the test, long enough for a slow real seeder.
fn live_fetch_limits() -> FetchLimits {
    FetchLimits {
        connect: Duration::from_secs(5),
        handshake: Duration::from_secs(5),
        total: Duration::from_secs(30),
        max_metadata: 8 * 1024 * 1024,
        byte_budget: None,
    }
}

/// Attempts spent on one key's peers before moving to the next swarm: a new
/// swarm may hold a reachable seeder while the current one is all firewalls.
/// IPv4 peers go first: most public swarms are v4-majority, so reachable
/// candidates surface earlier, but v6 peers are still tried afterwards.
const MAX_ATTEMPTS_PER_KEY: usize = 10;

/// Fetches metadata for sampled keys, trying v4 peers before v6 ones until
/// `want` succeed or `max_attempts` peers are exhausted. Returns the
/// verified (key, info) pairs plus the number of peers tried.
async fn fetch_from_live_peers(
    node: &LiveNode,
    keys: &[DhtKey],
    want: usize,
    max_attempts: usize,
) -> (Vec<(DhtKey, Vec<u8>)>, usize) {
    let own: HashSet<IpAddr> = node.dht.own_addrs().into_iter().collect();
    let mut tried = HashSet::new();
    let mut fetched = Vec::new();
    let mut failures: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut v4_tried = 0;
    let mut v6_tried = 0;
    let limits = live_fetch_limits();
    'keys: for key in keys {
        let mut peers = node.dht.get_peers(*key, Duration::from_secs(30)).await;
        peers.sort_by_key(|p| p.is_ipv6());
        announce(
            node.started,
            &format!("{key}: {} peers to try", peers.len()),
        );
        let mut key_attempts = 0;
        for peer in peers {
            if !tried.insert(peer) || own.contains(&peer.ip()) {
                continue;
            }
            if peer.is_ipv4() {
                v4_tried += 1;
            } else {
                v6_tried += 1;
            }
            match fetch_metadata(peer, *key, &limits).await {
                Ok(info) => {
                    announce(node.started, &format!("fetched {key} from {peer}"));
                    fetched.push((*key, info));
                    if fetched.len() >= want {
                        break 'keys;
                    }
                }
                Err(e) => {
                    *failures.entry(e.label()).or_insert(0) += 1;
                    note(node.started, &format!("{peer} for {key}: {e:?}"));
                }
            }
            if tried.len() >= max_attempts {
                break 'keys;
            }
            key_attempts += 1;
            if key_attempts >= MAX_ATTEMPTS_PER_KEY {
                announce(
                    node.started,
                    &format!("{key}: moving on after {key_attempts} attempts"),
                );
                break;
            }
        }
    }
    announce(
        node.started,
        &format!(
            "fetch done: {} ok / {} tried (v4={v4_tried} v6={v6_tried}), failures: {failures:?}",
            fetched.len(),
            tried.len(),
        ),
    );
    (fetched, tried.len())
}

/// Test 4: metadata fetched from real peers is authentic and parses —
/// `fetch_metadata` verifies the hash, and the test additionally pins the
/// SHA-1 itself, parses with `dc4-torrent`, and checks the v1 `pieces`
/// invariant on the raw dictionary.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_fetch_verifies_real_metadata() {
    require_live_env();
    tokio::time::timeout(Duration::from_secs(20 * 60), async {
        let mut node = LiveNode::start(true).await;
        node.wait_for_table().await;

        let keys =
            collect_samples(&mut node.rx, node.started, 10, Duration::from_secs(8 * 60)).await;
        assert!(
            !keys.is_empty(),
            "the live sampler produced no keys in 8 minutes: {}",
            stats_line(&node.dht),
        );
        let (fetched, attempts) = fetch_from_live_peers(&node, &keys, 1, 48).await;
        assert!(
            !fetched.is_empty(),
            "no peer yielded metadata after {attempts} attempts: {}",
            stats_line(&node.dht),
        );

        for (key, info) in &fetched {
            // Belt and braces: the fetcher verifies this, but the test owns
            // the live-network authenticity claim.
            use sha1::{Digest, Sha1};
            assert_eq!(
                &Sha1::digest(info)[..],
                &key.as_bytes()[..],
                "fetched bytes do not hash to the requested key"
            );
            let meta = dc4_torrent::parse_info(info)
                .unwrap_or_else(|e| panic!("live metadata for {key} must parse: {e:?}"));
            let root = dc4_bencode::decode(info, &dc4_bencode::Limits::METADATA)
                .expect("live metadata is bencode");
            if let Some(pieces) = root.as_dict().and_then(|d| d.get_bytes(b"pieces")) {
                assert_eq!(
                    pieces.len() % 20,
                    0,
                    "v1 pieces for {key} is not a multiple of 20"
                );
            }
            announce(
                node.started,
                &format!("{}: {} files", meta.name, meta.file_count),
            );
        }
        announce(
            node.started,
            &format!("fetch test done: {}", stats_line(&node.dht)),
        );
        node.shutdown().await;
    })
    .await
    .expect("the live fetch test timed out");
}

/// Test 5: fetched live torrents round-trip through a real search index:
/// upsert and commit, then query runs of each name and find the document
/// back. The parser and the index share a tokenizer, so a surviving run
/// must retrieve its own document.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_search_roundtrips_fetched_torrents() {
    require_live_env();
    tokio::time::timeout(Duration::from_secs(20 * 60), async {
        let mut node = LiveNode::start(true).await;
        node.wait_for_table().await;

        let keys =
            collect_samples(&mut node.rx, node.started, 15, Duration::from_secs(8 * 60)).await;
        assert!(
            !keys.is_empty(),
            "the live sampler produced no keys in 8 minutes: {}",
            stats_line(&node.dht),
        );
        let (fetched, attempts) = fetch_from_live_peers(&node, &keys, 2, 48).await;
        assert!(
            !fetched.is_empty(),
            "no peer yielded metadata after {attempts} attempts: {}",
            stats_line(&node.dht),
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let index = SearchIndex::create_in_ram().expect("a ram index");
        let mut writer = index.writer(20 * 1024 * 1024).expect("an index writer");
        let mut names = Vec::new();
        for (i, (key, info)) in fetched.iter().enumerate() {
            let meta = dc4_torrent::parse_info(info)
                .unwrap_or_else(|e| panic!("live metadata for {key} must parse: {e:?}"));
            let id = i as i64 + 1;
            let files: Vec<&str> = meta.files.iter().map(|f| f.path.as_str()).collect();
            writer
                .upsert(&IndexDoc {
                    id,
                    name: meta.name.clone(),
                    files: files.join("\n"),
                    size: meta.total_size,
                    created: now,
                    seen: 1,
                    file_count: meta.file_count,
                })
                .expect("upsert a live document");
            names.push((id, meta.name.clone()));
        }
        writer.commit(1).expect("commit the live documents");
        assert_eq!(
            index.doc_count(),
            names.len() as u64,
            "the index lost live documents"
        );

        let mut found = 0;
        for (id, name) in &names {
            let runs = name.split(|c: char| !c.is_alphanumeric());
            for cand in runs.filter(|s| s.chars().count() >= 3) {
                let hits = match index.search(&SearchQuery::new(cand)) {
                    Ok((results, _)) => results.hits,
                    // Unparseable runs (stop words, lone affixes) cannot
                    // retrieve anything; the next run may.
                    Err(_) => continue,
                };
                if hits.iter().any(|h| h.id == *id) {
                    announce(node.started, &format!("{cand:?} finds document {id}"));
                    found += 1;
                    break;
                }
            }
        }
        assert!(
            found >= 1,
            "no fetched torrent is retrievable by its own name terms: {}",
            stats_line(&node.dht),
        );
        announce(
            node.started,
            &format!(
                "search test done: {found} retrievable, {}",
                stats_line(&node.dht)
            ),
        );
        node.shutdown().await;
    })
    .await
    .expect("the live search test timed out");
}

/// ULA (`fc00::/7`) addresses are never a usable external identity.
fn is_unique_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}
