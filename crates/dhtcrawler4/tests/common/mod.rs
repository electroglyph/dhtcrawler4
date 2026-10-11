//! Helpers for the end-to-end tests: a private DHT on 127.0.0.1, test
//! torrents and seeders, crawl options with short timers, and a small HTTP
//! client. Nothing here touches the public internet.
// Helpers outside #[test] functions are not covered by clippy.toml's test
// exemptions; each test binary uses a different subset of them.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code
)]

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use dc4_bencode::OwnedValue;
use dc4_core::DhtKey;
use dc4_dht::{Dht, DhtConfig, DhtTuning, Discovered};
use dhtcrawler4::admission::AdmissionTuning;
use dhtcrawler4::crawl::CrawlOptions;
use dhtcrawler4::fetch::{DestLimits, FetchLimitsConfig, FetchTuning};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// DHT nodes besides the crawler's own (16 in total).
pub const NETWORK_NODES: usize = 15;
const SINK_CAPACITY: usize = 4096;
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// Prints progress when `DC4_E2E_VERBOSE` is set.
pub fn note(started: Instant, what: &str) {
    if std::env::var_os("DC4_E2E_VERBOSE").is_some() {
        eprintln!("[{:>6.2}s] {what}", started.elapsed().as_secs_f64());
    }
}

/// Timers short enough for a private network to converge in seconds.
pub fn fast_tuning() -> DhtTuning {
    DhtTuning {
        query_timeout: Duration::from_millis(700),
        query_slow_after: Duration::from_millis(300),
        lookup_timeout: Duration::from_secs(5),
        max_send_wait: Duration::from_secs(1),
        per_address_query_spacing: Duration::from_millis(50),
        maintenance_interval: Duration::from_millis(200),
        bucket_refresh_interval: Duration::from_secs(2),
        ping_interval: Duration::from_millis(500),
        max_pings_per_round: 16,
        bootstrap_retry_base: Duration::from_millis(200),
        bootstrap_retry_max: Duration::from_secs(1),
        state_save_interval: Duration::from_secs(1),
        sample_interval_sent: Duration::from_secs(1),
        sample_min_resample: Duration::from_millis(500),
        sample_unsupported_skip: Duration::from_secs(2),
        sample_timeout_skip: Duration::from_secs(2),
        sampler_idle_wait: Duration::from_millis(100),
        // Every node shares 127.0.0.1, so per-IP rules key on IP:port.
        limits_by_endpoint: true,
        ..DhtTuning::default()
    }
}

/// A loopback node bootstrapped from `bootstrap`.
pub fn node_config(bootstrap: &[SocketAddr], sampler: bool) -> DhtConfig {
    DhtConfig {
        bind_v4: Some("127.0.0.1:0".parse().unwrap()),
        bind_v6: None,
        bootstrap: bootstrap.iter().map(ToString::to_string).collect(),
        state_file: None,
        max_packets_per_sec: 2000,
        scrape_packets_per_sec: 2000,
        fetch_packets_per_sec: 2000,
        sampler,
        sampler_concurrency: 8,
        read_only: false,
        allow_private_addrs: true,
        client_version: *b"DT\x00\x01",
        bep42_r: None,
        tuning: fast_tuning(),
    }
}

/// A private DHT: the first node is everyone's bootstrap node.
pub struct Network {
    pub nodes: Vec<Dht>,
    // Kept open so the nodes' discovery channels stay connected.
    _sinks: Vec<mpsc::Receiver<Discovered>>,
}

impl Network {
    /// Starts `n` nodes without samplers.
    pub async fn start(n: usize) -> Network {
        let mut nodes = Vec::with_capacity(n);
        let mut sinks = Vec::with_capacity(n);
        let mut bootstrap = Vec::new();
        for _ in 0..n {
            let (tx, rx) = mpsc::channel(SINK_CAPACITY);
            let node = Dht::start(node_config(&bootstrap, false), tx)
                .await
                .expect("start a DHT node");
            if bootstrap.is_empty() {
                bootstrap.push(node.local_addrs()[0]);
            }
            nodes.push(node);
            sinks.push(rx);
        }
        Network {
            nodes,
            _sinks: sinks,
        }
    }

    /// The bootstrap node's address.
    pub fn seed(&self) -> SocketAddr {
        self.nodes[0].local_addrs()[0]
    }

    /// Stops every node.
    pub async fn shutdown(self) {
        for node in self.nodes {
            node.shutdown().await;
        }
    }
}

/// Waits until every node has at least `min` routing-table entries.
pub async fn wait_for_tables(nodes: &[&Dht], min: usize, limit: Duration) {
    let deadline = Instant::now() + limit;
    loop {
        let sizes: Vec<usize> = nodes.iter().map(|n| n.stats().v4.routing_nodes).collect();
        if sizes.iter().all(|s| *s >= min) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "routing tables did not fill: {sizes:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Polls `check` every 100 ms until it is true; fails after `limit`.
pub async fn wait_until<F, Fut>(what: &str, limit: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + limit;
    while !check().await {
        assert!(
            Instant::now() < deadline,
            "timed out after {limit:?} waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A v1 multi-file info dictionary.
pub fn info_dict(name: &str, files: &[(&str, i64)]) -> Vec<u8> {
    let mut d = BTreeMap::new();
    d.insert(b"name".to_vec(), OwnedValue::from(name));
    d.insert(b"piece length".to_vec(), OwnedValue::Int(262_144));
    d.insert(b"pieces".to_vec(), OwnedValue::Bytes(vec![0x5a; 60]));
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
    dc4_bencode::encode(&OwnedValue::Dict(d))
}

/// A torrent served over BEP 9 on 127.0.0.1.
pub struct Seeder {
    pub key: DhtKey,
    pub info: Vec<u8>,
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Seeder {
    /// Serves `info` until dropped.
    pub async fn start(info: Vec<u8>) -> Seeder {
        let key = dc4_torrent::parse_info(&info)
            .expect("a valid test torrent")
            .info_hash_v1
            .expect("a v1 test torrent");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(dc4_peer::seeder::serve(listener, key, info.clone()));
        Seeder {
            key,
            info,
            addr,
            task,
        }
    }
}

impl Drop for Seeder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Announces `seeder` from `node` and checks that another node can find it.
pub async fn announce(node: &Dht, other: &Dht, seeder: &Seeder) {
    let accepted = node.announce(seeder.key, seeder.addr.port()).await;
    assert!(accepted >= 1, "no node accepted the announce");
    wait_until(
        "the announced peer to be findable",
        Duration::from_secs(15),
        || async move {
            other
                .get_peers(seeder.key, Duration::from_secs(3))
                .await
                .contains(&seeder.addr)
        },
    )
    .await;
}

/// Crawl options for a crawler bootstrapped from `bootstrap`, with short
/// timers and relaxed per-destination limits (every seeder is on
/// 127.0.0.1).
pub fn crawl_options(bootstrap: SocketAddr) -> CrawlOptions {
    let mut opts = CrawlOptions::new(
        node_config(&[bootstrap], true),
        1_000_000,
        4,
        FetchLimitsConfig {
            max_connections: 32,
            max_metadata_bytes: 8 * 1024 * 1024,
            max_inflight_metadata_bytes: 64 * 1024 * 1024,
        },
    );
    opts.admission = AdmissionTuning {
        flush_interval: Duration::from_millis(100),
        retry_base: Duration::from_millis(100),
        retry_max: Duration::from_secs(1),
        ..AdmissionTuning::default()
    };
    opts.fetch = FetchTuning {
        idle_min: Duration::from_millis(50),
        idle_max: Duration::from_millis(150),
        get_peers_timeout: Duration::from_secs(5),
        key_deadline: Duration::from_secs(20),
        connect_timeout: Duration::from_secs(2),
        handshake_timeout: Duration::from_secs(2),
        peer_timeout: Duration::from_secs(10),
        store_retry_base: Duration::from_millis(100),
        store_retry_max: Duration::from_secs(1),
        destinations: DestLimits {
            max_attempts: 1000,
            negative_ttl: Duration::from_secs(1),
            ..DestLimits::default()
        },
        ..FetchTuning::default()
    };
    opts.stats_interval = Duration::from_millis(200);
    opts.queue_depth_interval = Duration::from_millis(500);
    opts.readiness_interval = Duration::from_millis(200);
    opts.min_good_nodes = 4;
    opts.shutdown_wait = Duration::from_secs(5);
    opts
}

/// A parsed HTTP response.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    /// The first header named `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Sends one HTTP/1.1 request and reads the whole response.
pub async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nUser-Agent: dc4-e2e\r\n"
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if method != "GET" {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        (&mut stream).take(MAX_RESPONSE_BYTES).read_to_end(&mut raw),
    )
    .await
    .expect("the response timed out")
    .unwrap();
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("the response has no header end");
    let head = std::str::from_utf8(&raw[..split]).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .expect("a status line");
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    if chunked {
        body = dechunk(&body);
    }
    HttpResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("a chunk size line");
        let size_text = std::str::from_utf8(&data[..line_end]).unwrap();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16).unwrap();
        data = &data[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}
