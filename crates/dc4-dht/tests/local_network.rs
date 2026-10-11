//! Private DHTs on the loopback interface: bootstrap, announce, BEP 51
//! discovery, get_peers, a read-only node, token checks, the responder
//! budget, per-IP limits and IPv6. Never leaves the host.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use dc4_core::DhtKey;
use dc4_dht::compact::CompactNode;
use dc4_dht::krpc::{self, Body, Message, Method, Query, Response, Want, error_code};
use dc4_dht::{Dht, DhtConfig, DhtTuning, Discovered, Error, NodeId, Source};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep, timeout};

/// Port announced by node A.
const ANNOUNCED_PORT: u16 = 51_413;
/// Regular nodes besides the seed, the announcer, the crawler and the read-only node.
const REGULAR_NODES: usize = 8;
const SINK_CAPACITY: usize = 4096;
const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const LOCALHOST_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

fn fast_tuning() -> DhtTuning {
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
        // Many nodes share 127.0.0.1, so the per-IP rules key on IP:port.
        limits_by_endpoint: true,
        // The tests below were written for a 10/s, burst-20 inbound limit;
        // production uses 4/s, burst 8 (see DhtTuning::default).
        inbound_rate: 10,
        inbound_burst: 20,
        ..DhtTuning::default()
    }
}

fn config(bootstrap: &[SocketAddr]) -> DhtConfig {
    DhtConfig {
        identities: 1,
        bind_v4: Some("127.0.0.1:0".parse().unwrap()),
        bind_v6: None,
        bootstrap: bootstrap.iter().map(ToString::to_string).collect(),
        state_file: None,
        max_packets_per_sec: 2000,
        scrape_packets_per_sec: 2000,
        fetch_packets_per_sec: 2000,
        sampler: false,
        sampler_concurrency: 8,
        read_only: false,
        allow_private_addrs: true,
        client_version: *b"DT\x00\x01",
        bep42_r: None,
        tuning: fast_tuning(),
    }
}

async fn start(cfg: DhtConfig) -> (Dht, mpsc::Receiver<Discovered>) {
    let (tx, rx) = mpsc::channel(SINK_CAPACITY);
    let dht = Dht::start(cfg, tx).await.expect("start DHT node");
    (dht, rx)
}

fn addr(dht: &Dht) -> SocketAddr {
    dht.local_addrs()[0]
}

fn random_key() -> DhtKey {
    DhtKey(rand::random())
}

/// Whether this host can bind `addr` (some hosts lack IPv6 or 127.0.0.2).
fn can_bind(addr: &str) -> bool {
    std::net::UdpSocket::bind(addr).is_ok()
}

/// A bare KRPC client on its own socket.
struct RawClient {
    socket: UdpSocket,
    id: NodeId,
    next_tid: u16,
}

impl RawClient {
    async fn new() -> Self {
        Self::bind("127.0.0.1:0").await
    }

    async fn bind(addr: &str) -> Self {
        let socket = UdpSocket::bind(addr).await.unwrap();
        Self {
            socket,
            id: NodeId::random(),
            next_tid: 1,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    async fn send_query_with(
        &mut self,
        to: SocketAddr,
        method: Method,
        want: Option<Want>,
    ) -> Vec<u8> {
        let tid = self.next_tid.to_be_bytes().to_vec();
        self.next_tid += 1;
        let msg = Message {
            tid: tid.clone(),
            version: None,
            ip: None,
            read_only: false,
            body: Body::Query(Query {
                id: self.id,
                want,
                method,
            }),
        };
        self.socket
            .send_to(&krpc::encode(&msg).unwrap(), to)
            .await
            .unwrap();
        tid
    }

    async fn send_query(&mut self, to: SocketAddr, method: Method) -> Vec<u8> {
        self.send_query_with(to, method, None).await
    }

    /// The replies from `from` whose transaction is in `tids`, until `wait` ends.
    async fn replies(&self, from: SocketAddr, tids: &[Vec<u8>], wait: Duration) -> Vec<Message> {
        let deadline = Instant::now() + wait;
        let mut buf = [0u8; 2048];
        let mut out = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(received) = timeout(remaining, self.socket.recv_from(&mut buf)).await else {
                return out;
            };
            let Ok((len, src)) = received else { continue };
            // Nodes that heard from us may ping us; skip everything else.
            let Ok(msg) = krpc::decode(&buf[..len]) else {
                continue;
            };
            if src == from && tids.contains(&msg.tid) && !matches!(msg.body, Body::Query(_)) {
                out.push(msg);
                if out.len() == tids.len() {
                    return out;
                }
            }
        }
    }

    /// The next reply from `from` with transaction `tid`, or `None` after `wait`.
    async fn reply(&self, from: SocketAddr, tid: &[u8], wait: Duration) -> Option<Message> {
        self.replies(from, &[tid.to_vec()], wait).await.pop()
    }

    async fn call_with(&mut self, to: SocketAddr, method: Method, want: Option<Want>) -> Message {
        let tid = self.send_query_with(to, method, want).await;
        self.reply(to, &tid, Duration::from_secs(3))
            .await
            .expect("no reply from node")
    }

    async fn call(&mut self, to: SocketAddr, method: Method) -> Message {
        self.call_with(to, method, None).await
    }

    /// Waits for a query from `from` and returns it.
    async fn next_query_from(&self, from: SocketAddr, wait: Duration) -> Option<Message> {
        let deadline = Instant::now() + wait;
        let mut buf = [0u8; 2048];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(received) = timeout(remaining, self.socket.recv_from(&mut buf)).await else {
                return None;
            };
            let Ok((len, src)) = received else { continue };
            if src != from {
                continue;
            }
            if let Ok(msg) = krpc::decode(&buf[..len])
                && matches!(msg.body, Body::Query(_))
            {
                return Some(msg);
            }
        }
    }
}

fn response(msg: &Message) -> &Response {
    match &msg.body {
        Body::Response(r) => r,
        other => panic!("expected a response, got {other:?}"),
    }
}

async fn wait_until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_tables(nodes: &[&Dht], min: usize, limit: Duration) {
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
        sleep(Duration::from_millis(100)).await;
    }
}

/// Every event already waiting in `rx`.
fn drain(rx: &mut mpsc::Receiver<Discovered>) -> Vec<Discovered> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_network() {
    timeout(Duration::from_secs(90), private_network_inner())
        .await
        .expect("test timed out");
}

async fn private_network_inner() {
    let started = Instant::now();
    let (seed, _seed_rx) = start(config(&[])).await;
    let seed_addr = addr(&seed);

    let mut regular = Vec::new();
    let mut sinks = Vec::new();
    for _ in 0..REGULAR_NODES {
        let (node, rx) = start(config(&[seed_addr])).await;
        regular.push(node);
        sinks.push(rx);
    }
    let (announcer, _announcer_rx) = start(config(&[seed_addr])).await;
    let (crawler, mut crawler_rx) = start(DhtConfig {
        sampler: true,
        ..config(&[seed_addr])
    })
    .await;

    // The read-only node also bootstraps from a raw socket, so we can see its queries.
    let ro_probe = RawClient::new().await;
    let (read_only, _ro_rx) = start(DhtConfig {
        read_only: true,
        ..config(&[seed_addr, ro_probe.addr()])
    })
    .await;
    let read_only_addr = addr(&read_only);

    let mut answering: Vec<&Dht> = vec![&seed, &announcer, &crawler];
    answering.extend(regular.iter());
    let initial_ids: Vec<Vec<NodeId>> = answering.iter().map(|n| n.node_ids()).collect();
    assert_eq!(answering.len() + 1, 12);

    wait_for_tables(&answering, 6, Duration::from_secs(20)).await;
    eprintln!("routing tables filled after {:?}", started.elapsed());

    // --- Read-only node (BEP 43) ---
    let ro_query = ro_probe
        .next_query_from(read_only_addr, Duration::from_secs(5))
        .await
        .expect("the read-only node sent no query");
    assert!(
        ro_query.read_only,
        "queries from a read-only node must carry ro=1"
    );
    let mut pinger = RawClient::new().await;
    let tid = pinger.send_query(read_only_addr, Method::Ping).await;
    assert!(
        pinger
            .reply(read_only_addr, &tid, Duration::from_secs(1))
            .await
            .is_none(),
        "read-only node answered"
    );
    let ro_stats = read_only.stats();
    assert!(ro_stats.queries_received.ping >= 1);
    assert_eq!(ro_stats.errors_sent, 0);
    assert_eq!(ro_stats.responder_dropped, 0);
    // Each of its bootstrap rounds waits for the silent probe to time out.
    wait_until(
        "the read-only node to learn nodes",
        Duration::from_secs(10),
        || read_only.stats().v4.routing_nodes > 0,
    )
    .await;
    for _ in 0..5 {
        for node in &answering {
            assert!(
                !node.routing_nodes().contains(&read_only_addr),
                "a read-only node was added to a routing table"
            );
        }
        sleep(Duration::from_millis(100)).await;
    }

    // --- Announce and BEP 51 discovery ---
    let keys: Vec<DhtKey> = (0..3).map(|_| random_key()).collect();
    for key in &keys {
        let accepted = announcer.announce(*key, ANNOUNCED_PORT).await;
        assert!(accepted >= 1, "no node accepted the announce");
    }
    eprintln!("announced after {:?}", started.elapsed());

    let wanted: HashSet<DhtKey> = keys.iter().copied().collect();
    let mut sampled = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !wanted.is_subset(&sampled) {
        let left = deadline.saturating_duration_since(Instant::now());
        let event = timeout(left, crawler_rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "crawler sampled only {} of 3 keys",
                    sampled.intersection(&wanted).count()
                )
            })
            .expect("crawler sink closed");
        if event.source == Source::Sample {
            assert_eq!(event.peer, None);
            assert_eq!(
                event.from, LOCALHOST_V4,
                "a sample names the answering node"
            );
            sampled.insert(event.key);
        }
    }
    eprintln!("all keys sampled after {:?}", started.elapsed());
    let crawler_stats = crawler.stats();
    assert!(crawler_stats.v4.samples >= 3);
    assert_eq!(crawler_stats.samples(), crawler_stats.v4.samples);
    assert!(crawler_stats.queries_sent.sample_infohashes >= 3);
    assert_eq!(
        crawler_stats.sampler_early, 0,
        "a node was sampled before its interval"
    );
    assert_eq!(crawler_stats.sampler_visited_full, 0);
    assert!(crawler_stats.v4.sampler_visited > 0);

    // --- get_peers from a third node ---
    let expected_peer = SocketAddr::new(addr(&announcer).ip(), ANNOUNCED_PORT);
    let getter = &regular[0];
    for key in &keys {
        let mut found = Vec::new();
        for _ in 0..3 {
            found = getter.get_peers(*key, Duration::from_secs(5)).await;
            if found.contains(&expected_peer) {
                break;
            }
        }
        assert!(
            found.contains(&expected_peer),
            "get_peers returned {found:?}"
        );
    }

    // --- Tokens ---
    let target = &regular[1];
    let target_addr = addr(target);
    drain(&mut sinks[1]);
    let errors_before = target.stats().errors_sent;
    let mut client = RawClient::new().await;
    let key = random_key();
    let bad = Method::AnnouncePeer {
        info_hash: key,
        port: 7000,
        implied_port: false,
        token: b"not-a-token".to_vec(),
        seed: false,
    };
    let reply = client.call(target_addr, bad).await;
    match &reply.body {
        Body::Error(e) => assert_eq!(e.code, error_code::PROTOCOL),
        other => panic!("expected error 203, got {other:?}"),
    }
    assert!(target.stats().errors_sent > errors_before);
    let lookup = client
        .call(
            target_addr,
            Method::GetPeers {
                info_hash: key,
                scrape: false,
            },
        )
        .await;
    let r = response(&lookup);
    assert_eq!(r.values, None, "an announce with a bad token was stored");
    assert!(r.nodes.as_ref().is_some_and(|n| !n.is_empty()));
    assert_eq!(lookup.ip, Some(client.addr()));
    // Positive control: the issued token works, with implied_port.
    let token = r.token.clone().expect("get_peers must return a token");
    let good = Method::AnnouncePeer {
        info_hash: key,
        port: 1,
        implied_port: true,
        token,
        seed: false,
    };
    let ok = client.call(target_addr, good).await;
    assert_eq!(response(&ok).id, target.node_ids()[0]);
    let lookup = client
        .call(
            target_addr,
            Method::GetPeers {
                info_hash: key,
                scrape: false,
            },
        )
        .await;
    assert_eq!(response(&lookup).values, Some(vec![client.addr()]));
    // The target reported both queries, with the client as the source.
    let events: Vec<Discovered> = drain(&mut sinks[1])
        .into_iter()
        .filter(|e| e.key == key)
        .collect();
    let get_peers = Discovered {
        key,
        source: Source::GetPeers,
        peer: None,
        seed: false,
        from: LOCALHOST_V4,
    };
    let announce = Discovered {
        key,
        source: Source::Announce,
        peer: Some(client.addr()),
        seed: false,
        from: LOCALHOST_V4,
    };
    assert_eq!(events, vec![get_peers, announce, get_peers]);

    // --- Housekeeping ---
    // Loopback addresses are exempt from BEP 42, so no node changed its ID.
    for (node, ids) in answering.iter().zip(&initial_ids) {
        assert_eq!(&node.node_ids(), ids);
        assert_eq!(node.stats().node_id_changes, 0);
        assert_eq!(node.own_addrs(), vec![LOCALHOST_V4]);
    }
    assert!(crawler.good_nodes() >= 1);
    let seed_stats = seed.stats();
    assert!(seed_stats.v4.enabled && !seed_stats.v6.enabled);
    assert!(seed_stats.v4.packets_in > 0 && seed_stats.v4.packets_out > 0);
    assert_eq!(seed_stats.packets_in(), seed_stats.v4.packets_in);
    assert_eq!(seed_stats.v6.packets_in + seed_stats.v6.packets_out, 0);
    assert_eq!(
        seed_stats.v4.dropped.oversized + seed_stats.v4.dropped.filtered,
        0
    );
    assert!(seed_stats.queries_received.find_node > 0);
    assert!(seed_stats.v4.good_nodes <= seed_stats.v4.routing_nodes);

    drop(answering);
    read_only.shutdown().await;
    for node in regular {
        node.shutdown().await;
    }
    announcer.shutdown().await;
    crawler.shutdown().await;
    seed.shutdown().await;
    eprintln!(
        "private network test finished after {:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_stack_network() {
    if !can_bind("[::1]:0") {
        eprintln!("skipping: this host has no IPv6 loopback");
        return;
    }
    timeout(Duration::from_secs(60), async {
        let dual = |bootstrap: &[SocketAddr]| DhtConfig {
            bind_v6: Some("[::1]:0".parse().unwrap()),
            ..config(bootstrap)
        };
        let (seed, _seed_rx) = start(dual(&[])).await;
        let routers = seed.local_addrs();
        assert_eq!(routers.len(), 2);
        assert!(routers[0].is_ipv4() && routers[1].is_ipv6());
        let mut nodes = Vec::new();
        for _ in 0..5 {
            nodes.push(start(dual(&routers)).await.0);
        }
        let all: Vec<&Dht> = std::iter::once(&seed).chain(nodes.iter()).collect();
        wait_until(
            "both routing tables to fill",
            Duration::from_secs(20),
            || {
                all.iter().all(|n| {
                    let s = n.stats();
                    s.v4.routing_nodes >= 3 && s.v6.routing_nodes >= 3
                })
            },
        )
        .await;
        for node in &all {
            assert_eq!(node.own_addrs(), vec![LOCALHOST_V4, LOCALHOST_V6]);
            assert_eq!(node.node_ids().len(), 2);
        }

        // One announce reaches both families, and a lookup finds both peers.
        let key = random_key();
        let accepted = nodes[0].announce(key, ANNOUNCED_PORT).await;
        assert!(accepted >= 2, "only {accepted} nodes accepted the announce");
        let expected = [
            SocketAddr::new(LOCALHOST_V4, ANNOUNCED_PORT),
            SocketAddr::new(LOCALHOST_V6, ANNOUNCED_PORT),
        ];
        let mut found = Vec::new();
        for _ in 0..3 {
            found = nodes[1].get_peers(key, Duration::from_secs(5)).await;
            if expected.iter().all(|p| found.contains(p)) {
                break;
            }
        }
        assert!(
            expected.iter().all(|p| found.contains(p)),
            "get_peers returned {found:?}"
        );

        // BEP 32: an IPv4 query that wants both families gets both node lists.
        wait_until("the seed to confirm nodes", Duration::from_secs(10), || {
            let s = seed.stats();
            s.v4.good_nodes > 0 && s.v6.good_nodes > 0
        })
        .await;
        let mut client = RawClient::new().await;
        let both = Some(Want { n4: true, n6: true });
        let reply = client
            .call_with(
                routers[0],
                Method::FindNode {
                    target: NodeId::random(),
                },
                both,
            )
            .await;
        let r = response(&reply);
        let list4 = r.nodes.clone().expect("no IPv4 nodes");
        let list6 = r.nodes6.clone().expect("no IPv6 nodes");
        assert!(!list4.is_empty() && list4.iter().all(|n| n.addr.is_ipv4()));
        assert!(!list6.is_empty() && list6.iter().all(|n| n.addr.is_ipv6()));
        // An IPv6 client gets IPv6 nodes and sees its own address in `ip`.
        let mut client6 = RawClient::bind("[::1]:0").await;
        let reply = client6
            .call(
                routers[1],
                Method::FindNode {
                    target: NodeId::random(),
                },
            )
            .await;
        assert_eq!(reply.ip, Some(client6.addr()));
        assert_eq!(response(&reply).nodes, None);
        assert!(
            response(&reply)
                .nodes6
                .as_ref()
                .is_some_and(|n| !n.is_empty())
        );

        let stats = seed.stats();
        assert!(stats.v6.enabled);
        assert!(stats.v6.packets_in > 0 && stats.v6.packets_out > 0);
        assert!(stats.v4.packets_in > 0 && stats.v4.packets_out > 0);
        assert_eq!(
            stats.packets_in(),
            stats.v4.packets_in + stats.v6.packets_in
        );
        assert!(seed.good_nodes() >= stats.v6.good_nodes);

        drop(all);
        for node in nodes {
            node.shutdown().await;
        }
        seed.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn responder_budget_drops_excess_queries() {
    let cfg = DhtConfig {
        tuning: DhtTuning {
            responder_replies_per_sec: 2,
            ..fast_tuning()
        },
        ..config(&[])
    };
    let (node, _rx) = start(cfg).await;
    let to = addr(&node);
    let mut client = RawClient::new().await;
    let started = Instant::now();
    let mut tids = Vec::new();
    for _ in 0..20 {
        tids.push(client.send_query(to, Method::Ping).await);
    }
    let replies = client
        .replies(to, &tids, Duration::from_millis(300))
        .await
        .len();
    // Two replies of burst, then two per second.
    let allowed = 2 + (started.elapsed().as_secs_f64() * 2.0).ceil() as usize;
    assert!(
        (2..=allowed).contains(&replies),
        "{replies} replies, at most {allowed} allowed"
    );
    let stats = node.stats();
    assert_eq!(stats.queries_received.ping, 20);
    assert_eq!(stats.v4.packets_in, 20);
    assert_eq!(stats.responder_dropped, 20 - replies as u64);
    assert_eq!(stats.v4.dropped.responder_budget, stats.responder_dropped);
    assert_eq!(stats.v4.dropped.rate_limited, 0);
    // The budget refills: a query a second later is answered.
    sleep(Duration::from_millis(1100)).await;
    let reply = client.call(to, Method::Ping).await;
    assert_eq!(response(&reply).id, node.node_ids()[0]);
    node.shutdown().await;
}

#[tokio::test]
async fn inbound_rate_limit_is_per_endpoint_in_tests() {
    let (node, _rx) = start(config(&[])).await;
    let to = addr(&node);
    let mut noisy = RawClient::new().await;
    let mut tids = Vec::new();
    for _ in 0..30 {
        tids.push(noisy.send_query(to, Method::Ping).await);
    }
    let answered = noisy
        .replies(to, &tids, Duration::from_millis(300))
        .await
        .len();
    // The burst is 20 packets, plus 10 per second.
    assert!((20..=24).contains(&answered), "{answered} replies");
    // Another endpoint on the same IP has its own bucket with `limits_by_endpoint`.
    let mut quiet = RawClient::new().await;
    quiet.call(to, Method::Ping).await;
    let stats = node.stats();
    assert_eq!(stats.v4.dropped.rate_limited, 30 - answered as u64);
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_limits_key_on_ip() {
    // Linux routes all of 127.0.0.0/8 to the loopback interface; other hosts may not.
    if !can_bind("127.0.0.2:0") {
        eprintln!("skipping: this host cannot bind 127.0.0.2");
        return;
    }
    timeout(Duration::from_secs(30), async {
        let production = |bind: &str, bootstrap: &[SocketAddr]| DhtConfig {
            bind_v4: Some(bind.parse().unwrap()),
            tuning: DhtTuning {
                limits_by_endpoint: false,
                ..fast_tuning()
            },
            ..config(bootstrap)
        };
        let (a, _a_rx) = start(production("127.0.0.1:0", &[])).await;
        let a_addr = addr(&a);
        let (b, _b_rx) = start(production("127.0.0.2:0", &[a_addr])).await;
        let (c, _c_rx) = start(production("127.0.0.2:0", &[a_addr])).await;
        let other_ip: IpAddr = "127.0.0.2".parse().unwrap();
        // B and C both query A, but A keeps one routing entry for their IP.
        wait_until("A to learn B or C", Duration::from_secs(10), || {
            a.stats().v4.routing_nodes > 0
        })
        .await;
        wait_until("A to hear from both", Duration::from_secs(10), || {
            a.stats().queries_received.total() >= 2
        })
        .await;
        for _ in 0..15 {
            let nodes = a.routing_nodes();
            assert_eq!(nodes.len(), 1, "{nodes:?}");
            assert_eq!(nodes[0].ip(), other_ip);
            sleep(Duration::from_millis(100)).await;
        }
        // B and C share an IP, so each treats the other as itself.
        assert_eq!(b.own_addrs(), vec![other_ip]);
        assert!(b.routing_nodes().is_empty() && c.routing_nodes().is_empty());
        // A third endpoint on that IP is answered but not added either.
        let mut client = RawClient::bind("127.0.0.2:0").await;
        client.call(a_addr, Method::Ping).await;
        assert_eq!(a.routing_nodes().len(), 1);
        a.shutdown().await;
        b.shutdown().await;
        c.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn ipv6_is_optional() {
    // An unspecified IPv6 address is used only when the host has a global IPv6 address.
    let cfg = DhtConfig {
        bind_v6: Some("[::]:0".parse().unwrap()),
        ..config(&[])
    };
    let (node, _rx) = start(cfg).await;
    let addrs = node.local_addrs();
    assert!(addrs[0].is_ipv4());
    assert!(addrs.len() <= 2);
    assert_eq!(node.stats().v6.enabled, addrs.len() == 2);
    node.shutdown().await;
    // An IPv6 bind failure is only a warning while IPv4 works (2001:db8::/32 is never assigned).
    let cfg = DhtConfig {
        bind_v6: Some("[2001:db8::1]:0".parse().unwrap()),
        ..config(&[])
    };
    let (node, _rx) = start(cfg).await;
    assert_eq!(node.local_addrs().len(), 1);
    assert!(!node.stats().v6.enabled);
    node.shutdown().await;
    // Without IPv4 it is an error.
    let (tx, _rx) = mpsc::channel(1);
    let cfg = DhtConfig {
        bind_v4: None,
        bind_v6: Some("[2001:db8::1]:0".parse().unwrap()),
        ..config(&[])
    };
    assert!(matches!(
        Dht::start(cfg, tx.clone()).await,
        Err(Error::Bind { .. })
    ));
    // IPv6 only on the unspecified address works exactly when the host has global IPv6.
    let cfg = DhtConfig {
        bind_v4: None,
        bind_v6: Some("[::]:0".parse().unwrap()),
        ..config(&[])
    };
    match Dht::start(cfg, tx).await {
        Ok(node) => {
            assert!(node.local_addrs()[0].is_ipv6());
            node.shutdown().await;
        }
        Err(e) => assert!(matches!(e, Error::NoSocket), "{e}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_file_round_trip() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht-state.json");
        let (seed, _seed_rx) = start(config(&[])).await;
        let seed_addr = addr(&seed);
        let (other, _other_rx) = start(config(&[seed_addr])).await;
        let other_addr = addr(&other);
        let (node, _rx) = start(DhtConfig {
            state_file: Some(path.clone()),
            ..config(&[seed_addr])
        })
        .await;
        let id = node.node_ids()[0];

        // The seed is a router for `node`, so `other` is the contact it learns.
        // Only nodes that have answered are saved, so wait for a good node.
        wait_until(
            "the node to confirm the other node",
            Duration::from_secs(15),
            || node.routing_nodes().contains(&other_addr) && node.good_nodes() >= 1,
        )
        .await;
        node.shutdown().await;
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains(&id.to_hex()));
        assert!(saved.contains(&other_addr.to_string()));

        // Restart without bootstrap routers: same ID, contacts come from the file.
        let (again, _rx) = start(DhtConfig {
            state_file: Some(path.clone()),
            ..config(&[])
        })
        .await;
        assert_eq!(again.node_ids(), vec![id]);
        wait_until("saved contacts to be used", Duration::from_secs(15), || {
            again.routing_nodes().contains(&other_addr)
        })
        .await;
        again.shutdown().await;
        other.shutdown().await;
        seed.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn start_errors() {
    let (tx, _rx) = mpsc::channel(1);
    let err = Dht::start(
        DhtConfig {
            identities: 1,
            bind_v4: None,
            bind_v6: None,
            ..DhtConfig::default()
        },
        tx.clone(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Config(_)));
    // A port that is already taken.
    let taken = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cfg = DhtConfig {
        bind_v4: Some(taken.local_addr().unwrap()),
        ..config(&[])
    };
    let err = Dht::start(cfg, tx).await.unwrap_err();
    assert!(matches!(err, Error::Bind { .. }));
}

#[tokio::test]
async fn full_sink_drops_and_counts() {
    // A sink of one slot: a second get_peers query is dropped, not buffered.
    let (tx, mut rx) = mpsc::channel(1);
    let node = Dht::start(config(&[]), tx).await.unwrap();
    let mut client = RawClient::new().await;
    for _ in 0..3 {
        let reply = client
            .call(
                addr(&node),
                Method::GetPeers {
                    info_hash: random_key(),
                    scrape: false,
                },
            )
            .await;
        assert!(response(&reply).token.is_some());
    }
    let stats = node.stats();
    assert_eq!(stats.discovered_emitted, 1);
    assert_eq!(stats.discovered_dropped, 2);
    let event = rx.recv().await.unwrap();
    assert_eq!(event.source, Source::GetPeers);
    assert_eq!(event.from, LOCALHOST_V4);
    // Dropping the last handle stops the node.
    let node_addr = addr(&node);
    drop(node);
    sleep(Duration::from_millis(200)).await;
    let tid = client.send_query(node_addr, Method::Ping).await;
    assert!(
        client
            .reply(node_addr, &tid, Duration::from_millis(500))
            .await
            .is_none()
    );
}

/// Sends `msg` to `to` from `client`'s socket.
async fn send_msg(client: &RawClient, to: SocketAddr, msg: &Message) {
    client
        .socket
        .send_to(&krpc::encode(msg).unwrap(), to)
        .await
        .unwrap();
}

/// A plain response to `query` that claims to come from `id`.
fn reply_as(query: &Message, id: NodeId) -> Message {
    Message {
        tid: query.tid.clone(),
        version: None,
        ip: None,
        read_only: false,
        body: Body::Response(Response {
            id,
            ..Response::default()
        }),
    }
}

/// A hand-encoded `sample_infohashes` response (it may exceed 1 024 bytes).
fn raw_sample_reply(tid: &[u8], id: NodeId, keys: &[DhtKey]) -> Vec<u8> {
    let mut out = b"d1:rd2:id20:".to_vec();
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(format!("8:intervali0e3:numi{}e7:samples", keys.len()).as_bytes());
    out.extend_from_slice(format!("{}:", keys.len() * 20).as_bytes());
    for key in keys {
        out.extend_from_slice(&key.0);
    }
    out.extend_from_slice(format!("e1:t{}:", tid.len()).as_bytes());
    out.extend_from_slice(tid);
    out.extend_from_slice(b"1:y1:re");
    out
}

/// Whether `observer` finds `node` among `at`'s confirmed nodes near `node.id`.
async fn advertises(observer: &mut RawClient, at: SocketAddr, node: CompactNode) -> bool {
    let reply = observer
        .call(at, Method::FindNode { target: node.id })
        .await;
    response(&reply)
        .nodes
        .as_ref()
        .is_some_and(|nodes| nodes.contains(&node))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_id_replies_count_as_failures() {
    timeout(Duration::from_secs(30), async {
        let (node, _rx) = start(DhtConfig {
            tuning: DhtTuning {
                node_questionable_after: Duration::from_millis(300),
                ..fast_tuning()
            },
            ..config(&[])
        })
        .await;
        let to = addr(&node);
        let mut peer = RawClient::new().await;
        let old = CompactNode {
            id: peer.id,
            addr: peer.addr(),
        };
        let new = CompactNode {
            id: NodeId::random(),
            addr: peer.addr(),
        };
        let mut observer = RawClient::new().await;
        // The peer is learned from its query and confirmed under its old ID.
        peer.call(to, Method::Ping).await;
        let query = peer.next_query_from(to, Duration::from_secs(5)).await;
        send_msg(&peer, to, &reply_as(&query.expect("no ping"), old.id)).await;
        wait_until("the old ID to be confirmed", Duration::from_secs(5), || {
            node.good_nodes() == 1
        })
        .await;
        assert!(advertises(&mut observer, to, old).await);
        // It restarts under a new ID on the same endpoint and keeps answering.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(q) = peer.next_query_from(to, Duration::from_millis(500)).await {
                send_msg(&peer, to, &reply_as(&q, new.id)).await;
            }
            if advertises(&mut observer, to, new).await {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the new ID was never learned: {:?}",
                node.routing_nodes()
            );
        }
        assert!(!advertises(&mut observer, to, old).await);
        node.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_only_responses_teach_nothing() {
    timeout(Duration::from_secs(30), async {
        let (node, _rx) = start(config(&[])).await;
        let to = addr(&node);
        let mut peer = RawClient::new().await;
        let me = CompactNode {
            id: peer.id,
            addr: peer.addr(),
        };
        let mut observer = RawClient::new().await;
        // Plain query: the node learns the peer and pings it back.
        peer.call(to, Method::Ping).await;
        // Answer every ping with ro=1 (BEP 43): delivered to the querier,
        // but must not confirm the responder or enter the table.
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut answered = 0u32;
        while Instant::now() < deadline {
            if let Some(q) = peer.next_query_from(to, Duration::from_millis(500)).await {
                let mut reply = reply_as(&q, me.id);
                reply.read_only = true;
                send_msg(&peer, to, &reply).await;
                answered += 1;
            }
        }
        assert!(answered > 0, "the node never pinged the peer back");
        assert_eq!(
            node.good_nodes(),
            0,
            "an ro=1 responder was confirmed as good"
        );
        assert!(
            !advertises(&mut observer, to, me).await,
            "an ro=1 responder is advertised"
        );
        node.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn junk_does_not_starve_replies() {
    timeout(Duration::from_secs(30), async {
        let (node, _rx) = start(config(&[])).await;
        let to = addr(&node);
        let mut peer = RawClient::new().await;
        let me = CompactNode {
            id: peer.id,
            addr: peer.addr(),
        };
        let mut observer = RawClient::new().await;
        peer.call(to, Method::Ping).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(q) = peer.next_query_from(to, Duration::from_secs(1)).await {
                // Junk from our endpoint (as a spoofer would send) empties
                // its inbound bucket right before the genuine reply.
                for _ in 0..30 {
                    peer.socket.send_to(b"x", to).await.unwrap();
                }
                send_msg(&peer, to, &reply_as(&q, me.id)).await;
            }
            sleep(Duration::from_millis(50)).await;
            if advertises(&mut observer, to, me).await {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the reply was dropped: {:?}",
                node.stats().v4.dropped
            );
        }
        assert!(node.stats().v4.dropped.rate_limited > 0);
        node.shutdown().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sample_replies_are_capped_and_checked() {
    timeout(Duration::from_secs(40), async {
        let (crawler, mut rx) = start(DhtConfig {
            sampler: true,
            ..config(&[])
        })
        .await;
        let to = addr(&crawler);
        let big: Vec<DhtKey> = (0..90u8)
            .map(|i| {
                let mut k = [1u8; 20];
                k[1] = i;
                DhtKey(k)
            })
            .collect();
        let foreign: Vec<DhtKey> = (0..10u8)
            .map(|i| {
                let mut k = [2u8; 20];
                k[1] = i;
                DhtKey(k)
            })
            .collect();
        // `honest` answers once with 90 samples; `liar` answers once under another ID.
        let mut peers = Vec::new();
        for (keys, wrong_id) in [(big, false), (foreign, true)] {
            let mut peer = RawClient::new().await;
            peer.call(to, Method::Ping).await;
            peers.push(tokio::spawn(async move {
                let mut answered = false;
                while let Some(q) = peer.next_query_from(to, Duration::from_secs(10)).await {
                    let Body::Query(query) = &q.body else {
                        continue;
                    };
                    if matches!(query.method, Method::SampleInfohashes { .. }) {
                        if !answered {
                            let id = if wrong_id { NodeId::random() } else { peer.id };
                            let bytes = raw_sample_reply(&q.tid, id, &keys);
                            peer.socket.send_to(&bytes, to).await.unwrap();
                            answered = true;
                        }
                    } else {
                        send_msg(&peer, to, &reply_as(&q, peer.id)).await;
                    }
                    if answered {
                        return;
                    }
                }
                panic!("the crawler never sampled this peer");
            }));
        }
        for peer in peers {
            peer.await.unwrap();
        }
        sleep(Duration::from_millis(500)).await;
        let events: Vec<Discovered> = drain(&mut rx)
            .into_iter()
            .filter(|e| e.source == Source::Sample)
            .collect();
        let honest = events.iter().filter(|e| e.key.0[0] == 1).count();
        let liar = events.iter().filter(|e| e.key.0[0] == 2).count();
        assert!(
            (1..=20).contains(&honest),
            "{honest} samples from one reply"
        );
        assert_eq!(liar, 0, "samples from a reply under another ID");
        crawler.shutdown().await;
    })
    .await
    .expect("test timed out");
}
