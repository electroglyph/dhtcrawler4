//! Iterative Kademlia lookups: `find_node`, `get_peers` and `announce`.
//!
//! A lookup queries the closest known nodes in rounds of α = 3. It stops when
//! a round that got answers finds nothing closer (after one final sweep over
//! the K closest nodes not yet asked), after 8 rounds, or at its deadline.
//! A query that has not answered within `query_slow_after` no longer holds
//! up its round, but its reply is still used if it arrives in time.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use dc4_core::DhtKey;
use futures::StreamExt;
use futures::future::join_all;
use futures::stream::FuturesUnordered;
use tokio::time::Instant;

use crate::compact::{AddrKey, AddrPolicy, CompactNode, Family, OwnAddrs, canonical_addr};
use crate::krpc::{Method, Response};
use crate::node::{Inner, QueryError, SocketNode};
use crate::node_id::{Distance, NodeId};
use crate::routing::K;
use crate::util::{after, lock};

/// Queries per round.
pub(crate) const ALPHA: usize = 3;
/// Rounds per lookup.
pub(crate) const MAX_ROUNDS: usize = 8;
/// Candidates remembered per lookup.
const MAX_CANDIDATES: usize = 128;
/// Candidates admitted from one /24 (IPv4) or /64 (IPv6): without a cap,
/// one responder returning distinct (ID, same-IP:port) pairs could occupy
/// a large fraction of [`MAX_CANDIDATES`] over rounds.
const MAX_CANDIDATES_PER_SUBNET: usize = 8;
/// Nodes taken from one response.
const MAX_NODES_PER_RESPONSE: usize = 16;
/// Peers collected per lookup.
pub(crate) const MAX_LOOKUP_PEERS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    FindNode,
    GetPeers,
    /// BEP 33 scrape: a `get_peers` traversal with `scrape=1` that also
    /// collects `BFsd`/`BFpe` filters from aware responses.
    Scrape,
    /// Fetch traversal: same wire shape as [`Kind::Scrape`]
    /// (`scrape=1`, filters collected) but charging the dedicated fetch
    /// budget instead of the scrape budget.
    FetchPeers,
}

/// Which outbound budget a traversal charges: crawl, scrape or fetch.
/// Pure so tests can pin the routing without network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Budget {
    Main,
    Scrape,
    Fetch,
}

impl Kind {
    /// The wire query of this traversal kind.
    fn method(self, target: NodeId) -> Method {
        match self {
            Kind::FindNode => Method::FindNode { target },
            Kind::GetPeers => Method::GetPeers {
                info_hash: DhtKey::from(target),
                scrape: false,
            },
            Kind::Scrape | Kind::FetchPeers => Method::GetPeers {
                info_hash: DhtKey::from(target),
                scrape: true,
            },
        }
    }

    /// The budget this traversal charges.
    fn budget(self) -> Budget {
        match self {
            Kind::FindNode | Kind::GetPeers => Budget::Main,
            Kind::Scrape => Budget::Scrape,
            Kind::FetchPeers => Budget::Fetch,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandState {
    Fresh,
    InFlight,
    Responded,
    Failed,
}

struct Candidate {
    node: CompactNode,
    dist: Distance,
    state: CandState,
    token: Option<Vec<u8>>,
}

/// What a lookup found.
pub(crate) struct Outcome {
    /// Nodes that answered, closest first (at most K), with their tokens.
    pub(crate) closest: Vec<(CompactNode, Option<Vec<u8>>)>,
    /// Dialable peers from `values`, IPv4-mapped ones as IPv4 (get_peers only).
    pub(crate) peers: Vec<SocketAddr>,
}

/// What a scrape traversal found: like [`Outcome`] plus the BEP 33
/// filters of every aware response (one entry per response that carried
/// filter keys) and the aware/unaware response counts.
pub(crate) struct ScrapeOutcome {
    /// Dialable peers from `values`, IPv4-mapped ones as IPv4.
    pub(crate) peers: Vec<SocketAddr>,
    /// `BFsd` filters of aware responses (seeds).
    pub(crate) seed_filters: Vec<[u8; crate::bloom::BLOOM_LEN]>,
    /// `BFpe` filters of aware responses (peers).
    pub(crate) peer_filters: Vec<[u8; crate::bloom::BLOOM_LEN]>,
    /// Responses that carried filter keys.
    pub(crate) aware: usize,
    /// Responses without filter keys.
    pub(crate) unaware: usize,
}

/// The pure bookkeeping of one lookup.
struct Lookup {
    target: NodeId,
    kind: Kind,
    family: Family,
    policy: AddrPolicy,
    own_ids: Vec<NodeId>,
    own: Arc<OwnAddrs>,
    /// Sorted by distance to `target`.
    cands: Vec<Candidate>,
    /// Live per-subnet candidate counts backing the
    /// `MAX_CANDIDATES_PER_SUBNET` cap, so `add` does one map lookup
    /// instead of recomputing every candidate's subnet key per call.
    /// Entries with a zero count are removed; the counts always sum to
    /// `cands.len()`.
    subnet_counts: HashMap<AddrKey, u8>,
    seen_addrs: HashSet<SocketAddr>,
    seen_ids: HashSet<NodeId>,
    peers: Vec<SocketAddr>,
    peer_set: HashSet<SocketAddr>,
    /// `BFsd` filters of aware scrape responses (one per response).
    seed_filters: Vec<[u8; crate::bloom::BLOOM_LEN]>,
    /// `BFpe` filters of aware scrape responses (one per response).
    peer_filters: Vec<[u8; crate::bloom::BLOOM_LEN]>,
    /// Scrape responses that carried filter keys.
    aware: usize,
    /// Scrape responses without filter keys.
    unaware: usize,
    /// Aware scrape responses whose own `BFsd` estimates nonzero (one live
    /// proof each, §4b win 2). Only these may end the traversal early; a
    /// dead verdict always needs the full traversal.
    live_proofs: usize,
}

impl Lookup {
    fn new(
        target: NodeId,
        kind: Kind,
        family: Family,
        policy: AddrPolicy,
        own: Arc<OwnAddrs>,
    ) -> Self {
        Self {
            target,
            kind,
            family,
            policy,
            own_ids: Vec::new(),
            own,
            cands: Vec::new(),
            subnet_counts: HashMap::new(),
            seen_addrs: HashSet::new(),
            seen_ids: HashSet::new(),
            peers: Vec::new(),
            peer_set: HashSet::new(),
            seed_filters: Vec::new(),
            peer_filters: Vec::new(),
            aware: 0,
            unaware: 0,
            live_proofs: 0,
        }
    }

    /// Adds a candidate; returns its distance if it was new. Candidates of
    /// another family (including IPv4-mapped ones), non-dialable addresses
    /// and our own IDs and addresses are ignored.
    fn add(&mut self, node: CompactNode) -> Option<Distance> {
        if self.own_ids.contains(&node.id)
            || Family::of(&node.addr) != self.family
            || canonical_addr(node.addr) != node.addr
            || !self.policy.dialable(&node.addr)
            || self.own.contains(&node.addr, self.policy)
            || self.seen_addrs.contains(&node.addr)
            || self.seen_ids.contains(&node.id)
        {
            return None;
        }
        let subnet = self.policy.subnet_key(&node.addr);
        if self.subnet_counts.get(&subnet).copied().unwrap_or(0) as usize
            >= MAX_CANDIDATES_PER_SUBNET
        {
            return None;
        }
        let dist = node.id.distance(&self.target);
        let pos = self.cands.partition_point(|c| c.dist < dist);
        if pos >= MAX_CANDIDATES {
            return None;
        }
        self.seen_addrs.insert(node.addr);
        self.seen_ids.insert(node.id);
        self.subnet_counts
            .entry(subnet)
            .and_modify(|c| *c = c.saturating_add(1))
            .or_insert(1);
        self.cands.insert(
            pos,
            Candidate {
                node,
                dist,
                state: CandState::Fresh,
                token: None,
            },
        );
        if self.cands.len() > MAX_CANDIDATES
            && let Some(i) = self
                .cands
                .iter()
                .rposition(|c| matches!(c.state, CandState::Fresh | CandState::Failed))
        {
            let removed = self.cands.remove(i);
            let key = self.policy.subnet_key(&removed.node.addr);
            if let Some(count) = self.subnet_counts.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.subnet_counts.remove(&key);
                }
            }
            if i == pos {
                // The newcomer evicted itself: no farther fresh candidate
                // existed, so it is not retained. Roll back the admission
                // marks so a later call may admit it again, and report
                // non-admission instead of a phantom success.
                self.seen_addrs.remove(&removed.node.addr);
                self.seen_ids.remove(&removed.node.id);
                return None;
            }
        }
        Some(dist)
    }

    fn best_live(&self) -> Option<Distance> {
        self.cands
            .iter()
            .find(|c| c.state != CandState::Failed)
            .map(|c| c.dist)
    }

    /// Up to `n` unasked nodes among the K closest live candidates, marked in flight.
    fn pick(&mut self, n: usize) -> Vec<CompactNode> {
        let mut out = Vec::new();
        let mut live = 0usize;
        for c in &mut self.cands {
            if c.state == CandState::Failed {
                continue;
            }
            if live >= K || out.len() >= n {
                break;
            }
            live = live.saturating_add(1);
            if c.state == CandState::Fresh {
                c.state = CandState::InFlight;
                out.push(c.node);
            }
        }
        out
    }

    /// Records a reply. Returns true if it revealed a node closer than `best_before`.
    fn complete(
        &mut self,
        addr: SocketAddr,
        result: Result<Response, QueryError>,
        best_before: Option<Distance>,
    ) -> bool {
        let Some(cand) = self.cands.iter_mut().find(|c| c.node.addr == addr) else {
            return false;
        };
        let response = match result {
            Ok(r) if r.id == cand.node.id => r,
            _ => {
                cand.state = CandState::Failed;
                return false;
            }
        };
        cand.state = CandState::Responded;
        cand.token = response.token;
        if self.kind == Kind::GetPeers || self.kind == Kind::Scrape || self.kind == Kind::FetchPeers
        {
            for peer in response.values.unwrap_or_default() {
                if self.peers.len() >= MAX_LOOKUP_PEERS {
                    break;
                }
                let peer = canonical_addr(peer);
                // A response on this socket's family must not seed the
                // traversal with the other family's peers, nor with our
                // own addresses (mirrors the `own` filter in `add`).
                if Family::of(&peer) == self.family
                    && self.policy.dialable(&peer)
                    && !self.own.contains(&peer, self.policy)
                    && self.peer_set.insert(peer)
                {
                    self.peers.push(peer);
                }
            }
        }
        if self.kind == Kind::Scrape || self.kind == Kind::FetchPeers {
            match (response.bf_sd, response.bf_pe) {
                (None, None) => {
                    self.unaware = self.unaware.saturating_add(1);
                }
                (Some(sd), Some(pe)) => {
                    self.aware = self.aware.saturating_add(1);
                    // A class the responder had no members of arrives as
                    // an empty (all-zero) filter estimating to 0; a
                    // response whose own seeds filter estimates nonzero
                    // is one live proof for the early exit (win 2); zeros
                    // and saturated filters prove nothing and never count.
                    // The estimate reads the wire bytes in place.
                    let live = crate::bloom::estimate_array(&sd).is_some_and(|e| e > 0.0);
                    if live {
                        self.live_proofs = self.live_proofs.saturating_add(1);
                    }
                    self.seed_filters.push(*sd);
                    self.peer_filters.push(*pe);
                }
                // One half present without the other: our responder always
                // sends both or neither, so this is a malformed reply. It
                // counts as unaware, never aware: an aware count plus a
                // zero seed filter would turn UNKNOWN (no estimate) into a
                // zero estimate (dead), letting one malformed reply steer
                // a swarm toward a tombstone.
                _ => {
                    self.unaware = self.unaware.saturating_add(1);
                }
            }
        }
        let nodes = match self.family {
            Family::V4 => response.nodes,
            Family::V6 => response.nodes6,
        };
        let mut improved = false;
        for node in nodes
            .unwrap_or_default()
            .into_iter()
            .take(MAX_NODES_PER_RESPONSE)
        {
            if let Some(d) = self.add(node)
                && best_before.is_none_or(|b| d < b)
            {
                improved = true;
            }
        }
        improved
    }

    fn outcome(self) -> Outcome {
        let closest = self
            .cands
            .into_iter()
            .filter(|c| c.state == CandState::Responded)
            .take(K)
            .map(|c| (c.node, c.token))
            .collect();
        Outcome {
            closest,
            peers: self.peers,
        }
    }

    fn scrape_outcome(self) -> ScrapeOutcome {
        ScrapeOutcome {
            peers: self.peers,
            seed_filters: self.seed_filters,
            peer_filters: self.peer_filters,
            aware: self.aware,
            unaware: self.unaware,
        }
    }

    /// Closest responded nodes, for the scrape node-list cache (win 2).
    /// Borrowed so the outcome stays available to the caller.
    fn closest_responded(&self) -> Vec<(CompactNode, Option<Vec<u8>>)> {
        self.cands
            .iter()
            .filter(|c| c.state == CandState::Responded)
            .take(K)
            .map(|c| (c.node, c.token.clone()))
            .collect()
    }
}

async fn ask(
    inner: &Inner,
    sock: &SocketNode,
    node: CompactNode,
    kind: Kind,
    target: NodeId,
) -> (SocketAddr, Result<Response, QueryError>) {
    // The budget dispatch is load-bearing (see `Kind::budget`): scrape and
    // fetch share the `scrape=1` wire shape but must never share a bucket.
    let method = kind.method(target);
    let reply = match kind.budget() {
        Budget::Main => inner.query(sock, node.addr, method, Some(node.id)).await,
        Budget::Scrape => {
            inner
                .query_scrape(sock, node.addr, method, Some(node.id))
                .await
        }
        Budget::Fetch => {
            inner
                .query_fetch(sock, node.addr, method, Some(node.id))
                .await
        }
    };
    (node.addr, reply)
}

/// Whether a reply counts towards `answered` for the final-sweep decision:
/// only an answer under the queried node's own ID. Wrong-ID replies fail
/// their candidate in [`Lookup::complete`] and must not trigger the final
/// sweep on their own.
fn counts_as_answered(
    batch: &[CompactNode],
    addr: &SocketAddr,
    result: &Result<Response, QueryError>,
) -> bool {
    match result {
        Ok(response) => batch.iter().any(|n| n.addr == *addr && n.id == response.id),
        Err(_) => false,
    }
}

async fn run(
    inner: &Inner,
    sock: &SocketNode,
    target: NodeId,
    kind: Kind,
    seeds: Vec<CompactNode>,
    deadline: Instant,
) -> Lookup {
    let tuning = &inner.cfg.tuning;
    let now = Instant::now();
    let mut lookup = Lookup::new(target, kind, sock.family, inner.policy, inner.own());
    lookup.own_ids = inner.own_ids();
    let known = lock(&sock.state).table.closest(&target, K, now, false);
    for node in known.into_iter().chain(seeds) {
        lookup.add(node);
    }

    let mut in_flight = FuturesUnordered::new();
    let mut rounds = 0usize;
    let mut final_sweep = false;
    // Live-only early exit (§4b win 2): a quorum of agreeing nonzero
    // responses proves the swarm live, so the traversal may stop and the
    // caller stores the partial-union lower bound. Zeros never stop early:
    // a dead verdict always needs the full traversal (LB-28).
    let quorum = if kind == Kind::Scrape || kind == Kind::FetchPeers {
        tuning.scrape_early_exit_quorum
    } else {
        0
    };
    let exited_early = |lookup: &Lookup| quorum > 0 && lookup.live_proofs >= quorum;
    'rounds: loop {
        if Instant::now() >= deadline || inner.cancel.is_cancelled() {
            break;
        }
        let batch = lookup.pick(if final_sweep { K } else { ALPHA });
        if batch.is_empty() {
            // Nothing left to ask; late replies may still add candidates.
            let next = tokio::select! {
                next = in_flight.next() => next,
                () = tokio::time::sleep_until(deadline) => None,
            };
            match next {
                Some((addr, result)) => {
                    lookup.complete(addr, result, None);
                    if exited_early(&lookup) {
                        break 'rounds;
                    }
                    continue;
                }
                None => break,
            }
        }
        rounds = rounds.saturating_add(1);
        let best_before = lookup.best_live();
        // Batches hold at most ALPHA nodes (K on the final sweep), so a
        // linear scan beats hashing a fresh set every round.
        let mut waiting = batch.len();
        for node in &batch {
            in_flight.push(ask(inner, sock, *node, kind, target));
        }
        let slow_at = after(Instant::now(), tuning.query_slow_after).min(deadline);
        let mut answered = 0usize;
        let mut improved = false;
        while waiting > 0 {
            let next = tokio::select! {
                next = in_flight.next() => next,
                () = tokio::time::sleep_until(slow_at) => None,
            };
            let Some((addr, result)) = next else { break };
            if batch.iter().any(|n| n.addr == addr) {
                waiting = waiting.saturating_sub(1);
                if counts_as_answered(&batch, &addr, &result) {
                    answered = answered.saturating_add(1);
                }
            }
            improved |= lookup.complete(addr, result, best_before);
            if exited_early(&lookup) {
                break 'rounds;
            }
        }
        if final_sweep || rounds >= MAX_ROUNDS {
            break;
        }
        if answered > 0 && !improved {
            final_sweep = true;
        }
    }
    lookup
}

/// Iterative `get_peers` for `key`.
pub(crate) async fn get_peers(
    inner: &Inner,
    sock: &SocketNode,
    key: DhtKey,
    deadline: Instant,
) -> Outcome {
    run(
        inner,
        sock,
        NodeId::from(key),
        Kind::GetPeers,
        Vec::new(),
        deadline,
    )
    .await
    .outcome()
}

/// Iterative BEP 33 scrape for `key`: a `get_peers` traversal with
/// `scrape=1` on the dedicated scrape budget, seeded from the node-list
/// cache when warm (win 2) and writing its closest nodes back after.
/// Unions and estimation happen in the caller via [`ScrapeOutcome`].
pub(crate) async fn scrape(
    inner: &Inner,
    sock: &SocketNode,
    key: DhtKey,
    deadline: Instant,
) -> ScrapeOutcome {
    let seeds = inner.scrape_cache_seeds(&key);
    let lookup = run(
        inner,
        sock,
        NodeId::from(key),
        Kind::Scrape,
        seeds,
        deadline,
    )
    .await;
    inner.scrape_cache_store(key, &lookup.closest_responded());
    lookup.scrape_outcome()
}

/// Iterative fetch traversal for `key`: a `get_peers`
/// traversal with `scrape=1` on the dedicated fetch budget, seeded from
/// the node-list cache when warm and writing its closest nodes back after.
/// The `scrape: true` piggyback is load-bearing: the BEP 33 seed filters
/// feed the queue's liveness ordering, so fetch must keep collecting them.
/// Unions and estimation happen in the caller via [`ScrapeOutcome`].
pub(crate) async fn scrape_fetch(
    inner: &Inner,
    sock: &SocketNode,
    key: DhtKey,
    deadline: Instant,
) -> ScrapeOutcome {
    let seeds = inner.scrape_cache_seeds(&key);
    let lookup = run(
        inner,
        sock,
        NodeId::from(key),
        Kind::FetchPeers,
        seeds,
        deadline,
    )
    .await;
    inner.scrape_cache_store(key, &lookup.closest_responded());
    lookup.scrape_outcome()
}

/// Iterative `find_node` towards `target`, starting from the routing table plus `seeds`.
pub(crate) async fn find_node(
    inner: &Inner,
    sock: &SocketNode,
    target: NodeId,
    seeds: Vec<CompactNode>,
    deadline: Instant,
) -> Outcome {
    run(inner, sock, target, Kind::FindNode, seeds, deadline)
        .await
        .outcome()
}

/// `get_peers` for `key`, then `announce_peer` to the (up to K) closest nodes
/// that gave a token. Returns the number of successful replies.
pub(crate) async fn announce(
    inner: &Inner,
    sock: &SocketNode,
    key: DhtKey,
    port: u16,
    deadline: Instant,
) -> usize {
    let outcome = get_peers(inner, sock, key, deadline).await;
    let targets: Vec<(CompactNode, Vec<u8>)> = outcome
        .closest
        .into_iter()
        .filter_map(|(node, token)| token.map(|t| (node, t)))
        .take(K)
        .collect();
    let replies = join_all(targets.into_iter().map(|(node, token)| {
        let method = Method::AnnouncePeer {
            info_hash: key,
            port,
            implied_port: false,
            token,
            seed: false,
        };
        inner.query(sock, node.addr, method, Some(node.id))
    }))
    .await;
    replies.iter().filter(|r| r.is_ok()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRODUCTION: AddrPolicy = AddrPolicy {
        allow_private: false,
        by_endpoint: false,
    };

    fn lookup(target: NodeId, kind: Kind, own: OwnAddrs) -> Lookup {
        Lookup::new(target, kind, Family::V4, PRODUCTION, Arc::new(own))
    }

    fn node(i: u8, id: NodeId) -> CompactNode {
        CompactNode {
            id,
            addr: SocketAddr::from(([8, 8, i, 1], 6881)),
        }
    }

    fn reply(id: NodeId, nodes: Vec<CompactNode>) -> Response {
        Response {
            id,
            nodes: Some(nodes),
            ..Response::default()
        }
    }

    #[test]
    fn candidates_are_sorted_filtered_and_bounded() {
        let target = NodeId([0; 20]);
        let mut own = OwnAddrs::default();
        own.add("8.8.200.1:6881".parse().unwrap());
        let mut l = lookup(target, Kind::FindNode, own);
        l.own_ids = vec![NodeId([1; 20])];
        let at = |addr: &str| CompactNode {
            id: NodeId([2; 20]),
            addr: addr.parse().unwrap(),
        };
        assert!(l.add(node(1, NodeId([1; 20]))).is_none()); // our own ID
        assert!(l.add(at("8.8.200.1:6881")).is_none()); // our own address
        assert!(l.add(at("8.8.200.1:6882")).is_none()); // our own IP
        assert!(l.add(at("10.0.0.1:1")).is_none());
        assert!(l.add(at("8.8.8.8:0")).is_none());
        assert!(l.add(at("[2a00::1]:1")).is_none());
        assert!(l.add(at("[::ffff:8.8.8.8]:1")).is_none());
        assert!(l.add(node(3, NodeId([9; 20]))).is_some());
        assert!(l.add(node(3, NodeId([8; 20]))).is_none()); // same address
        assert!(l.add(node(4, NodeId([9; 20]))).is_none()); // same ID
        assert!(l.add(node(5, NodeId([3; 20]))).is_some());
        assert_eq!(l.cands[0].node.id, NodeId([3; 20]));
        for i in 0..250u32 {
            let mut id = [0xff; 20];
            id[16..].copy_from_slice(&i.to_be_bytes());
            l.add(CompactNode {
                id: NodeId(id),
                addr: SocketAddr::from(([9, (i >> 8) as u8, i as u8, 1], 1)),
            });
        }
        assert!(l.cands.len() <= MAX_CANDIDATES);
        assert!(l.cands.windows(2).all(|w| w[0].dist <= w[1].dist));
    }

    #[test]
    fn one_subnet_cannot_fill_the_candidates() {
        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::FindNode, OwnAddrs::default());
        let mut admitted = 0;
        for i in 0..16u8 {
            let mut id = [0xaa; 20];
            id[19] = i;
            let admitted_now = l
                .add(CompactNode {
                    id: NodeId(id),
                    addr: SocketAddr::from(([1, 2, 3, 4], 1000 + u16::from(i))),
                })
                .is_some();
            admitted += usize::from(admitted_now);
        }
        assert_eq!(admitted, MAX_CANDIDATES_PER_SUBNET);
        // Other subnets are unaffected.
        let mut other = [0xbb; 20];
        other[19] = 0xff;
        assert!(
            l.add(CompactNode {
                id: NodeId(other),
                addr: SocketAddr::from(([9, 9, 9, 9], 1000)),
            })
            .is_some()
        );
    }

    #[test]
    fn returned_peers_exclude_our_own_addresses() {
        let target = NodeId([0; 20]);
        let mut own = OwnAddrs::default();
        let ours: SocketAddr = "8.8.200.1:6881".parse().unwrap();
        own.add(ours);
        let mut l = lookup(target, Kind::GetPeers, own);
        let responder = CompactNode {
            id: NodeId([7; 20]),
            addr: SocketAddr::from(([9, 9, 9, 9], 6881)),
        };
        assert!(l.add(responder).is_some());
        let good: SocketAddr = "8.8.8.8:6881".parse().unwrap();
        let response = Response {
            id: responder.id,
            values: Some(vec![ours, good]),
            ..Response::default()
        };
        l.complete(responder.addr, Ok(response), None);
        assert_eq!(l.peers, vec![good]);
    }

    #[test]
    fn only_matching_ids_count_as_answered() {
        let addr: SocketAddr = "8.8.8.8:6881".parse().unwrap();
        let batch = vec![CompactNode {
            id: NodeId([7; 20]),
            addr,
        }];
        let matching = || Response {
            id: NodeId([7; 20]),
            ..Response::default()
        };
        assert!(counts_as_answered(&batch, &addr, &Ok(matching())));
        let spoofed = Response {
            id: NodeId([9; 20]),
            ..Response::default()
        };
        assert!(!counts_as_answered(&batch, &addr, &Ok(spoofed)));
        assert!(!counts_as_answered(
            &batch,
            &addr,
            &Err(QueryError::Timeout)
        ));
        let elsewhere: SocketAddr = "8.8.4.4:6881".parse().unwrap();
        assert!(!counts_as_answered(&batch, &elsewhere, &Ok(matching())));
    }

    #[test]
    fn subnet_counts_track_admissions_and_evictions() {
        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::FindNode, OwnAddrs::default());
        let capped_subnet = PRODUCTION.subnet_key(&SocketAddr::from(([1, 2, 3, 4], 1)));
        // Fill one subnet to its cap with the farthest nodes, so later
        // overflow evicts them first.
        for i in 0..MAX_CANDIDATES_PER_SUBNET as u8 {
            let mut id = [0xff; 20];
            id[19] = i;
            assert!(
                l.add(CompactNode {
                    id: NodeId(id),
                    addr: SocketAddr::from(([1, 2, 3, 4], 1000 + u16::from(i))),
                })
                .is_some()
            );
        }
        // One more from the capped subnet is rejected.
        let mut capped = [0xff; 20];
        capped[19] = 0xff;
        assert!(
            l.add(CompactNode {
                id: NodeId(capped),
                addr: SocketAddr::from(([1, 2, 3, 4], 2000)),
            })
            .is_none()
        );
        // Overflow with closer nodes from other subnets evicts the far
        // capped ones, reopening that subnet.
        for i in 0..125u32 {
            let mut id = [0x10; 20];
            id[16..].copy_from_slice(&i.to_be_bytes());
            l.add(CompactNode {
                id: NodeId(id),
                addr: SocketAddr::from(([9, (i % 32) as u8, (i / 32) as u8, 1], 1)),
            });
        }
        assert_eq!(l.cands.len(), MAX_CANDIDATES);
        assert_eq!(l.subnet_counts.get(&capped_subnet), Some(&3));
        let mut reopened = [0x10; 20];
        reopened[16..].copy_from_slice(&1000u32.to_be_bytes());
        assert!(
            l.add(CompactNode {
                id: NodeId(reopened),
                addr: SocketAddr::from(([1, 2, 3, 4], 2000)),
            })
            .is_some()
        );
        // The counters always mirror the candidate list exactly.
        let mut recount: HashMap<AddrKey, u8> = HashMap::new();
        for c in &l.cands {
            *recount
                .entry(l.policy.subnet_key(&c.node.addr))
                .or_default() += 1;
        }
        assert_eq!(recount, l.subnet_counts);
        assert_eq!(
            l.subnet_counts
                .values()
                .map(|c| usize::from(*c))
                .sum::<usize>(),
            l.cands.len()
        );
        assert!(
            l.subnet_counts
                .values()
                .all(|c| usize::from(*c) <= MAX_CANDIDATES_PER_SUBNET)
        );
    }

    #[test]
    fn full_table_reports_self_eviction_as_non_admission() {
        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::FindNode, OwnAddrs::default());
        for i in 0..128u32 {
            let mut id = [0xff; 20];
            id[16..].copy_from_slice(&i.to_be_bytes());
            assert!(
                l.add(CompactNode {
                    id: NodeId(id),
                    addr: SocketAddr::from(([9, (i >> 8) as u8, i as u8, 1], 1)),
                })
                .is_some()
            );
        }
        assert_eq!(l.cands.len(), MAX_CANDIDATES);
        for c in &mut l.cands {
            c.state = CandState::InFlight;
        }
        let mut close = [0x10; 20];
        close[19] = 0x01;
        let node = CompactNode {
            id: NodeId(close),
            addr: SocketAddr::from(([8, 8, 8, 8], 6881)),
        };
        assert!(l.add(node).is_none());
        assert_eq!(l.cands.len(), MAX_CANDIDATES);
        // The failed admission left no permanent mark: once a slot frees,
        // the same node admits normally.
        l.cands[10].state = CandState::Failed;
        assert!(l.add(node).is_some());
        assert_eq!(l.cands.len(), MAX_CANDIDATES);
    }

    #[test]
    fn rounds_pick_the_closest_unasked() {
        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::GetPeers, OwnAddrs::default());
        for i in 1..=12u8 {
            l.add(node(i, NodeId([i; 20])));
        }
        let first = l.pick(ALPHA);
        assert_eq!(
            first.iter().map(|n| n.id.0[0]).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // Node 1 fails, node 2 answers with a closer node and peers, node 3 answers with nothing new.
        let best = l.best_live();
        assert!(!l.complete(first[0].addr, Err(QueryError::Timeout), best));
        let mut r = reply(NodeId([2; 20]), vec![node(50, NodeId([0; 20]))]);
        r.token = Some(b"tok".to_vec());
        r.values = Some(
            [
                "1.1.1.1:1",
                "10.0.0.1:1",
                "1.1.1.1:1",
                "[::ffff:1.1.1.1]:1",
                "[::ffff:2.2.2.2]:2",
                "1.1.1.1:0",
            ]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        );
        assert!(l.complete(first[1].addr, Ok(r), best));
        assert!(!l.complete(first[2].addr, Ok(reply(NodeId([3; 20]), vec![])), best));
        // A reply claiming a different ID counts as a failure.
        let next = l.pick(1);
        assert_eq!(next[0].id, NodeId([0; 20]));
        assert!(!l.complete(next[0].addr, Ok(reply(NodeId([7; 20]), vec![])), best));
        // The K closest live candidates bound what can still be picked.
        let rest = l.pick(K);
        assert_eq!(
            rest.iter().map(|n| n.id.0[0]).collect::<Vec<_>>(),
            vec![4, 5, 6, 7, 8, 9]
        );
        assert!(l.pick(K).is_empty());
        let outcome = l.outcome();
        let peers: Vec<SocketAddr> = ["1.1.1.1:1", "2.2.2.2:2"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(outcome.peers, peers);
        let closest: Vec<_> = outcome
            .closest
            .iter()
            .map(|(n, t)| (n.id.0[0], t.clone()))
            .collect();
        assert_eq!(closest, vec![(2, Some(b"tok".to_vec())), (3, None)]);
    }

    #[test]
    fn scrape_collects_filters_and_estimates_seeders() {
        use crate::bloom::ScrapeBloom;
        use std::net::IpAddr;

        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::Scrape, OwnAddrs::default());
        for i in 1..=3u8 {
            l.add(node(i, NodeId([i; 20])));
        }
        let batch = l.pick(ALPHA);
        let best = l.best_live();
        // One aware response: one seed IP in BFsd, empty BFpe.
        let mut sd = ScrapeBloom::empty();
        sd.insert_ip(&"9.9.9.9".parse::<IpAddr>().unwrap());
        let mut r = reply(NodeId([1; 20]), vec![]);
        r.bf_sd = Some(Box::new(sd.0));
        r.bf_pe = Some(Box::new([0u8; crate::bloom::BLOOM_LEN]));
        assert!(!l.complete(batch[0].addr, Ok(r), best));
        // One unaware response (no filter keys) still counts as answered.
        assert!(!l.complete(batch[1].addr, Ok(reply(NodeId([2; 20]), vec![])), best));
        let out = l.scrape_outcome();
        assert_eq!(out.aware, 1);
        assert_eq!(out.unaware, 1);
        assert_eq!(out.seed_filters.len(), 1);
        assert_eq!(out.peer_filters.len(), 1);
        // One seed across the union estimates to 1; the empty peer
        // union estimates to 0, never UNKNOWN.
        assert_eq!(crate::bloom::estimate_or(&out.seed_filters), Some(1));
        assert_eq!(crate::bloom::estimate_or(&out.peer_filters), Some(0));
        // No aware response at all is UNKNOWN.
        let empty = ScrapeOutcome {
            peers: Vec::new(),
            seed_filters: Vec::new(),
            peer_filters: Vec::new(),
            aware: 0,
            unaware: 3,
        };
        assert_eq!(crate::bloom::estimate_or(&empty.seed_filters), None);
    }

    #[test]
    fn fetch_peers_preserves_scrape_filters() {
        // load-bearing invariant: the fetch traversal keeps
        // `scrape: true` so the BEP 33 seed filters still feed the queue's
        // liveness ordering. `Kind::FetchPeers` must collect peers,
        // filters and live proofs exactly like `Kind::Scrape`.
        use crate::bloom::ScrapeBloom;
        use std::net::IpAddr;

        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::FetchPeers, OwnAddrs::default());
        for i in 1..=3u8 {
            l.add(node(i, NodeId([i; 20])));
        }
        let batch = l.pick(ALPHA);
        let best = l.best_live();
        let mut sd = ScrapeBloom::empty();
        sd.insert_ip(&"9.9.9.9".parse::<IpAddr>().unwrap());
        let mut r = reply(NodeId([1; 20]), vec![]);
        r.bf_sd = Some(Box::new(sd.0));
        r.bf_pe = Some(Box::new([0u8; crate::bloom::BLOOM_LEN]));
        r.values = Some(vec!["1.1.1.1:1".parse().unwrap()]);
        assert!(!l.complete(batch[0].addr, Ok(r), best));
        assert!(!l.complete(batch[1].addr, Ok(reply(NodeId([2; 20]), vec![])), best));
        assert_eq!(l.live_proofs, 1);
        let out = l.scrape_outcome();
        assert_eq!(out.peers, vec!["1.1.1.1:1".parse().unwrap()]);
        assert_eq!(out.aware, 1);
        assert_eq!(out.unaware, 1);
        assert_eq!(out.seed_filters.len(), 1);
        assert_eq!(crate::bloom::estimate_or(&out.seed_filters), Some(1));
    }

    #[test]
    fn kind_routes_fetch_to_its_own_budget() {
        // WS1: scrape and fetch share the `scrape=1` wire shape (so the BEP
        // 33 seed filters still feed the queue's liveness ordering) but must
        // never share a bucket. `ask` dispatches on both halves together, so
        // pin them together: a refactor that moves one without the other
        // fails here, not as a production starvation.
        let target = NodeId([7; 20]);
        let scraped = Method::GetPeers {
            info_hash: DhtKey::from(target),
            scrape: true,
        };
        assert_eq!(Kind::Scrape.method(target), scraped);
        assert_eq!(Kind::FetchPeers.method(target), scraped);
        assert_eq!(Kind::Scrape.budget(), Budget::Scrape);
        assert_eq!(Kind::FetchPeers.budget(), Budget::Fetch);
        // The crawl kinds keep the main bucket, and plain `get_peers`
        // stays `scrape=false`.
        assert_eq!(Kind::FindNode.budget(), Budget::Main);
        assert_eq!(Kind::GetPeers.budget(), Budget::Main);
        assert_eq!(Kind::FindNode.method(target), Method::FindNode { target });
        assert_eq!(
            Kind::GetPeers.method(target),
            Method::GetPeers {
                info_hash: DhtKey::from(target),
                scrape: false,
            }
        );
    }

    #[test]
    fn closest_responded_feeds_the_node_cache() {
        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::Scrape, OwnAddrs::default());
        for i in 1..=4u8 {
            l.add(node(i, NodeId([i; 20])));
        }
        let batch = l.pick(2);
        let best = l.best_live();
        assert!(!l.complete(batch[0].addr, Ok(reply(NodeId([1; 20]), vec![])), best));
        assert!(!l.complete(batch[1].addr, Err(QueryError::Timeout), best));
        // Only responded candidates are remembered, with their tokens.
        let closest = l.closest_responded();
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].0.id, NodeId([1; 20]));
        assert!(closest[0].1.is_none());
    }

    #[test]
    fn scrape_counts_live_proofs_for_the_early_exit() {
        use crate::bloom::ScrapeBloom;
        use std::net::IpAddr;

        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::Scrape, OwnAddrs::default());
        for i in 1..=5u8 {
            l.add(node(i, NodeId([i; 20])));
        }
        let batch = l.pick(ALPHA);
        let best = l.best_live();
        // An aware response for candidate `n`, with `ip` in its seeds
        // filter (empty string: an all-zero filter).
        let aware = |n: u8, ip: &str| {
            let mut sd = ScrapeBloom::empty();
            if !ip.is_empty() {
                sd.insert_ip(&ip.parse::<IpAddr>().unwrap());
            }
            let mut r = reply(NodeId([n; 20]), vec![]);
            r.bf_sd = Some(Box::new(sd.0));
            r.bf_pe = Some(Box::new([0u8; crate::bloom::BLOOM_LEN]));
            r
        };
        // Two nonzero proofs and one empty (zero) filter: only the
        // nonzero proofs count toward the quorum.
        assert!(!l.complete(batch[0].addr, Ok(aware(1, "9.9.9.9")), best));
        assert!(!l.complete(batch[1].addr, Ok(aware(2, "8.8.8.8")), best));
        assert!(!l.complete(batch[2].addr, Ok(aware(3, "")), best));
        assert_eq!(l.live_proofs, 2);
        assert_eq!(l.aware, 3);
        // A saturated filter proves nothing either.
        let mut saturated = ScrapeBloom::empty();
        saturated.0 = [0xff; crate::bloom::BLOOM_LEN];
        let mut r = reply(NodeId([4; 20]), vec![]);
        r.bf_sd = Some(Box::new(saturated.0));
        r.bf_pe = Some(Box::new([0u8; crate::bloom::BLOOM_LEN]));
        let batch = l.pick(2);
        assert!(!l.complete(batch[0].addr, Ok(r), best));
        assert_eq!(l.live_proofs, 2);
        assert_eq!(l.aware, 4);
    }

    #[test]
    fn scrape_half_present_filters_count_as_unaware() {
        // Our responder sends both filters or neither; a reply with only
        // one half is malformed and must not become an aware zero estimate.
        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::Scrape, OwnAddrs::default());
        for i in 1..=2u8 {
            l.add(node(i, NodeId([i; 20])));
        }
        let batch = l.pick(2);
        let best = l.best_live();
        let mut only_sd = reply(NodeId([1; 20]), vec![]);
        only_sd.bf_sd = Some(Box::new([0u8; crate::bloom::BLOOM_LEN]));
        only_sd.bf_pe = None;
        assert!(!l.complete(batch[0].addr, Ok(only_sd), best));
        let mut only_pe = reply(NodeId([2; 20]), vec![]);
        only_pe.bf_sd = None;
        only_pe.bf_pe = Some(Box::new([0u8; crate::bloom::BLOOM_LEN]));
        assert!(!l.complete(batch[1].addr, Ok(only_pe), best));
        assert_eq!(l.aware, 0);
        assert_eq!(l.unaware, 2);
        let out = l.scrape_outcome();
        assert!(out.seed_filters.is_empty());
        assert!(out.peer_filters.is_empty());
        // No aware response: UNKNOWN, not a zero (dead) estimate.
        assert_eq!(crate::bloom::estimate_or(&out.seed_filters), None);
    }

    #[test]
    fn values_of_the_other_family_are_ignored() {
        let target = NodeId([0; 20]);
        let mut l = lookup(target, Kind::GetPeers, OwnAddrs::default());
        l.add(node(1, NodeId([1; 20])));
        let batch = l.pick(1);
        let best = l.best_live();
        let mut r = reply(NodeId([1; 20]), vec![]);
        r.values = Some(
            [
                "8.8.8.8:6881",
                "[2a00:1450::1]:6881",
                "[::ffff:9.9.9.9]:6882",
            ]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        );
        l.complete(batch[0].addr, Ok(r), best);
        let out = l.outcome();
        // The native V4 peer and the mapped V4 peer stay; the V6 peer goes.
        let expected: Vec<SocketAddr> = ["8.8.8.8:6881", "9.9.9.9:6882"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(out.peers, expected);
    }
}
