# dc4-dht

The Mainline DHT node of dhtcrawler4 (design [§7](../../docs/03-design.md#7-dc4-dht-r1r4),
limits in [§3](../../docs/03-design.md#3-hard-limits-r7-r17-a6)). It joins the DHT on IPv4 and IPv6, answers
every standard query, and reports the keys it sees as `Discovered` events.

```rust
let (tx, mut rx) = tokio::sync::mpsc::channel(10_000);
let dht = dc4_dht::Dht::start(dc4_dht::DhtConfig::default(), tx).await?;
while let Some(found) = rx.recv().await {
    // found.key, found.source (Sample, Announce, GetPeers), found.peer, found.from
}
```

`Dht` is a cheap handle. It also offers `get_peers`, `announce`, `stats`, `local_addrs`,
`own_addrs`, `good_nodes` and `shutdown`. `is_dialable` is the address chokepoint for
the whole crawler.

## Modules

| Module | Contents |
|---|---|
| `lib.rs` | `Dht`, `Discovered`, `Source`, `Error`, re-exports |
| `config` | `DhtConfig`, and `DhtTuning` (every timer and threshold, with production defaults) |
| `krpc` (public) | strict KRPC decoding; encoding that trims `values`, `samples`, `nodes6` and `nodes` to fit 1 024 bytes |
| `compact` (public) | compact node and peer encodings, `Family`, and the address chokepoint `is_dialable` |
| `node_id` (public) | `NodeId`, XOR distance, BEP 42 ID generation and checks |
| `node` | sockets, datagram dispatch, queries, external-IP voting, bootstrap, maintenance, stats |
| `net` | socket binding, the global-IPv6 probe, the transaction table, the external-IP voter |
| `routing` | the per-family Kademlia routing table (a pure data structure; time is passed in) |
| `responder` | answers to incoming queries (a pure function) |
| `lookup` | iterative `find_node`, `get_peers` and `announce` |
| `sampler` | the BEP 51 sampler: frontier, visited map and workers |
| `peer_store` | announces, in memory only |
| `token` | `announce_peer` tokens |
| `ratelimit` | GCRA token buckets, the responder budget, per-IP inbound limits and outbound spacing |
| `state` | the state file (node IDs, external IPs, contacts) |
| `stats` | lock-free counters and `DhtStatsSnapshot` |

## BEPs

Implemented:
- **BEP 5**: KRPC, `ping`, `find_node`, `get_peers` and `announce_peer`. It covers the
  routing table (K = 8; only the bucket holding our ID splits), good, questionable and
  bad nodes, and the replacement cache. Tokens rotate every 5 minutes. There are no
  retries. The KRPC error codes are 201–204.
- **BEP 32**: one socket, node ID and routing table per address family; `nodes6`; and
  `want`, which is sent when both families run and honoured in answers.
- **BEP 42**: node IDs are derived from the external IP chosen by vote. Replacement
  prefers valid IDs. The test vectors follow the BEP's example code.
- **BEP 43**: `read_only` sends `ro=1` and answers nothing. Nodes that send `ro=1` are
  never added to the routing table.
- **BEP 51**: `sample_infohashes`, both as client (the sampler) and as server.

Not implemented:
- **BEP 33** (DHT scrape): `scrape`/`noseed` are ignored, and no bloom filters are sent.
- **BEP 44** (`put`/`get` storage): an unknown method that carries `target` or
  `info_hash` is answered like `find_node`, but nothing is stored.
- **BEP 45**, only partly: each socket has its own node ID and routing table. A host
  with several addresses in one family is not supported. The node binds one socket
  per family.

## Being a good citizen

- **Budgets.**
  - Outgoing queries: `max_packets_per_sec` in total (default 12000) and at least 1 s
    between queries to one IP. Sampler concurrency defaults to 1024.
  - BEP 33 scrapes charge a dedicated 100/s bucket, fetch traversals a
    dedicated 6000/s bucket (`fetch_packets_per_sec`); neither can starve
    the other or the crawl bucket.
  - A query waits at most 4 s for its budget, then is dropped
    (`throttled_spacing` / `throttled_budget_main` / `throttled_budget_scrape`
    / `throttled_budget_fetch` / `throttled_txn_full`, split per site in 0.7.0;
    formerly a single `throttled` label).
  - A lookup sends α = 3 queries at a time and runs at most 8 rounds.
- **Replies.**
  - Replies have their own budget: 1500 replies/s and 192 000 bytes/s.
  - A query beyond that budget is dropped unanswered (`responder_dropped`).
  - Every datagram we send is at most 1 024 bytes.
- **Inbound.** Each host (an IPv4 address or an IPv6 /48, one external-IP voter) may send 4 packets/s with a burst of 8, which keeps our replies to it under libtorrent's 5 packets/s ban threshold. The limiter map holds
  100 000 IPs.
- **The address chokepoint.** `is_dialable` rejects port 0 and the IANA special-purpose
  ranges. IPv4-mapped and IPv4-compatible addresses are checked as IPv4. Teredo, 6to4
  and NAT64 addresses are checked by the IPv4 address they embed. The filter applies to:
  - every compact node and peer;
  - every announce sender;
  - every routing-table insertion;
  - every destination.

  Our own addresses are never queried, returned or put in the routing table.
- **Routing table.**
  - One entry per IP, and no two entries from one /24 (IPv4) or /64 (IPv6) in a bucket.
  - A reply under another node ID than the entry at that endpoint counts as a failure
    of that entry; the ID that answered is learned like any responder.
  - Refreshes start at most 2 lookups per socket, for the least recently changed
    due buckets; the other buckets stay due.
- **Per-host limits.** Inbound buckets key on the IPv4 address or the IPv6 /48
  (one external-IP voter); outbound spacing keys on the IPv4 address or the
  IPv6 /64, with separate maps per family. Replies to our own outstanding
  queries are not charged to the inbound bucket.
- **Announces.** One peer entry per IP per key (at most 4 per IPv6 /64). A full key
  replaces the oldest entry of its most represented /24 or /64. One host may create
  at most 20 new keys, and one /24 or /48 at most 50, per 10 min; a full store refuses
  new keys. Refused announces get a normal answer but no `Discovered` event.
  - Bootstrap routers are used only while the table has fewer than `MIN_GOOD_NODES`
    (8) good nodes, with backoff from 1 s to 5 min. They are never added to the table.
- **External IP.**
  - Only the top-level `ip` of responses to our own queries counts.
  - Each /24 or /48 has one vote, and its latest vote counts. Votes expire after 30 min.
  - A winner needs at least 10 votes and more than two-thirds of the current votes.
  - The node ID changes, and the table re-bootstraps, at most once per hour.
- **Sampler.**
  - A node is sampled again only after `max(interval, 300 s)`. Nodes without BEP 51
    wait 6 h; consecutive timeouts back off 1 h, 2 h, 4 h, then 6 h per endpoint.
  - Sampler queries time out after 2 s so slow nodes fail fast; lookups still wait 4 s.
  - A node is remembered by its endpoint and, once it has answered, by its node ID.
  - At most 20 samples are taken from one reply, none from a reply under an
    unexpected node ID, and at most 200 per /24 or /48 per 10 min. At most 32
    nodes per response enter the sampler frontier.
  - A full frontier drops its oldest candidate for a new one; candidates queued
    more than 15 min ago are skipped.
  - The visited map (4 000 000 entries per family) first forgets expired entries;
    when still full it evicts the farthest next-sample times first, sparing
    in-flight keys. Picks refused for lack of room count `sampler_visited_full`;
    picks that find nothing count `sampler_pick_empty`.
  - The send path checks the recorded time once more. `sampler_early` counts failures
    and must stay 0.
- **Bounded state.** Everything has a named limit:
  - peer store: 20 000 keys × 100 peers, 45 min;
  - frontier: 200 000;
  - pending queries: 16 384 per socket;
  - external-IP votes: 1 024 per socket;
  - discoveries: a bounded channel; when it is full, events are dropped and counted.

## Privacy (R11)

Peer and node addresses stay in memory. The peer store is never written to disk. The
state file holds only node IDs, our external IPs and up to 300 routing contacts per
family. Log lines above `trace` never contain an IP address or endpoint, including
bootstrap hosts (they may be address literals) and state-file parse errors (they may
quote the file). `Error::Bind` names the configured bind address, which is our own.

## IPv6

`DhtConfig::default()` binds `0.0.0.0:6881` and `[::]:6881`. IPv6 is optional:
- **Unspecified `bind_v6`.** The node first checks for a global IPv6 address. It
  `connect()`s an unbound UDP socket to `[2001:4860:4860::8888]:53`, which sends no
  packet, and looks at the source address. Without a global address, IPv6 is skipped
  with a warning.
- **IPv6 bind failure.** A warning only.
- **No socket at all.** An error: `Error::Bind`, or `Error::NoSocket` when IPv4 is
  disabled and there is no global IPv6.

An IPv4 bind failure is always an error.

## Metrics

`Dht::stats()` returns a `DhtStatsSnapshot`. Its `v4` and `v6` fields are `FamilyStats`,
which hold the per-family counters. They map to
[04-operations §6](../../docs/04-operations.md#6-metrics):

| Metric | Source |
|---|---|
| `dc4_dht_packets_in_total{family}` | `family.packets_in` |
| `dc4_dht_packets_out_total{family}` | `family.packets_out` |
| `dc4_dht_packets_dropped_total{family,reason}` | `family.dropped.iter()`, labels from `DropReason::as_str` |
| `dc4_dht_queries_received_total{method}` | `queries_received.iter()` |
| `dc4_dht_timeouts_total` | `timeouts` |
| `dc4_dht_routing_nodes{family}` | `family.routing_nodes` |
| `dc4_dht_samples_total{family}` | `family.samples` |
| `dc4_dht_sampler_early_total` | `sampler_early` |
| `dc4_dht_sampler_visited_full_total` | `sampler_visited_full` |
| `dc4_dht_sampler_pick_empty_total` | `sampler_pick_empty` |
| `dc4_dht_sampler_frontier{family}` | `family.sampler_frontier` |
| `dc4_dht_sampler_visited{family}` | `family.sampler_visited` |
| `dc4_dht_recv_errors_total{family}` | `family.recv_errors` |
| `dc4_dht_responder_dropped_total` | `responder_dropped` (= the sum of `dropped.responder_budget`) |

`Family::as_str` gives the `family` label, and `Source::as_str` gives the `source`
label of the pipeline metrics.

The drop reasons are:
- `rate_limited`, `oversized`, `malformed`, `responder_budget`, `unsolicited` and
  `filtered` for inbound packets;
- `throttled_spacing`, `throttled_budget_main`, `throttled_budget_scrape`,
  `throttled_budget_fetch`, `throttled_txn_full` and `send_error` for
  outbound packets (the five `throttled_*` replace the pre-0.7.0 single
  `throttled` label).

## Tests

```sh
DC4_TARGET=dc4-dht scripts/cargo-docker.sh test -p dc4-dht --locked
```

**Unit tests** cover each module with an injected clock (`tokio::time::Instant`
values passed in):
- the chokepoint ranges;
- the voter: nine /24s cannot win, one /24 counts once, votes expire, and a two-thirds
  tie does not win;
- the responder budget;
- the routing rules;
- random `get_peers` values trimmed to 1 024 bytes, with 100 IPv4 and 100 IPv6 peers;
- the visited map. A seeded randomised run checks that nothing is ever sampled early.

**`tests/local_network.rs`** runs private networks on the loopback interface. They never
leave the host, and each finishes in seconds.

**How tests use `DhtTuning`.** Production defaults come from `DhtTuning::default()`.
Tests build on it with `..DhtTuning::default()`:
- **Short timers**: 700 ms query timeout, 200 ms maintenance, and sub-second sampler
  intervals.
- **`limits_by_endpoint: true`** (TEST ONLY). The per-IP rules key on IP:port. That
  covers one entry per IP, the bucket subnet rule, the inbound and outbound rate
  limits, vote diversity and the "own address" rule. Without it, nodes that share
  127.0.0.1 would count as one IP, and as our own address.
  `production_limits_key_on_ip` shows the production behaviour on 127.0.0.1/127.0.0.2.
- **`allow_private_addrs: true`** in `DhtConfig`, so loopback addresses are dialable.
- **`bind_v6` set explicitly**, to `None` or to `[::1]:0`. The default `[::]:6881` is
  never bound in tests.

The IPv6 and 127.0.0.2 tests skip themselves when the host cannot bind those addresses.
