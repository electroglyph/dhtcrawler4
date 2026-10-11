# Changelog (fork)

Forked from upstream at `3350799` (2026-09-17, merge of Rust rewrite).

## 0.7.0

- Expand: peer-finding workstreams (fetch budget, hints, live sampling, multi-identity, tracker hybrid). See entries below.
- Fetch budget: fetch traversals moved off the 100/s scrape bucket onto a dedicated `fetch_packets_per_sec` bucket (default 6000, ~3x measured need; `DC4_CRAWL__FETCH_PACKETS_PER_SEC`, validated 1..=u32::MAX). The traversal keeps `scrape=1` so BEP 33 seed filters still feed queue ordering; the scrape role keeps the now-uncontended 100/s. New `dc4_lookup_duration_seconds{kind}` histogram (`fetch`/`scrape`). Metric-label change: the single `throttled` drop reason is split per site (`throttled_spacing`, `throttled_budget_main`, `throttled_budget_scrape`, `throttled_budget_fetch`, `throttled_txn_full`) — update any dashboard/alert matching the old label. Rollback is revert + rebuild (no env value restores the shared budget).
- Hint strengthen: new `dc4_hint_added_total{source}` / `dc4_hint_used_total{outcome}` metrics (one diag answers whether hints carry yield); traversal-found peers are recorded into the `HintMap` (bounded 8/key) so retries dial known-good peers first instead of re-traversing. `HINT_TTL` stays 5 min — the new metrics decide any bump. No config changes.
- Live-neighborhood sampling: new `crawl.sampler_live_share` (default 0.10, `DC4_CRAWL__SAMPLER_LIVE_SHARE`, validated 0.0..=1.0 with NaN rejected; `"0"` is the kill switch). That fraction of sampler picks queries a known-live address directly — same `query()` path (spacing/budgets/`may_contact` unchanged), same `Source::Sample` admission path. Ring (4,096 addrs) is fed by any TCP-connected peer (hint peers included, even when metadata later fails — successful fetches are subsumed), inbound `announce_peer` endpoints, and `Dht::note_live_addr`; dead addrs evict after 3 consecutive failures (`dc4_dht_sampler_live_evicted_total`). Env overrides now support float keys (new `Float` value kind).
- Multi-identity operation: new `crawl.identities` (default 1, `DC4_CRAWL__IDENTITIES`, validated 1..=8). Each identity binds `dht_port + i` per family with its own node ID and routing table; sampler, budgets, spacing and peer store stay shared. Outbound lookups route per family through the XOR-closest identity, fanning out to the remaining identities when the closest finds nothing; inbound dispatch is by port. A port already in use surfaces as a clear bind error at startup. `identities` is the port count (no separate `dht_port_count` knob — a second count would only duplicate it). State file is now version 2 (one entry per identity) — old files are ignored with a warning and regenerate, never migrated. The identity port range is validated against `metrics.listen`/`web.listen`. Rollback is `"1"` plus a restart. Start with 2-4, not 8.
- Tracker hybrid: new `dc4-tracker` crate (BEP 15 UDP: cached connection IDs, 74-hash scrape batches, one-shot `started` announces at 200 peers wanted). Every claimed key joins a global scrape batcher (74 keys or 200 ms); each flush is scraped at 2 random live trackers, seeders>0 keys get announced at 3, the rest stay DHT-only. Announces race with DHT traversal in `obtain()` and merge into the same dial queue. Pool enabled by default on the vendored snapshot (17 UDP trackers); explicit `crawl.trackers` replaces it, `tracker_enabled=false` kills it with no sockets. List refresh defaults off (no TLS client for the `https://` list URL — point `tracker_list_url` at a plain-http mirror to enable); hourly `connect` sweeps evict dead servers. Two deviations from the draft: the re-announce floor defaults to 60 s when a tracker gives no interval, and per-tracker connection-refresh counts are emitted as a separate `dc4_tracker_conn_refresh_total{tracker,reason}` counter (`expiry`|`invalid`).

## 0.6.2

- Crawl (ops): tune discovery for junk-heavy swarms via the untracked compose override — sampler concurrency 1024→256, packet budget 12000→6000/s, purge sweep 3600→600 s, crawl pool 128→32 (PG `max_connections` stays 200). No code or default-config changes; `max_pending` 1M and sample corroboration stay conditional on the next diag.

## 0.6.1

- Crawl: sampler concurrency 512→1024 (the enforced ceiling) and packet budget 6000→12000/s, fetch workers 1536→3072 with connections 6144→12288; compose sized for 12 GB boxes (crawl 6g, db 3g, pools 128/PG 200, 1 GiB inflight budget).

## 0.6.0

- Crawl: sampler concurrency 160→512 and packet budget 3000→6000/s, responder budget 500→1500 replies/s and 64→192 kB/s, fetch workers 768→1536 with connections 3072→6144 and inflight metadata 512 MiB→1 GiB (4 conns/worker kept); compose crawl `mem_limit` 3→4 GiB. The scrape budget stays 100/s and the inbound 4/s + burst 8 gate is unchanged.
- DHT: sampler visited map 1M→4M entries per family; when full it now evicts the farthest next-sample times first (the long unsupported skips) instead of refusing until expiry, sparing in-flight keys.
- DHT: consecutive sampler timeouts back off 1h→2h→4h→6h per endpoint, capped at the unsupported skip; any other outcome resets the count.
- DHT: new `sampler_query_timeout` tuning (default 2 s) bounds sampler queries only; lookups keep the 4 s timeout.
- DHT: sampler frontier 50k→200k per family with up to 32 frontier nodes taken per response; new `dc4_dht_sampler_pick_empty_total` counter and per-family `dc4_dht_sampler_frontier` / `dc4_dht_sampler_visited` gauges.
- DHT: transaction table 4096→16384 per socket; UDP sockets request a 4 MiB receive buffer (best-effort, failures ignored); receive errors count in per-family `dc4_dht_recv_errors_total`.
- DHT: new optional `bep42_r` (0–7; `crawl.bep42_r`, `DC4_CRAWL__BEP42_R`) pins the BEP 42 `r` bits so replicas on one IP hold distinct IDs; saved valid IDs still win. The README gains a multi-replica runbook (distinct port/state_dir/`bep42_r`, staggered starts).
- Admission: a first get_peers sighting is admitted at once as non-priority (like sampled keys), capped at 20% of the flush batch (`get_peers_single_cap`, default 200); over cap counts `dc4_blocked_total{reason="get_peers_single_capped"}`. The two-network rule still admits regardless of the cap, and removal cooldowns still gate at flush.
- Fetch: destination negative cache split — refused/timed-out destinations skip 3 min, other connect errors 10 min (`negative_ttl_short`); post-connect failures still never negative-cache.

## 0.5.0

- DHT: responses with top-level `ro=1` (BEP 43) no longer enter the routing table, the external-IP vote, or the sampler frontier.
- DHT: `sample_infohashes` answers clamp `interval` to the BEP 51 maximum of 21 600 s, and configs with a larger `sample_interval_sent` are rejected at validation.
- DHT: peers returned inside `get_peers`/scrape `values` are filtered against our own addresses, like traversal candidates already were.
- DHT: `sample_infohashes` answers under an unexpected node ID are treated as unsupported (no samples, no visited entry, long backoff) instead of honouring the reply's interval.
- DHT: a bucket refresh that reaches no live node leaves the bucket due for the next round instead of silencing it for a full refresh interval.
- DHT: only replies under the queried node ID count towards an answer; wrong-ID replies no longer trigger the final sweep alone.
- DHT: the external-IP vote documents its accepted bound (a flood past voter capacity flushes honest votes; each vote costs a network).
- DHT: `sampler_concurrency = 0` is rejected at validation instead of silently running no sampler workers.
- DHT: a bootstrap round that resolves more routers than fit no longer wipes the known routers; overflow is dropped (but still queried that round).
- Web: the search cache drops in-flight singleflight cells on an index change, so a stale flight can no longer rewind the index stamp or insert stale results.
- Web: the search cache sweeps singleflight entries older than the entry TTL, so a cancelled leader can no longer leak its query text forever.

- Crawl: a failed claim top-up feeds the live leases already held instead of erroring the scan and idling workers while the leases tick down; an empty live pool still backs off.

- Web: a connection whose request-head bytes are already readable no longer times out on the head deadline; only a still-pending read does.

- Web: the torrent API reports `files_truncated` when the store hands back fewer files than `file_count`, matching the detail page (one shared helper).

- Config: a dual-stack `[::]` listen address overlapping any same-port IPv4 address is rejected at validation instead of failing later as a runtime `EADDRINUSE`.

- Web: the search API also returns the stable `index_total` next to the page-relative `total`, so clients can paginate without it shifting under them.

- Web: request bodies to routes that never read one are dropped before the concurrency permit, so chunked or slow bodies cannot hold server capacity hostage (only `POST /theme` keeps its body).

- Peer: redundant copies of an already-stored metadata piece no longer consume the shared byte budget, so duplicate-sending peers cannot starve other fetches.

- Peer: the test frame splitter applies the same dual length caps as the production frame reader (extension cap for extension frames, discard budget otherwise), so fuzzing models production exactly.

- Peer: a wrong-typed `m` or `ut_metadata` in an extended handshake is a protocol error instead of looking like missing metadata support.

- Search: prefix expansion keeps only the smallest term budget in memory and stops scanning past a fixed term-read backstop, so one common prefix cannot pin the indexer on vocabulary-size scans.

- Search: indexed torrent names are truncated to the same byte budget as file lists, so out-of-band oversized documents cannot pin indexing work.

- Store: scrape writes skip tombstoned rows, so a delayed scrape can no longer resurrect seeder stats on a dead row.

- Store: the tombstone purge holds the shared change-feed lock, so the indexer's high-water mark can no longer read an uncommitted purge stamp and miss deletions.

- Store: the tombstone purge locks its candidates and re-checks them at delete time, so a concurrently revived torrent is never hard-deleted.

- Store: concurrent `observe` batches lock the rows they bump, so racing sightings no longer lose `seen_count` increments.

- Store: the gave-up queue purge also removes rows with no attempt stamp, which could never satisfy the age comparison and leaked forever.

- Store: `observe` and `complete_batch` reject batches past fixed caps instead of holding the change-feed lock for an unbounded transaction.

- Store: repeat failures on an already-gave-up key change nothing and count nothing (single and batched paths, both backends).

- Store: the queue-depth gate counts exactly instead of trusting a possibly stale-small estimate, so a huge real depth is never misread as room.

- Store: tombstoning a torrent records removal memory under every name (stored key, v1 and v2 aliases), so hybrids cannot be re-queued through an alias with no cooldown.

- Store: the least-privilege role check covers the crawler's tombstone-purge duty (which needs its `DELETE` grant) instead of asserting a blanket denial that production contradicts.

- Torrent: the per-listing file cap is documented as applying to the v2 tree and the v1 list independently.
- Torrent: a path cut short by the length cap is shown component-wise only, instead of burning the visitor text budget twice with the truncated join too.

- Torrent: an empty v1 `files` list is rejected instead of parsing as a zero-file torrent.

- Torrent: a v2 `file tree` holding only empty directories (or only padding) is rejected instead of parsing as a zero-file torrent.

- Core: sanitised path components fit the filesystem 255-byte name limit as well as the character cap.

- Bencode: dict keys are gated by the depth limit like every other value, and the decoder holds no panicking assertions anymore (saturating arithmetic and checked fallbacks instead).

## 0.4.0

- Fetch effort scales by estimate: unscraped (`None`) and measured-dead (`Some(0)`) keys get 3 dials and one lookup, `1–4` keeps today's 8 dials and one lookup, `>= 5` gets 8 dials plus one second lookup when the first drains — fan-out stays 3-wide for every bucket and the key deadline still bounds the pair, so per-key concurrency never exceeds today's. `dc4_fetch_dials_total{est}` counts started dials and `dc4_fetch_total` gains the same `est` (`null`/`dead`/`low`/`high`) label for the ok-per-dial gate; both use the claim-time estimate so dials and outcomes stay joinable.

## 0.3.0

- Claim prefers live keys: the claimer leases `seeders_est > 0` keys first (`Store::claim_live`, same ordering and `pending_claim` index as the claim, no migration) and tops up with the unfiltered claim so workers never idle — live retries jump ahead of the fresh-NULL flood, NULLs still flow when the live pool is dry. Claimed keys carry their estimate (`PendingItem.seeders_est`) and each bulk counts `dc4_claimed_total{live="true"|"false"}` for the 1-hour gate.

## 0.2.0

- Admission sheds sampler-first: only `Announce` is priority now (`Sample` joins `GetPeers` as non-priority, still admitted at once since the sighting is our own sampler's rather than a stranger's claim needing corroboration), and sampled discoveries shed pre-batch while the last flush saw queue depth at or above `max_pending` — the same outcome as the store's priority-only gate, without the round-trips that `queue_full` drops used to pay. Shed keys skip the dedup set so recovery is instant; the shed volume shows as the new `shed_sampler` reason on `dc4_blocked_total`.

## 0.1.0

- Removed moderation stack: visitor report form/handlers/templates/tests, CSRF, `dc4-policy` crate, `policy/blocked-terms.txt`, denylist + `blocked.html`/`legal.html`/`report*.html`, takedown/admin paths, report/denylist DB tables (migrations `000006_drop_reports`, `000007_drop_denylist`), policy fuzz target, `SECURITY.md`.
- Added BEP 33: `bloom.rs` + estimator (BEP 33 test vector), `scrape=1` wire fields, seed flag, scrape schema (`000004_scrape`, `000005_pending_seeders`), scrape worker with dedicated budget and conditional tombstones, liveness-ordered fetch queue, seeder estimates in web/API + `sort=seeders`, removal-memory cooldown (7→28→90d, `seed=1` refreshes clock), scrape metrics, README/docs updates.
- DHT hardening: BEP 42 raw-IP forms, all-trusted chain attributed to socket peer, bad nodes only displaced by proven nodes, BEP 42-invalid senders parked in replacements, IPv6 `/48` inbound rate limits + vote limits, per-subnet candidate caps, cross-family `values` rejected, concatenated v4 `values` accepted, IPv6 peers string no longer misdecoded as IPv4, single max-send-wait budget, fail-closed wait/overflow handling, zero-duration tuning rejected.
- Torrent parsing: single-file v1 name sanitised as path component, padding checked raw + sanitised, `.pad` no longer misclassified, empty v2 tree rejected, v1 `pieces` must be multiple of 20, empty pieces = zero-length, UTF-8 preferred fields required, visited-text budget documented.
- Bencode: iterative decoder hardened — scalar `max_depth` gating, length-digit overflow → `string too long`, explicit overflow errors (no silent fallback), `max_items` covers dict keys, recursive `drop`/`to_owned_value` stack-overflow fixed.
- Peer fetch (BEP 9/10): deadline on every phase-2 read/write, timed-out pieces retried, rate-limited peers retried later in same obtain, transient store errors record failure, unsolicited rejects ignored, out-of-range requests ignored, trailing bytes / pieceless unknown messages rejected, assembly piece cap + fallible reserve, unknown `ut_metadata` shapes ignored.
- Search: global prefix-expansion budget, per-word token cap, empty prefix → no expansions, folded-char counting for prefix gate, trailing-ignored-word flip fixed, `per_page` validated on HTML like API, pagination uses index total, filtered-page next-link covered, `change_seq` only on content change, one shared clock per results page, one shared CJK definition, seeder sublinear boost / stale-hidden ranking.
- Store/DB: leased queue fixes (gave-up excluded, zero-cooldown-base disables, repeat-deny skips re-tombstone, tombstone rollback explicit), admission holds removal cache + fail-closed + zero-capacity rejected loudly, seed short-circuit + removal memory gate, scrape-denial recheck once per batch, least-privilege single-role DB users, abort hung roles on shutdown timeout, keep admission panic cause.
- Web/API: param validation before block gate (query hidden), `base_url` rejects default ports + shared origin policy, invalid configs rejected by router (not served), search total counts visible matches only, `per_page` links preserved, `fetch metadata alone refuses` on metadata-only fetch, secret keys/password URLs/fragments redacted.
- Config/ops/docs: `scrape_*` + crawl keys, listen overlap within the same family plus both-wildcard cross-family (metrics/web addrs also checked), config text trimmed of controls, URL passwords refused, Rust image digest pinned, README trimmed to BEP 33 + rewrite note, design/ops docs updated, `audit.md` added.
- Perf (~35 commits): no per-peer heap alloc for compact peers, `copy_from_slice` token prefix, two-copy peer IDs, branchless paths, single-peek decoder loop, counted key chars once, `format!`-free magnets, precomputed export sort keys, hoisted bucket/key lookups, per-subnet counting without scans, tiny-batch linear scan, zero-copy scrape filter union, owned-dict work-stack drains, constant-folded estimator, one-pass `Variants`/affix automaton, single `ParsedQuery`, one-shot path decode, borrowed `observe_chunk` keys, narrowed B-004 lock scope, partitioned refresh targets, batched evidence indexing, skipped lease renewal when untickable.
- Tests: `cargo fmt`, opt-in live-network tests (bootstrap/lookup/peers/fetch, policy/search, hardened diagnostics), BEP 33 vectors, audit-gap regressions, e2e DB/DHT updates for scrape + removal flows.
- Admission dedup: inserts now check both generations, so a key from the previous generation is not re-added to the current one and the dedup window keeps its full capacity.
- Search tokenizer: dropped overlong tokens still advance the token position, so phrase queries can no longer match across a gap left by a dropped token.
- Search query: a word cut short by the per-word token cap no longer gains prefix expansion on its truncated tail.
- DHT routing: replacing a bad same-IP entry in another bucket now removes it from its own bucket, so no orphaned member is left behind and one-entry-per-IP holds.
- DHT lookup: a candidate that would immediately evict itself from a full table is reported as not admitted (with its admission marks rolled back) instead of a phantom success.
- DHT tokens: a delayed rotation tick that skipped two or more intervals refreshes both secrets, so tokens issued before the gap expire instead of staying valid.
- DHT queries: failed sends now refund the send budget and release the per-host spacing reservation, like every other failure path.
- Torrent parsing: a v1/v2 entry whose filename is invalid counts toward the totals but lists nothing, instead of listing its parent directory as a file.
- Store `get_many`: the file preview now flags truncation when the torrent holds more files than the preview cap, matching `get_by_key`.
- Store `complete`: a successful fetch under an alias clears removal memory for every name of the torrent, so a resurgent torrent is not penalised by the stored key's leftover cooldown.
- Store `refresh_scraped`: seed announces match alias keys (v1 infohash, truncated v2 infohash) as well as stored DHT keys.
- Store `observe`: sightings of tombstoned rows no longer bump the dead row; the key flows to the queue so a refetch can revive it.
- Store `trim_removed_keys`: a negative cap deletes nothing instead of wiping all removal memory.
- Store tombstones: dead rows no longer keep stale seeder estimates, failure counts or scrape stamps, so a revived row schedules its next scrape fresh.
- Store counters: `seen_count` additions saturate at the bigint maximum instead of aborting the whole observe batch.
- Store scrape claims: claimed rows come back oldest-scrape-first (never-scraped first) in a deterministic order.
- Peer fetch: a redundant copy of an already-received piece is ignored instead of failing the whole fetch (our own retry can self-induce it on a slow peer); integrity still rests on the final hash check.
- Search cleanup: `sweep_trash` skips entries deleted concurrently, mirroring `cleanup`, instead of aborting the sweep with a spurious error.
- Config: `0.0.0.0:P` + `[::]:P` is rejected at validation (dual-stack `[::]` claims the IPv4 port on Linux) instead of failing later as a runtime `EADDRINUSE`.
- Store `record_scrapes`: duplicate ids in one batch merge last-wins with an exact count, deterministically (both backends).
- Store `set_setting`: concurrent writes to the same key are serialised, so every audit row carries the value its writer actually replaced.
- Crawl: a panicked fetch/scrape worker fails the role instead of being logged and swallowed as `Ok(())`.
- Roles: the post-abort reap is bounded by the shutdown timeout (stuck synchronous calls are detached) instead of waiting unboundedly.
- Store purge feed (migration `000008_purge_feed`): `purge_tombstoned` records every deleted id with a `change_seq` stamp served back as `visible=false`, so an indexer lagging past the grace still converges; feed entries older than 90 days are pruned.
- Store grants (migration `000009_reapply_grants`): re-applies all surviving service-role grants for roles created after the first migration run, and grants the crawler the missing `DELETE ON torrents` its purge sweep needs (every purge previously failed with 42501).
- Search query cache: `GET /search` and `GET /api/v1/search` share a server-side cache of raw index results keyed by `(text, sort, page, per_page)` (defaults: `web.search_cache_size = 100`, `web.search_cache_ttl_secs = 900`; either zero disables). Only non-empty successes are stored and hydration still runs per request; entries expire on a fixed TTL, evict least-recently-used past capacity, and clear wholesale on any index commit (segment-set stamp, not the generation number); concurrent identical misses share one index search. New metrics `dc4_search_cache_hits_total`, `dc4_search_cache_misses_total{reason}`, `dc4_search_cache_coalesced_total`, `dc4_search_cache_entries`; `dc4_search_seconds` now records one observation per index search only. HTTP stays `Cache-Control: no-store`.
- Web theme switch: header dark/light toggle backed by `POST /theme`, which stores a bare `theme` (`dark`/`light`, `Path=/`, `SameSite=Lax`, one year) cookie and redirects (303) to a validated local `next` path (`/` fallback). Pages render `data-theme` server-side with no JavaScript (dark default); HTML responses carry `Vary: Cookie`. Privacy/about pages now disclose the optional preference cookie instead of claiming no cookies.
- Web: removed `/.well-known/security.txt` (RFC 9116) and the now-unused `web.base_url` setting with its shared origin validator (`dc4_core::validate_base_url`, `MAX_BASE_URL_CHARS`). Old config files that still set `web.base_url` are rejected as unknown keys; remove the line. The `check-config` warning about `web.hsts` without an https origin is gone with it.
- Crawl budget defaults raised for servers: `max_packets_per_sec` 250→1000, `sampler_concurrency` 32→96, `fetch_workers` 64→192, `max_connections` 256→768, `max_inflight_metadata_bytes` 256→512 MiB (compose crawl `mem_limit` 1→2 GiB). Lower them on a home connection.
- Crawl throughput: fetch claim batch 1→8 with one transaction per batch (`Store::complete_batch`/`fail_batch`/`give_up_batch`; per-key fallbacks preserved), fetch timeouts tightened (get_peers 15→10 s, key 60→45 s, connect 5→3 s, handshake 5→4 s, per-peer total 30→20 s), scrape packet budget 25→100/s, sampler concurrency 96→160, crawler DB pool available at 48 via compose (Postgres `max_connections` 200), new `dc4_db_pool_size`/`dc4_db_pool_idle` gauges. Fetch batches hold one background renewal for all claimed keys (a full batch can outlive the 120 s lease); failure batches merge duplicate keys to one attempt each.
- Crawl throughput (dead-key sieve): `MAX_FETCH_ATTEMPTS` 6→2, so workers spend attempts on fresh keys instead of re-probing dead ones; the fetch claim queue now orders by attempts first (fresh keys before retries, then seeder estimate, then oldest attempt) in both the Postgres claim and the in-memory stand-in. Fetch scale-up: `fetch_workers` 192→512, `max_connections` 768→2048, compose crawl DB pool 48→96 (Postgres `max_connections` 200 still fits all roles).
- Store claim index (migration `000010_pending_claim`): the attempts-first reorder above shipped without a matching index, so every `CLAIM_SQL` sorted millions of `pending` rows for 8 keys and 512 workers held the 96-conn pool past the 10 s acquire timeout (`claiming queue items failed: pool timed out`). New partial index `pending_claim` on `(attempts, seeders_est DESC NULLS LAST, next_attempt_at) WHERE NOT gave_up` matches the claim's `ORDER BY` exactly — claims are an index walk again (no sort) — and replaces the now-unused `pending_seeders` index so the write-hot queue stops paying maintenance for it.
- Crawl throughput (dead-key sieve, round 2): `GET_PEERS_TIMEOUT` 10→6 s — 99.7% of keys die in the lookup stage, so a shorter lookup is pure keys/s. Fetch scale-up: `fetch_workers` 512→768, `max_connections` 2048→3072 (4/worker headroom preserved), compose crawl DB pool 96→128 (steady-state total ~148 of Postgres `max_connections` 200 across roles).
- Store queue churn (migration `000011_drop_pending_ready`): drops the unused `pending_ready` index (~194 MB, zero scans) so the write-hot `pending` table stops paying one index write per update for it. Nothing reads it — the claim leads with `attempts`, counts are unfiltered scans, the purge filters on `gave_up` — and the claim/purge/depth plans are byte-identical without it.
- Postgres queue tuning: crawler-only `synchronous_commit = off` (`10-roles.sh`; run once by hand on existing databases) cuts fsyncs/IOPS on the lease-healed queue while indexer/web keep full durability, and bigger checkpoints (`checkpoint_timeout=900`, `max_wal_size=4GB`) cut full-page-write amplification. README pool bullet fixed (compose sets 128, not 96) and extended with both settings.
- Crawl queue claim (single claimer): one task bulk-claims 512 keys per scan and feeds 8-key batches to the 768 workers over a bounded channel (256 batches = 2048 keys, the only bound — a full channel backpressures the claimer), replacing 64 contending 8-key scans per 512 keys (~95 scans/s of ~47k-tuple prefix walks become ~1.5/s). Workers park on `recv`; the claimer's idle cadence sets the empty-queue rate. Worst-case buffer dwell (~2.7 s, ~3.4 s with the in-hand bulk) sits two orders of magnitude inside the 120 s lease, so no claimer renewal guard is needed; shutdown drains the buffer inside the 30 s wait and unreached leases expire as on a crash. New `dc4_claim_chan_depth` gauge (`max_capacity() - capacity()`, sender-side).
- Store build fix (`dc4-store/build.rs`): `sqlx::migrate!` embeds `migrations/` at compile time, but Cargo only tracks the files the macro knew about at the last compile — a migration-only change never dirtied the crate, so the release image shipped a stale embedded list and `migrate` exited 0 without applying `000011` (found on the server: versions topped out at `...10` with the file on disk; the index was dropped by hand there, and the next `migrate` run records the version as a no-op). `rerun-if-changed=migrations` forces the rebuild; a regression test pins the embedded list against the directory at test time.
- Crawl queue purge: gave-up rows counted against `max_pending` without ever becoming claimable again, so the queue filled with corpses, admission shut, and the claimable set drained 1:1 into `gave_up` — a stall within hours. The scrape sweep now purges gave-up rows older than `gave_up_purge_hours` (default 1, same range as the tombstone grace), exposing `purge_gave_up` on the `CrawlStore` trait with a `MemoryStore` mirror and a `dc4_purge_gave_up_total` counter. A purged-then-resampled key returns as a fresh row, which is the only second chance a dead key gets (re-discovery never revives `gave_up` rows).
- Store queue churn (migration `000012_drop_pending_gave_up`): drops the unused `pending_gave_up` index (~92 MB, zero scans across four live samples) so the write-hot `pending` table stops paying one index write per update for it. The purge DELETE that filters on that predicate removes the bulk of the table per sweep and is correctly seq-scanned, so the index served nothing — not even the purge. Live-verified pattern matches `...11`: absent from `\di` after `migrate`, scans stay zero.
