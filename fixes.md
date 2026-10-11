# Fixes — diag 2026-10-11 (13h uptime)

Source: `/tmp/dc4-diag.txt` collected via `README.md:682` snippet.
All healthy in `docker compose ps`; no OOM (crawl 552MiB/6G, db 683MiB/3G).
No `pool timed out`, no `claim failures`. Index `lag 0/docs 2083`.

Yield collapsed, not stalled:

- `stats_daily`: `discovered 15M → fetched 1703 / fetch_failed 30M` (10-10), `3.6M → 380 / 7.3M` (10-11). `torrents 2083`.
- `dc4_fetch_total{no_peers,null}=34M`, `ok,null=1903`. `claimed{false}=34M / {true}=12k`.
- Queue: `queued 77k, gave_up 3.1M`, `null_est 77646/77836 (99.7%)`, `avg_attempts 0.97`, `oldest 02:14 newest 02:20` (6 min window).
- `dc4_queue_depth 3.1M` = `pending` planner estimate incl. corpses (`crates/dc4-store/src/crawler.rs:459-464` counts all rows, no `NOT gave_up` filter; above `EXACT_COUNT_THRESHOLD 1M` in `crates/dc4-store/src/lib.rs:137` the estimate is returned without counting, so treat as approximate).
- `admitted{sample}=19M`, `discovered{sample}=28M`, `shed_sampler=3.4M`, `queue_full=31k`.
- DHT: `dropped{throttled}=271M` vs `packets_in 7.6M`, `pick_empty=37M`, `frontier=4`, `good_nodes=150`, `timeouts 4.3M/samples 28M=15%`. Inbound OK (`queries_received{get_peers}=460k`).
- DB churn: `pending 748MB (pkey 317MB)`, `n_ins 19M / n_upd 79M / HOT 16M`, `WAL 48GB`, `write_time 35M ms`. `pgdata 4.5G` vs `db_size 761MB` = WAL cap 4GB (`deploy/docker-compose.yml:39`). Pool `128/127 idle`, `116 idle COMMIT`, `~134` pg_stat_activity rows (`142` is container PIDs).
- Disk: `Build Cache 3.9GB reclaimable`.

## P0-1 Junk sample admission floods queue

Symptom: `README.md:769` junk pattern — young queue, attempts~0, `admitted{sample}` dominant.

Why: `crates/dhtcrawler4/src/admission.rs:633-637` admits sample at once non-priority; shed check at `:614`, flag at `:767` (`depth >= max_pending 5M`, `deploy/config/dhtcrawler4.toml:62`). Snapshot depth 3.1M < 5M so shed is currently off (cumulative `shed_sampler=3.4M` is history), but admits ~400/s dead keys (19M admitted / 13h uptime). Fetch piggyback (`crates/dhtcrawler4/src/fetch.rs:978-980`) never gets an estimate for `no_peers`, so live-first `claim_bulk`/`claim_live` (`crates/dhtcrawler4/src/fetch.rs:196-201`) stays dry.

Plan (config first, in order):

1. `DC4_CRAWL__SAMPLER_CONCURRENCY=1024→256` + `DC4_CRAWL__MAX_PACKETS_PER_SEC=12000→6000` in `deploy/docker-compose.override.yml` (untracked, see `README.md:630`). `up -d` only, no rebuild.
   Expect: `discovered{sample}/s` down ~2-4x, `dropped{throttled}/s` down, `timeouts` share down, `shed_sampler/s` stays 0.
   Roll back if `discovered{sample}/s` drops >4x with no timeout improvement.
2. If still `no_peers/null` >95% of claims after 1h: lower `DC4_CRAWL__MAX_PENDING=5000000→1000000`. Forces `shed_sampler` + `PriorityOnly` gate (`crates/dc4-store/src/crawler.rs:321`) earlier. Corpses count toward cap, so do with P0-2.
3. Code (only if 1-2 insufficient): require 2nd sighting / get_peers corroboration for sample, or per-flush sample cap like `GET_PEERS_SINGLE_CAP` (`admission.rs:52`). Needs `Admission::handle` change + test.

Verify: two diags 10 min apart; compute `/s` for exact series `dc4_admitted_total{source="sample"}`, `dc4_claimed_total{live="false"}`, `dc4_fetch_total{outcome="no_peers",est="null"}`, `dc4_blocked_total{reason="shed_sampler"}`, `dc4_blocked_total{reason="queue_full"}`.

## P0-2 Gave-up corpses outrun purge, will close queue

`gave_up 3.1M`, `purge_gave_up 15.9M/13h (~340/s)` vs admit `~400/s`. `queue_full 31k` already. `MAX_FETCH_ATTEMPTS=2` (`crates/dc4-store/src/lib.rs:132`) already minimal; `avg_attempts 0.97` confirms churn, not retry backlog.

1. Shorten sweep: `DC4_CRAWL__SCRAPE_SWEEP_SECS=3600→600` (valid range `60-86400` per `crates/dhtcrawler4/src/config.rs:839`). `up -d` only.
   Expect `purge_gave_up/s` up, `gave_up` flat/down, `queue_depth` down, `queue_full/s` → 0.
2. If `gave_up_purge_hours=1` (`deploy/config/dhtcrawler4.toml:93`, integer hours `0-168` per `crates/dhtcrawler4/src/config.rs:838`) still lags: code change to allow minutes (conversion at `crates/dhtcrawler4/src/scrape.rs:97`, config type `u64` at `crates/dhtcrawler4/src/config.rs:212`) or raise `MAX_PURGE_BATCH` (`crates/dhtcrawler4/src/scrape.rs:43`, tombstone-only cap; `purge_gave_up` per sweep is unbounded but runs only once per sweep).
3. Do not raise `max_pending` to “make room” — hides junk, grows `pkey 317MB` + WAL.

Verify: `SELECT count(*) FILTER (WHERE gave_up) FROM pending` is a heavy seq scan on ~3M rows — prefer the `purge_gave_up_total` slope across two diags; run the count off-peak if needed.

## P1 DHT throttling + sampler starvation

`throttled 271M` sites: per-address spacing + budget + txn-full all map to `DropReason::Throttled` (`crates/dc4-dht/src/node.rs:603,619,647`, `crates/dc4-dht/src/stats.rs:85`). `pick_empty 37M + frontier 4` = no candidates; `good_nodes 150` low.

1. Same P0-1 concurrency cut is the fix; do not raise `max_packets_per_sec` to chase it.
2. Check: `docker compose logs crawl | grep -i "ipv6\|throttl\|sampler"` for v6-disable warning (v6 all-zero expected if no global v6); confirm `dht-state.json` mtime advances under `dhtcrawler4_state` (28K size itself is normal for a few hundred contacts); bootstrap reachability.
3. If `frontier` stays <10 after concurrency cut: verify `sampler_concurrency > 0` passes config validation and check visited-cap full (`dc4_dht_sampler_visited_full_total 0` now — OK).

## P2 Pool oversized, disk hygiene

- Pool: `DC4_DATABASE__MAX_CONNECTIONS=128→32` + keep PG `max_connections=200` (`deploy/docker-compose.yml:39`). Idle 127 proves no pressure (`README.md:518`). `up -d` only. Expect ~134 pg_stat_activity backends (116 idle COMMIT + rest; 142 is container PIDs, not backends) to fall to ~40, small connection-overhead saving — the 79M-update churn, not connections, dominates db CPU. Raise only if `pool_idle→0` + `pool timed out`. Keep role-pool sum comfortably under 200.
- Disk: `docker builder prune -f && docker image prune -f` (3.9GB reclaimable, `README.md:666`). `pgdata` gap is WAL cap, not leak; if `pg_wal` inside the volume is >3GB, run a superuser `CHECKPOINT` then re-`du` (recycles WAL; does not fix table/index bloat — that needs `VACUUM`/`autovacuum`):
  `docker compose exec -T db sh -c 'PGPASSWORD=$(cat /run/secrets/pg_superuser_password) psql -U postgres -d dc4 -c "CHECKPOINT;"'`
- Web `404 unmatched 314` vs `/ 66`: bots probing, no action. `dc4_rate_limited_total` (`crates/dc4-web/src/telemetry.rs:24`) absent from diag = zero, not missing.

## Order + gates

1. Override file with sampler 256 + packets 6000 + sweep 600 + pool 32 → `docker compose up -d` → 10 min → second diag.
2. Only then decide on `max_pending 1M` and code changes.
3. Stop if `dc4_blocked_total{reason="queue_full"}` > 0 sustained (fetch behind — fix fetch/purge before more discovery) or `dc4_claim_chan_depth` pinned at 256 with frozen `dc4_fetch_total` (workers stuck, per `README.md:787`).

## Commands

```sh
cat > deploy/docker-compose.override.yml <<'EOF'
services:
  crawl:
    environment:
      DC4_CRAWL__SAMPLER_CONCURRENCY: "256"
      DC4_CRAWL__MAX_PACKETS_PER_SEC: "6000"
      DC4_CRAWL__SCRAPE_SWEEP_SECS: "600"
      DC4_DATABASE__MAX_CONNECTIONS: "32"
EOF
cd deploy && docker compose up -d
# 10 min later, re-run README.md:682 diag to /tmp/dc4-diag2.txt and diff rates
docker builder prune -f && docker image prune -f
```
