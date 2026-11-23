# Scan Queue, Cache & Load Test

**Status:** implemented 2026-11-19 (3-week plan, done in one pass). Tests:
`backend/tests/scanQueueCache.test.js` (4/4), full backend suite 79/81
(the 2 failures are pre-existing: `compliance.test.js` and
`deployment_config.test.js` need a live Postgres + real env secrets).

## What changed and why

`POST /api/scans/trigger` used to run the whole scan inline in the
request: AST extraction + git churn + classifier calls + SBOM + DB writes,
all on the event loop. N concurrent triggers serialized on that loop, so
response time grew with N (measured: 10 concurrent → submit p95 3,889 ms).

Now the trigger only creates a `queued` scan row and enqueues a job.
A worker runs the scan; the dashboard polls `GET /api/scans/:id` to a
terminal status (it already did). Two bottlenecks were found by measuring:

1. `execFileSync git log` per finding blocked the event loop → async
   `execFile` with a bounded pool (8).
2. Spawning a worker thread per scan cost ~250 ms — more than the ~90 ms
   scan itself on a small repo → a persistent thread pool
   (`workers/scanThreadPool.js`, size defaults to the worker concurrency).

## Architecture

```
POST /api/scans/trigger
  -> scan row (status queued) -> BullMQ 'secureguard-scans'  [REDIS_URL set]
                              -> in-process FIFO               [REDIS_URL unset]
  -> 202 { scanId, status: 'queued' }

Worker (concurrency SCAN_WORKER_CONCURRENCY, default 2)
  -> executeScan (services/scanRunner.js)
       -> scan in pooled worker thread (workers/scanThread.js)
       -> thread failure falls back to inline (slow, scan still runs)
  -> scan queued -> running -> completed | failed
  -> org cache invalidated on completion/failure

GET /api/scans/:id            cached only when terminal (300 s)
GET /api/scans               cached 60 s
GET /api/scans/stats/summary cached 30 s
GET /api/vulnerabilities     cached 60 s (list), 120 s (detail)
GET /api/scans/queue/stats   queue counts + cache stats (no cache)
```

**Queue semantics.** Jobs are never retried automatically (`attempts: 1`;
a failed scan already failed honestly in its row). A BullMQ job whose
scan returns `{ ok: false }` is marked failed, not completed, so the
queue stats stay honest. Inline mode (no Redis) has the same FIFO +
concurrency, but jobs live in memory — a crash loses queued jobs (their
rows stay `queued`; re-trigger). BullMQ jobs survive a restart.

**Cache semantics.** Redis read-through, org-scoped keys
(`sg:cache:v1:org:<id>:...`), `X-Cache: HIT | MISS | BYPASS` headers.
Non-terminal scans are never cached — the dashboard's 2 s poll must
never see a stale `running`. 404s are never cached. PATCH on a
vulnerability invalidates the org's keys. Redis down or unset → bypass,
never throws. Stats: hits, misses, bypasses, sets, invalidations.

## Environment

| Var | Default | Meaning |
| --- | --- | --- |
| `REDIS_URL` | unset | BullMQ queue + cache. Unset → in-process queue, cache bypassed. |
| `SCAN_WORKER_CONCURRENCY` | `2` | Scans running at once (BullMQ worker + thread pool). |
| `SCAN_THREAD_POOL_SIZE` | = concurrency | Persistent scan worker threads. |
| `SCAN_THREAD_TIMEOUT_MS` | `600000` | Kill a stuck scan thread after this long. |

Local dev: `docker-compose.yml` adds a `redis:8-alpine` service and
wires `REDIS_URL` for the backend.

## Production setup (owner step)

Until `REDIS_URL` is set in the Render dashboard, production runs the
in-process fallback (works, no queue durability, no cache). To enable
BullMQ + cache: provision **Render Key Value** (or Upstash Redis) and
paste its URL as the `REDIS_URL` env var on the Render web service,
then redeploy. No code change needed — the mode switches automatically.

## Measured numbers

Harness: `backend/tests/scanPerfHarness.js` — runs the real HTTP routes
with stubbed Prisma/auth/RBAC/billing, a real local Redis 8.10.2, the
real `runSecurityScan`, classifier pointed at a closed port (fail-safe
REAL verdicts). Fixture repo: 152 files, 15 findings per scan
(12 critical, 3 high, 6 secrets), 1227 lines. Poll interval 250 ms
(turnaround inflated by ≤250 ms). Before = original synchronous code.

| Scenario | Before submit p50 / p95 | After submit p50 / p95 | After turnaround p50 / p95 |
| --- | --- | --- | --- |
| Single scan | 404 / 527 ms (cold) | 5 / 6 ms | 264 / 266 ms |
| 10 concurrent | 1897 / 3889 ms | 53 / 60 ms | 1162 / 1165 ms |
| 100 concurrent | 3230 / 6142 ms | 351 / 716 ms | 3990 / 6745 ms |

- 100-concurrent wall time (all submissions accepted): **6,499 ms → 936 ms**.
- 100 concurrent, after: **101/101 scans completed, 0 failed**, same
  findings per scan as before.
- Cache: 20 sequential `GET /api/vulnerabilities` → 1 MISS + 19 HITs,
  **hit rate 0.95** (before: 0). Latency p50 2 ms.

**Honest reading.** The queue makes *submission* fast (8.6× at 100
concurrent: 6,142 → 716 ms p95) — it does not make scans themselves
faster. Total scan work is unchanged, so the last scan in a 100-burst
finishes at roughly the same time as before (turnaround p95 6,142 →
6,745 ms; the small regression is queueing + thread handoff at
concurrency 2). What the queue buys: the API stays responsive under a
burst instead of holding every request for seconds, and scans are
bounded to `SCAN_WORKER_CONCURRENCY` instead of piling onto the loop.
The single-scan before number was cold (first touch of fixture files);
the C10/C100 comparisons are the clean ones. Cache latency is
unmeasurable in this harness because the stub DB is in-memory — the
measured win is the hit rate (DB reads skipped), not a local latency
delta; in production a HIT skips a Postgres round-trip.

**XYZ bullet (from these numbers only):**

> Moved SecureGaurd scans off the request thread onto a BullMQ/Redis
> queue with worker-thread execution and added a Redis read-through
> cache, cutting 100-concurrent scan-submit p95 latency from 6,142 ms
> to 716 ms (8.6×) with zero failed scans and a measured 95% cache hit
> rate on vulnerability lists.

### Scaling run (2026-11-23): 50 → 500 concurrent

Same harness and fixture, re-run on the dev VM (1.5 shared CPUs,
6 GiB RAM, Node v24.22.1, locally built Redis 8.12.0 on :6390 with
`maxmemory 512mb` / `allkeys-lru`, worker concurrency 2 = default).
The harness now accepts `concurrent<N>` for any N. Each run includes
1 warmup scan, so completed totals are N+1. Queue depth / Redis memory
/ node RSS were sampled every 500 ms during each run.

| Scenario | Submit p50 / p95 / p99 (ms) | Turnaround p50 / p95 / p99 (ms) | Wall (all submits) | Completed | Max queue depth | Redis peak mem | Node RSS peak |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 50 (dry run) | 221 / 425 / 426 | 2,836 / 3,884 / 3,888 | 440 ms | 51/51 | 46 | 2.0 MiB | — |
| 100 | 377 / 739 / 750 | 4,652 / 7,368 / 7,626 | 769 ms | 101/101 | 93 | 2.2 MiB | 391 MiB |
| 250 | 1,242 / 2,123 / 2,257 | 9,352 / 16,748 / 17,360 | 2,309 ms | 251/251 | 231 | 2.2 MiB | 555 MiB |
| 500 | 2,290 / 3,652 / 3,763 | 17,047 / 30,215 / 31,559 | 3,860 ms | 501/501 | 461 | 2.4 MiB | 652 MiB |

(50-run RSS not recorded — the sampler tracked the wrapper shell on
that first run; queue depth and Redis memory are from redis-cli and
are valid.)

- **Failure rate 0 at every level.** Redis `evicted_keys` stayed 0 —
  peak usage was 2.4 MiB of the 512 MiB cap (queue jobs are small; the
  cap was never a factor). Node CPU peaked at 105–123% (of one core).
- **Cache scenario re-run:** 1 MISS + 19 HITs, hit rate **0.95**,
  p50 2 ms — identical to the original measurement.
- **The 100 re-run lands next to the original numbers** (submit p95
  739 vs 716 ms; turnaround p95 7,368 vs 6,745 ms; wall 769 vs 936 ms),
  so the ladder is comparable to the table above.
- **Degradation is gradual, not a cliff.** Submit p95 grows ~5× from
  100 → 500 (event-loop contention: API, worker, and the harness's own
  500 fetch clients share one process on a shared-CPU VM). Turnaround
  p95 grows ~4× because total scan work is proportional to N at fixed
  worker concurrency 2 — the queue absorbs the burst and the tail is
  throughput-bound, exactly as designed.
- **No tuning was applied** — nothing failed, Redis never approached
  its cap, and the backlog drained on its own at every level. If the
  turnaround tail matters more than CPU headroom, raising
  `SCAN_WORKER_CONCURRENCY` is the knob; measure before changing the
  default. It was not changed here.

Caveats are the same as above: in-memory DB stub (no Postgres
roundtrips), classifier unreachable by design, 152-file fixture,
250 ms poll granularity (turnaround includes up to one poll interval
plus sequential-poll detection lag), single process on a shared-CPU VM.
Raw outputs: `loadtest-{50,100,250,500,cache}.json` + sampler logs
(kept with the run artifacts, not in the repo).

## Reproducing the numbers (your own machine)

The harness does not ship its fixture — generate it first, one command:

```bash
cd SecureGaurd-main
SCAN_LOCAL_BASE=/path/to/scan-fixtures \
  node backend/tests/generateScanFixture.js
# writes 152 files to /path/to/scan-fixtures/small-repo:
# 15 findings per scan (12 critical, 3 high, 6 secrets). The planted
# secrets are dummy values (Amazon's published example key, a placeholder
# password) — never replace them with real credentials.
```

Then, from `SecureGaurd-main` (backend deps installed, `npm install` in
`backend/`):

```bash
# After-mode needs a LOCAL Redis on :6390 (docker-compose up redis, or
# redis-server --port 6390). The harness FLUSHES that Redis, so never
# point REDIS_URL at a shared/production instance.
export SCAN_LOCAL_BASE=/path/to/scan-fixtures
export HARNESS_OUT=/path/to/scan-perf-after-concurrent100.json
node backend/tests/scanPerfHarness.js after concurrent100
node backend/tests/scanPerfHarness.js after cache
node backend/tests/scanPerfHarness.js after single
```

Three gotchas:

1. **Fixture first.** Without `small-repo` under `SCAN_LOCAL_BASE` the
   harness scans nothing and the numbers are meaningless.
2. **`HARNESS_OUT` must be set on your machine.** The default path is
   this VM's workspace (`/home/hatch/workspace/...`) and is invalid
   anywhere else.
3. **Before-numbers need the old code.** The harness does not simulate
   "before" — check out the parent commit of `84212d9`, run the same
   three commands with `before` instead of `after` (no Redis needed),
   then come back to `84212d9`. Compare only runs on the same machine
   with the same fixture; absolute ms will differ, the ratio is the
   signal. Live production numbers come from `GET /api/scans/queue/stats`
   and the `X-Cache: HIT` header on `GET /api/vulnerabilities`.

## Known limitations

- A crashed process leaves `queued`/`running` rows behind — no
  stale-scan sweep yet; the user re-triggers. (BullMQ jobs survive;
  inline jobs do not.)
- `SCAN_WORKER_CONCURRENCY` is a single-process bound; scaling past
  one API instance needs a shared Redis (BullMQ mode) and the
  concurrency tuned per instance.
- The load-test fixture is small (152 files). A large-repo burst will
  have a longer turnaround tail; re-measure with a real repo before
  quoting bigger numbers.
