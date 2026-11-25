# Day 13 — Background Architecture Audit

**Date:** 2026-11-26 (Day 13 of the 20-day program)
**Scope (plan Day 13):** queue, worker isolation, retries, resource
limits, scan lifecycle and cleanup.
**Gate status at run start:** STILL NOT PASSED — 29 PASS / 12 PARTIAL /
2 FAIL / 0 BLOCKED / 3 N/A (Day 12 recount, unchanged; remote HEAD
`7a80d45`, no commits since Day 12, no owner decisions since Day 12).
**Consequence:** no Phase 4 features built. This is a read-only audit
of the Day 13 scope against the code at `7a80d45`, plus the build plan
for when the gate passes. Nothing in this document claims a fix is
shipped — every gap below is still open in production.

**Run limitation (stated plainly):** no local test, build, OSV or
Gitleaks run happened this turn — the local clone content failed an
execution-risk check at run start, so no git/npm command ran inside
it. Test counts below are Day 12's fresh evidence (25 Nov) and the
existing load-test doc, labelled as such, not re-measured today.
Gate counts are unchanged because nothing changed: same remote HEAD,
no owner decisions, live probes green (below).

## 1. What already exists (verified by reading the code)

The background architecture was built on 19 Nov (`84212d9`,
`docs/SCAN_QUEUE_CACHE_LOADTEST.md`) and is real, not a stub:

| Piece | File | How it works |
|---|---|---|
| Queue | `SecureGaurd-main/backend/queues/scanQueue.js` | BullMQ `secureguard-scans` on Redis when `REDIS_URL` is set; in-process FIFO otherwise. Same API both ways. Concurrency `SCAN_WORKER_CONCURRENCY`, default 2. |
| Trigger | `SecureGaurd-main/backend/routes/scans.js` (`POST /trigger`) | Creates the `queued` scan row, then `enqueueScan`; returns 202. Rate-limited 10 triggers / 10 min per IP; monthly quota checked first (FREE 10/mo, PRO 200/mo — `config/plans.js`). Role OWNER/ADMIN/DEVELOPER only. |
| Worker | `scanQueue.js` `startWorker()` | Started once from `server.js` at boot, non-blocking (a start failure is logged, the API still serves). BullMQ job runs `executeScan`; `{ ok: false }` is thrown so the job lands as **failed**, not completed. |
| Thread pool | `SecureGaurd-main/backend/workers/scanThreadPool.js` + `scanThread.js` | Persistent worker threads (pool size = concurrency, default 2). Spawning a thread per scan cost ~250 ms, so warm threads are reused. A dead/stuck thread fails its job and is replaced. |
| Scan runner | `SecureGaurd-main/backend/services/scanRunner.js` | `executeScan` never throws: every failure path marks the scan row `failed` with a message and returns `{ ok: false }`. Own short RLS context per DB segment (no long transaction). |
| Clone / isolation | `SecureGaurd-main/backend/utils/repoScanSource.js` | Local paths only inside `SCAN_LOCAL_BASE` (unset → none allowed). Remote: host allowlist (github.com, gitlab.com + `EXTRA_GIT_HOSTS`), no credentials in the URL, every resolved address must be public, `http.followRedirects=false`, shallow `--depth 1` clone into `tmp-work/scan-clones/scan-<random>`, 180 s timeout. Clone failure deletes the temp dir. |
| Cache | `SecureGaurd-main/backend/utils/cache.js` + `utils/redis.js` | Redis read-through, org-scoped keys (`sg:cache:v1:org:<id>:…`). Non-terminal scans never cached; terminal scans cached 300 s; lists 60 s; summary 30 s. Redis down/unset → bypass, never throws. `GET /api/scans/queue/stats` exposes queue counts + cache stats. |
| Shutdown | `SecureGaurd-main/backend/server.js` | SIGTERM/SIGINT → `closeQueue()` → `closePool()` → `closeRedis()` → Prisma disconnect → `server.close()`, force-exit after 5 s. |
| Lifecycle | `routes/scans.js` | `queued → running → completed / failed`. Dashboard polls `GET /api/scans/:id` (2 s); terminal scans cached, live ones never cached. |

**Measured numbers (existing, `docs/SCAN_QUEUE_CACHE_LOADTEST.md`,
23 Nov scaling run — NOT re-measured today):** 500 concurrent
triggers, 501/501 completed, 0 failed; submit p95 3,652 ms,
turnaround p95 30,215 ms at concurrency 2; Redis peak 2.4 MiB;
cache hit rate 0.95 on vulnerability lists. Queue tests
`backend/tests/scanQueueCache.test.js` 4/4 (Day 12 base: full backend
suite 167/169, same 2 known env failures).

**Live probes this run (read-only):** frontend 200 (full landing
render); backend `/health` `{"status":"ok","db":"up"}`; classifier
`/health` ok, `model_loaded: true`, v2.2.1 / `v3_real` (after ~60 s
Render cold start).

## 2. Gaps — what Day 13 does NOT yet have

Each gap is a real code-level finding, not a roadmap wish. None is
built this run (gate-blocked); the fix sketch is recorded so the
post-gate build is exact.

### G1. No stale-scan reaper — orphaned `queued` / `running` rows (OPEN)
A crashed process leaves rows behind, and nothing ever sweeps them:
- Inline mode: a crash loses queued jobs; rows stay `queued` forever.
  The user re-triggers (the load-test doc already admits this).
- BullMQ mode: jobs survive a restart, but a job that was **active**
  when the process died becomes stalled → fails (attempts: 1) while
  its scan row stays `running` forever. No code anywhere transitions
  a stale `running`/`queued` row to `failed`.
- Fix (post-gate): a startup sweep + a periodic job — any scan row
  `running`/`queued` older than N minutes with no live job (check
  BullMQ by `scan-<id>` jobId; in inline mode, any row older than the
  thread timeout) → `failed` with `errorMessage: 'Scan interrupted
  (worker restart)'`. Needs a test that kills a worker mid-scan and
  asserts the row is failed afterwards, not `running`.

### G2. No scan cancellation (OPEN)
There is no cancel endpoint in `routes/scans.js` and no `cancelled`
status anywhere in the lifecycle. Once queued or running, a scan
cannot be stopped by its owner; it occupies a worker slot until the
10-minute thread timeout (or forever, in the inline fallback — see
G5). A user who triggers a scan against the wrong repo waits it out.
- Fix (post-gate): `POST /api/scans/:id/cancel` (OWNER/ADMIN/
  DEVELOPER, org-scoped, `parseIdParam`): queued job → remove the
  BullMQ job by `scan-<id>` + mark row `cancelled`; running job →
  mark `cancelled`, terminate its thread, let the runner's next DB
  write notice the row is no longer `running` and stop. Dashboard
  gets a Cancel button on queued/running scans.

### G3. No per-org fairness — one org can starve the queue (OPEN)
Concurrency 2 is global. One org's burst fills both slots and every
other org's scans wait behind it. Mitigations that exist (10
triggers / 10 min per IP, monthly quota) bound abuse, not fairness:
a PRO org legitimately firing 200 scans/month can still monopolise
the queue for minutes, and the per-IP limiter shares one bucket
behind NAT (trust-proxy hops are set to 2 for the Vercel path, but a
shared egress IP still collapses tenants).
- Fix (post-gate): per-org in-flight cap (e.g. 1 running scan per
  org at concurrency 2, or a fair-share round-robin across orgs in
  the worker). Measure the 500-burst harness with two orgs before
  and after; assert org B's turnaround does not grow with org A's
  burst size.

### G4. No clone size / disk guard (OPEN)
`git clone --depth 1` has a 180 s timeout but **no size limit, no
`--filter`, and no disk-space check** before cloning. A very large
public repo can fill the Render disk mid-clone; the only bound is
the clock. There is also no retention sweep for `tmp-work/scan-clones`:
`cleanup()` removes the dir on the success and error paths of
`executeScan`, but a process crash mid-scan leaks it, and nothing
ever reaps orphaned `scan-*` dirs.
- Fix (post-gate): pre-clone disk-space check (refuse with an honest
  `failed` + message when free space < threshold); `git clone
  --filter=blob:none` (or a `--depth 1` + post-clone `du` cap that
  fails the scan over a size limit); a startup sweep that deletes
  `scan-*` dirs older than 24 h with no live scan row.

### G5. Inline fallback has no timeout (OPEN)
The threaded path is bounded by `SCAN_THREAD_TIMEOUT_MS` (default
600,000 ms): a stuck thread is killed and the job fails honestly.
But the fallback — `runSecurityScan(scanPath, customRules)` called
directly in `scanRunner.js` when the thread fails — runs with **no
timeout at all**. A pathological repo that hangs the synchronous
scanner in the fallback hangs the BullMQ worker job (and, in inline
mode, the event loop) indefinitely.
- Fix (post-gate): run the inline fallback in a one-shot worker
  thread with the same timeout, or wrap it with a watchdog that
  marks the scan failed after `SCAN_THREAD_TIMEOUT_MS`. Never leave
  an unbounded synchronous scan on any path.

### G6. Shutdown does not drain in-flight scans (OPEN)
`server.js` calls `closeQueue()` then immediately `closePool()`,
which terminates every worker thread at once. Even if BullMQ's
`Worker.close()` waits for active jobs, the thread-pool termination
kills the scan underneath it — the row is left `running` (see G1)
and the clone temp dir leaks (see G4). The 5 s force-exit caps the
damage but does not fix it.
- Fix (post-gate): on SIGTERM, stop accepting new triggers
  (or new jobs), wait for active scans to finish up to a drain
  deadline (e.g. 30 s), mark anything still running as `failed`
  (`'Scan interrupted by deploy'`), then close the pool. G1's
  reaper is the backstop for anything the drain misses.

### G7. No retry for transient failures; no idempotency key (OPEN, low)
- A clone that fails on a network blip, or a classifier batch that
  times out (5 s per batch, fail-safe to REAL), fails the whole scan;
  the user re-triggers and gets a **new** scan row. Only the Prisma
  P2028 path retries (×3, backoff 500 ms/1 s). That is a deliberate
  honest-failure policy, but a single retry for *clone-only*
  failures (before any scan work) would cut user-visible flakes
  without ever re-running a scan that failed honestly.
- `POST /trigger` has no idempotency key: a double-click or a
  retried request creates two scan rows and consumes two quota
  units. The 10/10-min limiter blunts it but does not prevent it.
- Fix (post-gate): retry clone failures once (BullMQ attempts: 2
  for the clone step only, or an explicit re-enqueue before the scan
  starts); accept an `Idempotency-Key` header on trigger and return
  the existing queued scan row on a repeat within 10 minutes.

## 3. Production queue mode — UNVERIFIED this run
`render.yaml` declares `REDIS_URL` as an owner step ("provision a
Redis … and paste its URL here. Until then … scans run on an
in-process queue"). The Day 7 gate report states "queue + cache live
(BullMQ/Redis)". Those two do not agree on their face, and this run
could not settle it: `GET /api/scans/queue/stats` needs an
authenticated org session and no probe credentials were available.
**Exact check for a later run:** authenticated `GET
/api/scans/queue/stats` → `mode` field (`bullmq` vs `inline`); or a
Render dashboard read of the `REDIS_URL` env var (presence only,
never print the value). Until that check lands, do not claim
BullMQ is live in production — the in-process fallback is the
safe assumption, and G1's inline-mode orphan rows apply.

## 4. What the gate still needs (unchanged)
SEC-03 (git-history purge — Atlas MFA + rewrite word) and SEC-31
(Step E tenant policies — backup-first, extra tables, export-feedback
503 design) are owner-gated and unchanged. The Day 13 gaps above are
**not** gate items: they are Phase 4 engineering work, buildable
only after the gate passes. The gate report (`docs/SECURITY_GATE_REPORT.md`)
carries the Day 13 re-check; counts are unchanged at 29/12/2/0/3.

## 5. Post-gate build order (Day 13 work, for the first unblocked run)
1. G1 reaper (startup sweep + periodic job) — it is the backstop for
   G6 and the only fix that heals rows already orphaned in prod.
2. G5 inline-fallback timeout — closes the one unbounded-execution
   path; smallest change, highest safety value.
3. G2 cancel endpoint + dashboard button.
4. G4 clone size/disk guard + orphan-dir sweep.
5. G6 graceful drain on SIGTERM.
6. G3 per-org fairness (measure with the two-org harness first).
7. G7 clone-only retry + trigger idempotency key.
Each item ships with a regression test and a harness re-run
(500-concurrent table) before it is claimed done.
