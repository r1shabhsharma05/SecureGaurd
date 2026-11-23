# SecureGuard Re-Test #4 Report — 23 Nov 2026

Tested by Muse (code check locally + live browser test on production).
Repo HEAD: `36fee34` (code fixes at `93d710d`, pushed 23 Nov 01:01 IST, live on Render).
App: https://secureguard-main.vercel.app · Backend: https://securegaurd.onrender.com

## Verdict

Product is working end to end on the new least-privilege DB role. Counts agree
everywhere, pages are fast (warm), SOC2 regenerates cleanly. Two real bugs found
by this re-test: the AI model label still lies in the UI, and the monthly scan
quota never resets after the first billing period ends (fresh scans are blocked
permanently for org 1 right now). Fixes for both are identified below, not yet
applied.

## Code check (local, HEAD 36fee34)

- Backend tests: **162 total — 160 pass, 2 fail, 0 skip.** The 2 fails are the
  known environment ones (compliance needs live Postgres, deployment_config
  needs real secrets), identical on the base commit.
- Frontend build: green (4.2s; chunk-size warning only).
- Secrets scan (grep over tracked files): clean — only test-fixture fake keys
  and scanner-bait seed datasets.
- Gemini config: default model `gemini-3.1-flash-lite` (env `GEMINI_MODEL`
  overrides), 503/429 retry with backoff (up to 2 retries), status probe
  exercises real generation and reports the true engine.
- Live probe: new validation layer confirmed live (bad-typed login returns
  `400 {message, errors[]}`); `/health` db up (44s cold start, 0.9s warm).

## Live browser test (production, 23 Nov 11:31–11:37 IST)

1. **Login: PASS.** Saved login works as rishabhsharma14426@gmail.com. (The
   22 Nov login failures were the RLS-blind app before permissive policies —
   the password was never wrong; no reset was needed.)
2. **Counts: PASS, all agree.** Dashboard 72 (45C/22H/5M/0L), Health 20/100;
   Vulnerability Database 72 open; SOC2 report 72 findings. Sidebar: 1 repo,
   10 scans, 72 vulns.
3. **Scans: PASS.** 10 listed (5 COMPLETED, 5 FAILED — failures are 19 Nov
   clone errors against a test repo + 1 transaction timeout, historical).
   S-0021 detail lists all 72 findings. S-0019 detail shows 0 new findings
   with the honest explanation ("recorded 37 findings at scan time, but every
   one matched a finding already tracked from an earlier scan"). S-0020 does
   not exist ("Scan not found") — expected, ID consumed by a rolled-back
   insert, no data lost.
4. **Fresh scan: BLOCKED by quota.** Monthly Scans 10/10, "0 scans remaining
   this billing period" — but the billing period ended 11/19/2026. See Bug 2.
5. **AI Fix: generation works, label WRONG.** Fix generated for V-0237
   (SQL Injection). UI label reads "Google Gemini 3.1 Flash Engine" — the
   real engine is `gemini-3.1-flash-lite`. See Bug 1. Note: explanation said
   "Previously generated AI fix" — the shown fix was cached, not freshly
   generated this click.
6. **Page loads (warm, in-app navigation): PASS.** Dashboard 0.46s,
   Vulnerabilities 0.55s, Scans 0.38s, Compliance 0.32s (~1s for report
   data), Settings ~0.5s. Cold start on Render free tier still ~30–44s on
   first hit after idle (measured 44s today) — separate, known issue.
7. **SOC2 fresh report: PASS.** Generated 23 Nov: 13/100, 72 findings
   (45/22/5/0), 2 PASS / 0 PARTIAL / 4 FAIL — identical to 19 Nov report.
   Low score reflects the 72 open findings, not a report bug.
8. **Misc: PASS.** Search/filter correct (27 SQL-Injection, 22 HIGH,
   intersection 0). Members: 1 (Rishabh Sharma, OWNER). Billing prices:
   FREE ₹0, PRO ₹4,000/mo, ENTERPRISE ₹25,000/mo. Workspace "Rishabh's
   Workspace", repo r1shabhsharma05/SecureGaurd @ main.
   - API key `scan-test` (read + scan:trigger, created 19 Nov) is **still
     active** — not revoked. Owner can revoke in Settings → API Keys.

## Bugs found by this re-test

### Bug 1 — AI model label still wrong in UI
Backend `/api/ai/status` truthfully returns `gemini-3.1-flash-lite`, but
`engineName()` in `src/components/VulnerabilityDetailsPage.tsx` regex-maps it
to "Google Gemini 3.1 Flash" — a model that does not exist. Fix: display the
raw engine string for Gemini engines (keep the Rule-based mapping). One-file
frontend change.

### Bug 2 — Monthly scan quota never resets
`getOrgUsage` in `backend/services/billingService.js` counts scans since
`subscription.currentPeriodStart`, but nothing rolls the period forward when
`currentPeriodEnd` passes. Org 1's period ended 19 Nov; usage still counts
the old window → 10/10 forever, `checkCanTriggerScan` blocks every new scan.
Fix: in `getOrgUsage`, advance the window by whole months until it contains
now before counting (no writes; active paid periods unchanged; Razorpay
webhooks still own paid period dates). One-function backend change + test.

## What is fixed since re-test #2/#3

- Counts reconciled (72 everywhere, no duplicates).
- Scan detail lists real findings (S-0021 = 72).
- Page loads: ~20s → sub-second warm.
- S-0020 mystery closed (rolled-back insert, explained in UI/DB).
- Validation layer live on all mutating routes; 3 dep vulns fixed (OSV 0).
- App runs on least-privilege DB role `secureguard_app` (SEC-31 partial;
  tenant-scoped RLS policies still pending owner decisions).

## Next steps (owner decisions)

1. Apply Bug 1 + Bug 2 fixes and push (needs owner word; push auto-deploys).
2. Revoke `scan-test` API key if no longer needed (Settings → API Keys).
3. SEC-31 Step E: tenant RLS policies — needs backup-acceptance +
   export-feedback decisions.
4. Cold start: paid Render or external pinger (owner call).
5. Gate still NOT PASSED (25/14/4/3 at Day 10): SEC-03 history purge,
   SEC-32 backups, SEC-34 Turnstile remain owner-gated.

---

## Addendum — post-fix verification (23 Nov 2026, ~12:25 IST)

Bug 1 + Bug 2 fixes pushed as `e3aac19` (6 files, incl. this report) and
live-verified:

- **Bug 1 FIXED live:** V-0237 now shows "gemini-3.1-flash-lite Engine"
  (Remediation History likewise). No more "Google Gemini 3.1 Flash".
- **Bug 2 FIXED live:** Billing shows 4/10 used, 6 remaining, period ends
  12/19/2026 (was 10/10, 0 remaining, ended 11/19/2026). After the fresh
  scan below: 5/10, 5 remaining.
- **Counts still agree:** Dashboard 72 (45/22/5/0, Health 20/100) =
  Vuln Database 72 open.

### Bug 3 (found by the fresh scan) — scan inserts fail on detectedInScanIds

Fresh scan **S-0022** ran (377 files, 5.80s, 72 findings at scan time) but
recorded **0 findings**: `prisma.vulnerability.createMany()` failed with
"Null constraint violation on the (not available)". Scan row: status
`failed`, errorMessage stored, 0 Vulnerability rows for scanId 22.

Root cause (measured in prod DB, 23 Nov): `Vulnerability.detectedInScanIds`
is **NOT NULL with no column default**, although migration
`20261119_detected_scans_ai_engine` declares `DEFAULT '{}'` — the
`IF NOT EXISTS` add was a no-op against a column that already existed
without the default. `createMany` omits unlisted fields, and both insert
sites (`services/scanRunner.js`, `routes/integration.js`) omitted
`detectedInScanIds`, so every fresh-finding insert is rejected. Scanner
output itself has no nulls (local run: 72 findings, 0 null required
fields). Why S-0021 succeeded on 19 Nov is not fully reconstructable
(column/default state at that hour is unrecorded); the current state is
measured and the fix does not depend on the history.

Fix (prepared, needs owner word to push — push auto-deploys): send
`detectedInScanIds: [scan.id]` explicitly in both createMany mappings
(semantically right: a fresh finding was detected in this scan), plus a
regression test in `backend/tests/retest2Fixes.test.js`. Suite after fix:
165 tests, 163 pass, 2 pre-existing env failures. Optional DB-side
alignment (owner, one line in SQL Editor):
`ALTER TABLE "Vulnerability" ALTER COLUMN "detectedInScanIds" SET DEFAULT '{}';`
No schema/migration change was made: a DDL migration would run under the
least-privilege `secureguard_app` role on Render preDeploy and could
block deploys.

### Bug 3 fix — pushed and live-verified (23 Nov, ~12:52–12:59 IST)

Fix pushed as `14367bd` ("fix scan findings not saving", 5 files; remote
file list verified, tree identical, clone synced). Fresh scan **S-0023**
(12:55 IST, 377 files, 6.10s) then **completed and saved findings** — the
createMany error is gone:

- S-0023 detail: COMPLETED, 72 findings at scan time (45/22/5/0),
  "Findings in this scan (72)" — 71 re-detections recorded via
  `detectedInScanIds` + 1 new row inserted (**V-0242**, Potential SQL
  Injection, CRITICAL, `backend/tests/rlsMigration.test.js:91`).
- Live totals moved 72 → **73 open (46C/22H/5M/0L)**, Health 20/100;
  Dashboard = Vuln Database agree. (73 = 72 previously open + 1 new; one
  previously-open finding was not re-detected by S-0023 and remains open.)
- Quota after S-0023: 6/10 used, 4 remaining, period ends 12/19/2026.
  Security Scans count: 12.
- One transient artifact: immediately after S-0023, the Scans list and
  dashboard showed stale values (RUNNING / S-0021's 371 files) until a
  hard reload a few minutes later — org-cache lag, not a status bug.
  After reload, list and detail agree (COMPLETED, 377 files, 6.10s).
- S-0022 remains FAILED historically with its stored error (no backfill).

**Re-test #4 verdict: all three bugs fixed and live-verified.** Remaining
owner-gated items are unchanged (gate 25/14/4/3 NOT PASSED: SEC-03,
SEC-31 Step E, SEC-32, SEC-34; Razorpay live KYC; cold-start decision;
`scan-test` key revoke is owner's call).
