# SecureGaurd — Security Gate Report (Day 7 gate, re-verified 2026-11-20)

**Date:** 2026-11-20 (Day 7 of the 20-day program)
**Verdict: GATE NOT PASSED**
**Checklist:** `docs/SECURITY_HARDENING_CHECKLIST.md` — 29 PASS / 12 PARTIAL /
2 FAIL / 0 BLOCKED / 3 NOT APPLICABLE (46 items) — **five items crossed
since the 24/15/4/3 recount**: SEC-13 (0 OSV findings, Day 10),
SEC-18 + SEC-22 (strict id params, Day 11 commit `b36b839`), SEC-34
(Turnstile live, commit `1a11ff9`) and SEC-32 (first backup + trial
restore, 24 Nov evening). Count note (settled Day 12, 25 Nov): the
checklist file itself counts 29/12/2/0/3; the 28/13 figure in earlier
Day 11 text was a one-item arithmetic slip — SEC-13's Day 10 crossing
was missed in the report's addition, not in the file.
**Commits covered:** everything through `7d471db` (Day 5 `21def6a`,
Day 6 `4809fa0`, queue/cache `84212d9`, E2E batches `76149f2`/`b8d1ffb`,
API keys + connect fix `9611676`, dashboard fixes `dce4e57`/`f1527bf`,
re-test batches `ffad4fa`/`bfe2e6c`, Gemini `bda7896`/`c3b05e0`, perf
`e7b3a67`, keepalive `b62fc35`/`7d471db`)
**Gate rule (Day 7):** every applicable item PASS with evidence, no
unresolved critical/high issues, all exceptions documented and approved.
**Phase 4 rule: do not start Phase 4 features until this gate passes.
Day 8 (scanning engine) is therefore BLOCKED until the 2 FAILs below
clear. This report does not disguise any FAIL as PASS.**

Supersedes the 2026-11-18 gate-pass run report. Database detail:
`docs/DATABASE_SECURITY.md`.

---

## What changed since the 18 Nov gate report

Real progress, all verified live or by test — none of it clears a FAIL,
because every FAIL is owner/dashboard-gated, not code-gated:

| Area | 18 Nov | 20 Nov (Day 7) | Evidence |
|---|---|---|---|
| OAuth (SEC-07 note) | code present, none live | **Google + GitHub LIVE** | `GET /api/auth/oauth/providers` → google + github (19 Nov, re-probed Day 7). MFA still absent → SEC-07 stays PARTIAL. |
| AI fix engine | rule-based fallback, mislabelled | **Gemini verified working** | `gemini-3.1-flash-lite` generation proven on V-0004/V-0005 (19 Nov); status probe now runs a real 1-token generation; retries on 503/429. |
| Billing | mock Pro, no keys | **Razorpay TEST mode verified** | Test key regenerated + on Render; hosted checkout reached, test subscription created, no payment taken. LIVE keys still blocked on owner onboarding/KYC. |
| Scan pipeline | phantom repo, failing scans | **Real repo, real scans** | Repo 25 `r1shabhsharma05/SecureGaurd`; S-0017 (72 findings) + S-0021 (72, detail lists matched findings) completed; queue + cache live (BullMQ/Redis). |
| Prod data | 161 rows, dupes, phantom repo | **Cleaned + reconciled** | 181 → 72 open (45C/22H/5M), 0 dup groups, phantom repo deleted after re-point, workspace renamed. |
| Dependencies (SEC-13) | 568 pkgs, 3 findings (1 HIGH picomatch) | **587 pkgs, 2 findings** | OSV Day 7: minimatch 10.2.6 + glob 13.0.6 (both glob-DoS, fixes are major bumps). Picomatch advisory no longer returned — advisory state changed, package unchanged; NOT claimed fixed. |
| RLS coverage (SEC-31) | 54 files, 0 bare | **63 files, 0 bare** | `check-rls-coverage.js` Day 7. Migration still not applied → FAIL stands. |
| Routes (SEC-16) | 92 | **97** (95 router + 2 server) | 5 new routes since 18 Nov, all behind auth + org context (code-verified). Live matrix still outstanding → PARTIAL stands. |
| Tests | 75/77 | **147/149** | 2 fails = same pre-existing env failures (compliance: live Postgres; deployment_config: real secrets). 1 regression found + fixed Day 7 (keepalive cron literal). |
| Secrets history (SEC-03) | 6 FP findings, purge pending | **unchanged** | Gitleaks Day 7: 210 commits, same 6 FPs, 0 real secrets detected; known `e1e3dc9` leak still undetected by default rules; purge not done. |
| CAPTCHA (SEC-34) | 201 with no token | **PASS 24 Nov** | Widget "SecureGaurd" live; keys set on Render + Vercel (MATCH); backend 400s without a token; live `/signup` renders the widget (`1a11ff9`). |
| Backups (SEC-32) | none ever | **PASS 24 Nov** | First backup taken (`secureguard-20261124-134015.dump.gz`, 20 tables) + trial restore into local PG 17 passed (row counts matched). PITR still unverified (Free plan has none). |

Live probes Day 7 (read-only): frontend 200 (CSP/HSTS/nosniff/COOP),
backend `/health` 200 with `db: "up"`, classifier 200
`model_loaded: true`, `/api/_test-error` 404, `/api/ai/status` 401
unauthenticated, CORS denied for unlisted origin / allowed for app
origin. No probe accounts created.

---

## Why the gate does NOT pass — the 2 FAILs (all owner-gated)

### SEC-03 — Secrets in git history (FAIL)
Commit `e1e3dc9` (2026-04-16) committed `backend/.env` with a real
`JWT_SECRET` (rotated 2026-11-08) and a dev MongoDB credential
(`glanexus_admin`). Forks check done (0 forks).
**Day 8 evidence (2026-11-21):** Render dashboard read-only check —
current `JWT_SECRET` on the SecureGaurd service exists and is
**128 characters**; the leaked value in `e1e3dc9` is 38 characters.
The current secret therefore differs from the leaked one — rotation
is confirmed (length only; the value was never printed). Atlas
check attempted the same night: saved login accepted, then blocked
at Authenticator App MFA — console not reached, `glanexus_admin`
existence still unknown, nothing deleted. Still open: owner
completes Atlas MFA (or deletes `glanexus_admin` himself), and gives
the word for the history rewrite (`git filter-repo` + force-push).
Gitleaks does not detect this leak with default rules — a green scan
is not evidence of a clean history. Procedure:
`docs/SECRETS_AND_INFRASTRUCTURE.md` §2.

### SEC-31 — No Postgres RLS enforcement (FAIL)
Migration written + PGlite-validated (17 policies, 14 tables incl.
`ApiKey`, FORCE RLS, fail-closed); call-site conversion complete
(63 files, 0 bare accesses); `rlsMigration.test.js` 12/12 green
(re-run 2026-11-21).
**Day 8 evidence (2026-11-21, Supabase SQL Editor, read-only):**
step 1 done — app credential is `postgres` with `usesuper=false`
but **`usebypassrls=true`**, so RLS would still be bypassed;
`secureguard_app` role does not exist. Render `DATABASE_URL`
username confirmed as `postgres.wkvvxqlflhjiqkhwxrsl` (pooler).
`pg_policies` count = 0 (nothing applied yet). Step 3 done —
backfill check: every tenant table with an `organizationId` column
has **0 NULL-org rows** (Repository, Scan, Sbom, ComplianceReport,
ApiKey, CustomRule, AlertLog, AuditLog, Subscription all 0;
`Vulnerability` has no `organizationId` column — scoped via Scan).
Still open: (1b) create `secureguard_app` role (LOGIN, no
superuser, **no bypassrls**, DML grants) + repoint Render
`DATABASE_URL` + redeploy + re-run step 1; (4) apply via SQL Editor
(expect 17 policies); (5) push the migration folder + live matrix.
**Superseded 2026-11-22/23:** step 1b was executed (fix-forward
after a zero-policy outage) — `secureguard_app` is live with
NOBYPASSRLS and 20 permissive policies; the 17 tenant policies are
still NOT applied. See the Day 10 re-check section below for the
verified live state. SEC-31 remains FAIL.
Full procedure: `docs/DATABASE_SECURITY.md` §6.1. The scans
export-feedback operator path 503s under RLS (no service-role path)
— design decision still owed before apply. The role creation +
repoint is a production change — not done unattended.

### SEC-32 — Database backups (PASS, closed 2026-11-24)
First backup taken + trial restore passed. Owner picked the free
`pg_dump` route, then the postgres-password reset path (dashboard
reset 19:08 IST, user-chosen password). `pg_dump` 17.12 as the
`postgres` role over a direct connection — the app role cannot dump
(RLS blocks pg_dump's COPY/cursor, proven live). Archive
`backend/backups/secureguard-20261124-134015.dump.gz` (1.6 MB, 0600,
UNENCRYPTED — no passphrase set yet), manifest lists all 20 public
tables + data. Trial restore into a local PG 17.12 scratch DB (PGDG
server, deleted after): with `secureguard_app` created first,
pg_restore completed with only the benign `schema "public" already
exists` error; 20/20 tables + 20/20 policies restored; row counts
matched prod exactly (User 29, Organization 21, Scan 21,
Vulnerability 122, ApiKey 2, Repository 9). Script fixes landed with
it (`--schema=public`, `--inserts`, manifest temp-file fix). Full
record: `docs/BACKUP_AND_RESTORE.md` §2–§3. Remaining gaps (not
blockers for PASS): archive unencrypted, no recurring schedule yet.

### SEC-34 — CAPTCHA (PASS, closed 2026-11-24)
Cloudflare widget "SecureGaurd" (Managed, hostname
`secureguard-main.vercel.app`) created; `TURNSTILE_SECRET_KEY` on Render
(deploy Live 12:24 IST) + `VITE_TURNSTILE_SITE_KEY` on Vercel Production
(redeploy ready 12:29 IST); site keys verified MATCH character by
character. Backend enforcement proven by direct POST (`POST
/api/auth/register`, no token → **400**); register is also blocked
client-side without a token. The live widget first failed to load —
root cause was a wrong script URL (`turnstile/api.js` 404s; correct is
`turnstile/v0/api.js`), fixed in one line (`1a11ff9`, pushed on his
word). Live probe after deploy: `/signup` renders the "Verify you are
human" checkbox, no error. Note: `/login` has no Turnstile guard by
design (rate-limited); the guard covers register / forgot-password /
contact only.

---

## Open PARTIALs that also block a clean gate

- **SEC-13:** 2 OSV findings remain (minimatch 10.2.6 → 11.0.1,
  glob 13.0.6 → 14.0.2; both glob-pattern DoS, availability-low,
  build/transitive reach). Fixes are major bumps — Day 9 scope.
  The 18 Nov picomatch risk-accept ask is moot: OSV no longer
  returns that advisory for 4.0.7. No written exception needed for
  it; the 2 current findings need the Day 9 upgrades, not an
  exception.
- **SEC-15 / SEC-16:** live cross-tenant matrix outstanding (needs 2
  mailboxes). Code evidence is strong (97 routes classified, 0 bare
  tenant accesses, IDOR 404s) but the gate rule requires live proof.
- **SEC-17:** live 429 proof still inconclusive (rotating egress IP
  on this VM; limiter proven mounted in-process, Day 6 test).
- **SEC-33:** retention rules + purge script (no-RLS tables only);
  no scheduled job; no purge ever run; AuditLog append-only trigger
  vs 365-day retention conflict undecided.
- **SEC-04:** PAT plaintext-migration live run blocked (no DB creds
  on this VM; self-test 7/7).
- **SEC-07:** MFA absent (grep-verified); OAuth now live (Google +
  GitHub) — the remaining gap is MFA + per-account lockout design.
- **SEC-06:** deletions outstanding — `backend/generated/prisma/`
  (33 files tracked) + stale `classifier model/files/` copy still in
  the repo. Deletions need the browser web-UI push (App API cannot
  delete); the classifier copy additionally needs owner approval
  (model-files rule).
- **SEC-38 / SEC-39:** frontend validation still per-form inline;
  authenticated dashboard still unmeasured on a phone.
- **New Day 7 finding (audit logs):** auth events (login, logout,
  password change/reset) are not audit-logged. `AuditLog.organizationId`
  is required, so the fix needs a schema decision (nullable org for
  auth events vs primary-org resolution at login). Detail:
  `docs/DATABASE_SECURITY.md` §6.

## Items NOT pushed (need the browser web-UI push)

1. Deletion: committed `backend/generated/prisma/` (33 files). The
   GitHub App API cannot delete. (Stale classifier copy
   `classifier model/files/` is on the same list but deleting model
   files still needs owner approval — do NOT delete unapproved.)
2. RLS migration — NOT pushed deliberately (see SEC-31). Push only
   after the superuser check + ApiKey policy + backfill, in the same
   change as the SQL Editor apply.

## Leftovers in production

- Probe accounts from earlier probes (`sg-gate-20261118@example.com`,
  `sg-fixall-20261116@example.com`, unverified rows; owner deletes
  via DB) + ContactMessage rows id 4/5. No new probe rows were
  created on Day 7.
- Cached rule-based AI fixes on V-0001/V-0002/V-0003 (from the 19 Nov
  Gemini verification clicks; V-0004/V-0005 carry proven
  Gemini-generated fixes). Findings remain OPEN; fixes were
  generated, never applied.
- `scan-test` API key (created 19 Nov for the backend-path proof;
  owner may revoke it in Settings — its job is done).

## Decisions needed from the owner (pruned — 19 Nov completions removed)

1. **History purge (SEC-03):** approve the rewrite? JWT rotation
   confirmed Day 8 (128 vs 38 chars). Delete Atlas user
   `glanexus_admin` first — needs his Authenticator App code (MFA
   blocked the unattended check on 21 Nov).
2. **Turnstile keys (SEC-34):** create the widget + set the two keys
   (Render `TURNSTILE_SECRET_KEY`, Vercel `VITE_TURNSTILE_SITE_KEY`).
3. **Backups (SEC-32):** PITR check done Day 8 — Free plan has no
   backups. Pick: Pro upgrade ($25/mo) or scripted `pg_dump` backup
   + trial restore (`DATABASE_SECURITY.md` §6.2).
4. **RLS (SEC-31):** superuser check done Day 8 (`postgres`,
   bypassrls=true → role switch required); ApiKey policy done;
   backfill done (0 NULL-org rows); role-switch pack prepared Day 9
   (`docs/SEC31_ROLE_SWITCH.md`, not applied). Remaining: supervised
   role creation → repoint `DATABASE_URL` → verify → apply → push
   migration → live matrix (`DATABASE_SECURITY.md` §6.1). Includes
   the export-feedback operator-path decision.
5. **Retention (SEC-33):** amend the AuditLog trigger with a
   retention carve-out, or accept indefinite AuditLog retention.
6. **Deletions (SEC-06):** approve deleting `classifier model/files/`;
   `backend/generated/prisma/` goes via browser web-UI push.
7. **Live cross-tenant matrix:** 2 mailboxes (or word to use
   throwaway Gmails he controls).
8. **Auth audit logging:** schema decision — nullable
   `AuditLog.organizationId` for auth events, or primary-org
   resolution at login.
9. **Razorpay LIVE billing** (not a gate item, still blocked):
   finish business type + KYC; test mode is verified working.

**Until items 1–4 clear, Phase 4 does not start.** Day 8 (21 Nov)
re-checked the gate: still NOT PASSED (24/15/4/3) — no item crossed
to PASS, none regressed. Day 8 work was gate-clearing support only
(evidence above; backend suite 147/149, same 2 env failures; live
probes 200). The Day 8 evidence update landed as `af650fa`
(2026-11-21).

## Day 9 re-check (2026-11-22) — still NOT PASSED

Gate re-checked first, per the rule. Counts unchanged:
**24 PASS / 15 PARTIAL / 4 FAIL / 0 BLOCKED / 3 N/A**. No item
crossed to PASS, none regressed. Phase 4 (Day 9 dependency /
supply-chain features) therefore did **not** start; Day 9 work was
gate-clearing support only:

- **SEC-31 role-switch pack prepared:** `docs/SEC31_ROLE_SWITCH.md`
  — exact supervised-apply procedure for step 1b (create
  `secureguard_app` with `NOBYPASSRLS`, DML + sequence + function
  grants, default privileges, pooler `DATABASE_URL` repoint,
  verify queries, rollback, migration ownership split). **Not
  applied** — production credential change needs the owner present.
- **SEC-13 OSV re-scan (Day 9):** 587 packages, **3 findings** (was
  2 on Day 7): minimatch@10.2.6 (GHSA-g3hv-75wg-m249, fixed 11.0.1),
  glob@13.0.6 (GHSA-3g3m-2fjr-6pw4, fixed 14.0.2), and **new**
  effect@3.20.0 (GHSA-7589-6fvf-x4pw / CVE-2026-121707, fixed
  3.22.1, backend lockfile). The package did not change — a new
  advisory was published against it. Not claimed fixed; SEC-13
  stays PARTIAL. Raw: `osv-scan-results-2026-11-22.json` (kept out
  of the repo, program hidden files).
- **Local verification (HEAD `af650fa`):** `rlsMigration.test.js`
  12/12 green; RLS coverage 63 files / 0 bare accesses; full backend
  suite **147/149** (same 2 pre-existing env failures: compliance
  needs live Postgres, deployment_config needs real secrets).
- **Live probes (read-only):** frontend 200 (1.3s); backend
  `/health` 200 `db: "up"`; classifier `/health` ok
  `model_loaded: true` after a 60s cold-start timeout on the first
  probe (Render free tier sleeping — second probe answered).

Still blocked on the owner (unchanged): Atlas MFA code + history-
rewrite word (SEC-03), Turnstile widget + keys (SEC-34), backup
route pick (SEC-32), supervised role switch + export-feedback
decision (SEC-31), 2 mailboxes for the live matrix. Day 10 (23 Nov)
must re-check the gate first; if it still fails, Day 10 work stays
limited to gate-clearing support — no new product features.

## Day 10 re-check (2026-11-23) — still NOT PASSED (one item crossed)

Gate re-checked first, per the rule. Counts changed for the first
time: **25 PASS / 14 PARTIAL / 4 FAIL / 0 BLOCKED / 3 N/A** at
`93d710d`. SEC-13 crossed to PASS; nothing regressed. The 4 FAILs
stand, so Phase 4 (Day 10 ML/AI intelligence) did **not** start;
Day 10 work was gate-clearing support only:

- **SEC-13 → PASS:** the 3 OSV findings fixed via npm `overrides`
  (commit `93d710d`): minimatch 11.0.9, glob 14.0.6, effect 3.22.5 —
  verified in both lockfiles. OSV re-scan: **589 packages, 0
  vulnerable** (raw: `osv-scan-results-2026-11-23.json`, program
  hidden files). CI `dependency-scan.yml` already live.
- **SEC-18 gap shrank:** shared validation wired into 13 route files
  — **39 `validateBody` + 2 `validateQuery`** call sites; **19 of 51**
  mutating routes still use inline checks (ai.js 3, auth.js 4 incl.
  verify-email/OAuth, organizations.js 4, billingWebhook 1
  signature-verified, invitations 1, 6 singletons). Stays PARTIAL.
- **Auth audit logging (decision 8) closed in code:** `logAuthEvent`
  in `middleware/rbac.js` resolves the user's primary org and writes
  login/logout/password events to AuditLog; never throws into the
  auth handler. Covered by the RBAC/validation test files.
- **SEC-31 live state re-verified (Supabase SQL Editor, read-only,
  2026-11-23):** the 22 Nov role-switch fix-forward is real —
  `secureguard_app` exists (LOGIN, NOSUPERUSER, **NOBYPASSRLS**);
  `postgres` still bypasses RLS (rolbypassrls=true) but is no longer
  the app credential. `pg_policies` = **20**, all named
  `app_full_access`, role `{secureguard_app}`, cmd ALL, **qual =
  true (permissive)** — **0 tenant-scoped policies**. All 20 public
  tables: RLS enabled, **not forced**. So the database now enforces
  "app role only", but tenant isolation still relies entirely on
  application-level filtering. **SEC-31 stays FAIL** until the
  17-policy tenant migration replaces the permissive policies
  (Step E — still needs his decisions: backup-first or not, extra
  tables, export-feedback 503 design).
- **SEC-06 partially cleared:** `backend/generated/prisma/` (33
  files) deleted in `1204d5a` (22 Nov, browser web-UI). The stale
  `classifier model/files/` copy still needs owner approval —
  SEC-06 stays PARTIAL.
- **Local verification (HEAD `93d710d`):** full backend suite
  **160/162** (same 2 pre-existing env failures; count grew from
  149 with the new validation tests); RLS coverage 63 files / 0
  bare; frontend build green.
- **Live probes (read-only, post-push):** frontend 200; backend
  `/health` 200 `db: "up"`; classifier ok `model_loaded: true`
  (after cold start); bad-body login → 400 with field errors (no
  regression from the validation wiring).

Still blocked on the owner: Atlas MFA code + history-rewrite word
(SEC-03), Turnstile widget + keys (SEC-34), backup route pick
(SEC-32), SEC-31 Step E decisions (tenant-policy migration with or
without backup first, extra tables, export-feedback design),
classifier-copy deletion approval (SEC-06), 2 mailboxes for the
live matrix. Day 11 (24 Nov) must re-check the gate first; if it
still fails, Day 11 work stays limited to gate-clearing support —
no new product features.

## Day 11 re-check + SEC-34 close-out (2026-11-24) — still NOT PASSED (three items crossed)

Counts: **27 PASS / 13 PARTIAL / 3 FAIL / 0 BLOCKED / 3 N/A**.
SEC-18 + SEC-22 crossed to PASS (strict id params) and SEC-34 crossed
to PASS (Turnstile live); nothing regressed. The 3 FAILs stand, so
Phase 4 (Day 11 real AI remediation) did **not** start; Day 11 work
was gate-clearing support only. **Same evening, SEC-32 also closed**
(first backup + trial restore passed — see the SEC-32 section above);
counts moved to **28 PASS / 13 PARTIAL / 2 FAIL / 0 BLOCKED / 3 N/A**,
remaining FAILs SEC-03 + SEC-31.

- **SEC-18 / SEC-22 → PASS (commit `b36b839` "strict id params, no
  parseint coercion", 11 files):** route-by-route audit of the Day 10
  "19 inline routes" gap showed every body-bearing mutating route
  already runs shared `validateBody` — the real hole was id-param
  coercion (`parseInt("12abc")` → 12, `Number("12.5")` → 12.5).
  `parseIdParam` added to `backend/utils/validation.js` (digits-only
  safe positive int, else null), wired at **25 sites across 10 files**
  (16 `parseInt` + 8 `Number` path params + the `?scanId=` filter),
  each route keeping its 400 message; `grep parseInt(req.params|
  Number(req.params` after: no leftovers. New
  `backend/tests/validationParams.test.js` **4/4**; full backend suite
  **167/169** (same 2 env failures); RLS 63/0; frontend build green;
  secret-scan of the diff clean. Recovery note: the Day 11 cron's
  code was wiped the same day by a mistaken `git reset --hard` on a
  dirty tree (see `MEMORY.md` 2026-11-24) and re-applied + re-verified
  from the run log + manifest + surviving test file, same commit
  message, same 11 files. Lesson recorded: never `reset --hard` on a
  dirty tree.
- **SEC-34 → PASS (commit `1a11ff9` "update turnstile script url"):**
  see the SEC-34 section above — keys set + MATCH verified, backend
  400 proven by direct POST, live widget renders on `/signup`.
- **SEC-32 (backups) — owner route picked (free `pg_dump`), execution
  first BLOCKED on an RLS interaction, then CLOSED the same evening:**
  pg 17.12 client home-installed on the VM (prod is Postgres 17.6);
  `backup-db.sh` fixed to `--schema=public` (app role cannot lock
  Supabase-managed schemas) + `--inserts` — but `pg_dump` still
  aborted: its COPY and its cursor DECLARE both fail with "query
  would be affected by row-level security policy", while plain SELECT,
  COPY (SELECT) and DECLARE CURSOR all work as the same role in psql
  (policies verified: 20× PERMISSIVE ALL TO `secureguard_app`).
  Session-mode pooler `:6543` is closed. Owner then picked the
  postgres-password reset path: dashboard reset 19:08 IST
  (user-chosen password), `pg_dump` as `postgres` over a direct
  connection worked — archive `secureguard-20261124-134015.dump.gz`
  (1.6 MB, 20 tables, manifest verified) + trial restore into a local
  PG 17 scratch DB passed (row counts matched on all spot-checked
  tables). See the SEC-32 section above + `docs/BACKUP_AND_RESTORE.md`
  §2–§3. Archive is UNENCRYPTED (no passphrase yet) and no recurring
  schedule exists yet.
- **Gate rule reminder:** the Day 11 cron log claimed 27/12/4/3 before
  SEC-34 closed; the arithmetic from the 24/15/4/3 baseline is
  27/13/3/3 — the one-item discrepancy is for the Day 12 full recount
  to settle.

Still blocked on the owner: history-rewrite word + Atlas MFA code
(SEC-03), SEC-31 Step E decisions, classifier-copy deletion approval
(SEC-06), 2 mailboxes for the live matrix. Day 12 (25 Nov) must push
the Day 11 code commit first (verify HEAD, verify commit + SHAs),
then re-check the gate; if it still fails, Day 12 work stays limited
to gate-clearing support.

## Day 12 re-check + SEC-31 dry-run (2026-11-25) — still NOT PASSED

Counts: **29 PASS / 12 PARTIAL / 2 FAIL / 0 BLOCKED / 3 N/A** (recount
settled — see header). No item crossed; nothing regressed. The Day 11
push had already landed before this run: remote HEAD `c8aa61c` ==
local HEAD (the three Day 11 push attempts did land one commit; the
log's "push failed" was a stale read after a service restart). Phase 4
(Day 12 repository integrations) did **not** start; Day 12 work was
gate-clearing support + a read-only audit of the Day 12 scope.

- **Fresh evidence (base `c8aa61c`):** backend suite **167/169** (same 2
  known env fails: compliance = live Postgres, deployment_config =
  real secrets); OSV **589 packages, 0 vulnerable** (SEC-13 PASS
  holds; raw `hidden_files/osv-scan-results-2026-11-25.json`);
  RLS coverage **63 files / 0 bare**; Gitleaks full history **6
  findings, identical set to 20 Nov** (SEC-03 unchanged — same 6 FPs,
  0 real secrets by default rules; raw
  `hidden_files/gitleaks-full-history-2026-11-25.json`). Live probes:
  frontend 200 (full landing render), backend `/health`
  `{"status":"ok","db":"up"}`, classifier `model_loaded: true`
  v2.2.1 / `v3_real`; OAuth providers live = google + github only.
- **Day 12 audit — `docs/REPOSITORY_INTEGRATIONS_AUDIT.md`:**
  GitHub OAuth live; GitLab OAuth code-only (no app/env — owner step);
  PATs encrypted (AES-256-GCM) and used for repo listing + PR bot only;
  webhooks implemented + code-verified (HMAC-SHA256 raw-body GitHub,
  token-compare GitLab, per-repo secret, fail-closed, idempotent) but
  with **zero automated tests** and no live verification; repo sync
  **not implemented** (no scheduler anywhere); PR bot real (GitHub-only).
  Headline gap, stated plainly: **private cloning does NOT exist** —
  the scanner clones anonymously, `validateCloneUrl` rejects
  credentialed URLs, and `POST /api/repos` rejects non-public URLs, so
  plan acceptance #3 ("Private repository scans work") is unmet. Fix
  sketched in the audit (GIT_ASKPASS + least-privilege PAT, never in
  URL/logs) — NOT built, gate-blocked.
- **SEC-31 Step E dry-run (scratch PGlite 0.4.3, 24 Nov backup
  restored):** prod-shaped restore verified (20 tables; User 29, Org
  21, Scan 21, Vulnerability 122 — exact match to the 24 Nov record;
  20 permissive policies, RLS on 20 tables). Pre-steps
  (`docs/SEC31_STEP_E_APPLY.sql` §1–2) applied cleanly → 0 policies,
  RLS on 14 tenant tables, off on the 6 non-tenant. Migration applied
  cleanly → **self-check passes: 17 policies on 14 tables, RLS+FORCE
  on all 14, disabled on the 6**. Two scratch-only findings: (1) the
  migration fails in a session with an empty `search_path` (§1,
  "no schema has been selected to create in") — the pglite-server
  session inherited the empty path from pg_restore's `set_config`;
  a fresh Supabase SQL Editor session has the default path, so this
  does not block the real apply, but a `SET search_path TO public;`
  guard note was added to the pre-steps file; (2) behavioural
  isolation could NOT be verified in this scratch env — pglite-server
  ignores the requested role (always superuser, bypasses RLS) and
  raises "query would be affected by row-level security policy" on
  any RLS-table read as a non-superuser, proven on a trivial control
  table with a trivial policy. The in-process suite
  (`rlsMigration.test.js`, 12/12, stub data) already proves the
  policy logic; real-data behavioural proof stays with the live
  apply (SQL Editor step 4d smoke). Full log:
  goal `hidden_files/day12-dryrun.log`. Scratch DB holds a copy of
  prod data (backup-derived) — local only, 0600, never pushed.
- **SEC-32 archive re-verified:** pg_restore 17.12 `--list` reads the
  24 Nov archive; TOC identical to the stored manifest (255 entries,
  20 tables). Note: pg_restore 16 rejects this 17.12-written archive —
  use the 17 client (`~/workspace/pg-client-17`).

Still blocked on the owner: history-rewrite word + Atlas MFA code
(SEC-03), SEC-31 Step E decisions (backup-first, extra tables,
export-feedback 503 design), classifier-copy deletion approval
(SEC-06), 2 mailboxes for the live matrix. Day 13 (26 Nov) re-checks
the gate first; if it still fails, Day 13 work stays limited to
gate-clearing support — no Phase 4 features.

## Day 13 re-check + background architecture audit (2026-11-26) — still NOT PASSED

Counts: **29 PASS / 12 PARTIAL / 2 FAIL / 0 BLOCKED / 3 N/A**
(unchanged). No item crossed; nothing regressed. Remote HEAD
`7a80d45` (Day 12) == local HEAD — no commits since Day 12, no owner
decisions since Day 12. Phase 4 (Day 13 background architecture)
did **not** start; Day 13 work was a read-only audit of the Day 13
scope, `docs/BACKGROUND_ARCHITECTURE_AUDIT.md`.

- **Fresh evidence (base `7a80d45`):** live probes — frontend 200
  (full landing render), backend `/health`
  `{"status":"ok","db":"up"}`, classifier `model_loaded: true`
  v2.2.1 / `v3_real` (after ~60 s Render cold start).
- **Run limitation (stated plainly):** no local test, build, OSV or
  Gitleaks run happened this turn — the local clone content failed an
  execution-risk check at run start, so no git/npm command ran inside
  it. Test counts cited in the audit are Day 12's fresh evidence
  (25 Nov: backend suite 167/169, OSV 589 packages / 0 vulnerable,
  RLS 63 files / 0 bare, Gitleaks 6 findings identical to 20 Nov)
  and the existing load-test doc — labelled as such, not re-measured
  today. Counts are unchanged because nothing changed.
- **Day 13 audit — `docs/BACKGROUND_ARCHITECTURE_AUDIT.md`:**
  the queue/worker architecture built 19 Nov is real: BullMQ +
  Redis with an in-process FIFO fallback, concurrency 2, persistent
  worker-thread pool with a 10-minute stuck-thread kill, honest
  failure marking (no blind retries), SSRF-guarded shallow clones,
  org-scoped Redis cache, graceful-shutdown hooks. Seven gaps found,
  all still open, none built (gate-blocked): **G1** no stale-scan
  reaper (orphaned `queued`/`running` rows); **G2** no scan
  cancellation; **G3** no per-org queue fairness; **G4** no clone
  size / disk guard and no orphan temp-dir sweep; **G5** the inline
  scan fallback has no timeout; **G6** shutdown terminates worker
  threads instead of draining; **G7** no clone-only retry and no
  trigger idempotency key. Post-gate build order recorded in the
  audit (G1 → G5 → G2 → G4 → G6 → G3 → G7).
- **Production queue mode UNVERIFIED:** `render.yaml` says
  `REDIS_URL` is an owner step (until set, production runs the
  in-process fallback), while the Day 7 report states BullMQ live.
  `GET /api/scans/queue/stats` needs an authenticated session and
  no probe credentials were available this run, so the mode is not
  claimed either way in the audit.

Still blocked on the owner: history-rewrite word + Atlas MFA code
(SEC-03), SEC-31 Step E decisions (backup-first, extra tables,
export-feedback 503 design), classifier-copy deletion approval
(SEC-06), 2 mailboxes for the live matrix. Day 14 (27 Nov) re-checks
the gate first; if it still fails, Day 14 work stays limited to
gate-clearing support — no Phase 4 features.
