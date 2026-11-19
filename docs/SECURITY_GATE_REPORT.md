# SecureGaurd — Security Gate Report (Day 7 gate, re-verified 2026-11-20)

**Date:** 2026-11-20 (Day 7 of the 20-day program)
**Verdict: GATE NOT PASSED**
**Checklist:** `docs/SECURITY_HARDENING_CHECKLIST.md` — 24 PASS / 15 PARTIAL /
4 FAIL / 0 BLOCKED / 3 NOT APPLICABLE (46 items) — **counts unchanged
from 16 Nov** (re-verified item by item at `7d471db`; no item crossed
to PASS, none regressed)
**Commits covered:** everything through `7d471db` (Day 5 `21def6a`,
Day 6 `4809fa0`, queue/cache `84212d9`, E2E batches `76149f2`/`b8d1ffb`,
API keys + connect fix `9611676`, dashboard fixes `dce4e57`/`f1527bf`,
re-test batches `ffad4fa`/`bfe2e6c`, Gemini `bda7896`/`c3b05e0`, perf
`e7b3a67`, keepalive `b62fc35`/`7d471db`)
**Gate rule (Day 7):** every applicable item PASS with evidence, no
unresolved critical/high issues, all exceptions documented and approved.
**Phase 4 rule: do not start Phase 4 features until this gate passes.
Day 8 (scanning engine) is therefore BLOCKED until the 4 FAILs below
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
| CAPTCHA (SEC-34) | 201 with no token | **unchanged** | Live bundle has widget code, no site key baked in. Keys still unset. |
| Backups (SEC-32) | none ever | **unchanged** | Script + procedure exist; no backup taken, no restore tested, PITR unverified. |

Live probes Day 7 (read-only): frontend 200 (CSP/HSTS/nosniff/COOP),
backend `/health` 200 with `db: "up"`, classifier 200
`model_loaded: true`, `/api/_test-error` 404, `/api/ai/status` 401
unauthenticated, CORS denied for unlisted origin / allowed for app
origin. No probe accounts created.

---

## Why the gate does NOT pass — the 4 FAILs (all owner-gated)

### SEC-03 — Secrets in git history (FAIL)
Commit `e1e3dc9` (2026-04-16) committed `backend/.env` with a real
`JWT_SECRET` (rotated 2026-11-08) and a dev MongoDB credential
(`glanexus_admin`). Forks check done (0 forks). Still open: owner
confirms the current Render `JWT_SECRET` differs from the committed
value, deletes the Atlas user `glanexus_admin`, and gives the word
for the history rewrite (`git filter-repo` + force-push). Gitleaks
does not detect this leak with default rules — a green scan is not
evidence of a clean history. Procedure: `docs/SECRETS_AND_INFRASTRUCTURE.md` §2.

### SEC-31 — No Postgres RLS enforcement (FAIL)
Migration written + PGlite-validated (16 policies, 13 tables, FORCE
RLS, fail-closed); call-site conversion complete (63 files, 0 bare
accesses). Still open: (1) superuser check on the app credential —
if `postgres`, create `secureguard_app` role + repoint `DATABASE_URL`;
(2) add an `ApiKey` policy (table added 19 Nov, postdates the
migration); (3) backfill check; (4) apply via SQL Editor (expect 17
policies after ApiKey); (5) push the migration folder + live matrix.
Full procedure: `docs/DATABASE_SECURITY.md` §6.1. The scans
export-feedback operator path 503s under RLS (no service-role path)
— design decision still owed before apply.

### SEC-32 — No DB backups ever (FAIL)
No backup taken, no restore tested, Supabase PITR unverified
(Management API 403 for this project with the connected token).
Script + procedure ready (`backup-db.sh`, `BACKUP_AND_RESTORE.md`).
Owner step: dashboard PITR check → scripted backup on a host with
`pg_dump` + `DATABASE_URL` → restore into a disposable DB + row-count
spot checks. Procedure: `docs/DATABASE_SECURITY.md` §6.2.

### SEC-34 — CAPTCHA fail-open (FAIL)
Guard fully built (Turnstile middleware on register /
forgot-password / contact; CSP allows `challenges.cloudflare.com`;
widget code in the live bundle) — keys unset, so signup still works
with no token. Owner step: create the Cloudflare Turnstile widget
(domain `secureguard-main.vercel.app`) → `TURNSTILE_SECRET_KEY` on
Render + `VITE_TURNSTILE_SITE_KEY` on Vercel (Production) → redeploy
both → re-probe must 400 without a token. Do NOT flip the guard to
fail-closed before the keys exist (repeats the Nov 8 outage).

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
- **SEC-18 / SEC-22:** shared zod validator on 9 of 48 mutating
  routes (Day 6 wired the 6 auth routes). Remaining 39 have inline
  validation; the gap is consistency, tracked for Day 8+.
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

1. **History purge (SEC-03):** approve the rewrite? Confirm the
   current Render `JWT_SECRET` differs from the committed value;
   delete Atlas user `glanexus_admin` first.
2. **Turnstile keys (SEC-34):** create the widget + set the two keys
   (Render `TURNSTILE_SECRET_KEY`, Vercel `VITE_TURNSTILE_SITE_KEY`).
3. **Backups (SEC-32):** dashboard PITR check + scripted backup +
   trial restore (`DATABASE_SECURITY.md` §6.2).
4. **RLS (SEC-31):** superuser check → (role switch if needed) →
   ApiKey policy → backfill → apply → push migration → live matrix
   (`DATABASE_SECURITY.md` §6.1). Includes the export-feedback
   operator-path decision.
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

**Until items 1–4 clear, Phase 4 does not start.** The next scheduled
run (Day 8, 21 Nov) must re-check the gate first; if it still fails,
Day 8 work is limited to gate-clearing support (procedures, scripts,
tests) — no new product features.
