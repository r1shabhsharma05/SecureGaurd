# SecureGaurd — Security Gate Report (Day 7 gate, run early by the fix-all order)

**Date:** 2026-11-16
**Verdict: GATE NOT PASSED**
**Checklist:** `docs/SECURITY_HARDENING_CHECKLIST.md` — 24 PASS / 15 PARTIAL /
4 FAIL / 0 BLOCKED / 3 NOT APPLICABLE (46 items)
**Commits covered:** `670755d`, `25561d9`, `6dac31e` (fix-all run, 2026-11-16)
**Gate rule (Day 7):** every applicable item PASS with evidence, no
unresolved critical/high issues, all exceptions documented and approved.
**Phase 4 rule:** do not start Phase 4 features until this gate passes.

---

## What the fix-all run closed

| Item | Before | After | Evidence |
|---|---|---|---|
| SEC-09 email verification | FAIL (High) | **PASS** | Register → 201 `{ requiresVerification: true }`, no tokens; login → 403 `email_not_verified` — both probed live 2026-11-16. 8 new tests pass. |
| SEC-37 fake scan progress | FAIL | **PASS** | Fake interval + 0→100% animation removed (Dashboard + OnboardingWizard); honest indeterminate spinner + real `GET /api/scans/:id` poll. Build green. |
| SEC-19 security headers | PARTIAL | **PASS** | CSP live on Vercel + Render, verified by `curl -I` post-deploy. |
| SEC-06 unused packages | FAIL | PARTIAL | mongoose removed (0 hits in lockfile). Stale file deletions outstanding (browser push). |
| SEC-13 dependency scan | BLOCKED | PARTIAL | OSV scan: 585 packages, 15 findings (0 critical, 3 HIGH, 10 MOD, 2 LOW). CI workflow written; first run pending. |
| SEC-15 org isolation | PARTIAL | PARTIAL | S3 fixed (`requireOrgContext` strict-validates, 400 on malformed id). rbac tests 8/8. Live matrix outstanding. |
| SEC-16 route matrix | PARTIAL | PARTIAL | 92/92 routes re-verified, no holes; matrix rewritten. Live matrix outstanding. |
| SEC-17 rate limiting | PARTIAL | PARTIAL | `/refresh` + `/me` limiters added. Live 429 trigger inconclusive (VM IP rotates). |
| SEC-18/22 validation | PARTIAL | PARTIAL | zod 4.6.7 + shared lib, applied to contact / scan-trigger / export-feedback. 11/11 tests (incl. a real-Express-5 regression test for the `req.query` getter bug caught at merge). Remaining routes still ad-hoc. |
| SEC-38 form validation | PARTIAL | PARTIAL | Password-change + verification/resend UI added. No shared frontend schema yet. |
| SEC-39 mobile layout | PARTIAL | PARTIAL | Hamburger nav drawer (was: no mobile nav at all), table scroll wrappers. Real viewport check: no overflow at 390×844 / 360×740. Authenticated dashboard not measured. |
| SEC-04 PAT migration | PARTIAL | PARTIAL | Migration script written, 7/7 self-test. Live run blocked (no DB creds). |
| SEC-05 exposed files | PARTIAL | PARTIAL | Dev MongoDB proven dead/unused; rotation = delete Atlas user `glanexus_admin` (owner-only). |
| SEC-07 auth | PARTIAL | PARTIAL | `orgFetch` stale-token retry + `completeOnboarding` fixed; verification gate real. MFA + live OAuth remain. |
| SEC-33 retention | PARTIAL | PARTIAL | `DATA_RETENTION.md` written; AuditLog append-only trigger in the (unapplied) RLS migration. |
| T10 Razorpay idempotency | — | fixed | Idempotency inside the transaction (P2002 → 200 idempotent). |
| T11 classifier key | — | fixed | Key sent on the webhook path (`X-SecureGuard-Key`). |

Tests this run: full offline suite **47/47 pass** + astExtraction 4/4;
validation 11/11; rbac 8/8; RLS 12/12 + PGlite 42/42 (PostgreSQL 17.5);
auth-verification 8/8; PAT-migration self-test 7/7; vite build 1.66 s.

---

## Why the gate does NOT pass — the 4 FAILs

### SEC-03 — Secrets in git history (FAIL)
Real `JWT_SECRET` + a dev MongoDB credential remain retrievable from
pushed history. Purge verdict: SAFE subject to 2 preconditions — (a) forks
check at `github.com/r1shabhsharma05/SecureGaurd/forks`, (b) owner confirms
the current Render `JWT_SECRET` differs from the committed value. Verified:
241 commits, 2 authors only, 0 open PRs, no tags. Exact purge procedure
prepared; **no rewrite executed** — needs the owner's word. Caveat: the
2026-11-08 JWT rotation is assertion-only; no repo record proves the
production value actually changed.

### SEC-31 — No Postgres RLS (FAIL)
Migration written (`backend/prisma/migrations/20261116_rls_policies/migration.sql`,
534 lines, 16 policies, 13 tables, `FORCE ROW LEVEL SECURITY`) and validated
against real PostgreSQL 17.5 via PGlite (42/42 checks). **NOT applied.**
Non-negotiable rollout order: (1) convert call sites to `rlsContext.js`
(NOT done — list in `SecureGaurd-main/docs/BACKUP_AND_RESTORE.md` §5.1),
(2) verify the app DB user is NOT superuser (if `postgres`, create a
`secureguard_app` role + repoint Render `DATABASE_URL` — without this RLS
is a no-op even with FORCE), (3) backfill check, (4) apply via the browser
SQL Editor, (5) live cross-tenant matrix. The migration was deliberately
NOT pushed to main — Render's pre-deploy `prisma migrate deploy` would
auto-apply it and every org-scoped query would return zero rows.

### SEC-32 — No DB backups ever (FAIL)
No backup has ever been taken; no trial restore ever performed. Supabase
PITR status UNVERIFIED (Management API returns 403 — the connected token
only sees the "Saftey App" org, not project `wkvvxqlflhjiqkhwxrsl`).
`BACKUP_AND_RESTORE.md` now carries the true status + a restore-test
procedure. A backup that was never restored does not pass this item.

### SEC-34 — CAPTCHA fail-open (FAIL)
Re-confirmed live 2026-11-16: signup returns 201 with NO Turnstile token.
The guard is fully built; the keys are unset. Owner step: create the
Cloudflare Turnstile widget (domain `secureguard-main.vercel.app`) →
`TURNSTILE_SECRET_KEY` on Render (`secureguard-api`) +
`VITE_TURNSTILE_SITE_KEY` on Vercel (`secureguard-main`, Production) →
redeploy both → re-probe must 400 without a token. Do NOT flip the guard
to fail-closed before the keys exist (repeats the Nov 8 outage).

---

## Open PARTIALs that also block a clean gate

- **SEC-13:** 3 HIGHs unfixed (body-parser 2.3.0, deepmerge-ts 7.1.5,
  mysql2 3.15.3 — fix mysql2 first: auth-plugin downgrade leaks plaintext
  creds). CI workflow `.github/workflows/dependency-scan.yml` could NOT
  be pushed via the GitHub App API (403 on `git/trees` — the App cannot
  write `.github/workflows/`); it must go via the browser web-UI push,
  and its first run is still pending.
- **SEC-15 / SEC-16:** live cross-tenant matrix outstanding. It needs two
  verified accounts + two orgs; verification needs a mailbox to click the
  link, and no mailbox is available from this VM. (Using the user's own
  email for a probe account was NOT done without his word.)
- **SEC-17:** live 429 trigger INCONCLUSIVE — 35 rapid
  `POST /api/auth/refresh` → 35× 401, no 429. The VM's egress IP rotates
  per request and the limiters key on `req.ip`. Live proof needs a stable
  IP or Render logs. This is a probe limitation, not a limiter failure.
- **SEC-39:** authenticated dashboard NOT measured on a phone (needs a
  login). Unauthenticated routes verified clean at 390×844 / 360×740.
- **SEC-04:** PAT migration live run blocked (no DB creds on this VM).
- **SEC-32-adjacent (SEC-33):** no purge job exists for the retention
  rules; AuditLog append-only trigger is in the unapplied migration.

---

## Items NOT pushed (need the browser web-UI push)

1. `.github/workflows/dependency-scan.yml` — App API 403 (workflow files).
2. Deletions: stale classifier copy `classifier model/files/` + committed
   `backend/generated/prisma/` (~8.6 MB). Deleting the stale model copy
   still needs his approval per the standing rule (model files).
3. RLS migration — NOT pushed deliberately (see SEC-31 above). Push it
   only after call-site conversion + the app-role check.

## Leftovers in production

- Probe account `sg-fixall-20261116@example.com` (unverified row; cannot
  self-delete — no token, login blocked; owner deletes via DB).
- ContactMessage row id 4 (Day 3 probe; no API to delete it).

## Decisions needed from the user

1. History purge (SEC-03): approve the rewrite? (Forks check + JWT
   rotation confirmation first.)
2. Turnstile keys (SEC-34): create the widget + set the two keys.
3. Backups (SEC-32): take a backup + restore-test it (owner dashboard).
4. RLS (SEC-31): approve the call-site conversion + app-role work, then
   the SQL Editor apply.
5. Dependency HIGHs (SEC-13): approve the 3 upgrades (mysql2 first).
6. Deletion list + workflow file: browser push (or his word to proceed).
7. Live cross-tenant matrix: needs 2 mailboxes (or his word to use a
   throwaway Gmail he controls).
