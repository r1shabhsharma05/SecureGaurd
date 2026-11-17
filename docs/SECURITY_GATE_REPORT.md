# SecureGaurd — Security Gate Report (Day 7 gate, gate-pass run 2026-11-18)

**Date:** 2026-11-18
**Verdict: GATE NOT PASSED**
**Checklist:** `docs/SECURITY_HARDENING_CHECKLIST.md` — 24 PASS / 15 PARTIAL /
4 FAIL / 0 BLOCKED / 3 NOT APPLICABLE (46 items) — **unchanged from 16 Nov**
**Commits covered:** `9aa4ce5`, `a72de3d`, `1d7aa1f`, `f13a2ce` (gate-pass run,
2026-11-18) + the Day 5 commit `21def6a4`
**Gate rule (Day 7):** every applicable item PASS with evidence, no
unresolved critical/high issues, all exceptions documented and approved.
**Phase 4 rule:** do not start Phase 4 features until this gate passes.

---

## What the gate pass did — and did not — close

No item changed status in this run. The work below is real progress
*inside* items, but every one of the 4 FAILs still needs an owner action,
and no PARTIAL crossed to PASS. The counts are identical to 16 Nov
because the remaining gaps are owner-gated, not code-gated.

| Item | Before (16 Nov) | After (18 Nov) | Evidence |
|---|---|---|---|
| SEC-13 dependency scan | PARTIAL — 3 HIGHs unfixed, CI workflow push pending | **PARTIAL** — 3 HIGHs FIXED, 1 HIGH (picomatch, no fix) + 2 MOD majors remain; CI workflow verified LIVE | OSV re-scan: 568 packages, 3 findings (was 15). Commit `9aa4ce5`. `.github/workflows/dependency-scan.yml` present via GitHub API (pushed via browser 17 Nov). |
| SEC-31 RLS | FAIL — migration written, call-site conversion NOT done | **FAIL** — rollout step (1) DONE in code; steps (2)–(5) outstanding | Commits `a72de3d` / `1d7aa1f` / `f13a2ce`. Coverage script passes (54 files, 0 bare tenant accesses). PGlite migration test 12/12. Migration deliberately STILL NOT pushed. |
| SEC-33 retention | PARTIAL — rules only, no purge job | **PARTIAL** — purge script landed (no-RLS tables); AuditLog trigger conflict documented; no scheduled job, no purge ever run | `backend/scripts/purge-retention.js`, 4/4 offline tests. `docs/DATA_RETENTION.md` updated. |
| SEC-15 org isolation | PARTIAL — live matrix outstanding | **PARTIAL** — code-level isolation now enforced by RLS conversion; live matrix still outstanding | PGlite 12/12 (cross-org 0 rows, fail-closed); coverage script 0 bare accesses. Live matrix still BLOCKED (mailbox). |
| SEC-16 route matrix | PARTIAL — 92/92 routes, live matrix outstanding | **PARTIAL** — 92 routes re-counted (90 router + 2 server-level), no holes; live matrix still outstanding | Fresh grep count: 42 GET, 33 POST, 7 PATCH, 7 DELETE, 1 PUT + `/health` + `/api/_test-error`. |
| SEC-18/22 validation | PARTIAL — shared lib on 3 routes, rest ad-hoc | **PARTIAL** — gap now measured exactly: 45 of 48 mutating routes lack the shared validator | 3 use `validateBody` (change-password, scan trigger, contact). Per-file lacking list below. |
| SEC-03 secrets in history | FAIL — purge SAFE subject to forks check + JWT confirm | **FAIL** — forks check DONE (0 forks); JWT confirm + owner word still open | GitHub API `/forks` → `[]`, `forks_count: 0`. |
| SEC-32 backups | FAIL — none ever taken | **FAIL** — re-probed, still unverified, still none | Management API 401 unauth / 403 with token. |
| SEC-34 CAPTCHA | FAIL — 201 with no token | **FAIL** — re-probed live, still 201 with no token | Register → 201, forgot-password → 200, contact → 201 (row id 5). Bundle 0 Turnstile refs. |
| SEC-04 PAT migration | PARTIAL — script 7/7, live run blocked | **PARTIAL** — self-test re-verified 7/7; live run still blocked | `node scripts/migrate-plaintext-pats.js --self-test` → 7/7. Dry-run fails on missing `ENCRYPTION_KEY` (by design). |
| SEC-07 auth | PARTIAL — no MFA, no live OAuth | **PARTIAL** — MFA confirmed absent in code; OAuth code present, none live | `grep -rni totp|mfa|authenticator|2fa` → 0 hits. |
| SEC-38 form validation | PARTIAL — no shared frontend schema | **PARTIAL** — confirmed: zero `zod` imports in `src/` | Per-form inline validation only. |
| SEC-06 stale files | PARTIAL — deletions outstanding | **PARTIAL** — both files verified still present | GitHub API: `backend/generated/prisma/` + `classifier model/files/` still in repo. |
| SEC-17 rate limiting | PARTIAL — live 429 inconclusive | **PARTIAL** — Render logs unreachable (401), still inconclusive | Probe limitation, not a limiter failure. |
| SEC-39 mobile layout | PARTIAL — authenticated dashboard unmeasured | **PARTIAL** — still unmeasured (needs his phone) | No change. |

Tests this run: full offline suite **77 tests, 75 pass** (2 known
environmental failures: compliance.test.js needs live Postgres,
deployment_config.test.js needs real secrets — NOT regressions);
rbac 11/11 + rlsContext 16/16 + rlsMigration 12/12 (PGlite, PostgreSQL
17.5); purgeRetention 4/4; PAT-migration self-test 7/7; OSV re-scan
568 packages / 3 findings.

---

## Why the gate does NOT pass — the 4 FAILs

### SEC-03 — Secrets in git history (FAIL)
Real `JWT_SECRET` + a dev MongoDB credential remain retrievable from
pushed history. **Gate-pass progress:** the forks check is DONE —
GitHub API `/repos/r1shabhsharma05/SecureGaurd/forks` returns `[]`,
`forks_count: 0` — so precondition (a) is cleared. Still open: (b)
owner confirms the current Render `JWT_SECRET` differs from the
committed value, and his word for the rewrite. The 2026-11-08 JWT
rotation is assertion-only; no repo record proves the production value
actually changed. No purge prep dir exists yet — prepare it from the
`~/workspace/tmp-work/safelife-purge` pattern before the rewrite.
**No rewrite executed** — destructive rewrite needs his word, and no
force-push credentials exist on this VM.

### SEC-31 — No Postgres RLS (FAIL)
Migration written (`backend/prisma/migrations/20261116_rls_policies/migration.sql`,
534 lines, 16 policies, 13 tables, `FORCE ROW LEVEL SECURITY`) and validated
against real PostgreSQL 17.5 via PGlite (12/12 in the new
`backend/tests/rlsMigration.test.js`; the 42/42 figure from 16 Nov was the
same checks run as a one-off script). **Rollout step (1) is now DONE:**
every tenant-table call site runs inside an `rlsContext`
(commits `a72de3d` / `1d7aa1f` / `f13a2ce`; `scripts/check-rls-coverage.js`
passes — 54 files, 0 bare `prisma.<tenant-table>` accesses; `routes/public.js`
and `routes/classifier.js` verified as needing no change). The migration
was deliberately **NOT pushed** — Render's pre-deploy `prisma migrate deploy`
would auto-apply it. Still outstanding: (2) verify the app DB user is NOT
superuser (if `postgres`, create a `secureguard_app` role + repoint Render
`DATABASE_URL` — without this RLS is a no-op even with FORCE), (3) backfill
check, (4) apply via the browser SQL Editor, (5) live cross-tenant matrix.
**Leftovers needing decisions:** the scans export-feedback operator path
now 503s under RLS (no service-role path — needs a design decision); the
public analytics summary's Scan/Vulnerability counts need a context when
called from `routes/public.js`.

### SEC-32 — No DB backups ever (FAIL)
No backup has ever been taken; no trial restore ever performed. Re-probed
2026-11-18: Supabase Management API unauthenticated → 401; with the
connected token → 403 (the token only sees the "Saftey App" org, not
project `wkvvxqlflhjiqkhwxrsl`). PITR status STILL UNVERIFIED.
`BACKUP_AND_RESTORE.md` carries the true status + a restore-test procedure
and `backend/scripts/backup-db.sh` exists, but both need `pg_dump` +
production `DATABASE_URL` (Render env only). A backup that was never
restored does not pass this item.

### SEC-34 — CAPTCHA fail-open (FAIL)
Re-probed live 2026-11-18: signup returns **201 with NO Turnstile token**
(`sg-gate-20261118@example.com`, `{ requiresVerification: true }`),
forgot-password → 200, contact → **201** (new ContactMessage row id 5).
The live bundle (`assets/index-Ac2tFl7a.js`) has 0 Turnstile references.
The guard is fully built; the keys are unset. Owner step: create the
Cloudflare Turnstile widget (domain `secureguard-main.vercel.app`) →
`TURNSTILE_SECRET_KEY` on Render (`secureguard-api`) +
`VITE_TURNSTILE_SITE_KEY` on Vercel (`secureguard-main`, Production) →
redeploy both → re-probe must 400 without a token. Do NOT flip the guard
to fail-closed before the keys exist (repeats the Nov 8 outage).

---

## Open PARTIALs that also block a clean gate

- **SEC-13:** picomatch@4.0.7 HIGH (GHSA-fc5q-39xc-vjpf, CVE-2026-112366)
  has NO fixed version — latest release is 4.0.7. Build-time only (transitive
  dep of vite; no user-controlled glob reaches it at runtime; backend does
  not depend on it). Needs the owner's written risk-accept with an expiry,
  or waiting for upstream 4.0.8. The 2 MODERATEs (minimatch 11.0.1, glob
  14.0.2) are major bumps — Day 9 work.
- **SEC-15 / SEC-16:** live cross-tenant matrix outstanding. It needs two
  verified accounts + two orgs; verification needs a mailbox to click the
  link, and no mailbox is available from this VM. (Using the user's own
  email for a probe account was NOT done without his word.)
- **SEC-18 / SEC-22:** 45 of 48 mutating routes lack the shared zod
  validator. The 3 that use it: auth change-password, scan trigger,
  public contact. The 45: ai.js 3, alerts.js 2, auth.js 10, billing.js 2,
  billingWebhook.js 1, compliance.js 2, customRules.js 5, integration.js 3,
  invitations.js 1, ml.js 1, organizations.js 9, public.js 1, repos.js 2,
  scans.js 1 (api-spec), vulnerabilities.js 2. Every route has inline
  validation; the gap is consistency. Wiring all 45 is Day 8+ refactor
  work, not a gate-pass change.
- **SEC-17:** live 429 trigger INCONCLUSIVE — the VM's egress IP rotates
  per request and the limiters key on `req.ip`; Render logs unreachable
  (401, no token/service ID on the VM). Live proof needs a stable IP or
  Render logs. This is a probe limitation, not a limiter failure.
- **SEC-33:** purge script covers only the no-RLS tables. **Open
  conflict:** the `docs/DATA_RETENTION.md` §3 AuditLog DELETE will FAIL
  once the RLS migration is applied — the append-only trigger blocks
  direct DELETE while the org exists, for every role including superuser.
  Needs a decision: amend the trigger with a retention carve-out, or
  accept indefinite AuditLog retention. No scheduled purge job exists
  (no in-process scheduler in this backend — monthly Render Cron Job);
  no purge has ever run.
- **SEC-39:** authenticated dashboard NOT measured on a phone (needs a
  login on his device). Unauthenticated routes verified clean at 390×844 /
  360×740.
- **SEC-04:** PAT migration live run blocked (no DB creds, no
  `ENCRYPTION_KEY` on this VM). Self-test 7/7 re-verified.
- **SEC-07:** no MFA anywhere (grep-verified 0 hits); OAuth code present
  (Google/GitHub/GitLab, PKCE + HMAC state) but none live.

---

## Items NOT pushed (need the browser web-UI push)

1. Deletion: committed `backend/generated/prisma/` (~8.6 MB). The GitHub
   App API cannot delete. (Stale classifier copy `classifier model/files/`
   is on the same list but deleting model files still needs his approval
   per the standing rule — do NOT delete it unapproved.)
2. RLS migration — NOT pushed deliberately (see SEC-31 above). Push it
   only after the superuser check + backfill, immediately before the
   SQL Editor apply.
3. ~~`.github/workflows/dependency-scan.yml`~~ — DONE, verified live via
   GitHub API 2026-11-18 (pushed via browser 17 Nov morning). No re-push
   needed.

## Leftovers in production

- Probe account `sg-gate-20261118@example.com` (unverified row; cannot
  self-delete — no token, login blocked; owner deletes via DB).
- ContactMessage row id 5 (this run's Turnstile probe; no API to delete it).
- Probe account `sg-fixall-20261116@example.com` (16 Nov, same).
- ContactMessage row id 4 (Day 3 probe).

## Decisions needed from the user

1. **History purge (SEC-03):** approve the rewrite? Forks check is done
   (0 forks). Confirm the current Render `JWT_SECRET` differs from the
   committed value.
2. **Turnstile keys (SEC-34):** create the widget + set the two keys
   (Render `TURNSTILE_SECRET_KEY`, Vercel `VITE_TURNSTILE_SITE_KEY`).
3. **Backups (SEC-32):** take a backup + restore-test it (owner
   dashboard; procedure in `docs/BACKUP_AND_RESTORE.md` §5).
4. **RLS (SEC-31):** run the superuser check
   (`SELECT usesuper FROM pg_user WHERE usename = current_user;` — must
   be `false`; if `true`, create the `secureguard_app` role + repoint
   Render `DATABASE_URL` + redeploy), then the backfill check, then apply
   the migration via the Supabase dashboard SQL Editor (expect `NOTICE:
   RLS migration self-check passed: 16 policies on 13 tables`; confirm
   `SELECT count(*) FROM pg_policies WHERE schemaname='public';` = 16),
   then the live cross-tenant matrix (§5.3, two throwaway accounts,
   delete afterwards).
5. **Dependency HIGH (SEC-13):** risk-accept picomatch@4.0.7 in writing
   with an expiry, or wait for upstream 4.0.8.
6. **Retention (SEC-33):** amend the AuditLog append-only trigger with
   a retention carve-out, or accept indefinite AuditLog retention.
7. **RLS operator path:** the scans export-feedback operator path now
   503s under RLS — decide the service-role design before the migration
   is applied.
8. **Deletions (SEC-06):** approve deleting the stale classifier copy
   `classifier model/files/`; `backend/generated/prisma/` deletion goes
   via the browser web-UI push.
9. **Live cross-tenant matrix:** needs 2 mailboxes (or his word to use
   a throwaway Gmail he controls).
