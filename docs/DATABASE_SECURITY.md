# SecureGaurd — Database Security (Day 7, 20-Day Transformation)

**Date:** 2026-11-20 (Day 7 of the 20-day program)
**Verified commit:** `7d471db` — "move keepalive cron to off-peak minutes"
**Companion:** `docs/SECURITY_HARDENING_CHECKLIST.md` (SEC-15, SEC-29,
SEC-30, SEC-31, SEC-32, SEC-33), `docs/SECURITY_GATE_REPORT.md` (Day 7
gate verdict), `SecureGaurd-main/docs/BACKUP_AND_RESTORE.md`,
`SecureGaurd-main/docs/DATA_RETENTION.md`,
`SecureGaurd-main/docs/route-auth-matrix.md`.

Day 7 scope per the plan: database isolation, backup/restore, audit
logs, security regression testing. This document records what was
re-verified against `7d471db` with evidence, what is still open, and
the exact owner procedure for each open item. Nothing here is marked
PASS on assertion.

---

## 1. Tenant isolation — app layer (SEC-15)

- Every tenant-table query runs inside an `rlsContext` transaction
  (`backend/utils/rlsContext.js`: `withOrgContext`,
  `withUserContext`, `withRequestOrgContext`). The context sets
  `app.current_org_id` / `app.current_user_id` with
  `set_config(..., true)` (transaction-local) and the queries filter
  by `organizationId` in code.
- Re-verified Day 7: `node scripts/check-rls-coverage.js` →
  **63 files, 0 bare `prisma.<tenant-table>` accesses** (54 files at
  the 18 Nov gate pass; the 19 Nov batches — API keys, scan queue,
  perf fixes — all landed inside the wrapper).
- IDOR posture (Day 5, unchanged): every `:id` lookup sampled scopes
  by `organizationId` and returns 404 on a cross-org id.
- **Still open:** the live cross-tenant matrix (two verified accounts,
  two orgs, cross-org reads/writes on every `:id` route, expect 404)
  has never run. It needs two mailboxes to click verification links;
  no mailbox is available from this VM. Procedure: §6.3.

## 2. Tenant isolation — database layer (SEC-31, FAIL)

Row Level Security is written, tested offline, and **not applied**:

- Migration `backend/prisma/migrations/20261116_rls_policies/migration.sql`
  (local, deliberately untracked — pushing it would make Render's
  pre-deploy `prisma migrate deploy` auto-apply it before the
  superuser check). 16 policies on 13 tenant tables,
  `FORCE ROW LEVEL SECURITY`, fail-closed when the session variables
  are unset (`app_current_org_id()` returns NULL → no rows).
- Validated against real PostgreSQL 17.5 via PGlite
  (`backend/tests/rlsMigration.test.js`, 12/12; re-run green in the
  Day 7 suite — see §7).
- **Blocker, unchanged since 16 Nov:** Supabase's `postgres` role is a
  superuser and superusers bypass RLS even with FORCE. If the Render
  `DATABASE_URL` logs in as `postgres`, the policies enforce nothing.
  The app must first switch to a dedicated least-privilege role.
  Procedure: §6.1. Until then SEC-31 stays FAIL — the migration file
  existing is not enforcement.

Tables deliberately without RLS (documented in the migration header):
`User` (login lookup runs before any context exists),
`StripeWebhookEvent` / `RazorpayWebhookEvent` / `WebhookDelivery`
(provider idempotency, no tenant column), `AnalyticsEvent` /
`ContactMessage` (no tenant data). `ApiKey` (added 19 Nov) is NOT in
the migration's 13 tables — when the migration is applied, `ApiKey`
needs its own policy added first (org-scoped like the others), or key
lookups will run unscoped at the DB layer. Flagged here so the apply
step does not silently miss it.

## 3. Parameterized queries (SEC-29)

Re-verified Day 7 by grep over `routes/ utils/ middleware/ services/
queues/ workers/ server.js`:

- 15 raw-SQL sites total. Every one is a Prisma tagged template
  (`tx.$executeRaw` / `tx.$queryRaw` with `${value}` bindings) — the
  values are bound parameters, never string-concatenated:
  4× `pg_advisory_xact_lock` (repos.js:117, organizations.js:359/450/505),
  3× `set_config` (rlsContext.js:108/115/122), 6× resolver functions
  (rlsContext.js:194–230), 1× `SELECT 1` health check (server.js:112),
  1 comment line. All other data access goes through the Prisma
  query builder (parameterized by construction).
- `$queryRawUnsafe` / `$executeRawUnsafe`: **0 hits**.
- No string interpolation into SQL anywhere. SQL injection via the
  data layer is closed at code level; the scanner's own SQLi findings
  in this repo are test fixtures (`backend/tests/fixtures/`), not
  production code paths.

## 4. Schema, migrations, least privilege (SEC-30)

- Schema: 20 models, 29 `@@index`, 3 `@@unique`
  (`[userId, organizationId]`, `[userId, fullName]`,
  `[organizationId, ruleId]`). `ApiKey.keyHash` is unique (sha256 of
  the key; the key itself is shown once at creation, never stored).
- Migrations tracked in git: 10 (20261024 → 20261119, including the
  three 19 Nov migrations: scan error + vuln indexes, API keys,
  detected-scans + AI engine). Render applies them via pre-deploy
  `prisma migrate deploy`; the build runs `prisma generate`.
- Foreign keys: `ON DELETE CASCADE` from Organization/Repository/Scan
  down to tenant rows (verified live 19 Nov via the SQL Editor FK
  check — Scan/Sbom/ComplianceReport all CASCADE). Deleting an org
  deletes its data; deleting a repo deletes its scans, findings,
  SBOMs and reports. This is by design (org is the unit of deletion,
  `DATA_RETENTION.md` §1) but it is why the 19 Nov phantom-repo
  cleanup re-pointed rows before deleting.
- **Least privilege: UNVERIFIED.** The app connects with a single
  `DATABASE_URL` credential. Whether that credential is the
  `postgres` superuser or a restricted role cannot be checked from
  this VM (no DB credentials here; the connected Supabase token sees
  only the "Saftey App" org, project `wkvvxqlflhjiqkhwxrsl` returns
  403). The check is one query in the SQL Editor — §6.1 step 1. Until
  it runs, both least-privilege and RLS enforcement are unproven.
- Sensitive data at rest: passwords bcrypt-hashed; refresh tokens
  bcrypt-hashed + rotating with reuse detection; GitHub/GitLab PATs
  AES-256-GCM encrypted (`ENCRYPTION_KEY`, 64-hex enforced at
  startup); API keys sha256-hashed; webhook secrets per-repo,
  generated with `crypto.randomBytes(32)`. No plaintext secrets in
  the schema.

## 5. Backups and restore (SEC-32, FAIL)

Unchanged since 16 Nov, re-confirmed Day 7:

- **No backup has ever been taken. No trial restore has ever run.**
- Supabase automated backups / PITR: UNVERIFIED (Management API 403
  for this project with the connected token — see
  `BACKUP_AND_RESTORE.md`).
- `backend/scripts/backup-db.sh` exists (pg_dump custom format,
  umask 077 + chmod 600, optional AES-256-CBC encryption, 30-day
  prune, retention-days validated) and is statically verified
  (`bash -n`). It needs `pg_dump` + production `DATABASE_URL` on a
  host that has both (Render shell or a laptop) — this VM has
  neither.
- A backup that was never restored does not pass this item. Full
  procedure: `BACKUP_AND_RESTORE.md` §§1–3, summarized in §6.2.

## 6. Audit logs (SEC-33 area)

- `AuditLog` is org-scoped (`organizationId` required, indexed on
  org + createdAt). `createAuditLog` (middleware/rbac.js) is called
  across the privileged surface: organization create/update/delete,
  member invite/accept/role/remove/leave, ownership transfer, repo
  add/remove, scan queued/completed/failed, billing checkout +
  subscription lifecycle, API key create/revoke, custom-rule CRUD,
  alert settings, compliance generate/delete, AI fix
  generated/applied, vulnerability status/label changes. 40+ action
  types (grep-verified Day 7).
- **Gap found Day 7:** authentication events are NOT audit-logged —
  no LOGIN / LOGOUT / PASSWORD_CHANGED / PASSWORD_RESET actions exist
  in `routes/auth.js` (the only auth audit writes are inside account
  deletion). Because `AuditLog.organizationId` is required and login
  happens before an org is chosen, closing this needs a schema
  decision first: make `organizationId` nullable for auth events, or
  resolve the user's primary org at login. Recorded as an open item
  in the gate report; not silently patched on gate day.
- Append-only: the RLS migration adds a trigger blocking direct
  `AuditLog` DELETE while the org exists. That trigger conflicts
  with the retention rule (365 days, then archive + delete) — the
  conflict and the two options (retention carve-out vs indefinite
  retention) are documented in `DATA_RETENTION.md`; the decision is
  still owed. No purge has ever run; `purge-retention.js` covers only
  the no-RLS tables (AnalyticsEvent, ContactMessage, webhook events)
  and has no scheduled job.

## 7. Security regression testing (Day 7 run)

Offline suite, `node --test tests/*.test.js` in `backend/`:

- **149 tests, 147 pass, 2 fail.** Both failures are the known
  pre-existing environment failures, unchanged: `compliance.test.js`
  (needs live Postgres) and `deployment_config.test.js` (needs real
  secrets at import). Neither is a regression from any 19 Nov batch
  (stash-verified on 19 Nov; same two files fail the same way today).
- One real regression found and fixed this run: commit `7d471db`
  moved the keepalive cron to off-peak minutes
  (`3,13,23,33,43,53 1-20 * * *`) but `retest2Fixes.test.js` still
  pinned the old `*/10` literal, so the suite was red at HEAD
  (146/149). The test now pins the current literal (19/19 in that
  file). Tests pin behaviour with literals — when behaviour changes
  on purpose, the literal changes in the same commit; that pairing
  was missed on 19 Nov and is restored here.
- Frontend `vite build`: green.
- Route inventory re-counted: **95 router routes + 2 server-level =
  97** (92 at the 18 Nov gate). The 5 new routes since then —
  `POST/GET /api/api-keys`, `POST /api/api-keys/:id/revoke`,
  `GET /api/scans/queue/stats`, `PATCH /api/auth/me` — are all behind
  auth + org context (apiKeys router mounts `authMiddleware` +
  `requireOrgContext` + OWNER/ADMIN role on writes; queue/stats sits
  under the scans router's `authenticateRequest`; `/me` PATCH takes
  `authMiddleware`). No new unauthenticated surface. The live matrix
  remains outstanding (§1).
- Dependency scan (OSV, `scripts/osv-scan.mjs`): 587 packages
  (568 on 18 Nov; +19 from bullmq/ioredis), **2 findings**:
  `minimatch@10.2.6` GHSA-g3hv-75wg-m249 (CVE-2026-118764, glob DoS,
  fixed in 11.0.1) and `glob@13.0.6` GHSA-3g3m-2fjr-6pw4
  (CVE-2026-118773, fixed in 14.0.2). The picomatch HIGH reported on
  18 Nov is no longer returned by OSV for `picomatch@4.0.7` — the
  package is unchanged, the advisory state changed; this is NOT a
  fix and is not claimed as one. Both remaining fixes are major
  bumps (Day 9 scope). Raw results:
  `hidden_files/osv-scan-results-2026-11-20.json`.
- Secret scan (gitleaks 8.28.0, full history): 210 commits, 6
  findings, 0 real secrets — the same 6 false positives as Day 4
  (test fixtures + doc placeholders). The known real leak in commit
  `e1e3dc9` (`backend/.env` with a rotated JWT secret + dev MongoDB
  credential) is still NOT detected by default rules — the detection
  gap from Day 4 stands, and SEC-03 (history purge) stays FAIL.
  Raw report: `hidden_files/gitleaks-full-history-2026-11-20.json`.
- Live probes (20 Nov, read-only): frontend 200 with CSP + HSTS +
  nosniff + COOP; backend `/health` 200 `{"status":"ok","db":"up"}`;
  classifier `/health` 200, `model_loaded: true`;
  `/api/_test-error` 404; `/api/ai/status` unauthenticated 401;
  `/api/auth/oauth/providers` lists google + github (OAuth live
  since 19 Nov); CORS preflight from an unlisted origin denied (no
  `Access-Control-Allow-Origin`, no 500), from the app origin 204
  with credentials. Live bundle `index-DAcJsNBs.js` contains the
  Turnstile widget code but **no site key** — SEC-34 (CAPTCHA
  fail-open) stays FAIL; no probe account was created this run.

## 8. Owner procedures (exact)

### 6.1 RLS rollout (SEC-31) — in order, do not reorder

1. Supabase dashboard → SQL Editor (project `wkvvxqlflhjiqkhwxrsl`),
   run as the app credential:
   `SELECT usesuper FROM pg_user WHERE usename = current_user;`
   Must return `false`. If `true`: create a `secureguard_app` role
   (LOGIN, no superuser, grant DML on public tables + sequences),
   repoint Render `DATABASE_URL` to it, redeploy, re-run the check.
2. Add an `ApiKey` policy to the migration (org match, same shape as
   `CustomRule`) — the table postdates the migration.
3. Backfill check: every tenant row's `organizationId` non-null and
   pointing at a live org (the migration self-check does this;
   expect `NOTICE: RLS migration self-check passed`).
4. Apply the migration in the SQL Editor, then confirm
   `SELECT count(*) FROM pg_policies WHERE schemaname='public';` = 17
   (16 + ApiKey).
5. Push the migration folder to git in the same change (so
   `prisma migrate deploy` and the live DB agree), redeploy, run the
   live cross-tenant matrix (§6.3).

### 6.2 Backup + restore test (SEC-32)

1. Dashboard → Settings → Database → Backups: record whether daily
   backups / PITR are enabled + retention (3 min). Write the finding
   into `BACKUP_AND_RESTORE.md`.
2. On a host with `pg_dump` + `DATABASE_URL` (Render shell):
   `BACKUP_ENCRYPTION_PASSPHRASE='…' ./backend/scripts/backup-db.sh`
   — archive must verify before the script calls it done.
3. Restore the archive into a disposable database
   (`pg_restore` into a scratch Supabase project or local Postgres),
   run row-count spot checks (User, Organization, Scan,
   Vulnerability) against production counts, record date + counts in
   `BACKUP_AND_RESTORE.md`. Only then does SEC-32 pass.

### 6.3 Live cross-tenant matrix (SEC-15/16)

Two throwaway verified accounts + two orgs; for every `:id` route,
request org B's ids with org A's token — expect 404 everywhere;
cross-org writes expect 403/404. Delete both accounts after. Needs
two mailboxes (or the owner's word to use throwaway Gmails he
controls). Until it runs, SEC-15/16 stay PARTIAL on code evidence
only.

---

**Day 7 database verdict:** the data layer is parameterized,
org-scoped in code, audited on the privileged surface, and covered
by a green regression suite — but RLS is not enforced, no backup
exists, the DB credential's privilege level is unverified, and auth
events are not audit-logged. SEC-31 and SEC-32 remain FAIL. The gate
verdict is in `docs/SECURITY_GATE_REPORT.md`.
