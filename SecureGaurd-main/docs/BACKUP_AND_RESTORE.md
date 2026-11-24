# Database backups & restore — SecureGuard

**Project:** Supabase `wkvvxqlflhjiqkhwxrsl` (ap-southeast-1). The ref was
not recorded anywhere in the repo until 2026-11-16 — it is now, so future
checks can identify the project without guessing from the Render URL.

**Status (24 Nov 2026, ~19:11 IST): FIRST BACKUP TAKEN.** Archive
`backend/backups/secureguard-20261124-134015.dump.gz` (1.6 MB, 0600,
UNENCRYPTED — no passphrase set yet), manifest lists all **20 public
tables** + their data (20 TABLE + 20 TABLE DATA entries). Dumped as the
`postgres` role (direct connection) after a dashboard password reset
the same evening — the app role cannot dump (RLS blocks pg_dump's
COPY/cursor). Script fixes landed with it: `--schema=public` +
`--inserts` (app-role failures) and the manifest step (pg_restore does
NOT read from stdin — decompress to a temp file first; same fix applied
to the §3 restore command below). `_prisma_migrations` is NOT in the
archive — the table does not exist in prod (schema was synced without
migration history). **Trial restore still pending** — SEC-32 stays FAIL
until §3 passes.
Supabase automated backups / PITR remain **UNVERIFIED**: the Management
API was checked read-only on 2026-11-16 and returned **403 Forbidden**
for both `GET /v1/projects/wkvvxqlflhjiqkhwxrsl` and
`GET /v1/projects/wkvvxqlflhjiqkhwxrsl/database/backups` — the connected
token can only see the "Saftey App" org (`ivwejzjgbvvqwjtfuljd`), not this
project, so the API cannot confirm or deny PITR. The dashboard check in
step 1 below is still the only way to confirm it (owner step). **SEC-32
stays FAIL** until a backup exists AND a trial restore into a disposable
database has passed (step 3) — do not mark PASS on an unrestored backup.

(Previous status, 1 Nov 2026: the backup *script*
(`backend/scripts/backup-db.sh`) and the restore procedure below are
written and statically verified, but **no backup has been taken and no
trial restore has been performed** from this VM: the VM has no `pg_dump`
and no `DATABASE_URL` (it lives only in Render env). The first real backup
+ trial restore is a ~15-minute HIS STEP below. Supabase automated backups
for this project are likewise **not confirmed** — the project ref is not
recorded anywhere in the repo, so no API check could identify it; confirm
in the dashboard (step 1 below). The ref is recorded now; the rest of
that paragraph still holds.)

## 1. Confirm Supabase automated backups (dashboard, ~3 min)

1. Open the SecureGuard project in the Supabase dashboard (the project whose
   pooler URL is the Render `DATABASE_URL`).
2. Settings → Database → Backups: note whether daily backups / point-in-time
   recovery (PITR) are enabled and the retention window. Free-tier projects
   have limited backup guarantees — if PITR is off, the scripted backup in
   step 2 is the recovery path, not a supplement.
3. Record the finding here (date + what is enabled) so the next run does not
   re-ask.

## 2. Scripted backup (Render shell or laptop, ~5 min)

Prerequisites: `pg_dump` + `pg_restore` (PostgreSQL client tools) and the
production `DATABASE_URL` in the environment. Never paste the URL into chat,
files, or logs.

```bash
cd SecureGaurd-main/backend/scripts
DATABASE_URL='<production URL>' BACKUP_DIR=~/secureguard-backups \
  BACKUP_ENCRYPTION_PASSPHRASE='<passphrase>' ./backup-db.sh
```

The script writes `secureguard-<UTC timestamp>.dump.gz` + a `.manifest.txt`
(table list), verifies gzip integrity and that the manifest lists tables,
then prunes archives older than 30 days. With
`BACKUP_ENCRYPTION_PASSPHRASE` set the archive is additionally encrypted
with `openssl enc -aes-256-cbc -pbkdf2` and stored as
`secureguard-<UTC timestamp>.dump.gz.enc` (the plaintext archive is
deleted after a decrypt round-trip verifies the encrypted copy); without
the passphrase the script prints a loud warning and the backup is
unencrypted. All archive/manifest files are created owner-only
(`umask 077` + `chmod 600`). Store the archive somewhere private
(encrypted disk / private bucket) — it contains full production data.
Suggested cadence: daily via the host's scheduler until Supabase automated
backups are confirmed; weekly at minimum after that.

## 3. Trial restore into a scratch database (~10 min, do this once, then after any schema change)

1. Create a scratch database: a fresh Supabase project, or a local Postgres
   (`createdb secureguard_restore`).
2. Restore. `pg_restore` cannot read an archive from stdin (it treats
   `-` as a literal filename), so decompress to a temp file first:
   ```bash
   gzip -dc ~/secureguard-backups/secureguard-<timestamp>.dump.gz > /tmp/sg-restore.dump
   pg_restore --dbname='<SCRATCH DATABASE_URL>' --no-owner --no-privileges /tmp/sg-restore.dump
   rm -f /tmp/sg-restore.dump
   ```
   For an encrypted archive (`.dump.gz.enc`), decrypt first, then
   decompress — the passphrase is passed via the environment, never on the
   command line:
   ```bash
   openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_PASSPHRASE \
     -in ~/secureguard-backups/secureguard-<timestamp>.dump.gz.enc \
     | gzip -dc > /tmp/sg-restore.dump
   pg_restore --dbname='<SCRATCH DATABASE_URL>' --no-owner --no-privileges /tmp/sg-restore.dump
   rm -f /tmp/sg-restore.dump
   ```
3. Point a local backend copy at the scratch URL and run the smoke checks:
   `GET /health` → 200; register a throwaway account; create an organization;
   list organizations. All three must work against the restored data.
4. Delete the scratch database when done. Record the trial date + result here.

**Trial restore PASSED — 2026-11-24 ~19:15 IST (first backup,
`secureguard-20261124-134015.dump.gz`):** scratch DB was a local
PostgreSQL 17.12 from PGDG debs (home-installed server binaries, run
as `nobody` from /tmp; deleted after). Two gotchas recorded for the
next restore: (1) create the `secureguard_app` role first
(`CREATE ROLE secureguard_app NOLOGIN`) — the dump contains the 20
permissive RLS policies naming that role, and without it pg_restore
logs 20 errors; (2) the single remaining error, `schema "public"
already exists`, is benign (every fresh DB already has a public
schema). With the role present: pg_restore completed, 20/20 tables +
20/20 policies restored, row counts matched prod exactly on all
spot-checked tables (User 29, Organization 21, Scan 21,
Vulnerability 122, ApiKey 2, Repository 9). Scratch DB + server
deleted after the check. **SEC-32 → PASS on this evidence.**
Remaining gaps (not blockers for PASS): the archive is UNENCRYPTED
(no `BACKUP_ENCRYPTION_PASSPHRASE` yet — set one, store it as a
Render env var, re-run for an encrypted archive); no recurring
schedule yet (suggested: daily until Supabase automated backups are
confirmed, weekly after).

## 4. Real restore (incident only)

**Authoritative path — fresh-database swap.** Never restore over the live
production database: a failed or partial restore over live tables leaves
the production database in an unknown state with no clean rollback.

1. Stop writes: put the backend in maintenance (Render → suspend the service)
   so no new data lands after the restore point. This is a maintenance
   window: the service stays suspended until step 4 below completes.
2. Create a fresh database (a new Supabase project, or a local Postgres
   `createdb secureguard_restored`) and restore the newest verified archive
   into it with the decompress-first command from step 3 above (decrypting
   first if the archive is `.enc`), using the *fresh* database's URL.
3. Run the step-3 smoke checks against the fresh database (point a local
   backend copy at it first): `GET /health` → 200; log in with a known
   account; list organizations. Only proceed if all three pass.
4. Swap `DATABASE_URL` to the fresh database (Render env var), run
   `npx prisma migrate deploy` (no-op if the schema matches), restart the
   service, and repeat the smoke checks against production.
5. Keep the old production database untouched until the restored service is
   verified healthy — it is the rollback target if the swap is bad.
6. Expect data loss back to the backup timestamp (RPO = backup age; RTO ≈
   30–60 min including verification). Tell affected users what window was lost.

## What is NOT backed up by this script

- Uploaded files: SecureGuard stores no user-uploaded files (specs are
  fetched/parsed, never stored as files), so the database dump is the whole
  state.
- Secrets in Render/Vercel env vars (JWT secret, API keys): those live in
  the platforms' env stores, not the database — rotate/re-enter them
  separately if a platform account is lost.

## 5. RLS apply + verification (SEC-31)

Migration `backend/prisma/migrations/20261116_rls_policies/migration.sql`
(17 policies on 14 tenant tables, `app.current_org_id` /
`app.current_user_id` session variables, AuditLog append-only trigger) is
written and validated offline against real PostgreSQL 17.5 (PGlite, 42/42
checks: cross-org reads 0 rows, unset-variable reads 0 rows, same-org
reads return rows, AuditLog UPDATE/DELETE raise, org-cascade delete still
works, backfill correct). It is **NOT applied to production**. Apply it
only in this order — applying it first breaks the app (every org-scoped
query returns zero rows, by design: fail closed).

### 5.1 Prerequisites (all must be true before §5.2)

1. **App code deployed.** `backend/utils/rlsContext.js` is deployed AND
   the call sites are converted to run inside `withOrgContext` /
   `withUserContext`: org routes, `requireOrgContext` discovery,
   org creation (`routes/organizations.js`, `utils/orgMigration.js`),
   invitation accept (`routes/invitations.js` — resolve via
   `app_org_id_for_invitation` first), Razorpay webhook
   (`routes/billingWebhook.js` — resolve via
   `app_org_id_for_razorpay_subscription` first), push webhook
   (`routes/integration.js` — resolve via
   `app_org_id_for_repository` / `app_user_id_for_repository` first),
   and `createAuditLog` (must accept a `tx` and run inside the request's
   transaction — audit writes outside a wrapped transaction are denied
   by RLS and logged as "Audit Log Error", non-fatally). Until the call
   sites are converted, the app issues plain `prisma.*` calls with no
   variables set.
2. **Least-privilege app role.** A true superuser bypasses RLS even with
   `FORCE ROW LEVEL SECURITY`. Check what the app connects as — in the
   SQL Editor, as the app credential:
   ```sql
   SELECT usesuper FROM pg_user WHERE usename = current_user;
   ```
   Must return `false`. If it returns `true` (the Supabase `postgres`
   role), create a dedicated role first (run as `postgres` superuser in
   the SQL Editor; generate the password fresh, store it in Render only,
   never in chat or a file):
   ```sql
   CREATE ROLE secureguard_app LOGIN PASSWORD '<generated>';
   GRANT CONNECT ON DATABASE postgres TO secureguard_app;
   GRANT USAGE ON SCHEMA public TO secureguard_app;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secureguard_app;
   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO secureguard_app;
   ALTER DEFAULT PRIVILEGES IN SCHEMA public
     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO secureguard_app;
   ALTER DEFAULT PRIVILEGES IN SCHEMA public
     GRANT USAGE, SELECT ON SEQUENCES TO secureguard_app;
   ```
   Then repoint Render `DATABASE_URL` at `secureguard_app` and redeploy.
   Note: `prisma migrate deploy` must keep running as the owner role —
   the app role must not own the migrations.
3. **Backfill check.** The migration backfills `Scan` /
   `ComplianceReport` from their `Repository` and `Sbom` from its `Scan`,
   and reports remaining NULL-org rows as a `NOTICE`. Any `Repository`
   row still NULL-org after the login-time migration (`orgMigration.js`)
   stays visible only to its owning user — acceptable, but confirm the
   count is small before applying.

### 5.2 Apply (SQL Editor — the Management API cannot run SQL)

1. Open the Supabase dashboard → project `wkvvxqlflhjiqkhwxrsl` → SQL
   Editor → New query.
2. Paste the entire contents of
   `backend/prisma/migrations/20261116_rls_policies/migration.sql` and
   run it. Expected output: `NOTICE: RLS migration self-check passed:
   16 policies on 13 tables` plus a `NOTICE` line with the remaining
   NULL-org counts. Any `ERROR` aborts the apply — fix and re-run; the
   file is safely re-runnable (`DROP POLICY IF EXISTS`,
   `CREATE OR REPLACE FUNCTION`, idempotent backfill).
3. Do NOT also run `npx prisma migrate deploy` for this migration
   afterwards unless `_prisma_migrations` already records it — applying
   via both paths double-applies. If the migration was applied via the
   SQL Editor, record that here with the date so a later `migrate
   deploy` is not run blindly.
4. Confirm: `SELECT count(*) FROM pg_policies WHERE schemaname =
   'public';` — expect 16 on the tenant tables (plus any pre-existing
   policies, of which there were none).

### 5.3 Live cross-tenant matrix (the verification — SEC-31 stays FAIL until this passes)

Use two throwaway accounts; delete both orgs and accounts afterwards.
Never use real user data.

1. Register user A, create org A, add one repository + trigger one scan.
   Register user B, create org B, add one repository + trigger one scan.
   Note both org ids and both user ids.
2. As user A (frontend or API with A's token):
   - `GET /api/repos` (or the org repo list) returns ONLY org A's repo.
   - `GET /api/scans/<org-B-scan-id>` → 404.
   - `GET /api/organizations/<org-B-id>` → 403.
   - `GET /api/vulnerabilities` (or the scan's findings) returns only
     org A's findings.
3. As user B: mirror — only org B's rows, org A's ids → 404/403.
4. Direct database check (SQL Editor, one script, as the app role —
   `SET ROLE secureguard_app;` first; the SQL Editor's own `postgres`
   session bypasses RLS and would show everything):
   ```sql
   BEGIN;
   SET LOCAL app.current_org_id = '<org A id>';
   SET LOCAL app.current_user_id = '<user A id>';
   SELECT count(*) FROM "Repository";   -- expect: org A repos only (+ A's own NULL-org repos)
   SELECT count(*) FROM "Subscription"; -- expect: 1 (org A's) or 0 if org A has none
   SELECT count(*) FROM "AuditLog";     -- expect: only org A's rows
   ROLLBACK;
   ```
   Repeat with org B / user B and confirm the counts swap.
5. Append-only: as the app role with org A context,
   `UPDATE "AuditLog" SET action='x' WHERE "organizationId" = <org A id>;`
   must raise `AuditLog is append-only`; same for `DELETE`.
6. Regression: log in as user A, complete onboarding, create a second
   org, accept an invitation to org B as a new member — all three flows
   must still work (they are the bootstrap/resolver paths).
7. Record the date + results here. Only then may SEC-31 move to PASS.

### 5.4 Rollback (if the apply breaks the app)

Run as the owner role in the SQL Editor. This disables RLS but keeps
the tables and data — the app returns to app-code-only isolation.

```sql
ALTER TABLE "Organization" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "OrganizationMembership" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "OrganizationInvitation" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "AuditLog" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Subscription" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "AlertSetting" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "AlertLog" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "CustomRule" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Repository" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Scan" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "ComplianceReport" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Sbom" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Vulnerability" DISABLE ROW LEVEL SECURITY;
DROP TRIGGER IF EXISTS audit_log_append_only ON "AuditLog";
DROP FUNCTION IF EXISTS prevent_audit_log_mutation();
DROP FUNCTION IF EXISTS app_current_org_id();
DROP FUNCTION IF EXISTS app_current_user_id();
DROP FUNCTION IF EXISTS app_org_has_members(integer);
DROP FUNCTION IF EXISTS app_org_id_for_invitation(text);
DROP FUNCTION IF EXISTS app_org_id_for_razorpay_subscription(text);
DROP FUNCTION IF EXISTS app_org_id_for_stripe_subscription(text);
DROP FUNCTION IF EXISTS app_org_id_for_repository(text, text);
DROP FUNCTION IF EXISTS app_user_id_for_repository(text, text);
```

Re-enabling after a rollback is a fresh apply of §5.2 (the file is
re-runnable), followed by the full §5.3 matrix again.

## 6. Status log

| Date | Event |
|---|---|
| 2026-11-01 | Backup script + restore procedure written, statically verified; no backup taken, no trial restore performed. |
| 2026-11-16 | Management API re-check (read-only): project detail + backups endpoints both 403 — token scoped to "Saftey App" org only; PITR still unverified. Project ref `wkvvxqlflhjiqkhwxrsl` recorded. RLS migration written + validated offline (42/42, PGlite PG 17.5); NOT applied. Retention rules defined in `DATA_RETENTION.md`; no purge job, no purge run. |
