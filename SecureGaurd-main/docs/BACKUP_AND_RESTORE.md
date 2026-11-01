# Database backups & restore — SecureGuard

**Status, stated honestly (1 Nov 2026):** the backup *script* (`backend/scripts/backup-db.sh`)
and the restore procedure below are written and statically verified, but **no backup has
been taken and no trial restore has been performed** from this VM: the VM has no `pg_dump`
and no `DATABASE_URL` (it lives only in Render env). The first real backup + trial restore
is a ~15-minute HIS STEP below. Supabase automated backups for this project are likewise
**not confirmed** — the project ref is not recorded anywhere in the repo, so no API check
could identify it; confirm in the dashboard (step 1 below).

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
DATABASE_URL='<production URL>' BACKUP_DIR=~/secureguard-backups ./backup-db.sh
```

The script writes `secureguard-<UTC timestamp>.dump.gz` + a `.manifest.txt`
(table list), verifies gzip integrity and that the manifest lists tables,
then prunes archives older than 30 days. Store the archive somewhere private
(encrypted disk / private bucket) — it contains full production data.
Suggested cadence: daily via the host's scheduler until Supabase automated
backups are confirmed; weekly at minimum after that.

## 3. Trial restore into a scratch database (~10 min, do this once, then after any schema change)

1. Create a scratch database: a fresh Supabase project, or a local Postgres
   (`createdb secureguard_restore`).
2. Restore:
   ```bash
   pg_restore --dbname='<SCRATCH DATABASE_URL>' --no-owner --no-privileges \
     ~/secureguard-backups/secureguard-<timestamp>.dump.gz
   ```
3. Point a local backend copy at the scratch URL and run the smoke checks:
   `GET /health` → 200; register a throwaway account; create an organization;
   list organizations. All three must work against the restored data.
4. Delete the scratch database when done. Record the trial date + result here.

## 4. Real restore (incident only)

1. Stop writes: put the backend in maintenance (Render → suspend the service)
   so no new data lands after the restore point.
2. Restore the newest verified archive into the production database with the
   `pg_restore` command above (production `DATABASE_URL`). For a full
   overwrite, restore into a fresh database and swap `DATABASE_URL` instead
   of restoring over live tables.
3. Run `npx prisma migrate deploy` (no-op if the schema matches), restart the
   service, and repeat the step-3 smoke checks.
4. Expect data loss back to the backup timestamp (RPO = backup age; RTO ≈
   30–60 min including verification). Tell affected users what window was lost.

## What is NOT backed up by this script

- Uploaded files: SecureGuard stores no user-uploaded files (specs are
  fetched/parsed, never stored as files), so the database dump is the whole
  state.
- Secrets in Render/Vercel env vars (JWT secret, API keys): those live in
  the platforms' env stores, not the database — rotate/re-enter them
  separately if a platform account is lost.
