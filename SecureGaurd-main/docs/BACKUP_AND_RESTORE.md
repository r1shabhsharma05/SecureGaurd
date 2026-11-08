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
2. Restore. `pg_restore` cannot read gzip, so decompress first and pipe the
   custom-format dump into `pg_restore` on stdin (`-`):
   ```bash
   gzip -dc ~/secureguard-backups/secureguard-<timestamp>.dump.gz \
     | pg_restore --dbname='<SCRATCH DATABASE_URL>' --no-owner --no-privileges -
   ```
   For an encrypted archive (`.dump.gz.enc`), decrypt first, then
   decompress — the passphrase is passed via the environment, never on the
   command line:
   ```bash
   openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_PASSPHRASE \
     -in ~/secureguard-backups/secureguard-<timestamp>.dump.gz.enc \
     | gzip -dc \
     | pg_restore --dbname='<SCRATCH DATABASE_URL>' --no-owner --no-privileges -
   ```
3. Point a local backend copy at the scratch URL and run the smoke checks:
   `GET /health` → 200; register a throwaway account; create an organization;
   list organizations. All three must work against the restored data.
4. Delete the scratch database when done. Record the trial date + result here.

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
