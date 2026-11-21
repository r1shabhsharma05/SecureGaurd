# SEC-31 — `secureguard_app` role switch (supervised-apply pack)

**Status: PREPARED 2026-11-22 (Day 9), NOT APPLIED.** This document is
the exact, reviewed procedure for step 1b of the RLS rollout
(`docs/DATABASE_SECURITY.md` §6.1). Nothing in it has been run against
production. It exists so the supervised apply is copy-paste, not
improvisation. SEC-31 stays **FAIL** until every step below is done
and verified live.

## Why this step exists (evidence, 2026-11-21)

- Supabase SQL Editor (read-only): the app credential `postgres` has
  `usesuper=false` but **`usebypassrls=true`** — Postgres skips RLS
  for this role even with `FORCE ROW LEVEL SECURITY`. Applying the
  RLS migration while the app connects as `postgres` would enforce
  nothing.
- The `secureguard_app` role does not exist yet.
- Render `DATABASE_URL` username is `postgres.wkvvxqlflhjiqkhwxrsl`
  (Supabase pooler).
- `pg_policies` count = 0 (migration not applied).
- Backfill is clean: every tenant table with an `organizationId`
  column has 0 NULL-org rows.

So the order is fixed: **create least-privilege role → repoint
`DATABASE_URL` → redeploy → re-verify → only then apply the RLS
migration** (`backend/prisma/migrations/20261116_rls_policies/`).

## Preconditions (all must hold before starting)

1. Owner present for the whole apply (production credential change).
2. A database backup exists, or the owner explicitly accepts applying
   without one. Today: **no backup exists** (SEC-32 FAIL, Free plan
   has none). The role switch itself does not modify data, but the
   migration apply after it does change enforcement — do not skip
   this decision.
3. The export-feedback design decision is made (the scans
   export-feedback operator path 503s under RLS; see
   `docs/DATABASE_SECURITY.md` §6.1). If undecided, stop after the
   role switch and do not apply the migration.
4. Current `DATABASE_URL` value copied somewhere safe by the owner
   (rollback needs it). Never paste it into chat, git, or this doc.

## Step A — create the role (Supabase SQL Editor, as `postgres`)

Run in the SQL Editor of project `wkvvxqlflhjiqkhwxrsl`. Replace
`<APP_ROLE_PASSWORD>` with a fresh generated password the owner
stores in the Secure Vault / Render dashboard only. **Never commit
the real password anywhere.**

```sql
-- A1. Least-privilege app role: can log in, cannot bypass RLS,
--     cannot create objects, cannot replicate.
CREATE ROLE secureguard_app LOGIN PASSWORD '<APP_ROLE_PASSWORD>'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;

-- A2. Schema access.
GRANT USAGE ON SCHEMA public TO secureguard_app;

-- A3. DML on every current table + sequence use (Prisma needs
--     SELECT/INSERT/UPDATE/DELETE; sequences for autoincrement ids).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
  TO secureguard_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
  TO secureguard_app;

-- A4. Same grants for tables/sequences created later by `postgres`
--     (future Prisma migrations run as postgres — see Step D).
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO secureguard_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO secureguard_app;

-- A5. The RLS migration's helper/resolver functions are called by
--     the app (app_current_org_id, app_current_user_id,
--     app_org_has_members, resolveOrgIdFor*). Functions get EXECUTE
--     to PUBLIC by default in Postgres; grant explicitly anyway so
--     a future REVOKE cannot silently break the app.
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO secureguard_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO secureguard_app;
```

Verify immediately (still as `postgres`):

```sql
SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
FROM pg_roles WHERE rolname = 'secureguard_app';
-- expect: secureguard_app | f | f | t
```

## Step B — repoint Render `DATABASE_URL`

In the Render dashboard (service `SecureGaurd`), set `DATABASE_URL`
to the **pooler** URL with the new role. Supabase pooler usernames
are `<role>.<project-ref>`:

```text
postgresql://secureguard_app.wkvvxqlflhjiqkhwxrsl:<APP_ROLE_PASSWORD>@<pooler-host>:6543/postgres?pgbouncer=true
```

Use the same pooler host/port and query params as the current value;
change only the username and password. Save → Render redeploys.

**Rollback (any time):** restore the old `DATABASE_URL` value and
redeploy. The role can stay in place harmlessly, or be dropped with
`DROP ROLE secureguard_app;` after the repoint is reverted.

## Step C — verify the switch (before touching the migration)

1. Render logs: service starts clean, no Prisma auth errors.
2. `GET https://securegaurd.onrender.com/health` → 200,
   `db: "up"`.
3. SQL Editor, connected as the app credential (or via a one-off
   `psql` with the new URL from the owner's machine):
   `SELECT usesuper, usebypassrls FROM pg_user WHERE usename = current_user;`
   — expect `false | false`. **If either is true, stop: RLS would
   still be bypassed.**
4. App smoke test (owner account): log in, open dashboard, list
   repositories, open a scan. All must return real data. Note: RLS
   is not applied yet, so behaviour must be identical to today —
   any change here means the grants are wrong, not that RLS works.

## Step D — migration ownership split (read before Step E)

`secureguard_app` deliberately has **no DDL rights**: it cannot
create/alter tables. Consequences, accepted by design:

- `prisma migrate deploy` must **not** run with the app credential.
  Future migrations run as `postgres` (Supabase SQL Editor or a
  direct-connection `DATABASE_URL` used only for the migration
  command, never stored on Render).
- The default-privilege grants in A4/A5 cover objects `postgres`
  creates later, so new tables are usable by the app immediately.
- If a future migration creates objects as a different role, re-run
  A3–A5 for that role.

## Step E — apply the RLS migration (only after A–D verify)

1. Push `backend/prisma/migrations/20261116_rls_policies/` to git in
   the same change (it is deliberately unpushed today).
2. Run the migration SQL in the SQL Editor (as `postgres`). Expect
   the self-check `NOTICE: RLS migration self-check passed`.
3. Confirm: `SELECT count(*) FROM pg_policies WHERE schemaname='public';`
   → **17** (14 tables).
4. Redeploy backend; re-run Step C smoke test.
5. Run the live cross-tenant matrix (`docs/DATABASE_SECURITY.md`
   §6.3) — needs two mailboxes / owner word for throwaway accounts.
6. Only with 3+4+5 green does SEC-31 move from FAIL. Record the
   evidence in `docs/SECURITY_GATE_REPORT.md` and
   `docs/SECURITY_HARDENING_CHECKLIST.md` in the same change.

## What this pack does NOT do

- It does not create the role, change any credential, or apply any
  policy. Unattended production credential changes are out of scope
  for the daily runs.
- It does not clear SEC-03 (history purge + Atlas), SEC-32
  (backups), or SEC-34 (Turnstile keys). The gate needs all four
  FAILs cleared; this pack covers one sub-step of one of them.
