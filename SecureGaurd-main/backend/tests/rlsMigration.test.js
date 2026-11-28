// Validates the RLS migration (SEC-31) against real PostgreSQL 17.5 via
// in-process PGlite — no DB creds, no network, no psql.
// Run: node --test tests/rlsMigration.test.js
// RUN THIS after ANY edit to
// backend/prisma/migrations/20261116_rls_policies/migration.sql.
// Shape: stub tables (only the columns the policies / backfill /
// resolvers touch), execute the migration file, then SET ROLE to the
// non-superuser app_user — FORCE RLS is a no-op for the superuser, so
// every behavioural check runs as app_user. RLS session variables are
// set with SET LOCAL exactly as the app sets them (set_config in
// utils/rlsContext.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

let PGlite;
try {
  ({ PGlite } = require('@electric-sql/pglite'));
} catch {
  // PGlite is a devDependency; if it is missing the suite must say so,
  // not silently skip the migration checks.
  test('rlsMigration requires @electric-sql/pglite (devDependency)', () => {
    assert.fail('@electric-sql/pglite is not installed — run npm install');
  });
}

const MIGRATION = path.join(__dirname, '..', 'prisma', 'migrations', '20261116_rls_policies', 'migration.sql');

// F-03/F-04 (ARTEX 28 Nov 2026): the §5 resolver bundle was never
// applied in prod, so the functions were absent and every unauthenticated
// resolver call raised instead of returning NULL. This tracked migration
// carries the same NULL-on-miss definitions into the normal migrate
// chain; it must apply cleanly over §5 and keep the same behaviour.
const RESOLVER_MIGRATION = path.join(__dirname, '..', 'prisma', 'migrations', '20261128_resolver_null_on_miss', 'migration.sql');

const STUBS = `
CREATE TABLE "User" (id serial PRIMARY KEY, email text);
CREATE TABLE "Organization" (id serial PRIMARY KEY, name text);
CREATE TABLE "OrganizationMembership" (id serial PRIMARY KEY, "organizationId" integer NOT NULL, "userId" integer NOT NULL);
CREATE TABLE "OrganizationInvitation" (id serial PRIMARY KEY, "organizationId" integer NOT NULL, "tokenHash" text NOT NULL, status text NOT NULL, "expiresAt" timestamptz NOT NULL, "invitedEmail" text);
CREATE TABLE "AuditLog" (id serial PRIMARY KEY, "organizationId" integer NOT NULL REFERENCES "Organization"(id) ON DELETE CASCADE);
CREATE TABLE "Subscription" (id serial PRIMARY KEY, "organizationId" integer NOT NULL, "razorpaySubscriptionId" text, "stripeSubscriptionId" text, status text, plan text);
CREATE TABLE "AlertSetting" (id serial PRIMARY KEY, "organizationId" integer NOT NULL);
CREATE TABLE "AlertLog" (id serial PRIMARY KEY, "organizationId" integer NOT NULL);
CREATE TABLE "CustomRule" (id serial PRIMARY KEY, "organizationId" integer NOT NULL);
CREATE TABLE "ApiKey" (id serial PRIMARY KEY, "organizationId" integer NOT NULL, "userId" integer NOT NULL, "keyHash" text UNIQUE);
CREATE TABLE "Repository" (id serial PRIMARY KEY, "organizationId" integer, "userId" integer, "fullName" text, platform text);
CREATE TABLE "Scan" (id serial PRIMARY KEY, "organizationId" integer, "userId" integer, "repositoryId" integer);
CREATE TABLE "ComplianceReport" (id serial PRIMARY KEY, "organizationId" integer, "userId" integer, "repositoryId" integer);
CREATE TABLE "Sbom" (id serial PRIMARY KEY, "organizationId" integer, "scanId" integer);
CREATE TABLE "Vulnerability" (id serial PRIMARY KEY, "scanId" integer);
`;

const SEED = `
INSERT INTO "User" (id, email) VALUES (1, 'a@org1.test'), (2, 'b@org2.test'), (5, 'c@none.test');
INSERT INTO "Organization" (id, name) VALUES (1, 'org-one'), (2, 'org-two'), (3, 'org-three-memberless');
INSERT INTO "OrganizationMembership" ("organizationId", "userId") VALUES (1, 1), (2, 2);
INSERT INTO "OrganizationInvitation" ("organizationId", "tokenHash", status, "expiresAt", "invitedEmail")
  VALUES (1, 'aaa', 'PENDING', now() + interval '1 day', 'a@org1.test'),
         (1, 'bbb', 'ACCEPTED', now() + interval '1 day', 'a@org1.test'),
         (2, 'ccc', 'PENDING', now() - interval '1 day', 'b@org2.test');
INSERT INTO "Subscription" ("organizationId", "razorpaySubscriptionId", status, plan) VALUES (1, 'sub_rz_1', 'active', 'PRO');
INSERT INTO "Repository" (id, "organizationId", "userId", "fullName", platform)
  VALUES (1, 1, 1, 'acme/web', 'GITHUB'), (2, NULL, 1, 'solo/legacy', 'GITHUB'), (3, 2, 2, 'other/app', 'GITHUB');
INSERT INTO "Scan" (id, "organizationId", "userId", "repositoryId") VALUES (1, 1, 1, 1), (2, NULL, 1, 2), (3, 2, 2, 3);
INSERT INTO "ComplianceReport" ("organizationId", "userId", "repositoryId") VALUES (1, 1, 1);
INSERT INTO "Sbom" ("organizationId", "scanId") VALUES (1, 1), (NULL, 2);
INSERT INTO "Vulnerability" ("scanId") VALUES (1), (3);
INSERT INTO "AuditLog" (id, "organizationId") VALUES (1, 1), (2, 3);
INSERT INTO "AlertSetting" ("organizationId") VALUES (1);
INSERT INTO "AlertLog" ("organizationId") VALUES (1);
INSERT INTO "CustomRule" ("organizationId") VALUES (1);
`;

let db;

// Run one statement as the non-superuser app role, with the RLS session
// variables set exactly as the app sets them. Returns the rows.
async function asApp({ org = null, user = null, garbageOrg = false } = {}, sql, params = []) {
  const sets = [`SET LOCAL ROLE app_user`];
  if (garbageOrg) sets.push(`SET LOCAL app.current_org_id = '12abc'`);
  else if (org !== null) sets.push(`SET LOCAL app.current_org_id = '${org}'`);
  if (user !== null) sets.push(`SET LOCAL app.current_user_id = '${user}'`);
  await db.query('BEGIN');
  try {
    for (const s of sets) await db.query(s);
    const res = await db.query(sql, params);
    await db.query('COMMIT');
    return res.rows;
  } catch (err) {
    await db.query('ROLLBACK');
    throw err;
  }
}

async function countAsApp(ctx, table, where = '') {
  const rows = await asApp(ctx, `SELECT count(*)::int AS n FROM "${table}" ${where}`);
  return rows[0].n;
}

test.before(async () => {
  // The migration file is deliberately NOT committed yet (SEC-31: it
  // must not reach main until call-site conversion + the superuser check
  // are complete — Render's pre-deploy would auto-apply it). When the
  // file is absent the checks below skip instead of failing.
  if (!fs.existsSync(MIGRATION)) return;
  db = new PGlite();
  await db.exec(STUBS);
  await db.exec(SEED);
  // Seed rows use explicit ids, so advance every serial sequence past
  // them — otherwise the first app INSERT draws a colliding id (and the
  // RETURNING check then sees the wrong org's memberships).
  await db.exec(`SELECT setval(pg_get_serial_sequence('"Organization"', 'id'), (SELECT max(id) FROM "Organization"));
    SELECT setval(pg_get_serial_sequence('"OrganizationMembership"', 'id'), (SELECT max(id) FROM "OrganizationMembership"));
    SELECT setval(pg_get_serial_sequence('"OrganizationInvitation"', 'id'), (SELECT max(id) FROM "OrganizationInvitation"));
    SELECT setval(pg_get_serial_sequence('"AuditLog"', 'id'), (SELECT max(id) FROM "AuditLog"));`);
  await db.exec(fs.readFileSync(MIGRATION, 'utf8'));
  await db.exec(`CREATE ROLE app_user NOLOGIN;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;`);
});

test.after(async () => { if (db) await db.close(); });

test.beforeEach((t) => {
  if (!db) t.skip('migration file not committed yet — held back until SEC-31 conversion completes');
});

test('migration self-check: 17 policies on 14 tables', async () => {
  const rows = await db.query(`SELECT count(*)::int AS n, count(DISTINCT tablename)::int AS t
    FROM pg_policies WHERE schemaname = 'public' AND tablename IN (
      'Organization', 'OrganizationMembership', 'OrganizationInvitation',
      'AuditLog', 'Subscription', 'AlertSetting', 'AlertLog', 'CustomRule',
      'ApiKey', 'Repository', 'Scan', 'ComplianceReport', 'Sbom', 'Vulnerability')`);
  assert.equal(rows.rows[0].n, 17);
  assert.equal(rows.rows[0].t, 14);
});

test('same-org reads return rows; cross-org reads return 0', async () => {
  assert.equal(await countAsApp({ org: 1, user: 1 }, 'Repository'), 2); // org1 repo + own NULL-org repo
  assert.equal(await countAsApp({ org: 2, user: 2 }, 'Repository'), 1); // org2 repo only
  assert.equal(await countAsApp({ org: 2, user: 2 }, 'Repository', `WHERE "organizationId" = 1`), 0);
  assert.equal(await countAsApp({ org: 1, user: 1 }, 'Scan'), 2);
  assert.equal(await countAsApp({ org: 2, user: 2 }, 'Scan', `WHERE "organizationId" = 1`), 0);
  assert.equal(await countAsApp({ org: 1, user: 1 }, 'AlertSetting'), 1);
  assert.equal(await countAsApp({ org: 2, user: 2 }, 'AlertSetting'), 0);
  assert.equal(await countAsApp({ org: 1, user: 1 }, 'AuditLog'), 1);
  assert.equal(await countAsApp({ org: 2, user: 2 }, 'AuditLog'), 0);
  assert.equal(await countAsApp({ org: 1, user: 1 }, 'Vulnerability'), 1); // via org1 Scan
  assert.equal(await countAsApp({ org: 2, user: 2 }, 'Vulnerability'), 1); // via org2 Scan
});

test('unset variables return 0 rows (fail closed)', async () => {
  for (const table of ['OrganizationMembership', 'OrganizationInvitation', 'AuditLog', 'Subscription', 'AlertSetting', 'AlertLog', 'CustomRule', 'Repository', 'Scan', 'ComplianceReport', 'Sbom', 'Vulnerability']) {
    assert.equal(await countAsApp({}, table), 0, `${table} leaked with no context`);
  }
  // Organization: both seeded orgs have members, so none is visible with no context.
  assert.equal(await countAsApp({}, 'Organization'), 1); // the memberless org-three only (deliberate carve-out, §4)
});

test('garbage session variable denies (regex guard, §1)', async () => {
  // AlertSetting has an org-only policy (no user disjunct to confuse it).
  assert.equal(await countAsApp({ garbageOrg: true, user: 1 }, 'AlertSetting'), 0);
  // And no org-scoped Repository row is visible under a garbage org var.
  assert.equal(await countAsApp({ garbageOrg: true, user: 1 }, 'Repository', `WHERE "organizationId" = 1`), 0);
});

test('membership discovery: user-only context sees own memberships only', async () => {
  const mine = await asApp({ user: 1 }, `SELECT "organizationId" FROM "OrganizationMembership"`);
  assert.deepEqual(mine.map((r) => r.organizationId), [1]);
  const theirs = await asApp({ user: 2 }, `SELECT "organizationId" FROM "OrganizationMembership"`);
  assert.deepEqual(theirs.map((r) => r.organizationId), [2]);
});

test('NULL-org repository visible to owning user only', async () => {
  assert.equal(await countAsApp({ user: 1 }, 'Repository', `WHERE "organizationId" IS NULL`), 1);
  assert.equal(await countAsApp({ user: 2 }, 'Repository', `WHERE "organizationId" IS NULL`), 0);
  assert.equal(await countAsApp({ org: 2, user: 2 }, 'Repository', `WHERE "organizationId" IS NULL`), 0);
});

test('cross-org INSERT violates RLS', async () => {
  await assert.rejects(
    () => asApp({ org: 2, user: 2 }, `INSERT INTO "AlertSetting" ("organizationId") VALUES (1)`),
    /row-level security/
  );
});

test('Organization bootstrap INSERT works with user-only context, fails with org context', async () => {
  const rows = await asApp({ user: 5 }, `INSERT INTO "Organization" (name) VALUES ('bootstrapped') RETURNING id`);
  assert.equal(rows.length, 1);
  await assert.rejects(
    () => asApp({ org: 1, user: 1 }, `INSERT INTO "Organization" (name) VALUES ('nope')`),
    /row-level security/
  );
});

test('AuditLog append-only: UPDATE and DELETE raise as the app role', async () => {
  await assert.rejects(
    () => asApp({ org: 1, user: 1 }, `UPDATE "AuditLog" SET "organizationId" = 1 WHERE id = 1`),
    /append-only/
  );
  await assert.rejects(
    () => asApp({ org: 1, user: 1 }, `DELETE FROM "AuditLog" WHERE id = 1`),
    /append-only/
  );
});

test('AuditLog org-cascade delete still works (trigger carve-out, §6)', async () => {
  await db.query(`DELETE FROM "Organization" WHERE id = 3`);
  const rows = await db.query(`SELECT count(*)::int AS n FROM "AuditLog" WHERE "organizationId" = 3`);
  assert.equal(rows.rows[0].n, 0);
});

test('invitation resolvers: PENDING-only vs any-status', async () => {
  const one = async (fn, arg) => (await asApp({ org: 1, user: 1 }, `SELECT ${fn}($1) AS id`, [arg]))[0].id;
  assert.equal(await one('app_org_id_for_invitation', 'aaa'), 1); // PENDING + unexpired
  assert.equal(await one('app_org_id_for_invitation', 'bbb'), null); // ACCEPTED
  assert.equal(await one('app_org_id_for_invitation', 'ccc'), null); // expired
  assert.equal(await one('app_org_id_for_invitation', 'zzz'), null); // unknown
  assert.equal(await one('app_org_id_for_invitation_any', 'aaa'), 1);
  assert.equal(await one('app_org_id_for_invitation_any', 'bbb'), 1); // ACCEPTED still resolves
  assert.equal(await one('app_org_id_for_invitation_any', 'ccc'), 2); // expired still resolves
  assert.equal(await one('app_org_id_for_invitation_any', 'zzz'), null);
});

test('razorpay + repository resolvers', async () => {
  const one = async (sql, params) => (await asApp({ org: 1, user: 1 }, sql, params))[0];
  assert.equal((await one(`SELECT app_org_id_for_razorpay_subscription($1) AS id`, ['sub_rz_1'])).id, 1);
  assert.equal((await one(`SELECT app_org_id_for_razorpay_subscription($1) AS id`, ['sub_nope'])).id, null);
  const repo = await one(`SELECT app_org_id_for_repository($1, $2) AS org, app_user_id_for_repository($1, $2) AS usr`, ['acme/web', 'GITHUB']);
  assert.equal(repo.org, 1);
  assert.equal(repo.usr, 1);
  const miss = await one(`SELECT app_org_id_for_repository($1, $2) AS org`, ['acme/web', 'GITLAB']);
  assert.equal(miss.org, null);
});

test('resolver migration 20261128 applies over §5: NULL on miss, ids on hit', async (t) => {
  if (!fs.existsSync(RESOLVER_MIGRATION)) {
    t.skip('resolver migration file not present');
    return;
  }
  await db.exec(fs.readFileSync(RESOLVER_MIGRATION, 'utf8'));
  const one = async (fn, arg) => (await asApp({ org: 1, user: 1 }, `SELECT ${fn}($1) AS id`, [arg]))[0].id;
  // Invitation resolvers: hit + miss (the F-04 shape — a real token and
  // an unknown one must never raise).
  assert.equal(await one('app_org_id_for_invitation', 'aaa'), 1);
  assert.equal(await one('app_org_id_for_invitation', 'zzz'), null);
  assert.equal(await one('app_org_id_for_invitation_any', 'bbb'), 1);
  assert.equal(await one('app_org_id_for_invitation_any', 'zzz'), null);
  // Repository resolvers: hit + miss (the F-03 webhook shape).
  const repo = await asApp({ org: 1, user: 1 },
    `SELECT app_org_id_for_repository($1, $2) AS org, app_user_id_for_repository($1, $2) AS usr`,
    ['acme/web', 'GITHUB']);
  assert.equal(repo[0].org, 1);
  assert.equal(repo[0].usr, 1);
  const miss = await asApp({ org: 1, user: 1 },
    `SELECT app_org_id_for_repository($1, $2) AS org, app_user_id_for_repository($1, $2) AS usr`,
    ['nobody/nothing', 'GITHUB']);
  assert.equal(miss[0].org, null);
  assert.equal(miss[0].usr, null);
});
