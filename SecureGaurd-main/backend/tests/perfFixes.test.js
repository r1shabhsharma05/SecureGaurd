'use strict';

// Perf fix batch regressions (19 Nov 2026, night): pages took ~20 s
// despite the keepalive workflow. Root causes pinned here:
//  1. pg Pool reaped idle clients after 30 s (default) and capped at
//     10 — every visit paid cross-region connection handshakes and the
//     dashboard's parallel requests queued into P2028 retries.
//  2. /health never touched the DB, so keepalive warmed Node only.
//  3. requireOrgContext ran a full RLS transaction on EVERY request.
//  4. /api/scans/stats/summary opened two transactions and shipped
//     every open finding to Node just to count severities.
// Offline: no Redis, no Postgres (prisma stubbed like rbac.test.js).
// Run: node --test backend/tests/perfFixes.test.js
//   from SecureGaurd-main.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const readSrc = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

// ── membershipCache unit behavior ─────────────────────────────────────

const { createMembershipCache } = require('../utils/membershipCache');

test('membershipCache: miss returns null, set/get round-trips', () => {
  const cache = createMembershipCache(60_000);
  assert.equal(cache.get('7:1'), null);
  const value = { organizationId: 1, role: 'OWNER' };
  cache.set('7:1', value);
  assert.equal(cache.get('7:1'), value);
  assert.equal(cache.get('7:2'), null);
});

test('membershipCache: entries expire after the TTL', async () => {
  const cache = createMembershipCache(30);
  cache.set('7:1', { organizationId: 1 });
  assert.notEqual(cache.get('7:1'), null);
  await new Promise((r) => setTimeout(r, 45));
  assert.equal(cache.get('7:1'), null);
});

test('membershipCache: clear() drops everything; size cap prevents unbounded growth', () => {
  const cache = createMembershipCache(60_000, 2);
  cache.set('a', 1);
  cache.set('b', 2);
  cache.set('c', 3); // at cap -> clears first
  assert.equal(cache.get('a'), null);
  assert.equal(cache.get('c'), 3);
  cache.clear();
  assert.equal(cache.size(), 0);
});

// ── requireOrgContext actually uses the cache ─────────────────────────

const prismaPath = require.resolve('../prismaClient');
const orgMigrationPath = require.resolve('../utils/orgMigration');

const calls = { findUnique: 0 };
const MEMBER = {
  id: 1,
  userId: 7,
  organizationId: 12,
  role: 'OWNER',
  organization: { id: 12, name: 'Org' },
};
const txStub = {
  organizationMembership: {
    findUnique: async () => { calls.findUnique++; return MEMBER; },
    findFirst: async () => MEMBER,
  },
  auditLog: { create: async () => ({}) },
  $executeRaw: async () => {},
  $queryRaw: async () => [],
};
require.cache[prismaPath] = {
  id: prismaPath,
  filename: prismaPath,
  loaded: true,
  exports: { ...txStub, $transaction: async (fn) => fn(txStub) },
};
require.cache[orgMigrationPath] = {
  id: orgMigrationPath,
  filename: orgMigrationPath,
  loaded: true,
  exports: { ensureDefaultOrganization: async () => null },
};

const { requireOrgContext, clearMembershipCache } = require('../middleware/rbac');

async function run(userId, orgHeader) {
  const req = { userId, headers: { 'x-organization-id': orgHeader }, query: {}, params: {} };
  let nextCalled = false;
  let statusCode = null;
  const res = {
    status(code) { statusCode = code; return this; },
    json() { return this; },
  };
  await requireOrgContext(req, res, () => { nextCalled = true; });
  return { req, nextCalled, statusCode };
}

test('requireOrgContext: second identical request is served from cache (no second DB lookup)', async () => {
  clearMembershipCache();
  calls.findUnique = 0;
  const first = await run(7, '12');
  assert.equal(first.nextCalled, true);
  assert.equal(first.req.organizationId, 12);
  assert.equal(calls.findUnique, 1);

  const second = await run(7, '12');
  assert.equal(second.nextCalled, true);
  assert.equal(second.req.organizationId, 12);
  assert.equal(second.req.orgRole, 'OWNER');
  assert.equal(calls.findUnique, 1, 'cache hit must skip the membership transaction');

  // A different org is a different cache key -> fresh lookup.
  await run(7, '13');
  assert.equal(calls.findUnique, 2);

  // clearMembershipCache forces a fresh lookup (mutation invalidation).
  clearMembershipCache();
  await run(7, '12');
  assert.equal(calls.findUnique, 3);
});

test('requireOrgContext: malformed org id still 400s (cache never swallows validation)', async () => {
  clearMembershipCache();
  const r = await run(7, '12abc');
  assert.equal(r.statusCode, 400);
  assert.equal(r.nextCalled, false);
});

// ── source pins ───────────────────────────────────────────────────────

test('prismaClient: pool keeps clients warm and survives idle-client errors', () => {
  const src = readSrc('backend/prismaClient.js');
  assert.match(src, /idleTimeoutMillis: 0/);
  assert.match(src, /keepAlive: true/);
  assert.match(src, /pool\.on\('error'/);
});

test('server.js: /health exercises the DB pool (keepalive warms the DB too)', () => {
  const src = readSrc('backend/server.js');
  const health = src.slice(src.indexOf("app.get('/health'"), src.indexOf("app.get('/health'") + 800);
  assert.match(health, /SELECT 1/);
  assert.match(health, /db/);
});

test('scans stats/summary: one transaction + groupBy counts, same response shape', () => {
  const src = readSrc('backend/routes/scans.js');
  const stats = src.slice(src.indexOf("router.get('/stats/summary'"));
  assert.match(stats, /groupBy/);
  const txCount = (stats.match(/withRequestOrgContext/g) || []).length;
  assert.equal(txCount, 1, 'stats handler must open exactly one RLS transaction');
  assert.match(stats, /computeHealthScore/);
});

test('organizations.js: membership mutations clear the membership cache', () => {
  const src = readSrc('backend/routes/organizations.js');
  const clears = (src.match(/clearMembershipCache\(\)/g) || []).length;
  assert.ok(clears >= 4, `expected >= 4 cache clears (role/remove/leave/transfer), got ${clears}`);
});
