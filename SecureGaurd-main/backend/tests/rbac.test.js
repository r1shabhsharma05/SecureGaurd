const test = require('node:test');
const assert = require('node:assert/strict');

// Unit tests for backend/middleware/rbac.js requireOrgContext (SEC-15 / T4).
// Prisma is stubbed in the require cache before rbac loads, so no DB or
// env is needed. This pins the strict org-id validation: a supplied org id
// must be a plain integer, and anything else is a 400 — never a silent
// fall back to the caller's first org.
const prismaPath = require.resolve('../prismaClient');
const orgMigrationPath = require.resolve('../utils/orgMigration');

const calls = { findUnique: [], findFirst: [], auditCreate: [], transactions: 0 };
let findUniqueImpl = async () => null;
let findFirstImpl = async () => null;
let ensureDefaultOrgImpl = async () => null;

// SEC-31: requireOrgContext now runs its lookups inside withUserContext,
// which opens a prisma.$transaction and sets the RLS user variable via
// tx.$executeRaw (SET LOCAL) before the query. The stub mirrors that
// boundary so the tests still run with no DB: $transaction hands the
// callback a tx client whose model methods record the same calls.
const txStub = {
  organizationMembership: {
    findUnique: async (args) => { calls.findUnique.push(args); return findUniqueImpl(args); },
    findFirst: async (args) => { calls.findFirst.push(args); return findFirstImpl(args); },
  },
  auditLog: { create: async (args) => { calls.auditCreate.push(args); return {}; } },
  $executeRaw: async () => {},
  $queryRaw: async () => [],
};
require.cache[prismaPath] = {
  id: prismaPath,
  filename: prismaPath,
  loaded: true,
  exports: {
    ...txStub,
    $transaction: async (fn) => { calls.transactions++; return fn(txStub); },
  },
};
require.cache[orgMigrationPath] = {
  id: orgMigrationPath,
  filename: orgMigrationPath,
  loaded: true,
  exports: {
    ensureDefaultOrganization: async (...args) => ensureDefaultOrgImpl(...args),
  },
};

const { requireOrgContext, requireOrgRole, createAuditLog, logAuthEvent, clearMembershipCache } = require('../middleware/rbac');

const MEMBER = {
  organizationId: 12,
  role: 'ADMIN',
  organization: { id: 12, name: 'Acme' },
};

function reset() {
  calls.findUnique.length = 0;
  calls.findFirst.length = 0;
  calls.auditCreate.length = 0;
  calls.transactions = 0;
  findUniqueImpl = async () => null;
  findFirstImpl = async () => null;
  ensureDefaultOrgImpl = async () => null;
}

async function run({ userId = 7, headers = {}, query = {}, body, params = {} } = {}) {
  // requireOrgContext caches successful resolutions for 60 s; each test
  // invocation must resolve fresh against its own stubbed impls.
  clearMembershipCache();
  const req = { userId, headers, query, body, params };
  let statusCode = null;
  let payload = null;
  let nextCalled = false;
  const res = {
    status(code) { statusCode = code; return this; },
    json(p) { payload = p; return this; },
  };
  await requireOrgContext(req, res, () => { nextCalled = true; });
  return { req, statusCode, payload, nextCalled };
}

test('malformed org id "12abc" in header is a 400, not a fallback to first org', async () => {
  reset();
  findFirstImpl = async () => MEMBER; // would resolve if fallback ran
  const r = await run({ headers: { 'x-organization-id': '12abc' } });
  assert.equal(r.statusCode, 400);
  assert.equal(r.payload.message, 'Invalid organization id');
  assert.equal(r.nextCalled, false);
  assert.equal(calls.findUnique.length, 0);
  assert.equal(calls.findFirst.length, 0);
});

test('malformed org ids "abc" and "12.5" are 400s', async () => {
  reset();
  for (const bad of ['abc', '12.5', '0x12', '']) {
    // '' is falsy and takes the absent-id path; the rest must 400.
    findFirstImpl = async () => MEMBER;
    const r = await run({ headers: { 'x-organization-id': bad } });
    if (bad === '') {
      assert.equal(r.nextCalled, true, 'empty id takes the default-org path');
    } else {
      assert.equal(r.statusCode, 400, `expected 400 for ${JSON.stringify(bad)}`);
      assert.equal(r.nextCalled, false);
    }
    reset();
  }
});

test('malformed org id in query and body is a 400', async () => {
  reset();
  findFirstImpl = async () => MEMBER;
  const viaQuery = await run({ query: { organizationId: '7x' } });
  assert.equal(viaQuery.statusCode, 400);
  assert.equal(viaQuery.nextCalled, false);

  reset();
  findFirstImpl = async () => MEMBER;
  const viaBody = await run({ body: { organizationId: '12abc' } });
  assert.equal(viaBody.statusCode, 400);
  assert.equal(viaBody.nextCalled, false);
  assert.equal(calls.findFirst.length, 0);
});

test('valid org id still resolves membership (string, number, padded)', async () => {
  reset();
  findUniqueImpl = async (args) => {
    assert.equal(args.where.userId_organizationId.organizationId, 12);
    return MEMBER;
  };
  const r = await run({ headers: { 'x-organization-id': '12' } });
  assert.equal(r.nextCalled, true);
  assert.equal(r.req.organizationId, 12);
  assert.equal(r.req.orgRole, 'ADMIN');

  reset();
  findUniqueImpl = async () => MEMBER;
  const viaBody = await run({ body: { organizationId: 12 } });
  assert.equal(viaBody.nextCalled, true);
  assert.equal(viaBody.req.organizationId, 12);

  reset();
  findUniqueImpl = async () => MEMBER;
  const padded = await run({ headers: { 'x-organization-id': ' 12 ' } });
  assert.equal(padded.nextCalled, true);
  assert.equal(padded.req.organizationId, 12);
});

test('valid org id, non-member is a 403', async () => {
  reset();
  findUniqueImpl = async () => null;
  const r = await run({ headers: { 'x-organization-id': '12' } });
  assert.equal(r.statusCode, 403);
  assert.equal(r.nextCalled, false);
  assert.equal(calls.findFirst.length, 0);
});

test('absent org id still takes the default-org path', async () => {
  reset();
  findFirstImpl = async () => MEMBER;
  const r = await run({});
  assert.equal(r.nextCalled, true);
  assert.equal(r.req.organizationId, 12);
  assert.equal(calls.findUnique.length, 0);
});

test('absent org id with no membership and no default org is a 400', async () => {
  reset();
  findFirstImpl = async () => null;
  ensureDefaultOrgImpl = async () => null;
  const r = await run({});
  assert.equal(r.statusCode, 400);
  assert.equal(r.nextCalled, false);
});

test('requireOrgRole blocks a role outside the allowlist', () => {
  let statusCode = null;
  let nextCalled = false;
  const res = {
    status(code) { statusCode = code; return this; },
    json() { return this; },
  };
  requireOrgRole(['OWNER', 'ADMIN'])({ orgRole: 'AUDITOR' }, res, () => { nextCalled = true; });
  assert.equal(statusCode, 403);
  assert.equal(nextCalled, false);
});

test('createAuditLog without tx opens its own withOrgContext transaction', async () => {
  reset();
  await createAuditLog(12, 7, 'REPO_ADDED', 'REPOSITORY', '5', { name: 'x' });
  assert.equal(calls.transactions, 1, 'one transaction opened for the audit write');
  assert.equal(calls.auditCreate.length, 1);
  assert.equal(calls.auditCreate[0].data.organizationId, 12);
  assert.equal(calls.auditCreate[0].data.actorId, 7);
  assert.equal(calls.auditCreate[0].data.action, 'REPO_ADDED');
});

test('createAuditLog with tx reuses the caller transaction, opens none', async () => {
  reset();
  let usedTx = null;
  const tx = { auditLog: { create: async (args) => { usedTx = args; return {}; } } };
  await createAuditLog(12, 7, 'REPO_ADDED', 'REPOSITORY', '5', {}, tx);
  assert.equal(calls.transactions, 0, 'no new transaction when tx is passed');
  assert.equal(usedTx.data.organizationId, 12);
  assert.equal(calls.auditCreate.length, 0);
});

test('createAuditLog without actorId skips the write (no RLS context can be set)', async () => {
  reset();
  await createAuditLog(12, null, 'REPO_ADDED');
  assert.equal(calls.transactions, 0);
  assert.equal(calls.auditCreate.length, 0);
});

// ── logAuthEvent (auth audit logging, Day 7 finding) ─────────────────────────
// AuditLog.organizationId is required; auth events resolve the user's
// primary (earliest) membership org. No membership → skip. Never throws.

test('logAuthEvent writes the event against the primary org', async () => {
  reset();
  findFirstImpl = async () => ({ organizationId: 12 });
  await logAuthEvent(7, 'USER_LOGIN', { method: 'password' });
  assert.equal(calls.auditCreate.length, 1);
  assert.equal(calls.auditCreate[0].data.organizationId, 12);
  assert.equal(calls.auditCreate[0].data.actorId, 7);
  assert.equal(calls.auditCreate[0].data.action, 'USER_LOGIN');
  assert.equal(calls.auditCreate[0].data.targetType, 'USER');
  assert.equal(calls.auditCreate[0].data.targetId, '7');
  assert.deepEqual(calls.auditCreate[0].data.details, { method: 'password' });
});

test('logAuthEvent skips the write when the user has no membership yet', async () => {
  reset();
  findFirstImpl = async () => null;
  await logAuthEvent(7, 'USER_LOGIN', {});
  assert.equal(calls.auditCreate.length, 0);
});

test('logAuthEvent never throws when the membership lookup fails', async () => {
  reset();
  findFirstImpl = async () => { throw new Error('db down'); };
  await logAuthEvent(7, 'USER_LOGIN', {});
  assert.equal(calls.auditCreate.length, 0);
});

test('logAuthEvent ignores a non-numeric user id', async () => {
  reset();
  await logAuthEvent('abc', 'USER_LOGIN', {});
  assert.equal(calls.findFirst.length, 0);
  assert.equal(calls.auditCreate.length, 0);
});
