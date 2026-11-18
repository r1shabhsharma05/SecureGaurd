'use strict';

// API key management regressions (19 Nov 2026). Offline: no Redis, no Postgres.
// Run: node --test backend/tests/apiKeys.test.js
//   from SecureGaurd-main.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

delete process.env.REDIS_URL;

// ── In-memory ApiKey rows ─────────────────────────────────────────────────
const KEYS = [];
let nextId = 1;

const txStub = {
  apiKey: {
    create: async ({ data, select }) => {
      const row = { id: nextId++, ...data, lastUsedAt: null, revokedAt: null, createdAt: new Date() };
      KEYS.push(row);
      return pick(row, select);
    },
    findMany: async ({ where = {}, select }) =>
      KEYS.filter((k) => where.organizationId === undefined || k.organizationId === where.organizationId)
        .map((k) => pick(k, select)),
    findFirst: async ({ where = {}, select }) => {
      const row = KEYS.find((k) => (where.id === undefined || k.id === where.id)
        && (where.organizationId === undefined || k.organizationId === where.organizationId));
      return row ? pick(row, select) : null;
    },
    findUnique: async ({ where = {} }) => KEYS.find((k) => k.keyHash === where.keyHash) || null,
    update: async ({ where = {}, data }) => {
      const row = KEYS.find((k) => k.id === where.id);
      Object.assign(row, data);
      return row;
    },
  },
};
function pick(row, select) {
  if (!select) return { ...row };
  const out = {};
  for (const k of Object.keys(select)) if (select[k]) out[k] = row[k];
  return out;
}
const prismaStub = { ...txStub, $transaction: async (fn) => fn(txStub), $connect: async () => {}, $disconnect: async () => {} };

// Stubs must land before any module under test is required.
const prismaPath = require.resolve('../prismaClient');
require.cache[prismaPath] = { id: prismaPath, filename: prismaPath, loaded: true, exports: prismaStub };
require.cache[require.resolve('../middleware/auth')] = {
  id: 'auth-stub', filename: 'auth-stub', loaded: true,
  exports: (req, _res, next) => { req.userId = 7; next(); },
};
require.cache[require.resolve('../middleware/rbac')] = {
  id: 'rbac-stub', filename: 'rbac-stub', loaded: true,
  exports: {
    requireOrgContext: (req, _res, next) => { req.organizationId = 1; req.userId = 7; next(); },
    requireOrgRole: () => (_req, _res, next) => next(),
    createAuditLog: async () => {},
  },
};
require.cache[require.resolve('../utils/rlsContext')] = {
  id: 'rls-stub', filename: 'rls-stub', loaded: true,
  exports: { withRequestOrgContext: (_req, fn) => fn(txStub), withUserContext: (_u, fn) => fn(txStub), withOrgContext: (_o, _u, fn) => fn(txStub), setOrgContext: async () => {} },
};

const { API_KEY_SCOPES, generateApiKey, hashApiKey } = require('../utils/apiKeys');
const { authenticateRequest } = require('../middleware/apiKeyAuth');

function makeRes() {
  const res = { statusCode: 200, body: undefined };
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (b) => { res.body = b; return res; };
  return res;
}
async function runMiddleware(mw, req) {
  const res = makeRes();
  let nexted = false;
  await mw(req, res, () => { nexted = true; });
  return { res, nexted };
}
function keyReq(key, { method = 'GET', path = '/' } = {}) {
  return { method, path, headers: { 'x-api-key': key } };
}
function seedKey({ scopes = ['read'], revokedAt = null, expiresAt = null, organizationId = 1, userId = 7 } = {}) {
  const { key, keyPrefix, keyHash } = generateApiKey();
  const row = { id: nextId++, organizationId, userId, name: 'ci', keyPrefix, keyHash, scopes, lastUsedAt: null, expiresAt, revokedAt, createdAt: new Date() };
  KEYS.push(row);
  return { key, row };
}

// ── utils ────────────────────────────────────────────────────────────────
test('apiKeys utils: key format, prefix, hash round-trip', () => {
  const a = generateApiKey();
  const b = generateApiKey();
  assert.match(a.key, /^sg_[0-9a-f]{48}$/);
  assert.equal(a.keyPrefix, a.key.slice(0, 12));
  assert.equal(a.keyHash, crypto.createHash('sha256').update(a.key).digest('hex'));
  assert.equal(a.keyHash.length, 64);
  assert.notEqual(a.key, b.key);
  assert.deepEqual(API_KEY_SCOPES, ['read', 'scan:trigger']);
});

// ── middleware ───────────────────────────────────────────────────────────
test('apiKeyAuth: valid read key passes GET and pins org + creator', async () => {
  const { key } = seedKey({ scopes: ['read'] });
  const { res, nexted } = await runMiddleware(authenticateRequest(), keyReq(key));
  assert.equal(nexted, true);
  assert.equal(res.statusCode, 200);
});

test('apiKeyAuth: read-only key cannot trigger a scan (403), trigger scope can', async () => {
  const read = seedKey({ scopes: ['read'] });
  const r1 = await runMiddleware(authenticateRequest({ allowTrigger: true }), keyReq(read.key, { method: 'POST', path: '/trigger' }));
  assert.equal(r1.nexted, false);
  assert.equal(r1.res.statusCode, 403);
  const trig = seedKey({ scopes: ['read', 'scan:trigger'] });
  const r2 = await runMiddleware(authenticateRequest({ allowTrigger: true }), keyReq(trig.key, { method: 'POST', path: '/trigger' }));
  assert.equal(r2.nexted, true);
});

test('apiKeyAuth: revoked, expired and unknown keys are 401; other writes are 403', async () => {
  const revoked = seedKey({ revokedAt: new Date() });
  assert.equal((await runMiddleware(authenticateRequest(), keyReq(revoked.key))).res.statusCode, 401);
  const expired = seedKey({ expiresAt: new Date(Date.now() - 1000) });
  assert.equal((await runMiddleware(authenticateRequest(), keyReq(expired.key))).res.statusCode, 401);
  assert.equal((await runMiddleware(authenticateRequest(), keyReq('sg_' + '0'.repeat(48)))).res.statusCode, 401);
  const read = seedKey({ scopes: ['read', 'scan:trigger'] });
  const w = await runMiddleware(authenticateRequest({ allowTrigger: true }), keyReq(read.key, { method: 'POST', path: '/api-spec' }));
  assert.equal(w.res.statusCode, 403);
  const p = await runMiddleware(authenticateRequest(), keyReq(read.key, { method: 'PATCH', path: '/5/status' }));
  assert.equal(p.res.statusCode, 403);
});

test('apiKeyAuth: no key header falls through to JWT auth', async () => {
  const req = { method: 'GET', path: '/', headers: {} };
  const { nexted } = await runMiddleware(authenticateRequest(), req);
  assert.equal(nexted, true);
  assert.equal(req.userId, 7); // set by the JWT stub
});

// ── management routes ────────────────────────────────────────────────────
// The router is mounted at / in a throwaway app, so paths here are the
// router-relative ones ('/', '/:id') — not the /api/api-keys mount point.
async function invoke(route, req) {
  // Express Router.handle via a one-off app-less dispatch: call the layer
  // stack by mounting the router on a throwaway express app.
  const express = require('express');
  const app = express();
  app.use(express.json());
  app.use(route);
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const port = server.address().port;
      const http = require('node:http');
      const payload = req.body !== undefined ? JSON.stringify(req.body) : undefined;
      const headers = { 'Content-Type': 'application/json', ...(req.headers || {}) };
      const r = http.request({ port, path: req.path, method: req.method, headers }, (resp) => {
        let data = '';
        resp.on('data', (c) => { data += c; });
        resp.on('end', () => { server.close(() => resolve({ status: resp.statusCode, body: JSON.parse(data || 'null') })); });
      });
      r.on('error', (e) => { server.close(() => reject(e)); });
      if (payload) r.write(payload);
      r.end();
    });
  });
}

test('apiKeys routes: create returns key once and stores only the hash; list strips it; revoke works', async () => {
  const router = require('../routes/apiKeys');
  const created = await invoke(router, { method: 'POST', path: '/', body: { name: 'ci-key', scopes: ['read'] } });
  assert.equal(created.status, 201);
  assert.match(created.body.key, /^sg_[0-9a-f]{48}$/);
  assert.equal(created.body.keyHash, undefined);
  const stored = KEYS.find((k) => k.keyPrefix === created.body.keyPrefix);
  assert.equal(stored.keyHash, crypto.createHash('sha256').update(created.body.key).digest('hex'));
  assert.equal(stored.key, undefined);

  const listed = await invoke(router, { method: 'GET', path: '/' });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.some((k) => k.keyHash), false);
  assert.equal(listed.body.some((k) => k.key), false);

  const revoked = await invoke(router, { method: 'DELETE', path: `/${stored.id}` });
  assert.equal(revoked.status, 200);
  assert.ok(revoked.body.revokedAt);
  assert.equal(KEYS.find((k) => k.id === stored.id).revokedAt instanceof Date, true);

  const missing = await invoke(router, { method: 'DELETE', path: '/99999' });
  assert.equal(missing.status, 404);
});

test('apiKeys routes: bad name and empty scopes are 400', async () => {
  const router = require('../routes/apiKeys');
  const badName = await invoke(router, { method: 'POST', path: '/', body: { name: '', scopes: ['read'] } });
  assert.equal(badName.status, 400);
  const badScope = await invoke(router, { method: 'POST', path: '/', body: { name: 'x', scopes: ['admin'] } });
  assert.equal(badScope.status, 400);
});
