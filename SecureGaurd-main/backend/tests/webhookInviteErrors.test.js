// F-03/F-04 (ARTEX 28 Nov 2026): with the §5 resolver SQL functions
// missing (never applied in prod), invitation inspect/accept and
// unauthenticated webhooks all 500'd — for unknown AND real tokens
// alike. The resolvers now fail closed to null and the webhook verifies
// the shared secret before any DB call, so the documented statuses
// return: unknown token → 404, no/bad webhook signature → 401, valid
// signature + unregistered repo → 404.
// Run: node --test tests/webhookInviteErrors.test.js
// (no DB, no network: prisma is faked to throw exactly like a missing
// SQL function; the secrets below are test-only dummies, never real ones.)
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

process.env.ENCRYPTION_KEY = 'ab'.repeat(32); // dummy, load-time only
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.WEBHOOK_SECRET = 'test-shared-webhook-secret';

// Fake prisma: every resolver query throws "function does not exist" —
// the prod F-03/F-04 state. Handlers must still answer 404/401.
const prismaPath = require.resolve('../prismaClient');
const throwingTx = {
  async $queryRaw() {
    throw new Error('function app_org_id_for_invitation_any(text) does not exist');
  },
  async $executeRaw() { return 1; },
};
require.cache[prismaPath] = {
  exports: { $transaction: async (fn) => fn(throwingTx) },
};

const express = require('express');
const invitationsRouter = require('../routes/invitations');
const integrationRouter = require('../routes/integration');

let base;
let server;

test.before(async () => {
  const app = express();
  // Mirror server.js: capture the raw body for HMAC verification.
  app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
  app.use('/api/invitations', invitationsRouter);
  app.use('/api/integration', integrationRouter);
  server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
});

const UNKNOWN_TOKEN = 'deadbeef'.repeat(8); // 64 hex, matches no invitation
const authHeader = {
  Authorization: `Bearer ${jwt.sign({ id: 43 }, process.env.JWT_SECRET, { algorithm: 'HS256' })}`,
};

test('GET invitation inspect with unknown token → 404, not 500', async () => {
  const res = await fetch(`${base}/api/invitations/${UNKNOWN_TOKEN}`);
  assert.equal(res.status, 404);
  assert.match((await res.json()).message, /Invalid or non-existent invitation/);
});

test('POST invitation accept with unknown token → 404, not 500', async () => {
  const res = await fetch(`${base}/api/invitations/${UNKNOWN_TOKEN}/accept`, {
    method: 'POST',
    headers: { ...authHeader, 'Content-Type': 'application/json' },
    body: '{}',
  });
  assert.equal(res.status, 404);
  assert.match((await res.json()).message, /Invalid or non-existent invitation/);
});

const GITHUB_PAYLOAD = {
  repository: { full_name: 'acme/web' },
  head_commit: { id: 'abc123' },
  ref: 'refs/heads/main',
};

async function postWebhook(platform, body, headers = {}) {
  const raw = JSON.stringify(body);
  return fetch(`${base}/api/integration/webhook/${platform}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: raw,
  });
}

test('github webhook with no signature → 401, not 500', async () => {
  const res = await postWebhook('github', GITHUB_PAYLOAD);
  assert.equal(res.status, 401);
});

test('github webhook with bad signature → 401, not 500', async () => {
  const res = await postWebhook('github', GITHUB_PAYLOAD, {
    'x-hub-signature-256': 'sha256=deadbeef',
  });
  assert.equal(res.status, 401);
});

test('github webhook with valid shared signature + unregistered repo → 404, not 500', async () => {
  const raw = JSON.stringify(GITHUB_PAYLOAD);
  const sig = 'sha256=' + crypto.createHmac('sha256', process.env.WEBHOOK_SECRET)
    .update(Buffer.from(raw)).digest('hex');
  const res = await postWebhook('github', GITHUB_PAYLOAD, { 'x-hub-signature-256': sig });
  assert.equal(res.status, 404);
  assert.match((await res.json()).message, /not registered/);
});

test('gitlab webhook with no token → 401, not 500', async () => {
  const res = await postWebhook('gitlab', {
    project: { path_with_namespace: 'acme/web' },
    checkout_sha: 'abc123',
    ref: 'refs/heads/main',
  });
  assert.equal(res.status, 401);
});
