'use strict';

// Day 6 — shared validation on the auth routes (SEC-18 / SEC-22).
// register, login, resend-verification, forgot-password, reset-password
// and delete-account now run through validateBody with zod schemas
// (utils/validation.js) instead of inline presence/length checks. These
// tests prove the wiring rejects bad shapes with 400 AND that accepted
// behaviour is unchanged: a short login password still answers "Invalid
// credentials" (login deliberately does NOT use zPassword), unknown
// emails on forgot-password still get the generic 200, and a mistyped
// DELETE confirmation still 400s. Offline: same in-memory prisma stub
// and stubbed Brevo fetch as authEmailNormalization.test.js. Run:
//   node --test backend/tests/authValidation.test.js
// from SecureGaurd-main. (Separate file because the shared authLimiter
// budget is 10 requests per IP — authVerification.test.js and
// authEmailNormalization.test.js already use all 10 in their processes.)

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.FRONTEND_URL = 'http://localhost:5173';
process.env.BREVO_API_KEY = 'stubbed-brevo-key';

// ── In-memory prisma stub (same shape as authEmailNormalization.test.js) ──
const users = [];
let nextId = 1;

function matchesWhere(row, where) {
  if (!where) return true;
  return Object.entries(where).every(([key, cond]) => {
    if (cond && typeof cond === 'object' && !(cond instanceof Date)) {
      if ('gt' in cond) return row[key] > cond.gt;
      if ('equals' in cond) {
        return cond.mode === 'insensitive'
          ? String(row[key]).toLowerCase() === String(cond.equals).toLowerCase()
          : row[key] === cond.equals;
      }
      return false;
    }
    return row[key] === cond;
  });
}

const prismaStub = {
  user: {
    findUnique: async ({ where }) => users.find((u) => matchesWhere(u, where)) || null,
    findFirst: async ({ where }) => users.find((u) => matchesWhere(u, where)) || null,
    create: async ({ data }) => {
      const user = { id: nextId++, refreshToken: null, previousRefreshToken: null, refreshGraceExpiresAt: null, passwordResetToken: null, passwordResetExpiry: null, isEmailVerified: false, onboardingCompleted: false, emailVerifyToken: null, emailVerifyTokenExpiresAt: null, createdAt: new Date(), ...data };
      users.push(user);
      return { ...user };
    },
    update: async ({ where, data }) => {
      const user = users.find((u) => u.id === where.id);
      assert.ok(user, 'stub update: user must exist');
      Object.assign(user, data);
      return { ...user };
    },
    updateMany: async ({ where, data }) => {
      const user = users.find((u) => u.id === where.id && (where.refreshToken === undefined || u.refreshToken === where.refreshToken));
      if (!user) return { count: 0 };
      Object.assign(user, data);
      return { count: 1 };
    },
    delete: async ({ where }) => {
      const i = users.findIndex((u) => u.id === where.id);
      assert.ok(i >= 0, 'stub delete: user must exist');
      return users.splice(i, 1)[0];
    },
  },
  subscription: { findUnique: async () => null },
  $transaction: async (fn) => fn(prismaStub),
};

const prismaId = require.resolve('../prismaClient');
require.cache[prismaId] = { id: prismaId, filename: prismaId, loaded: true, exports: prismaStub };

// ── Stubbed Brevo fetch ────────────────────────────────────────────────────
const nodeFetch = global.fetch;
global.fetch = async (url, opts) => {
  if (typeof url === 'string' && url.startsWith('https://api.brevo.com/')) {
    return { ok: true, json: async () => ({ messageId: 'stubbed-id' }) };
  }
  return nodeFetch(url, opts);
};

const authRouter = require('../routes/auth');

let server;
let base;
test.before(async () => {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use('/api/auth', authRouter);
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => server.close());

async function req(method, path, body, extraHeaders = {}) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
const post = (path, body, headers) => req('POST', path, body, headers);
const del = (path, body, headers) => req('DELETE', path, body, headers);

const VALID_REGISTER = { firstName: 'Val', lastName: 'Idation', email: 'validation@example.com', password: 'password123' };

test('register rejects a missing field, a short password, a bad email, an over-long password', async () => {
  const missing = await post('/api/auth/register', { firstName: 'Val', email: 'a@example.com', password: 'password123' });
  assert.equal(missing.status, 400);
  const short = await post('/api/auth/register', { ...VALID_REGISTER, password: 'short' });
  assert.equal(short.status, 400);
  const badEmail = await post('/api/auth/register', { ...VALID_REGISTER, email: 'not-an-email' });
  assert.equal(badEmail.status, 400);
  const long = await post('/api/auth/register', { ...VALID_REGISTER, email: 'other@example.com', password: 'x'.repeat(129) });
  assert.equal(long.status, 400);
});

test('register accepts valid input (201) — wiring did not break the happy path', async () => {
  const { status, body } = await post('/api/auth/register', VALID_REGISTER);
  assert.equal(status, 201);
  assert.equal(body.requiresVerification, true);
  assert.equal(users.find((u) => u.email === 'validation@example.com').firstName, 'Val');
});

test('login rejects a missing password and a malformed email', async () => {
  const missing = await post('/api/auth/login', { email: 'validation@example.com' });
  assert.equal(missing.status, 400);
  const badEmail = await post('/api/auth/login', { email: 'not-an-email', password: 'password123' });
  assert.equal(badEmail.status, 400);
});

test('login with a short but present password still answers "Invalid credentials"', async () => {
  // Behaviour preservation: login must NOT apply zPassword's 8-char
  // floor — a short password is a wrong password, not a shape error.
  const { status, body } = await post('/api/auth/login', { email: 'validation@example.com', password: 'short' });
  assert.equal(status, 400);
  assert.equal(body.message, 'Invalid credentials');
});

test('resend-verification rejects a missing or malformed email', async () => {
  assert.equal((await post('/api/auth/resend-verification', {})).status, 400);
  assert.equal((await post('/api/auth/resend-verification', { email: 'not-an-email' })).status, 400);
});

test('forgot-password rejects a missing or malformed email', async () => {
  assert.equal((await post('/api/auth/forgot-password', {})).status, 400);
  assert.equal((await post('/api/auth/forgot-password', { email: 'not-an-email' })).status, 400);
});

test('forgot-password still answers the generic 200 for an unknown email', async () => {
  const { status, body } = await post('/api/auth/forgot-password', { email: 'nobody@example.com' });
  assert.equal(status, 200);
  assert.match(body.message, /If that email exists/);
});

test('reset-password rejects a missing token and a short new password', async () => {
  assert.equal((await post('/api/auth/reset-password', { newPassword: 'newpassword123' })).status, 400);
  assert.equal((await post('/api/auth/reset-password', { token: 'abc', newPassword: 'short' })).status, 400);
});

test('delete-account rejects a wrong confirmation and a missing password', async () => {
  // validateBody runs after authMiddleware here, so both requests carry
  // a signed Bearer token; the 400s come from the schema, before the
  // handler (and its destructive path) ever runs.
  const token = jwt.sign({ id: 1 }, process.env.JWT_SECRET, { algorithm: 'HS256' });
  const auth = { Authorization: `Bearer ${token}` };
  const wrong = await del('/api/auth/account', { password: 'password123', confirmation: 'delete' }, auth);
  assert.equal(wrong.status, 400);
  const missing = await del('/api/auth/account', { confirmation: 'DELETE' }, auth);
  assert.equal(missing.status, 400);
});

test('verify-email POST still rejects a missing token (handler check, not a schema)', async () => {
  const { status } = await post('/api/auth/verify-email', {});
  assert.equal(status, 400);
});

test('authLimiter trips after 10 attempts in this process (limiter is mounted, not decorative)', async () => {
  // This test MUST stay last: it spends the process's shared authLimiter
  // budget (10/15 min). The 8 login/register hits above leave exactly
  // 2: the first two attempts answer 400 (shape), the rest 429.
  const statuses = [];
  for (let i = 0; i < 11; i++) {
    const { status } = await post('/api/auth/login', { email: 'not-an-email', password: 'password123' });
    statuses.push(status);
  }
  assert.deepEqual(statuses.slice(0, 2), [400, 400]);
  assert.equal(statuses[10], 429);
  assert.ok(statuses.slice(2).every((s) => s === 429), `expected 429s after the budget, got ${statuses}`);
});
