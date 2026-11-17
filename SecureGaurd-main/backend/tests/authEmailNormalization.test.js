'use strict';

// Day 5 — email normalization (SEC-07). Register/login/forgot-password
// treat the address case-insensitively and ignore stray spaces, so
// `Rishabh@Example.com` at signup and `rishabh@example.com` at login are
// the same account; accounts created before the change keep working via
// a case-insensitive fallback. Offline: same in-memory prisma stub and
// stubbed Brevo fetch as authVerification.test.js. Run:
//   node --test backend/tests/authEmailNormalization.test.js
// from SecureGaurd-main. (Separate file because the shared authLimiter
// budget is 10 requests per IP — authVerification.test.js already uses
// all 10, and node:test runs each file in its own process.)

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');

process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.FRONTEND_URL = 'http://localhost:5173';
process.env.BREVO_API_KEY = 'stubbed-brevo-key';

// ── In-memory prisma stub ──────────────────────────────────────────────────
const users = [];
let nextId = 1;

function matchesWhere(row, where) {
  if (!where) return true;
  return Object.entries(where).every(([key, cond]) => {
    if (cond && typeof cond === 'object' && !(cond instanceof Date)) {
      if ('gt' in cond) return row[key] > cond.gt;
      // Day 5 — the case-insensitive fallback in findUserByEmail.
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
let lastMailBody = null;
global.fetch = async (url, opts) => {
  if (typeof url === 'string' && url.startsWith('https://api.brevo.com/')) {
    lastMailBody = JSON.parse(opts.body);
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

async function post(path, body, extraHeaders = {}) {
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})), headers: res.headers };
}

test('register stores the trimmed lowercase address; login works in any case', async () => {
  const { status, body } = await post('/api/auth/register', {
    firstName: 'Case', lastName: 'Test', email: '  MixedCase@Example.COM ', password: 'password123',
  });
  assert.equal(status, 201);
  assert.equal(body.requiresVerification, true);
  const row = users.find((u) => u.email === 'mixedcase@example.com');
  assert.ok(row, 'stored trimmed + lowercase');
  assert.equal(users.filter((u) => u.email.toLowerCase() === 'mixedcase@example.com').length, 1, 'one account, not two');
  assert.equal(lastMailBody.to[0].email, 'mixedcase@example.com', 'verification mail goes to the canonical address');

  // Full flow: verify with the mailed token, then log in in another case.
  const rawToken = lastMailBody.htmlContent.match(/verify-email\?token=([a-f0-9]+)/)[1];
  const verified = await post('/api/auth/verify-email', { token: rawToken });
  assert.equal(verified.status, 200);
  const login = await post('/api/auth/login', { email: 'MIXEDCASE@EXAMPLE.COM', password: 'password123' });
  assert.equal(login.status, 200);
  assert.ok(login.body.accessToken);
});

test('pre-normalization mixed-case account still logs in, in any case', async () => {
  await prismaStub.user.create({
    data: { firstName: 'Mixed', lastName: 'Legacy', email: 'LegacyMixed@Example.com', password: bcrypt.hashSync('password123', 12), emailVerifyToken: null, isEmailVerified: true },
  });
  const { status, body } = await post('/api/auth/login', { email: 'legacymixed@example.com', password: 'password123' });
  assert.equal(status, 200);
  assert.ok(body.accessToken);
});

test('forgot-password finds the account in any case and mails the stored address', async () => {
  const { status } = await post('/api/auth/forgot-password', { email: 'MIXEDCASE@EXAMPLE.COM' });
  assert.equal(status, 200);
  assert.equal(lastMailBody.to[0].email, 'mixedcase@example.com');
});

test('register rejects a differently-cased duplicate of an existing account', async () => {
  const { status, body } = await post('/api/auth/register', {
    firstName: 'Dup', lastName: 'Licate', email: 'MixedCase@example.com', password: 'password123',
  });
  assert.equal(status, 400);
  assert.match(body.message, /already exists/);
  assert.equal(users.filter((u) => u.email.toLowerCase() === 'mixedcase@example.com').length, 1);
});
