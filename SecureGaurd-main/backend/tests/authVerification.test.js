'use strict';

// SEC-09 / SEC-17 / SEC-38 — email-verification gate, session-endpoint
// rate limiters, change-password. Offline: the real auth router runs
// against an in-memory prisma stub (require.cache) and a stubbed Brevo
// fetch, so no DB, no mail and no network are touched. Run:
//   node --test backend/tests/authVerification.test.js
// from SecureGaurd-main.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.FRONTEND_URL = 'http://localhost:5173';

// ── In-memory prisma stub ──────────────────────────────────────────────────
const users = [];
let nextId = 1;

function matchesWhere(row, where) {
  if (!where) return true;
  return Object.entries(where).every(([key, cond]) => {
    if (cond && typeof cond === 'object' && !(cond instanceof Date)) {
      if ('gt' in cond) return row[key] > cond.gt;
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

// Install the stub BEFORE requiring the router (its import chain also
// pulls routes/organizations, which requires the same prismaClient).
const prismaId = require.resolve('../prismaClient');
require.cache[prismaId] = { id: prismaId, filename: prismaId, loaded: true, exports: prismaStub };

// ── Stubbed Brevo fetch ────────────────────────────────────────────────────
// Only the Brevo API URL is stubbed; everything else (incl. the test
// server on localhost) goes through the real fetch.
const nodeFetch = global.fetch;
const sentMails = [];
let lastMailBody = null;
global.fetch = async (url, opts) => {
  if (typeof url === 'string' && url.startsWith('https://api.brevo.com/')) {
    lastMailBody = JSON.parse(opts.body);
    sentMails.push(url);
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

test('register without a configured mailer fails honestly and creates nobody', async () => {
  delete process.env.BREVO_API_KEY;
  const before = users.length;
  const { status, body } = await post('/api/auth/register', {
    firstName: 'No', lastName: 'Mail', email: 'nomail@example.com', password: 'password123',
  });
  assert.equal(status, 503);
  assert.match(body.message, /not configured/);
  assert.equal(users.length, before);
});

test('register issues no session and mails a frontend verification link', async () => {
  process.env.BREVO_API_KEY = 'stubbed-brevo-key';
  const { status, body } = await post('/api/auth/register', {
    firstName: 'Vera', lastName: 'Fied', email: 'vera@example.com', password: 'password123',
  });
  assert.equal(status, 201);
  assert.equal(body.requiresVerification, true);
  assert.equal(body.accessToken, undefined);
  const row = users.find((u) => u.email === 'vera@example.com');
  assert.ok(row);
  assert.equal(row.isEmailVerified, false);
  assert.ok(row.emailVerifyToken, 'hashed token stored');
  assert.ok(lastMailBody.htmlContent.includes('/verify-email?token='), 'link points at the frontend page');
  assert.ok(!lastMailBody.htmlContent.includes('/api/auth/verify-email'), 'link does not point at the raw API');
});

test('login before verification is gated with a resendable code', async () => {
  const { status, body } = await post('/api/auth/login', { email: 'vera@example.com', password: 'password123' });
  assert.equal(status, 403);
  assert.equal(body.code, 'email_not_verified');
  assert.equal(body.accessToken, undefined);
});

test('verify-email consumes the token, then login succeeds', async () => {
  const rawToken = lastMailBody.htmlContent.match(/verify-email\?token=([a-f0-9]+)/)[1];
  const { status } = await post('/api/auth/verify-email', { token: rawToken });
  assert.equal(status, 200);
  const row = users.find((u) => u.email === 'vera@example.com');
  assert.equal(row.isEmailVerified, true);
  assert.equal(row.emailVerifyToken, null);
  const login = await post('/api/auth/login', { email: 'vera@example.com', password: 'password123' });
  assert.equal(login.status, 200);
  assert.ok(login.body.accessToken);
  // Replaying the consumed token fails.
  const replay = await post('/api/auth/verify-email', { token: rawToken });
  assert.equal(replay.status, 400);
});

test('resend-verification is generic for unknown emails (no enumeration)', async () => {
  const sentBefore = sentMails.length;
  const { status, body } = await post('/api/auth/resend-verification', { email: 'nobody@example.com' });
  assert.equal(status, 200);
  assert.match(body.message, /If that email/);
  assert.equal(sentMails.length, sentBefore, 'no mail sent for an unknown email');
});

test('legacy account without a pending token is grandfathered (login works)', async () => {
  // Pre-gate account: verified flag false, but NO token was ever issued.
  await prismaStub.user.create({
    data: { firstName: 'Old', lastName: 'Timer', email: 'old@example.com', password: require('bcryptjs').hashSync('password123', 12), emailVerifyToken: null, isEmailVerified: false },
  });
  const { status, body } = await post('/api/auth/login', { email: 'old@example.com', password: 'password123' });
  assert.equal(status, 200);
  assert.ok(body.accessToken);
});

test('change-password requires the current password and invalidates the old one', async () => {
  const login = await post('/api/auth/login', { email: 'vera@example.com', password: 'password123' });
  assert.equal(login.status, 200);
  const bearer = { Authorization: `Bearer ${login.body.accessToken}` };
  const wrong = await post('/api/auth/change-password', { currentPassword: 'nope-nope-nope', newPassword: 'newpassword123' }, bearer);
  assert.equal(wrong.status, 401);
  const ok = await post('/api/auth/change-password', { currentPassword: 'password123', newPassword: 'newpassword123' }, bearer);
  assert.equal(ok.status, 200);
  const oldLogin = await post('/api/auth/login', { email: 'vera@example.com', password: 'password123' });
  assert.equal(oldLogin.status, 400);
  const newLogin = await post('/api/auth/login', { email: 'vera@example.com', password: 'newpassword123' });
  assert.equal(newLogin.status, 200);
});

test('/refresh and /me without a session cookie are 401 (limiters attached)', async () => {
  const refresh = await post('/api/auth/refresh', {});
  assert.equal(refresh.status, 401);
  const me = await fetch(`${base}/api/auth/me`);
  assert.equal(me.status, 401);
});
