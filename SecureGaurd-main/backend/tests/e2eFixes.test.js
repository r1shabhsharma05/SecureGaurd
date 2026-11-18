'use strict';

// E2E fix-batch regressions (19 Nov 2026). Offline: no Redis, no Postgres.
// Run: node --test backend/tests/e2eFixes.test.js
//   from SecureGaurd-main.
const test = require('node:test');
const assert = require('node:assert/strict');

delete process.env.REDIS_URL;

// ── In-memory rows for the vuln-list route test ───────────────────────────
const ROWS = [
  { id: 1, severity: 'critical', status: 'open', title: 'SQLi a', filePath: 'a.js', lineStart: 1, createdAt: new Date('2026-11-19T01:00:00Z'), scanId: 2 },
  { id: 2, severity: 'high', status: 'open', title: 'XSS', filePath: 'b.js', lineStart: 5, createdAt: new Date('2026-11-19T01:01:00Z'), scanId: 2 },
  { id: 3, severity: 'critical', status: 'open', title: 'SQLi b', filePath: 'a.js', lineStart: 9, createdAt: new Date('2026-11-19T01:02:00Z'), scanId: 2 },
  { id: 4, severity: 'medium', status: 'open', title: 'Weak crypto', filePath: 'c.js', lineStart: 3, createdAt: new Date('2026-11-19T01:03:00Z'), scanId: 2 },
  { id: 5, severity: 'critical', status: 'fixed', title: 'SQLi fixed', filePath: 'a.js', lineStart: 1, createdAt: new Date('2026-10-19T01:00:00Z'), scanId: 1 },
  { id: 6, severity: 'high', status: 'fixed', title: 'XSS fixed', filePath: 'b.js', lineStart: 5, createdAt: new Date('2026-10-19T01:01:00Z'), scanId: 1 },
];

function matchVulnRow(row, where = {}) {
  if (!where) return true;
  if (where.scan && where.scan.organizationId !== undefined && where.scan.organizationId !== 1) return false;
  if (where.severity && row.severity !== where.severity) return false;
  if (where.status && row.status !== where.status) return false;
  if (where.scanId !== undefined && row.scanId !== where.scanId) return false;
  return true;
}

const txStub = {
  $executeRaw: async () => [],
  $queryRaw: async () => [],
  vulnerability: {
    findMany: async (args = {}) => {
      const rows = ROWS.filter((r) => matchVulnRow(r, args.where)).map((r) => ({
        ...r,
        scan: { id: r.scanId, repository: { id: 1, name: 'sg', fullName: 'r/sg', platform: 'github', language: 'TypeScript' } },
      }));
      return rows;
    },
  },
  subscription: {
    findUnique: async () => txStub._sub,
  },
};
const prismaStub = {
  ...txStub,
  $transaction: async (fn) => fn(txStub),
  $connect: async () => {},
  $disconnect: async () => {},
};

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

function fakeRedis() {
  const store = new Map();
  return {
    store,
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async set(k, v) { store.set(k, v); return 'OK'; },
    async del(...ks) { let n = 0; for (const k of ks) if (store.delete(k)) n++; return n; },
    async scan(cursor, ...args) {
      const match = args[args.indexOf('MATCH') + 1];
      const prefix = match.replace(/\*$/, '');
      return ['0', [...store.keys()].filter((k) => k.startsWith(prefix))];
    },
    on() {},
  };
}
require('../utils/redis').__setCacheClient(fakeRedis());

const { dedupeFindings } = require('../utils/findingDedup');
const { evaluateCompliance } = require('../services/complianceEngine');
const { getOrgPlan } = require('../services/billingService');
const { buildAnalyticsSummary } = require('../utils/analyticsSummary');

const express = require('express');
const app = express();
app.use(express.json());
app.use('/api/vulnerabilities', require('../routes/vulnerabilities'));

async function getVulns(query) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, async () => {
      const port = server.address().port;
      try {
        const res = await fetch(`http://127.0.0.1:${port}/api/vulnerabilities${query}`);
        const body = await res.json();
        resolve({ status: res.status, total: res.headers.get('x-total-count'), body });
      } catch (e) { reject(e); } finally { server.close(); }
    });
  });
}

// ── Dedup ──────────────────────────────────────────────────────────────────
test('dedupe: same rule+file+line already open is skipped, a different line is kept', () => {
  const findings = [
    { ruleId: 'SAST-001', filePath: 'a.js', lineStart: 1 },
    { ruleId: 'SAST-001', filePath: 'a.js', lineStart: 9 },
    { ruleId: 'SAST-002', filePath: 'a.js', lineStart: 1 },
  ];
  const open = [{ ruleId: 'SAST-001', filePath: 'a.js', lineStart: 1 }];
  const fresh = dedupeFindings(findings, open);
  assert.equal(fresh.length, 2);
  assert.deepEqual(fresh.map((f) => f.lineStart), [9, 1]);
});

test('dedupe: a fixed finding re-appearing in a re-scan is re-inserted', () => {
  // Only OPEN rows are passed in as alreadyOpen — a fixed row is absent,
  // so the same triple comes back as fresh.
  const fresh = dedupeFindings(
    [{ ruleId: 'SAST-001', filePath: 'a.js', lineStart: 1 }],
    []
  );
  assert.equal(fresh.length, 1);
});

// ── Compliance: ignored counts as resolved ─────────────────────────────────
test('compliance: an ignored finding counts as resolved, not open', () => {
  const out = evaluateCompliance({
    framework: 'SOC2',
    vulnerabilities: [
      { id: 1, status: 'ignored', severity: 'critical', cweId: 'CWE-89', type: 'sast', title: 'SQLi', filePath: 'a.js', lineStart: 1 },
    ],
    repository: { id: 1, name: 'sg', fullName: 'r/sg', platform: 'github' },
    reportName: 'test',
  });
  assert.equal(out.summary.totalFindings, 0);
  assert.ok(out.controls.some((c) => String(c.evidence || '').includes('previously identified finding(s) have been successfully remediated or resolved')));
});

// ── Billing: expired period is not a paid plan ─────────────────────────────
test('billing: active PRO row past its period end resolves to FREE', async () => {
  txStub._sub = { organizationId: 1, plan: 'PRO', status: 'active', currentPeriodEnd: new Date('2026-11-01T00:00:00Z') };
  const plan = await getOrgPlan(1, txStub);
  assert.equal(plan.name, 'Free');
});

test('billing: active PRO row inside its period stays PRO', async () => {
  txStub._sub = { organizationId: 1, plan: 'PRO', status: 'active', currentPeriodEnd: new Date('2027-11-01T00:00:00Z') };
  const plan = await getOrgPlan(1, txStub);
  assert.equal(plan.name, 'Pro');
});

// ── Analytics: probe/404 paths are not "most visited pages" ───────────────
test('analytics: topPaths excludes probe and 404 paths', async () => {
  const db = {
    user: { count: async () => 0, findMany: async () => [] },
    scan: { count: async () => 0, findMany: async () => [] },
    vulnerability: { count: async () => 0 },
    contactMessage: { count: async () => 0 },
    analyticsEvent: {
      count: async () => 0,
      groupBy: async ({ by }) => {
        if (by[0] === 'event') return [];
        return [
          { path: '/dashboard', _count: { path: 5 } },
          { path: '/__day8_probe__', _count: { path: 9 } },
          { path: '/this-page-does-not-exist-123', _count: { path: 7 } },
          { path: '/vulnerabilities/68', _count: { path: 3 } },
        ];
      },
    },
  };
  const from = new Date('2026-11-01T00:00:00Z');
  const to = new Date('2026-11-19T00:00:00Z');
  const summary = await buildAnalyticsSummary(db, { from, to, days: 19 });
  assert.deepEqual(summary.topPaths.map((p) => p.path), ['/dashboard', '/vulnerabilities/68']);
});

// ── Vuln list: canonical definition ────────────────────────────────────────
test('vuln list: no ?status= means open only, severity-ranked, with X-Total-Count', async () => {
  const { status, total, body } = await getVulns('');
  assert.equal(status, 200);
  assert.equal(total, '4');
  assert.deepEqual(body.map((v) => v.id), [1, 3, 2, 4]); // critical, critical, high, medium — not alphabetical
});

test('vuln list: ?status=fixed returns only fixed rows; ?page&limit paginates', async () => {
  const fixed = await getVulns('?status=fixed');
  assert.deepEqual(fixed.body.map((v) => v.id), [5, 6]);
  const page = await getVulns('?page=2&limit=2');
  assert.equal(page.total, '4');
  assert.deepEqual(page.body.map((v) => v.id), [2, 4]);
});

test('vuln list: ?status=all returns every status', async () => {
  const all = await getVulns('?status=all');
  assert.equal(all.total, '6');
  assert.equal(all.body.length, 6);
});
