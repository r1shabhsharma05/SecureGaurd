'use strict';
// Scan performance harness — measures the REAL trigger path end to end.
// Run from SecureGaurd-main:
//   SCAN_LOCAL_BASE=/home/hatch/workspace/tmp-work/scan-fixtures \
//   node backend/tests/scanPerfHarness.js [before|after] [single|concurrent100|cache]
//
// How it works: the prisma client, auth, RBAC and billing are stubbed in
// the require cache (same pattern as backend/tests/rbac.test.js), so no
// Postgres is needed. The scan itself is REAL: runSecurityScan walks the
// fixture repo on disk, the classifier is unreachable (FP_CLASSIFIER_URL
// points at a closed port, so findings keep the fail-safe REAL verdict),
// and SBOM generation runs for real. What is NOT real here: DB roundtrips
// (in-memory stub) and the classifier (unreachable by design).
// MODE=before: POST /trigger blocks until the scan finishes (current code).
// MODE=after:  POST /trigger returns 202; the harness polls GET /:id until
//   terminal and records submit latency + turnaround separately.

const path = require('path');

const MODE = process.argv[2] || 'before';
const SCENARIO = process.argv[3] || 'single';
const FIXTURE_BASE = process.env.SCAN_LOCAL_BASE || '/home/hatch/workspace/tmp-work/scan-fixtures';
const FIXTURE_REPO = path.join(FIXTURE_BASE, 'small-repo');
const OUT = process.env.HARNESS_OUT || `/home/hatch/workspace/goals/securegaurd-20-day-transformation/hidden_files/scan-perf-${MODE}-${SCENARIO}-2026-11-19.json`;

process.env.FP_CLASSIFIER_URL = 'http://127.0.0.1:9'; // closed port: instant refuse
process.env.SCAN_LOCAL_BASE = FIXTURE_BASE;
process.env.ENCRYPTION_KEY = 'aa'.repeat(32); // dummy 64-hex key: lets the scan-alert path load in the harness
if (MODE === 'after') process.env.REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6390';

// ── In-memory DB ──────────────────────────────────────────────────────────
const db = {
  scans: [],
  vulnerabilities: [],
  repositories: [{
    id: 1, organizationId: 1, name: 'fixture', fullName: 'fixture/small-repo',
    platform: 'github', url: FIXTURE_REPO, riskLevel: 'low',
  }],
  customRules: [],
  sboms: [],
  auditLogs: [],
  memberships: [{ userId: 7, organizationId: 1, role: 'ADMIN' }],
};
let nextScanId = 1;
let nextVulnId = 1;

function matchValue(rowVal, cond) {
  if (cond && typeof cond === 'object' && !(cond instanceof Date)) {
    if ('not' in cond) return cond.not === null ? rowVal !== null && rowVal !== undefined : rowVal !== cond.not;
    if ('equals' in cond) return rowVal === cond.equals;
    if ('gt' in cond) return rowVal > cond.gt;
    return false;
  }
  return rowVal === cond;
}
function matchRow(row, where) {
  if (!where) return true;
  return Object.entries(where).every(([key, cond]) => {
    if (key === 'scan' && cond && typeof cond === 'object') {
      const scan = db.scans.find((s) => s.id === row.scanId);
      if (!scan) return false;
      return matchRow(scan, cond);
    }
    if (key === 'repository' && cond && typeof cond === 'object') return true; // not used by harness paths
    return matchValue(row[key], cond);
  });
}
function applySelect(row, select) {
  if (!select) return row;
  const out = {};
  for (const k of Object.keys(select)) if (select[k]) out[k] = row[k];
  return out;
}

function makeTx() {
  return {
    $executeRaw: async () => {},
    $queryRaw: async () => [],
    scan: {
      findMany: async (args = {}) => db.scans.filter((s) => matchRow(s, args.where)).slice(0, args.take || 50),
      findFirst: async (args = {}) => db.scans.find((s) => matchRow(s, args.where)) || null,
      create: async ({ data }) => {
        const row = { id: nextScanId++, status: 'queued', branch: 'main', totalFiles: 0, totalLines: 0,
          criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, secretsFound: 0,
          durationMs: 0, startedAt: new Date(), completedAt: null, createdAt: new Date(), ...data };
        db.scans.push(row);
        return row;
      },
      update: async ({ where, data }) => {
        const row = db.scans.find((s) => s.id === where.id);
        Object.assign(row, data);
        return row;
      },
    },
    vulnerability: {
      findMany: async (args = {}) => {
        let rows = db.vulnerabilities.filter((v) => matchRow(v, args.where));
        if (args.orderBy) rows = rows.slice().sort((a, b) => String(a.severity).localeCompare(String(b.severity)));
        return rows.slice(0, args.take || 100).map((v) => {
          const out = { ...v };
          if (args.include && args.include.scan) {
            const s = db.scans.find((x) => x.id === v.scanId);
            out.scan = s ? { id: s.id, repository: { id: 1, name: 'fixture', fullName: 'fixture/small-repo', platform: 'github', language: 'JavaScript' } } : null;
          }
          return out;
        });
      },
      findFirst: async (args = {}) => {
        const v = db.vulnerabilities.find((x) => matchRow(x, args.where)) || null;
        if (!v) return null;
        if (args.select) return applySelect(v, args.select);
        return v;
      },
      count: async (args = {}) => db.vulnerabilities.filter((v) => matchRow(v, args.where)).length,
      createMany: async ({ data }) => {
        for (const d of data) db.vulnerabilities.push({ id: nextVulnId++, status: 'open', createdAt: new Date(), updatedAt: new Date(), ...d });
        return { count: data.length };
      },
      update: async ({ where, data }) => {
        const row = db.vulnerabilities.find((v) => v.id === where.id);
        Object.assign(row, data);
        return row;
      },
    },
    repository: {
      findFirst: async (args = {}) => db.repositories.find((r) => matchRow(r, args.where)) || null,
      update: async ({ where, data }) => {
        const row = db.repositories.find((r) => r.id === where.id);
        Object.assign(row, data);
        return row;
      },
    },
    customRule: { findMany: async () => [] },
    sbom: { create: async ({ data }) => { const row = { id: db.sboms.length + 1, ...data }; db.sboms.push(row); return row; } },
    alertSetting: { findUnique: async () => null }, // no alert settings in harness: alerts stay off
    organization: { findUnique: async () => ({ id: 1, name: 'Fixture Org' }) },
    alertLog: { create: async ({ data }) => data },
    auditLog: { create: async ({ data }) => { db.auditLogs.push(data); return data; } },
    organizationMembership: {
      findMany: async () => db.memberships,
      findUnique: async () => db.memberships[0],
      findFirst: async () => db.memberships[0],
    },
  };
}
const tx = makeTx();
const prismaStub = { ...tx, $transaction: async (fn) => fn(tx), $connect: async () => {}, $disconnect: async () => {} };
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
    createAuditLog: async (orgId, userId, action) => { db.auditLogs.push({ organizationId: orgId, userId, action }); },
  },
};
require.cache[require.resolve('../services/billingService')] = {
  id: 'billing-stub', filename: 'billing-stub', loaded: true,
  exports: { checkCanTriggerScan: async () => ({ allowed: true }) },
};

// Real RLS context over the stubbed prisma ($transaction hands back tx).
const express = require('express');
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use('/api/scans', require('../routes/scans'));
app.use('/api/vulnerabilities', require('../routes/vulnerabilities'));

const fs = require('fs');
function pct(sorted, p) {
  if (!sorted.length) return null;
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
}
function summary(name, values) {
  const s = values.slice().sort((a, b) => a - b);
  return { name, n: s.length, min: s[0], p50: pct(s, 50), p95: pct(s, 95), p99: pct(s, 99), max: s[s.length - 1],
    mean: Math.round(s.reduce((a, b) => a + b, 0) / s.length) };
}

async function triggerOne(ip) {
  const t0 = Date.now();
  const res = await fetch(`http://127.0.0.1:${PORT}/api/scans/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip },
    body: JSON.stringify({ repositoryId: 1 }),
  });
  const submitMs = Date.now() - t0;
  const body = await res.json().catch(() => ({}));
  return { status: res.status, submitMs, submitT0: t0, body };
}
// Turnaround is measured from SUBMIT start to the terminal poll, not
// from the first poll — the worker runs while the 202 is in flight.
async function pollScan(id, submitT0, timeoutMs = 120000) {
  for (;;) {
    const res = await fetch(`http://127.0.0.1:${PORT}/api/scans/${id}`, { headers: { 'X-Forwarded-For': '127.0.0.1' } });
    const scan = await res.json().catch(() => ({}));
    if (scan.status === 'completed' || scan.status === 'failed') return { status: scan.status, turnaroundMs: Date.now() - submitT0, scan };
    if (Date.now() - submitT0 > timeoutMs) return { status: 'poll-timeout', turnaroundMs: Date.now() - submitT0, scan };
    await new Promise((r) => setTimeout(r, 250));
  }
}

let PORT = 0;
async function main() {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  PORT = server.address().port;
  // After-mode: the trigger only enqueues — a worker must actually run
  // the scans, same as server.js starts in production.
  if (MODE === 'after') {
    const { startWorker } = require('../queues/scanQueue');
    await startWorker();
    // The harness DB is in-memory (fresh scan ids every run) but Redis
    // persists: a jobId from a previous run would deduplicate the new
    // job and the scan would sit 'queued' forever. Flush ONLY the local
    // test Redis (port 6390) — never a shared/production one.
    if ((process.env.REDIS_URL || '').includes(':6390')) {
      // One-off client (default queueing): the cache client is lazy with
      // offline queue disabled, so it cannot run the first command itself.
      const Redis = require('ioredis');
      const rc = new Redis(process.env.REDIS_URL);
      await rc.flushdb();
      await rc.quit();
    }
  }
  const result = { mode: MODE, scenario: SCENARIO, fixture: FIXTURE_REPO,
    fixtureFiles: 152, classifier: 'unreachable (127.0.0.1:9, fail-safe REAL)', db: 'in-memory stub (no Postgres roundtrips)' };

  if (SCENARIO === 'cache') {
    // Prime: one completed scan so the vuln list is non-empty.
    const t = await triggerOne('10.0.0.1');
    if (MODE === 'after' && t.body.scan) await pollScan(t.body.scan.id, t.submitT0);
    const lat = [];
    const cacheStates = [];
    for (let i = 0; i < 20; i++) {
      const t0 = Date.now();
      const res = await fetch(`http://127.0.0.1:${PORT}/api/vulnerabilities`, { headers: { 'X-Forwarded-For': '10.0.0.2' } });
      lat.push(Date.now() - t0);
      cacheStates.push(res.headers.get('x-cache') || 'none');
      await res.json().catch(() => ({}));
    }
    result.vulnList = summary('GET /api/vulnerabilities latency ms (20 sequential)', lat);
    result.cacheStates = cacheStates;
    result.hitRate = cacheStates.filter((s) => s === 'HIT').length / cacheStates.length;
    result.vulnRows = db.vulnerabilities.length;
  } else {
    const N = SCENARIO === 'concurrent100' ? 100 : SCENARIO === 'concurrent10' ? 10 : 3;
    const concurrent = SCENARIO.startsWith('concurrent');
    // Warmup (not counted): one trigger to warm require/module caches.
    const w = await triggerOne('10.0.0.250');
    if (MODE === 'after' && w.body.scan) await pollScan(w.body.scan.id, w.submitT0);
    const submitLat = [];
    const turnarounds = [];
    const statuses = [];
    if (concurrent) {
      const t0 = Date.now();
      const jobs = Array.from({ length: N }, (_, i) => triggerOne(`10.1.${Math.floor(i / 250)}.${(i % 250) + 1}`));
      const resps = await Promise.all(jobs);
      result.wallMs = Date.now() - t0;
      for (const r of resps) {
        submitLat.push(r.submitMs);
        statuses.push(r.status);
        if (MODE === 'after' && r.body.scan) {
          const p = await pollScan(r.body.scan.id, r.submitT0);
          turnarounds.push(p.turnaroundMs);
          statuses.push(p.status);
        } else if (MODE === 'before') {
          turnarounds.push(r.submitMs); // sync: response IS the turnaround
        }
      }
    } else {
      for (let i = 0; i < N; i++) {
        const r = await triggerOne(`10.0.0.${10 + i}`);
        submitLat.push(r.submitMs);
        statuses.push(r.status);
        if (MODE === 'after' && r.body.scan) {
          const p = await pollScan(r.body.scan.id, r.submitT0);
          turnarounds.push(p.turnaroundMs);
        } else {
          turnarounds.push(r.submitMs);
        }
      }
    }
    result.submit = summary('POST /api/scans/trigger response ms', submitLat);
    result.turnaround = summary('submit -> scan completed ms', turnarounds);
    result.statuses = statuses;
    result.scansCompleted = db.scans.filter((s) => s.status === 'completed').length;
    result.scansFailed = db.scans.filter((s) => s.status === 'failed').length;
    result.vulnRows = db.vulnerabilities.length;
    const last = db.scans.filter((s) => s.status === 'completed').pop();
    if (last) result.lastScan = { files: last.totalFiles, lines: last.totalLines, durationMs: last.durationMs, critical: last.criticalCount, high: last.highCount, medium: last.mediumCount, low: last.lowCount, secrets: last.secretsFound };
  }

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
  server.close();
  // In after-mode the worker may hold the process open; exit explicitly.
  process.exit(0);
}

main().catch((err) => { console.error(err); process.exit(1); });
