/**
 * Day 9 — unit verification (no network, no database, except where a test
 * explicitly injects a stubbed fetch/DB).
 * Proves the pure pieces the Day-9 routes depend on:
 *  - Turnstile token extraction + siteverify handling (pass / fail /
 *    Cloudflare error / missing token / unconfigured secret),
 *  - account-deletion handoff planner (transfer / delete / leave rules),
 *  - analytics summary range parsing + daily bucketing + aggregates,
 *  - Sentry init is inert without a DSN.
 * The REAL Cloudflare siteverify call (test secret + dummy token) is
 * proven separately by hidden_files/day9_turnstile_live.py — this file
 * must stay offline so the suite runs anywhere.
 */
const assert = require('assert');
const {
  extractTurnstileToken,
  verifyTurnstileToken,
  isTurnstileConfigured,
} = require('../utils/turnstile');
const { planAccountDeletion } = require('../utils/accountDeletion');
const { parseSummaryRange, buildAnalyticsSummary } = require('../utils/analyticsSummary');
const { initSentry } = require('../utils/sentry');

let passed = 0, total = 0;
function test(name, fn) {
  total++;
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; console.log(`  ✓ PASS: ${name}`); })
    .catch((e) => { console.error(`  ✗ FAIL: ${name}\n    ${e.message}`); });
}

async function main() {
  console.log('\n=== Day 9: turnstile + account deletion + analytics unit verification ===\n');

  await test('turnstile: token extraction prefers turnstileToken, falls back to cf-turnstile-response', () => {
    assert.strictEqual(extractTurnstileToken({ turnstileToken: 'abc', 'cf-turnstile-response': 'xyz' }), 'abc');
    assert.strictEqual(extractTurnstileToken({ 'cf-turnstile-response': 'xyz' }), 'xyz');
    assert.strictEqual(extractTurnstileToken({ turnstileToken: '  ' }), null);
    assert.strictEqual(extractTurnstileToken({}), null);
    assert.strictEqual(extractTurnstileToken(null), null);
  });

  await test('turnstile: siteverify success passes, failure returns error codes', async () => {
    const okFetch = async () => ({ ok: true, json: async () => ({ success: true }) });
    const r1 = await verifyTurnstileToken('tok', { secret: 's', fetchImpl: okFetch });
    assert.strictEqual(r1.ok, true);
    const failFetch = async () => ({ ok: true, json: async () => ({ success: false, 'error-codes': ['timeout-or-duplicate'] }) });
    const r2 = await verifyTurnstileToken('tok', { secret: 's', fetchImpl: failFetch });
    assert.strictEqual(r2.ok, false);
    assert.deepStrictEqual(r2.errorCodes, ['timeout-or-duplicate']);
  });

  await test('turnstile: missing token fails closed, Cloudflare 5xx throws, no secret throws', async () => {
    const neverFetch = async () => { throw new Error('must not be called'); };
    const r = await verifyTurnstileToken('', { secret: 's', fetchImpl: neverFetch });
    assert.strictEqual(r.ok, false);
    assert.deepStrictEqual(r.errorCodes, ['missing-input-response']);
    const errFetch = async () => ({ ok: false, status: 502 });
    await assert.rejects(() => verifyTurnstileToken('tok', { secret: 's', fetchImpl: errFetch }));
    await assert.rejects(() => verifyTurnstileToken('tok', { fetchImpl: neverFetch }));
    assert.strictEqual(isTurnstileConfigured({}), false);
    assert.strictEqual(isTurnstileConfigured({ TURNSTILE_SECRET_KEY: 'x' }), true);
  });

  const members = (list) => list.map(([userId, role, createdAt]) => ({ userId, role, createdAt }));
  await test('deletion planner: sole owner transfers to oldest ADMIN, then oldest member', () => {
    const plan = planAccountDeletion(1, [
      { organizationId: 10, role: 'OWNER', members: members([[1, 'OWNER', '2026-01-01'], [3, 'DEVELOPER', '2026-01-02'], [2, 'ADMIN', '2026-01-03']]) },
      { organizationId: 11, role: 'OWNER', members: members([[1, 'OWNER', '2026-01-01'], [5, 'DEVELOPER', '2026-01-05'], [4, 'DEVELOPER', '2026-01-02']]) },
    ]);
    assert.deepStrictEqual(plan.transfers, [
      { organizationId: 10, newOwnerId: 2 },
      { organizationId: 11, newOwnerId: 4 },
    ]);
    assert.deepStrictEqual(plan.deletions, []);
    assert.deepStrictEqual(plan.leaves, []);
  });

  await test('deletion planner: sole member deletes org, co-owner and non-owner just leave', () => {
    const plan = planAccountDeletion(1, [
      { organizationId: 20, role: 'OWNER', members: members([[1, 'OWNER', '2026-01-01']]) },
      { organizationId: 21, role: 'OWNER', members: members([[1, 'OWNER', '2026-01-01'], [2, 'OWNER', '2026-01-02']]) },
      { organizationId: 22, role: 'DEVELOPER', members: members([[1, 'DEVELOPER', '2026-01-01'], [2, 'OWNER', '2026-01-02']]) },
    ]);
    assert.deepStrictEqual(plan.deletions, [20]);
    assert.deepStrictEqual(plan.leaves, [21, 22]);
    assert.deepStrictEqual(plan.transfers, []);
    assert.deepStrictEqual(planAccountDeletion(1, []), { transfers: [], deletions: [], leaves: [] });
  });

  await test('analytics: range parsing accepts only 7d/30d/90d, defaults to 30 when absent', () => {
    assert.strictEqual(parseSummaryRange('7d'), 7);
    assert.strictEqual(parseSummaryRange('30d'), 30);
    assert.strictEqual(parseSummaryRange('90d'), 90);
    assert.strictEqual(parseSummaryRange('1d'), null);
    assert.strictEqual(parseSummaryRange(''), null);
    assert.strictEqual(parseSummaryRange(undefined), 30);
  });

  await test('analytics: summary aggregates, sorts events, fills zero days', async () => {
    const from = new Date('2026-10-29T00:00:00.000Z');
    const to = new Date('2026-10-31T12:00:00.000Z');
    const stub = {
      user: {
        count: async () => 3,
        findMany: async () => [
          { createdAt: new Date('2026-10-29T08:00:00.000Z') },
          { createdAt: new Date('2026-10-29T09:00:00.000Z') },
          { createdAt: new Date('2026-10-31T10:00:00.000Z') },
        ],
      },
      scan: {
        count: async () => 2,
        findMany: async () => [
          { completedAt: new Date('2026-10-30T08:00:00.000Z') },
          { completedAt: new Date('2026-10-30T09:00:00.000Z') },
        ],
      },
      vulnerability: { count: async () => 5 },
      analyticsEvent: {
        count: async () => 9,
        groupBy: async ({ by }) => (by[0] === 'event'
          ? [{ event: 'page_view', _count: { event: 9 } }, { event: 'contact_sent', _count: { event: 2 } }]
          : [{ path: '/dashboard', _count: { path: 7 } }]),
      },
      contactMessage: { count: async () => 1 },
    };
    const s = await buildAnalyticsSummary(stub, { from, to, days: 3 });
    assert.deepStrictEqual(s.totals, { signups: 3, scansCompleted: 2, fixesApplied: 5, pageViews: 9, contactMessages: 1 });
    assert.deepStrictEqual(s.eventsByType, [{ event: 'page_view', count: 9 }, { event: 'contact_sent', count: 2 }]);
    assert.deepStrictEqual(s.topPaths, [{ path: '/dashboard', count: 7 }]);
    assert.deepStrictEqual(s.signupsByDay, [
      { date: '2026-10-29', count: 2 },
      { date: '2026-10-30', count: 0 },
      { date: '2026-10-31', count: 1 },
    ]);
    assert.deepStrictEqual(s.scansByDay, [
      { date: '2026-10-29', count: 0 },
      { date: '2026-10-30', count: 2 },
      { date: '2026-10-31', count: 0 },
    ]);
  });

  await test('sentry: init without DSN is inert and never throws', () => {
    assert.strictEqual(initSentry({}), null);
  });

  console.log(`\nDay 9 unit verification: ${passed}/${total} passed`);
  if (passed !== total) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
