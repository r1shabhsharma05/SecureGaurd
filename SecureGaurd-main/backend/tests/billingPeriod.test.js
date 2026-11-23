// Unit tests for the billing-period rollover in services/billingService.js.
// Run: node --test tests/billingPeriod.test.js (no DB, no network, no keys).
// A fake tx stands in for Prisma: getOrgUsage/getOrgPlan accept tx, so the
// period math is exercised without touching a database. Dates are relative
// to now so the tests hold on any run date.
const test = require('node:test');
const assert = require('node:assert/strict');

const { getOrgUsage, checkCanTriggerScan } = require('../services/billingService');

const DAY = 24 * 60 * 60 * 1000;

function fakeTx(sub, scanCountFor) {
  const calls = { scanGte: null };
  const tx = {
    subscription: { findUnique: async () => sub },
    repository: { count: async () => 1 },
    organizationMembership: { count: async () => 1 },
    scan: {
      count: async ({ where }) => {
        calls.scanGte = where.createdAt.gte;
        return scanCountFor(where.createdAt.gte);
      },
    },
  };
  return { tx, calls };
}

function freeSub(start, end) {
  return {
    organizationId: 1,
    plan: 'FREE',
    status: 'active',
    currentPeriodStart: start,
    currentPeriodEnd: end,
    cancelAtPeriodEnd: false,
  };
}

test('ended FREE period rolls forward — quota resets instead of pinning at 10/10', async () => {
  const now = new Date();
  const start = new Date(now.getTime() - 40 * DAY);
  const end = new Date(now.getTime() - 10 * DAY);
  // 10 scans counted from the stale start, 3 from the rolled start.
  const { tx, calls } = fakeTx(freeSub(start, end), (gte) => (gte <= start ? 10 : 3));

  const usage = await getOrgUsage(1, tx);

  assert.ok(calls.scanGte > start, 'scan window must move past the stale period start');
  assert.equal(usage.usage.scans.used, 3);
  assert.equal(usage.usage.scans.remaining, 7);
  assert.ok(new Date(usage.currentPeriodEnd) > now, 'reported period end must be in the future');

  const check = await checkCanTriggerScan(1, tx);
  assert.equal(check.allowed, true);
});

test('active period is unchanged — window stays at the stored start', async () => {
  const now = new Date();
  const start = new Date(now.getTime() - 5 * DAY);
  const end = new Date(now.getTime() + 25 * DAY);
  const { tx, calls } = fakeTx(freeSub(start, end), () => 4);

  const usage = await getOrgUsage(1, tx);

  assert.equal(calls.scanGte.getTime(), start.getTime());
  assert.equal(usage.usage.scans.used, 4);
  assert.equal(usage.usage.scans.remaining, 6);
  assert.equal(new Date(usage.currentPeriodEnd).getTime(), end.getTime());
});
