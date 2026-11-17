// Tests for the retention purge script (SEC-33). No DB: the purge core
// takes a stub client with the same count/deleteMany methods.
// Run: node --test tests/purgeRetention.test.js
const test = require('node:test');
const assert = require('node:assert/strict');

const { purgeRetention, RETENTION, cutoff } = require('../scripts/purge-retention');

const NOW = new Date('2026-11-18T00:00:00.000Z');

function stubDb(counts) {
  const calls = [];
  const db = { calls };
  for (const t of RETENTION) {
    db[t.model] = {
      count: async ({ where }) => { calls.push({ op: 'count', model: t.model, where }); return counts[t.model] ?? 0; },
      deleteMany: async ({ where }) => { calls.push({ op: 'deleteMany', model: t.model, where }); return { count: counts[t.model] ?? 0 }; },
    };
  }
  return db;
}

test('cutoff windows match DATA_RETENTION.md §1', () => {
  assert.equal(cutoff(90, NOW).toISOString(), '2026-08-20T00:00:00.000Z');
  assert.equal(cutoff(730, NOW).toISOString(), '2024-11-18T00:00:00.000Z');
  assert.equal(RETENTION.find((t) => t.label === 'AnalyticsEvent').days, 90);
  assert.equal(RETENTION.find((t) => t.label === 'ContactMessage').days, 730);
  assert.equal(RETENTION.find((t) => t.label === 'AlertLog'), undefined); // RLS table: not purged here
  assert.equal(RETENTION.find((t) => t.label === 'AuditLog'), undefined); // append-only trigger: not purged here
  assert.equal(RETENTION.length, 5);
});

test('dry run counts but never deletes', async () => {
  const db = stubDb({ analyticsEvent: 12, contactMessage: 0, stripeWebhookEvent: 3, razorpayWebhookEvent: 0, webhookDelivery: 7 });
  const results = await purgeRetention(db, { now: NOW });
  assert.deepEqual(results.map((r) => [r.label, r.expired, r.deleted]), [
    ['AnalyticsEvent', 12, 0],
    ['ContactMessage', 0, 0],
    ['StripeWebhookEvent', 3, 0],
    ['RazorpayWebhookEvent', 0, 0],
    ['WebhookDelivery', 7, 0],
  ]);
  assert.equal(db.calls.filter((c) => c.op === 'deleteMany').length, 0);
  assert.equal(db.calls.filter((c) => c.op === 'count').length, 5);
  // Cutoff uses the right field per table.
  const analytics = db.calls.find((c) => c.model === 'analyticsEvent');
  assert.deepEqual(analytics.where, { createdAt: { lt: new Date('2026-08-20T00:00:00.000Z') } });
  const stripe = db.calls.find((c) => c.model === 'stripeWebhookEvent');
  assert.deepEqual(stripe.where, { processedAt: { lt: new Date('2026-08-20T00:00:00.000Z') } });
});

test('--apply deletes only tables with expired rows', async () => {
  const db = stubDb({ analyticsEvent: 5, contactMessage: 2, stripeWebhookEvent: 0, razorpayWebhookEvent: 1, webhookDelivery: 0 });
  const results = await purgeRetention(db, { apply: true, now: NOW });
  assert.deepEqual(results.map((r) => [r.label, r.expired, r.deleted]), [
    ['AnalyticsEvent', 5, 5],
    ['ContactMessage', 2, 2],
    ['StripeWebhookEvent', 0, 0],
    ['RazorpayWebhookEvent', 1, 1],
    ['WebhookDelivery', 0, 0],
  ]);
  assert.deepEqual(db.calls.filter((c) => c.op === 'deleteMany').map((c) => c.model), [
    'analyticsEvent', 'contactMessage', 'razorpayWebhookEvent',
  ]);
});

test('a failing table aborts the run with the error (no silent partial purge)', async () => {
  const db = stubDb({ analyticsEvent: 1 });
  db.contactMessage.count = async () => { throw new Error('boom'); };
  await assert.rejects(() => purgeRetention(db, { apply: true, now: NOW }), /boom/);
});
