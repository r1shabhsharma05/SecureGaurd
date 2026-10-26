const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Plan IDs are env-driven; set test values BEFORE requiring plans.js.
process.env.RAZORPAY_PLAN_PRO = 'plan_test_pro_123';
process.env.RAZORPAY_PLAN_ENTERPRISE = 'plan_test_ent_456';
delete process.env.RAZORPAY_KEY_ID;
delete process.env.RAZORPAY_KEY_SECRET;
delete process.env.RAZORPAY_WEBHOOK_SECRET;

const {
  SUBSCRIPTION_TOTAL_COUNT,
  getRazorpayCredentials,
  createSubscription,
  cancelSubscription,
  fetchPlan,
  verifyWebhookSignature,
  mapRazorpayStatus,
  mapInvoice
} = require('../utils/razorpay');
const { PLANS, getPlanConfig } = require('../config/plans');

async function runRazorpayVerificationSuite() {
  console.log('\n================================================================');
  console.log(' SECUREGUARD PHASE 2: RAZORPAY BILLING UNIT VERIFY (DB-free) ');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✕ ${name}`);
      console.error(`     Error: ${err.message}`);
      failed++;
    }
  }

  async function asyncTest(name, fn) {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✕ ${name}`);
      console.error(`     Error: ${err.message}`);
      failed++;
    }
  }

  console.log('--- 1. WEBHOOK SIGNATURE (HMAC-SHA256 over raw body) ---');
  const secret = 'test_webhook_secret_only_for_unit_tests';
  const rawBody = Buffer.from(JSON.stringify({ event: 'subscription.activated', payload: {} }));
  const goodSig = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');

  test('valid signature verifies', () => {
    assert.strictEqual(verifyWebhookSignature(rawBody, goodSig, secret), true);
  });
  test('tampered body fails', () => {
    const tampered = Buffer.from(JSON.stringify({ event: 'subscription.cancelled', payload: {} }));
    assert.strictEqual(verifyWebhookSignature(tampered, goodSig, secret), false);
  });
  test('wrong secret fails', () => {
    assert.strictEqual(verifyWebhookSignature(rawBody, goodSig, 'other_secret'), false);
  });
  test('missing signature fails (no throw)', () => {
    assert.strictEqual(verifyWebhookSignature(rawBody, undefined, secret), false);
    assert.strictEqual(verifyWebhookSignature(rawBody, '', secret), false);
  });
  test('length-mismatched signature fails (no throw)', () => {
    assert.strictEqual(verifyWebhookSignature(rawBody, 'abc', secret), false);
  });
  test('missing secret fails (no throw)', () => {
    assert.strictEqual(verifyWebhookSignature(rawBody, goodSig, undefined), false);
  });

  console.log('--- 2. STATUS MAPPING (never downgrades on created/authenticated) ---');
  test('active -> active', () => assert.strictEqual(mapRazorpayStatus('active'), 'active'));
  test('pending/halted -> past_due', () => {
    assert.strictEqual(mapRazorpayStatus('pending'), 'past_due');
    assert.strictEqual(mapRazorpayStatus('halted'), 'past_due');
  });
  test('cancelled/completed/expired -> canceled', () => {
    assert.strictEqual(mapRazorpayStatus('cancelled'), 'canceled');
    assert.strictEqual(mapRazorpayStatus('completed'), 'canceled');
    assert.strictEqual(mapRazorpayStatus('expired'), 'canceled');
  });
  test('created/authenticated/paused/unknown -> null (no local move)', () => {
    assert.strictEqual(mapRazorpayStatus('created'), null);
    assert.strictEqual(mapRazorpayStatus('authenticated'), null);
    assert.strictEqual(mapRazorpayStatus('paused'), null);
    assert.strictEqual(mapRazorpayStatus('bogus'), null);
  });

  console.log('--- 3. INVOICE MAPPING (subscription invoice shape) ---');
  test('maps Razorpay invoice to billing-tab shape', () => {
    const mapped = mapInvoice({
      id: 'inv_test_1',
      invoice_number: null,
      status: 'paid',
      amount: 499900,
      amount_paid: 499900,
      amount_due: 0,
      currency: 'INR',
      short_url: 'https://rzp.io/i/test',
      created_at: 1700000000
    });
    assert.strictEqual(mapped.id, 'inv_test_1');
    assert.strictEqual(mapped.number, null);
    assert.strictEqual(mapped.status, 'paid');
    assert.strictEqual(mapped.amountDue, 0);
    assert.strictEqual(mapped.amountPaid, 499900);
    assert.strictEqual(mapped.currency, 'INR');
    assert.strictEqual(mapped.created, 1700000000);
    assert.strictEqual(mapped.hostedInvoiceUrl, 'https://rzp.io/i/test');
    assert.strictEqual(mapped.invoicePdf, null);
  });

  console.log('--- 4. FAIL-CLOSED WITHOUT KEYS ---');
  test('getRazorpayCredentials throws without keys', () => {
    assert.throws(() => getRazorpayCredentials(), /not configured/);
  });
  await asyncTest('createSubscription rejects without keys (no state change possible)', async () => {
    await assert.rejects(
      () => createSubscription({ planId: 'plan_test_pro_123', organizationId: 1, planKey: 'PRO' }),
      /not configured/
    );
  });
  await asyncTest('cancelSubscription rejects without keys', async () => {
    await assert.rejects(() => cancelSubscription('sub_test_1', true), /not configured/);
  });
  await asyncTest('fetchPlan rejects without keys', async () => {
    await assert.rejects(() => fetchPlan('plan_test_pro_123'), /not configured/);
  });

  console.log('--- 5. PLAN CONFIG (env-driven, no invented amounts) ---');
  test('PRO/ENTERPRISE priceMonthly is null (amount lives in Razorpay Plan)', () => {
    assert.strictEqual(PLANS.PRO.priceMonthly, null);
    assert.strictEqual(PLANS.ENTERPRISE.priceMonthly, null);
    assert.strictEqual(PLANS.FREE.priceMonthly, 0);
  });
  test('getPlanConfig resolves by Razorpay plan ID', () => {
    assert.strictEqual(getPlanConfig('plan_test_pro_123').key, 'PRO');
    assert.strictEqual(getPlanConfig('plan_test_ent_456').key, 'ENTERPRISE');
  });
  test('getPlanConfig falls back to FREE for unknown plan IDs (never a paid guess)', () => {
    assert.strictEqual(getPlanConfig('plan_unknown').key, 'FREE');
  });
  test('subscription total_count is a positive integer', () => {
    assert.ok(Number.isInteger(SUBSCRIPTION_TOTAL_COUNT) && SUBSCRIPTION_TOTAL_COUNT > 0);
  });

  console.log('--- 6. NO DEAD STRIPE CODE PATHS IN BILLING ---');
  const billingJs = fs.readFileSync(path.join(__dirname, '../routes/billing.js'), 'utf8');
  const webhookJs = fs.readFileSync(path.join(__dirname, '../routes/billingWebhook.js'), 'utf8');
  const plansJs = fs.readFileSync(path.join(__dirname, '../config/plans.js'), 'utf8');
  test('billing routes contain no Stripe references or portal endpoint', () => {
    assert.ok(!/stripe/i.test(billingJs), 'billing.js still mentions Stripe');
    assert.ok(!billingJs.includes('create-portal-session'), 'portal endpoint still present');
    assert.ok(!billingJs.includes('create-checkout-session'), 'checkout endpoint still present');
    assert.ok(billingJs.includes('create-subscription'), 'create-subscription endpoint missing');
  });
  test('webhook uses x-razorpay-signature, not stripe-signature', () => {
    assert.ok(webhookJs.includes('x-razorpay-signature'), 'Razorpay signature header missing');
    assert.ok(!/stripe-signature/i.test(webhookJs), 'Stripe signature header still present');
    assert.ok(webhookJs.includes('razorpayWebhookEvent'), 'RazorpayWebhookEvent model not used');
  });
  test('plans config has no stripePriceId', () => {
    assert.ok(!plansJs.includes('stripePriceId'), 'stripePriceId still present');
    assert.ok(plansJs.includes('razorpayPlanId'), 'razorpayPlanId missing');
  });
  test('utils/stripe.js is deleted', () => {
    assert.strictEqual(fs.existsSync(path.join(__dirname, '../utils/stripe.js')), false);
  });

  console.log('\n================================================================');
  console.log(` RESULTS: ${passed} passed, ${failed} failed`);
  console.log('================================================================\n');

  if (failed > 0) {
    console.error('RAZORPAY BILLING VERIFICATION FAILED');
    process.exit(1);
  }
  console.log('RAZORPAY BILLING VERIFICATION PASSED');
}

runRazorpayVerificationSuite().catch((err) => {
  console.error('Fatal error running verification suite:', err);
  process.exit(1);
});
