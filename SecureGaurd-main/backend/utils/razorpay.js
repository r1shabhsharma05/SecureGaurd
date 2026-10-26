const crypto = require('crypto');

const RAZORPAY_API_BASE = 'https://api.razorpay.com/v1';

// Razorpay Subscriptions run for a fixed number of billing cycles; 120 monthly
// cycles (10 years) is the effectively-ongoing value. The subscription ends
// (subscription.completed) after the last cycle — the owner creates a new one.
const SUBSCRIPTION_TOTAL_COUNT = 120;
// Authorization window for the hosted auth page (short_url). After expiry the
// owner simply creates a fresh subscription; nothing is charged meanwhile.
const SUBSCRIPTION_EXPIRE_AFTER_SECONDS = 7 * 24 * 60 * 60;

/**
 * Returns { keyId, secret } or throws. Fail-closed: no client without real
 * credentials, so no billing call can ever run against a placeholder.
 */
function getRazorpayCredentials() {
  const keyId = process.env.RAZORPAY_KEY_ID;
  const secret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !secret || /mock|placeholder/i.test(keyId) || /mock|placeholder/i.test(secret)) {
    throw new Error('Razorpay is not configured in environment variables.');
  }
  return { keyId, secret };
}

async function razorpayRequest(method, path, body) {
  const { keyId, secret } = getRazorpayCredentials();
  const res = await fetch(`${RAZORPAY_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Basic ${Buffer.from(`${keyId}:${secret}`).toString('base64')}`,
      'Content-Type': 'application/json'
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = data?.error?.description || data?.error?.code || `HTTP ${res.status}`;
    throw new Error(`Razorpay API error (${res.status}): ${detail}`);
  }
  return data;
}

/**
 * Creates a subscription for a plan. The customer is created by Razorpay at
 * authorization time (the hosted auth page collects their details), so no
 * customer step exists here. notes.organizationId / notes.plan are the only
 * link back to our org — the webhook resolves the org from them.
 */
async function createSubscription({ planId, organizationId, planKey }) {
  return razorpayRequest('POST', '/subscriptions', {
    plan_id: planId,
    total_count: SUBSCRIPTION_TOTAL_COUNT,
    quantity: 1,
    customer_notify: 1,
    expire_by: Math.floor(Date.now() / 1000) + SUBSCRIPTION_EXPIRE_AFTER_SECONDS,
    notes: { organizationId: String(organizationId), plan: planKey }
  });
}

async function cancelSubscription(subscriptionId, cancelAtCycleEnd = true) {
  return razorpayRequest('POST', `/subscriptions/${subscriptionId}/cancel`, {
    cancel_at_cycle_end: cancelAtCycleEnd ? 1 : 0
  });
}

async function fetchPlan(planId) {
  return razorpayRequest('GET', `/plans/${planId}`);
}

async function fetchSubscriptionInvoices(subscriptionId, count = 20) {
  const data = await razorpayRequest(
    'GET',
    `/invoices?subscription_id=${encodeURIComponent(subscriptionId)}&count=${count}`
  );
  return Array.isArray(data.items) ? data.items : [];
}

/**
 * Verifies a Razorpay webhook signature: HMAC-SHA256 hex of the RAW body,
 * keyed with the webhook secret, compared in constant time. The body must be
 * the untouched bytes (express.raw), never re-serialized JSON.
 */
function verifyWebhookSignature(rawBody, signature, secret) {
  if (!secret || !signature) return false;
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(signature);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * Maps a Razorpay subscription status to our local Subscription.status, or
 * null when the event must not move local status (created/authenticated mean
 * "not yet paying" — the org keeps its current plan until activation).
 */
function mapRazorpayStatus(rzStatus) {
  switch (rzStatus) {
    case 'active':
      return 'active';
    case 'pending':
    case 'halted':
      return 'past_due';
    case 'cancelled':
    case 'completed':
    case 'expired':
      return 'canceled';
    default:
      return null;
  }
}

/**
 * Maps a Razorpay invoice entity to the shape the billing tab renders
 * (same shape the Stripe invoices endpoint used, so the UI is unchanged).
 * Amounts are paise; invoice_number is null for subscription invoices.
 */
function mapInvoice(inv) {
  return {
    id: inv.id,
    number: inv.invoice_number || null,
    status: inv.status,
    amountDue: inv.amount_due ?? inv.amount ?? 0,
    amountPaid: inv.amount_paid ?? 0,
    currency: inv.currency,
    created: inv.created_at,
    hostedInvoiceUrl: inv.short_url || null,
    invoicePdf: null
  };
}

module.exports = {
  SUBSCRIPTION_TOTAL_COUNT,
  getRazorpayCredentials,
  razorpayRequest,
  createSubscription,
  cancelSubscription,
  fetchPlan,
  fetchSubscriptionInvoices,
  verifyWebhookSignature,
  mapRazorpayStatus,
  mapInvoice
};
