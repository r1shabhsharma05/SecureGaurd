const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const { verifyWebhookSignature, mapRazorpayStatus } = require('../utils/razorpay');
const { getPlanConfig } = require('../config/plans');

/**
 * Resolves the local subscription row for a Razorpay subscription entity.
 * Lookup order: stored razorpaySubscriptionId, then the organizationId we
 * stamped into notes at creation time. Returns { record, organizationId }
 * (either may be null when the event cannot be tied to an org).
 */
async function resolveOrg(tx, subEntity) {
  if (subEntity?.id) {
    const record = await tx.subscription.findFirst({
      where: { razorpaySubscriptionId: subEntity.id }
    });
    if (record) return { record, organizationId: record.organizationId };
  }
  const orgId = Number(subEntity?.notes?.organizationId);
  if (orgId) {
    const record = await tx.subscription.findUnique({
      where: { organizationId: orgId }
    });
    return { record, organizationId: orgId };
  }
  return { record: null, organizationId: null };
}

/**
 * Plan key for a subscription entity: the configured Razorpay plan ID wins,
 * then the plan stamped into notes at creation. Unknown plan IDs resolve to
 * null (never FREE) so a misconfigured plan can never silently downgrade.
 */
function planKeyFor(subEntity) {
  const planId = subEntity?.plan_id;
  if (planId) {
    const cfg = getPlanConfig(planId);
    if (cfg.key !== 'FREE') return cfg.key;
  }
  const notePlan = subEntity?.notes?.plan;
  if (notePlan === 'PRO' || notePlan === 'ENTERPRISE') return notePlan;
  return null;
}

function periodFrom(subEntity) {
  const data = {};
  if (subEntity?.current_start) data.currentPeriodStart = new Date(subEntity.current_start * 1000);
  if (subEntity?.current_end) data.currentPeriodEnd = new Date(subEntity.current_end * 1000);
  return data;
}

function idsFrom(subEntity) {
  const data = {};
  if (subEntity?.id) data.razorpaySubscriptionId = subEntity.id;
  if (subEntity?.customer_id) data.razorpayCustomerId = subEntity.customer_id;
  if (subEntity?.plan_id) data.razorpayPlanId = subEntity.plan_id;
  return data;
}

/**
 * Updates the resolved row, or creates the org's subscription row when the
 * org is known but has no row yet (mirrors getOrgSubscription's auto-create).
 * Returns the saved row or null when nothing could be resolved.
 */
async function saveSubscription(tx, record, organizationId, data) {
  if (record) {
    return tx.subscription.update({ where: { id: record.id }, data });
  }
  if (organizationId) {
    return tx.subscription.upsert({
      where: { organizationId },
      create: {
        organizationId,
        plan: 'FREE',
        status: 'active',
        cancelAtPeriodEnd: false,
        ...data
      },
      update: data
    });
  }
  return null;
}

/**
 * POST /api/billing/webhook
 * Handles raw Razorpay webhook payloads and HMAC-SHA256 signature verification
 * over the raw body. Mounted before express.json (see server.js) so the raw
 * bytes survive for verification.
 */
router.post('/', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = req.headers['x-razorpay-signature'];
  const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

  // 1. Signature Verification — fail closed: without a real webhook secret
  // there is no way to trust the payload, so reject and process nothing.
  if (!webhookSecret || /mock|placeholder/i.test(webhookSecret)) {
    console.error('[Razorpay Webhook] RAZORPAY_WEBHOOK_SECRET is missing or a placeholder; rejecting webhook.');
    return res.status(503).json({ message: 'Razorpay webhook is not configured' });
  }

  const rawBody = req.body;
  if (!verifyWebhookSignature(rawBody, signature, webhookSecret)) {
    console.error('[Razorpay Webhook Error] Signature verification failed.');
    return res.status(400).send('Webhook Signature Error: invalid signature');
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).send('Webhook body is not valid JSON');
  }

  const eventType = payload.event;
  const subEntity = payload.payload?.subscription?.entity || null;
  const payEntity = payload.payload?.payment?.entity || null;

  // 2. Idempotency: Razorpay sends a unique event id per delivery.
  const eventId =
    req.headers['x-razorpay-event-id'] ||
    `${eventType}:${subEntity?.id || ''}:${payEntity?.id || ''}`;

  const existingEvent = await prisma.razorpayWebhookEvent.findUnique({
    where: { razorpayEventId: eventId }
  });

  if (existingEvent) {
    console.log(`[Razorpay Webhook] Duplicate event ${eventId} ignored.`);
    return res.status(200).json({ received: true, idempotent: true });
  }

  // 3. Process Event inside a Transaction (event row first, so a failure
  // rolls everything back and Razorpay's retry can re-deliver cleanly).
  try {
    await prisma.$transaction(async (tx) => {
      await tx.razorpayWebhookEvent.create({
        data: {
          razorpayEventId: eventId,
          eventType
        }
      });

      const audit = (organizationId, action, details) =>
        tx.auditLog.create({
          data: {
            organizationId,
            action,
            targetType: 'ORGANIZATION',
            targetId: String(organizationId),
            details
          }
        });

      switch (eventType) {
        case 'subscription.authenticated': {
          // Auth done, first charge pending: record ids only. Plan/status
          // must NOT move yet — the org keeps its current plan until
          // subscription.activated.
          const { record, organizationId } = await resolveOrg(tx, subEntity);
          await saveSubscription(tx, record, organizationId, idsFrom(subEntity));
          break;
        }

        case 'subscription.activated': {
          const { record, organizationId } = await resolveOrg(tx, subEntity);
          const priorPlan = record?.plan;
          const planKey = planKeyFor(subEntity);
          const data = {
            ...idsFrom(subEntity),
            ...periodFrom(subEntity),
            cancelAtPeriodEnd: false,
            status: 'active'
          };
          if (planKey) data.plan = planKey;
          const saved = await saveSubscription(tx, record, organizationId, data);
          if (saved) {
            await audit(
              saved.organizationId,
              !priorPlan || priorPlan === 'FREE' ? 'SUBSCRIPTION_CREATED' : 'SUBSCRIPTION_UPDATED',
              { plan: saved.plan, status: 'active', razorpaySubscriptionId: subEntity?.id }
            );
          }
          break;
        }

        case 'subscription.updated': {
          const { record, organizationId } = await resolveOrg(tx, subEntity);
          const planKey = planKeyFor(subEntity);
          const mappedStatus = mapRazorpayStatus(subEntity?.status);
          const data = { ...idsFrom(subEntity), ...periodFrom(subEntity) };
          if (planKey) data.plan = planKey;
          if (mappedStatus) data.status = mappedStatus;
          const saved = await saveSubscription(tx, record, organizationId, data);
          if (saved) {
            await audit(saved.organizationId, 'SUBSCRIPTION_UPDATED', {
              plan: saved.plan,
              status: saved.status
            });
          }
          break;
        }

        case 'subscription.pending':
        case 'subscription.halted': {
          const { record, organizationId } = await resolveOrg(tx, subEntity);
          const saved = await saveSubscription(tx, record, organizationId, {
            ...idsFrom(subEntity),
            status: 'past_due'
          });
          if (saved) {
            await audit(saved.organizationId, 'SUBSCRIPTION_UPDATED', { status: 'past_due' });
          }
          break;
        }

        case 'subscription.cancelled':
        case 'subscription.completed': {
          const { record, organizationId } = await resolveOrg(tx, subEntity);
          const saved = await saveSubscription(tx, record, organizationId, {
            ...idsFrom(subEntity),
            plan: 'FREE',
            status: 'canceled',
            cancelAtPeriodEnd: false
          });
          if (saved) {
            await audit(saved.organizationId, 'SUBSCRIPTION_CANCELED', {
              previousPlan: record?.plan
            });
          }
          break;
        }

        case 'subscription.charged':
        case 'invoice.paid':
          // Invoices are served live from the Razorpay API; the event row
          // above is the trail. No local state moves on a charge.
          break;

        case 'subscription.paused':
        case 'subscription.resumed': {
          // Local model has no paused state; plan/status stay untouched.
          const { record, organizationId } = await resolveOrg(tx, subEntity);
          const saved = await saveSubscription(tx, record, organizationId, idsFrom(subEntity));
          if (saved) {
            await audit(saved.organizationId, 'SUBSCRIPTION_UPDATED', { event: eventType });
          }
          break;
        }

        case 'payment.failed': {
          const subId = payEntity?.subscription_id || subEntity?.id;
          const { record } = await resolveOrg(tx, subId ? { id: subId } : null);
          if (record) {
            await tx.subscription.update({
              where: { id: record.id },
              data: { status: 'past_due' }
            });
            await audit(record.organizationId, 'PAYMENT_FAILED', {
              paymentId: payEntity?.id,
              amount: payEntity?.amount
            });
          }
          break;
        }

        default:
          // Unhandled event types acknowledged safely
          break;
      }
    });

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error(`[Razorpay Webhook Transaction Error] ${eventType}:`, err);
    return res.status(500).json({ message: 'Webhook handler database error' });
  }
});

module.exports = router;
