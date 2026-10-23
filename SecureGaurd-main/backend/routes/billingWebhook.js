const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const { getStripeClient } = require('../utils/stripe');
const { getPlanConfig } = require('../config/plans');

/**
 * POST /api/billing/webhook
 * Handles raw Stripe webhook payloads and signature verification.
 */
router.post('/', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;

  // 1. Signature Verification — fail closed: without a real webhook secret
  // there is no way to trust the payload, so reject and process nothing.
  if (!webhookSecret || webhookSecret === 'whsec_mock_secret_key') {
    console.error('[Stripe Webhook] STRIPE_WEBHOOK_SECRET is missing or a placeholder; rejecting webhook.');
    return res.status(503).json({ message: 'Stripe webhook is not configured' });
  }

  try {
    const stripe = getStripeClient();
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('[Stripe Webhook Error] Signature verification failed:', err.message);
    return res.status(400).send(`Webhook Signature Error: ${err.message}`);
  }

  const { id: stripeEventId, type: eventType } = event;

  // 2. Idempotency Check
  const existingEvent = await prisma.stripeWebhookEvent.findUnique({
    where: { stripeEventId }
  });

  if (existingEvent) {
    console.log(`[Stripe Webhook] Duplicate event ${stripeEventId} ignored.`);
    return res.status(200).json({ received: true, idempotent: true });
  }

  // 3. Process Event inside a Transaction
  try {
    await prisma.$transaction(async (tx) => {
      // Record event ID first to ensure idempotency
      await tx.stripeWebhookEvent.create({
        data: {
          stripeEventId,
          eventType
        }
      });

      switch (eventType) {
        case 'checkout.session.completed': {
          const session = event.data.object;
          const organizationId = Number(session.client_reference_id || session.metadata?.organizationId);
          const planKey = session.metadata?.plan || 'PRO';

          if (organizationId) {
            const customerId = session.customer ? String(session.customer) : null;
            const subId = session.subscription ? String(session.subscription) : null;
            // session.line_items is not expanded in webhook payloads, so fall
            // back to an expanded subscription object, then to the configured
            // price for the plan named in metadata (never a placeholder).
            const configuredPriceId = getPlanConfig(planKey)?.stripePriceId;
            const stripePriceId =
              session.line_items?.data?.[0]?.price?.id ||
              (typeof session.subscription === 'object'
                ? session.subscription?.items?.data?.[0]?.price?.id
                : null) ||
              (configuredPriceId && !/mock|placeholder|secureguard_test/i.test(configuredPriceId)
                ? configuredPriceId
                : null);

            await tx.subscription.upsert({
              where: { organizationId },
              create: {
                organizationId,
                stripeCustomerId: customerId,
                stripeSubscriptionId: subId,
                stripePriceId,
                plan: planKey,
                status: 'active',
                currentPeriodStart: new Date(),
                currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
              },
              update: {
                stripeCustomerId: customerId || undefined,
                stripeSubscriptionId: subId || undefined,
                stripePriceId: stripePriceId || undefined,
                plan: planKey,
                status: 'active',
                currentPeriodStart: new Date(),
                currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
              }
            });

            await tx.auditLog.create({
              data: {
                organizationId,
                action: 'SUBSCRIPTION_CREATED',
                targetType: 'ORGANIZATION',
                targetId: String(organizationId),
                details: { plan: planKey, stripeCustomerId: customerId, stripeSubscriptionId: subId }
              }
            });
          }
          break;
        }

        case 'customer.subscription.created':
        case 'customer.subscription.updated': {
          const sub = event.data.object;
          const stripeSubscriptionId = sub.id;
          const stripeCustomerId = String(sub.customer);
          const priceId = sub.items?.data?.[0]?.price?.id;
          const planConfig = getPlanConfig(priceId || sub.metadata?.plan);

          const status = sub.status; // active | trialing | past_due | canceled etc.
          const currentPeriodStart = new Date(sub.current_period_start * 1000);
          const currentPeriodEnd = new Date(sub.current_period_end * 1000);
          const cancelAtPeriodEnd = sub.cancel_at_period_end || false;

          // Find subscription record
          let subRecord = await tx.subscription.findFirst({
            where: {
              OR: [
                { stripeSubscriptionId },
                { stripeCustomerId }
              ]
            }
          });

          if (subRecord) {
            await tx.subscription.update({
              where: { id: subRecord.id },
              data: {
                stripeSubscriptionId,
                stripePriceId: priceId || subRecord.stripePriceId,
                plan: planConfig.key,
                status,
                currentPeriodStart,
                currentPeriodEnd,
                cancelAtPeriodEnd
              }
            });

            await tx.auditLog.create({
              data: {
                organizationId: subRecord.organizationId,
                action: 'SUBSCRIPTION_UPDATED',
                targetType: 'ORGANIZATION',
                targetId: String(subRecord.organizationId),
                details: { plan: planConfig.key, status, cancelAtPeriodEnd }
              }
            });
          }
          break;
        }

        case 'customer.subscription.deleted': {
          const sub = event.data.object;
          const stripeSubscriptionId = sub.id;

          const subRecord = await tx.subscription.findFirst({
            where: { stripeSubscriptionId }
          });

          if (subRecord) {
            await tx.subscription.update({
              where: { id: subRecord.id },
              data: {
                plan: 'FREE',
                status: 'canceled',
                cancelAtPeriodEnd: false
              }
            });

            await tx.auditLog.create({
              data: {
                organizationId: subRecord.organizationId,
                action: 'SUBSCRIPTION_CANCELED',
                targetType: 'ORGANIZATION',
                targetId: String(subRecord.organizationId),
                details: { previousPlan: subRecord.plan }
              }
            });
          }
          break;
        }

        case 'invoice.payment_failed': {
          const invoice = event.data.object;
          const stripeCustomerId = String(invoice.customer);

          const subRecord = await tx.subscription.findFirst({
            where: { stripeCustomerId }
          });

          if (subRecord) {
            await tx.subscription.update({
              where: { id: subRecord.id },
              data: { status: 'past_due' }
            });

            await tx.auditLog.create({
              data: {
                organizationId: subRecord.organizationId,
                action: 'PAYMENT_FAILED',
                targetType: 'ORGANIZATION',
                targetId: String(subRecord.organizationId),
                details: { invoiceId: invoice.id, amountDue: invoice.amount_due }
              }
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
    console.error(`[Stripe Webhook Transaction Error] ${eventType}:`, err);
    return res.status(500).json({ message: 'Webhook handler database error' });
  }
});

module.exports = router;
