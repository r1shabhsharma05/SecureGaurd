const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { getOrgUsage, getOrgSubscription } = require('../services/billingService');
const { PLANS, getPlanConfig } = require('../config/plans');
const { getStripeClient } = require('../utils/stripe');

router.use(authMiddleware);

/**
 * GET /api/billing/usage
 * Returns active organization subscription status, usage metrics, limits, and plan details.
 * Allowed for: OWNER, ADMIN, DEVELOPER, AUDITOR (read-only role may read usage).
 */
router.get('/usage', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']), async (req, res) => {
  try {
    const usage = await getOrgUsage(req.organizationId);
    return res.json(usage);
  } catch (err) {
    console.error('Error fetching billing usage:', err);
    return res.status(500).json({ message: 'Failed to fetch billing usage' });
  }
});

/**
 * Helper to ensure a Stripe Customer exists for the Organization
 */
async function ensureStripeCustomer(organizationId, userEmail, orgName) {
  const sub = await getOrgSubscription(organizationId);

  if (sub.stripeCustomerId) {
    return sub.stripeCustomerId;
  }

  // No mock fallback: if Stripe is misconfigured or errors, propagate so the
  // caller can fail without persisting a fake customer ID or activating a plan.
  const stripe = getStripeClient();
  const customer = await stripe.customers.create({
    email: userEmail,
    name: orgName,
    metadata: {
      organizationId: String(organizationId)
    }
  });

  await prisma.subscription.update({
    where: { organizationId: Number(organizationId) },
    data: { stripeCustomerId: customer.id }
  });

  return customer.id;
}

/**
 * POST /api/billing/create-checkout-session
 * Initiates Stripe Checkout Session for PRO or ENTERPRISE upgrade.
 * Allowed for: OWNER only
 */
router.post('/create-checkout-session', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  try {
    const { plan } = req.body; // 'PRO' | 'ENTERPRISE'
    const targetPlan = getPlanConfig(plan);

    if (!targetPlan || targetPlan.key === 'FREE') {
      return res.status(400).json({ message: 'Invalid target plan selected for upgrade.' });
    }

    // Fail closed on misconfiguration: a missing/placeholder price ID must
    // never reach Stripe or a success path.
    if (!targetPlan.stripePriceId || /mock|placeholder|secureguard_test/i.test(targetPlan.stripePriceId)) {
      console.error(`[Billing] Stripe price ID for plan ${targetPlan.key} is missing or a placeholder.`);
      return res.status(503).json({ message: 'Billing is not configured for the selected plan. Please try again later.' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: req.organizationId }
    });

    if (!org) {
      return res.status(404).json({ message: 'Organization not found' });
    }

    // Fetch user record for email
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    const userEmail = user ? user.email : 'unknown@secureguard.dev';

    let stripeCustomerId;
    try {
      stripeCustomerId = await ensureStripeCustomer(req.organizationId, userEmail, org.name);
    } catch (customerErr) {
      console.error('[Billing] Failed to ensure Stripe customer:', customerErr.message);
      return res.status(503).json({ message: 'Billing is temporarily unavailable. Please try again later.' });
    }
    const domain = process.env.FRONTEND_URL || 'http://localhost:5173';

    try {
      const stripe = getStripeClient();
      const session = await stripe.checkout.sessions.create({
        customer: stripeCustomerId,
        mode: 'subscription',
        payment_method_types: ['card'],
        line_items: [
          {
            price: targetPlan.stripePriceId,
            quantity: 1
          }
        ],
        client_reference_id: String(req.organizationId),
        metadata: {
          organizationId: String(req.organizationId),
          plan: targetPlan.key
        },
        success_url: `${domain}/dashboard?billing_success=true&session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${domain}/dashboard?billing_canceled=true`
      });

      await createAuditLog(
        req.organizationId,
        req.userId,
        'BILLING_CHECKOUT_STARTED',
        'ORGANIZATION',
        String(req.organizationId),
        { targetPlan: targetPlan.key }
      );

      return res.json({ url: session.url });
    } catch (stripeErr) {
      // No mock fallback: never activate a paid plan without a real Stripe
      // checkout. Change nothing and surface a provider error.
      console.error('[Billing] Stripe checkout session creation failed:', stripeErr.message);
      return res.status(502).json({ message: 'Billing provider error. Please try again later.' });
    }
  } catch (err) {
    console.error('Error creating checkout session:', err);
    return res.status(500).json({ message: 'Failed to create checkout session' });
  }
});

/**
 * POST /api/billing/create-portal-session
 * Creates a Stripe Customer Billing Portal session for managing invoices/cards.
 * Allowed for: OWNER only
 */
router.post('/create-portal-session', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  try {
    const sub = await getOrgSubscription(req.organizationId);

    if (!sub.stripeCustomerId) {
      return res.status(400).json({ message: 'No Stripe billing customer record found for this organization.' });
    }

    const domain = process.env.FRONTEND_URL || 'http://localhost:5173';

    try {
      const stripe = getStripeClient();
      const portalSession = await stripe.billingPortal.sessions.create({
        customer: sub.stripeCustomerId,
        return_url: `${domain}/dashboard`
      });

      await createAuditLog(
        req.organizationId,
        req.userId,
        'BILLING_PORTAL_OPENED',
        'ORGANIZATION',
        String(req.organizationId)
      );

      return res.json({ url: portalSession.url });
    } catch (stripeErr) {
      // No simulated fallback: a portal URL that does not come from Stripe
      // would be a fake billing flow. Fail honestly instead.
      console.error('[Billing] Stripe portal session creation failed:', stripeErr.message);
      return res.status(502).json({ message: 'Billing provider error. Please try again later.' });
    }
  } catch (err) {
    console.error('Error creating portal session:', err);
    return res.status(500).json({ message: 'Failed to create billing portal session' });
  }
});

/**
 * GET /api/billing/invoices
 * Lists the organization's Stripe invoices (real Stripe data, no local copy).
 * Allowed for: OWNER, ADMIN (invoices are payment records, not member-visible).
 */
router.get('/invoices', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  try {
    const sub = await getOrgSubscription(req.organizationId);

    if (!sub.stripeCustomerId) {
      return res.json({ invoices: [] });
    }

    try {
      const stripe = getStripeClient();
      const list = await stripe.invoices.list({
        customer: sub.stripeCustomerId,
        limit: 20
      });

      return res.json({
        invoices: list.data.map((inv) => ({
          id: inv.id,
          number: inv.number,
          status: inv.status,
          amountDue: inv.amount_due,
          amountPaid: inv.amount_paid,
          currency: inv.currency,
          created: inv.created,
          hostedInvoiceUrl: inv.hosted_invoice_url,
          invoicePdf: inv.invoice_pdf
        }))
      });
    } catch (stripeErr) {
      console.error('[Billing] Stripe invoice list failed:', stripeErr.message);
      return res.status(502).json({ message: 'Billing provider error. Please try again later.' });
    }
  } catch (err) {
    console.error('Error fetching billing invoices:', err);
    return res.status(500).json({ message: 'Failed to fetch invoices' });
  }
});

/**
 * POST /api/billing/cancel-subscription
 * Schedules subscription cancellation at the end of the current billing period.
 * Allowed for: OWNER only
 */
router.post('/cancel-subscription', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  try {
    const sub = await getOrgSubscription(req.organizationId);

    // Nothing to cancel without a real Stripe subscription: setting the flag
    // on a FREE plan would report a cancellation that does not exist.
    if (!sub.stripeSubscriptionId) {
      return res.status(400).json({ message: 'No active paid subscription to cancel.' });
    }

    // Fail closed: if Stripe rejects the cancel, the local flag must not move
    // — otherwise the product would report "cancels at period end" while Stripe
    // keeps billing.
    try {
      const stripe = getStripeClient();
      await stripe.subscriptions.update(sub.stripeSubscriptionId, {
        cancel_at_period_end: true
      });
    } catch (stripeErr) {
      console.error('[Billing] Stripe cancel failed:', stripeErr.message);
      return res.status(502).json({ message: 'Billing provider error. Subscription was not canceled.' });
    }

    const updatedSub = await prisma.subscription.update({
      where: { organizationId: req.organizationId },
      data: { cancelAtPeriodEnd: true }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'SUBSCRIPTION_CANCELED',
      'ORGANIZATION',
      String(req.organizationId),
      { cancelAtPeriodEnd: true }
    );

    return res.json({
      message: 'Subscription scheduled for cancellation at end of period',
      subscription: updatedSub
    });
  } catch (err) {
    console.error('Error canceling subscription:', err);
    return res.status(500).json({ message: 'Failed to cancel subscription' });
  }
});

module.exports = router;
