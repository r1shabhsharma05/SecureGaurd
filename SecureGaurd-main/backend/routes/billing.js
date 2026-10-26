const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { getOrgUsage, getOrgSubscription } = require('../services/billingService');
const { PLANS, getPlanConfig } = require('../config/plans');
const {
  createSubscription,
  cancelSubscription,
  fetchSubscriptionInvoices,
  mapInvoice
} = require('../utils/razorpay');

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
 * POST /api/billing/create-subscription
 * Creates a Razorpay subscription for a PRO or ENTERPRISE upgrade and returns
 * the hosted authorization URL (short_url). The customer authorizes the
 * mandate there; the plan activates only via the subscription.activated
 * webhook — this endpoint changes NO local plan or status, so a failed or
 * abandoned authorization can never leave a paid plan behind.
 * Allowed for: OWNER only
 */
router.post('/create-subscription', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  try {
    const { plan } = req.body; // 'PRO' | 'ENTERPRISE'
    const targetPlan = getPlanConfig(plan);

    if (!targetPlan || targetPlan.key === 'FREE') {
      return res.status(400).json({ message: 'Invalid target plan selected for upgrade.' });
    }

    // Fail closed on misconfiguration: a missing/placeholder plan ID must
    // never reach Razorpay or a success path.
    if (!targetPlan.razorpayPlanId || /mock|placeholder/i.test(targetPlan.razorpayPlanId)) {
      console.error(`[Billing] Razorpay plan ID for plan ${targetPlan.key} is missing or a placeholder.`);
      return res.status(503).json({ message: 'Billing is not configured for the selected plan. Please try again later.' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: req.organizationId }
    });

    if (!org) {
      return res.status(404).json({ message: 'Organization not found' });
    }

    try {
      const subscription = await createSubscription({
        planId: targetPlan.razorpayPlanId,
        organizationId: req.organizationId,
        planKey: targetPlan.key
      });

      await createAuditLog(
        req.organizationId,
        req.userId,
        'BILLING_CHECKOUT_STARTED',
        'ORGANIZATION',
        String(req.organizationId),
        { targetPlan: targetPlan.key, razorpaySubscriptionId: subscription.id }
      );

      return res.json({ url: subscription.short_url, subscriptionId: subscription.id });
    } catch (providerErr) {
      // No mock fallback: never activate a paid plan without a real Razorpay
      // subscription. Change nothing and surface a provider error.
      console.error('[Billing] Razorpay subscription creation failed:', providerErr.message);
      return res.status(502).json({ message: 'Billing provider error. Please try again later.' });
    }
  } catch (err) {
    console.error('Error creating subscription:', err);
    return res.status(500).json({ message: 'Failed to create subscription' });
  }
});

/**
 * GET /api/billing/invoices
 * Lists the organization's Razorpay subscription invoices (real Razorpay data,
 * no local copy). Razorpay auto-generates one invoice per billing cycle.
 * Allowed for: OWNER, ADMIN (invoices are payment records, not member-visible).
 */
router.get('/invoices', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  try {
    const sub = await getOrgSubscription(req.organizationId);

    if (!sub.razorpaySubscriptionId) {
      return res.json({ invoices: [] });
    }

    try {
      const items = await fetchSubscriptionInvoices(sub.razorpaySubscriptionId, 20);
      return res.json({ invoices: items.map(mapInvoice) });
    } catch (providerErr) {
      console.error('[Billing] Razorpay invoice list failed:', providerErr.message);
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

    // Nothing to cancel without a real Razorpay subscription: setting the flag
    // on a FREE plan would report a cancellation that does not exist.
    if (!sub.razorpaySubscriptionId) {
      return res.status(400).json({ message: 'No active paid subscription to cancel.' });
    }

    // Fail closed: if Razorpay rejects the cancel, the local flag must not move
    // — otherwise the product would report "cancels at period end" while
    // Razorpay keeps billing.
    try {
      await cancelSubscription(sub.razorpaySubscriptionId, true);
    } catch (providerErr) {
      console.error('[Billing] Razorpay cancel failed:', providerErr.message);
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
