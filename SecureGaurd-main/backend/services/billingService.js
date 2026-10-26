const prisma = require('../prismaClient');
const { PLANS, getPlanConfig } = require('../config/plans');

/**
 * Fetches live Razorpay Plan amounts (paise + currency) for the paid plans.
 * Best-effort: a missing key, missing plan ID, or provider error degrades to
 * null per plan — usage must never fail because pricing lookup failed. The
 * amounts are owned by the Razorpay Plans (set in the dashboard), never here.
 */
async function getPlanPrices() {
  const prices = { PRO: null, ENTERPRISE: null };
  let fetchPlan;
  try {
    ({ fetchPlan } = require('../utils/razorpay'));
  } catch {
    return prices;
  }
  for (const key of ['PRO', 'ENTERPRISE']) {
    const planId = PLANS[key].razorpayPlanId;
    if (!planId) continue;
    try {
      const plan = await fetchPlan(planId);
      const amountPaise = plan?.item?.amount;
      const currency = plan?.item?.currency;
      if (typeof amountPaise === 'number' && currency) {
        prices[key] = { amountPaise, currency };
      }
    } catch {
      // Degrade to null; the UI renders "set in Razorpay dashboard".
    }
  }
  return prices;
}

/**
 * Ensures an organization has a Subscription record.
 * Auto-creates a FREE plan subscription if none exists (backwards compatibility).
 */
async function getOrgSubscription(organizationId) {
  const orgId = Number(organizationId);
  if (!orgId || isNaN(orgId)) {
    throw new Error('Invalid organizationId provided to billingService');
  }

  let sub = await prisma.subscription.findUnique({
    where: { organizationId: orgId }
  });

  if (!sub) {
    const now = new Date();
    const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, now.getDate());

    sub = await prisma.subscription.create({
      data: {
        organizationId: orgId,
        plan: 'FREE',
        status: 'active',
        currentPeriodStart: now,
        currentPeriodEnd: periodEnd,
        cancelAtPeriodEnd: false
      }
    });
  }

  return sub;
}

/**
 * Gets the active Plan configuration for an Organization.
 * Falls back to FREE if subscription is inactive or canceled beyond grace period.
 */
async function getOrgPlan(organizationId) {
  const sub = await getOrgSubscription(organizationId);

  // Check if status is valid
  const validStatuses = ['active', 'trialing'];
  const isActive = validStatuses.includes(sub.status);

  if (!isActive) {
    return PLANS.FREE;
  }

  return getPlanConfig(sub.plan);
}

/**
 * Calculates current period usage for an Organization.
 * Counts scans in current month/billing period, total repositories, and total members.
 */
async function getOrgUsage(organizationId) {
  const orgId = Number(organizationId);
  const sub = await getOrgSubscription(orgId);
  const plan = await getOrgPlan(orgId);

  // Determine period boundaries
  const now = new Date();
  const startOfPeriod = sub.currentPeriodStart || new Date(now.getFullYear(), now.getMonth(), 1);
  const endOfPeriod = sub.currentPeriodEnd || new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

  // 1. Repositories count
  const reposCount = await prisma.repository.count({
    where: { organizationId: orgId }
  });

  // 2. Members count
  const membersCount = await prisma.organizationMembership.count({
    where: { organizationId: orgId }
  });

  // 3. Scans count in current period
  const scansCount = await prisma.scan.count({
    where: {
      organizationId: orgId,
      createdAt: {
        gte: startOfPeriod
      }
    }
  });

  return {
    organizationId: orgId,
    plan: plan.key,
    planName: plan.name,
    priceMonthly: plan.priceMonthly,
    planPrices: await getPlanPrices(),
    status: sub.status,
    cancelAtPeriodEnd: sub.cancelAtPeriodEnd,
    currentPeriodStart: startOfPeriod,
    currentPeriodEnd: endOfPeriod,
    usage: {
      scans: {
        used: scansCount,
        limit: plan.maxScansPerMonth,
        remaining: Math.max(0, plan.maxScansPerMonth - scansCount)
      },
      repositories: {
        used: reposCount,
        limit: plan.maxRepositories,
        remaining: Math.max(0, plan.maxRepositories - reposCount)
      },
      members: {
        used: membersCount,
        limit: plan.maxMembers,
        remaining: Math.max(0, plan.maxMembers - membersCount)
      }
    },
    features: plan.features
  };
}

/**
 * Checks if organization can add a new repository.
 */
async function checkCanAddRepository(organizationId) {
  const usage = await getOrgUsage(organizationId);
  if (usage.usage.repositories.used >= usage.usage.repositories.limit) {
    return {
      allowed: false,
      reason: `REPOSITORY_LIMIT_REACHED`,
      message: `Your organization has reached the limit of ${usage.usage.repositories.limit} repositories on the ${usage.planName} plan. Upgrade to Pro for up to 25 repositories.`,
      usage: usage.usage.repositories
    };
  }
  return { allowed: true };
}

/**
 * Checks if organization can invite/add a new member.
 */
async function checkCanInviteMember(organizationId) {
  const usage = await getOrgUsage(organizationId);
  if (usage.usage.members.used >= usage.usage.members.limit) {
    return {
      allowed: false,
      reason: `MEMBER_LIMIT_REACHED`,
      message: `Your organization has reached the limit of ${usage.usage.members.limit} team members on the ${usage.planName} plan. Upgrade to Pro for up to 15 members.`,
      usage: usage.usage.members
    };
  }
  return { allowed: true };
}

/**
 * Checks if organization can trigger a new scan.
 */
async function checkCanTriggerScan(organizationId) {
  const usage = await getOrgUsage(organizationId);
  if (usage.usage.scans.used >= usage.usage.scans.limit) {
    return {
      allowed: false,
      reason: `SCAN_LIMIT_REACHED`,
      message: `Your organization has reached its limit of ${usage.usage.scans.limit} scans this month on the ${usage.planName} plan. Upgrade to Pro for 200 scans/month.`,
      usage: usage.usage.scans
    };
  }
  return { allowed: true };
}

module.exports = {
  getOrgSubscription,
  getOrgPlan,
  getOrgUsage,
  getPlanPrices,
  checkCanAddRepository,
  checkCanInviteMember,
  checkCanTriggerScan
};
