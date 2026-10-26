/**
 * Centralized Plan & Limits Configuration for SecureGuard
 *
 * Billing provider: Razorpay (INR). Plan amounts live in the Razorpay Plan
 * itself (created in the dashboard by the owner) — priceMonthly is null for
 * paid plans until fetched live via getPlanPrices(); never invent an amount.
 */

const PLANS = {
  FREE: {
    key: 'FREE',
    name: 'Free',
    priceMonthly: 0,
    razorpayPlanId: null,
    maxRepositories: 3,
    maxScansPerMonth: 10,
    maxMembers: 3,
    features: [
      'Basic Vulnerability Scanning',
      'SOC 2 & HIPAA Compliance Reports',
      'Up to 3 Code Repositories',
      'Up to 3 Team Members',
      '10 Scans per Month'
    ]
  },
  PRO: {
    key: 'PRO',
    name: 'Pro',
    priceMonthly: null,
    razorpayPlanId: process.env.RAZORPAY_PLAN_PRO || null,
    maxRepositories: 25,
    maxScansPerMonth: 200,
    maxMembers: 15,
    features: [
      'Everything in Free',
      '25 Code Repositories',
      '200 Scans per Month',
      '15 Team Members',
      'AI Vulnerability Remediation',
      'ML False Positive Classifier',
      'PDF & JSON Compliance Report Exports'
    ]
  },
  ENTERPRISE: {
    key: 'ENTERPRISE',
    name: 'Enterprise',
    priceMonthly: null,
    razorpayPlanId: process.env.RAZORPAY_PLAN_ENTERPRISE || null,
    maxRepositories: 9999,
    maxScansPerMonth: 99999,
    maxMembers: 9999,
    features: [
      'Unlimited Code Repositories',
      'Unlimited Monthly Scans',
      'Unlimited Team Members',
      'Priority AI Remediation Engine',
      'Custom Security Compliance Frameworks',
      'Dedicated Security Engineer Support',
      '24/7 SLA Guarantee'
    ]
  }
};

/**
 * Helper to get plan config by key or Razorpay plan ID
 */
function getPlanConfig(planKeyOrPlanId) {
  if (!planKeyOrPlanId) return PLANS.FREE;

  const keyUpper = String(planKeyOrPlanId).toUpperCase();
  if (PLANS[keyUpper]) return PLANS[keyUpper];

  if (planKeyOrPlanId === PLANS.PRO.razorpayPlanId) return PLANS.PRO;
  if (planKeyOrPlanId === PLANS.ENTERPRISE.razorpayPlanId) return PLANS.ENTERPRISE;

  return PLANS.FREE;
}

module.exports = {
  PLANS,
  getPlanConfig
};
