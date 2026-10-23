/**
 * Centralized Plan & Limits Configuration for SecureGuard
 */

const PLANS = {
  FREE: {
    key: 'FREE',
    name: 'Free',
    priceMonthly: 0,
    stripePriceId: null,
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
    priceMonthly: 49,
    stripePriceId: process.env.STRIPE_PRICE_PRO || null,
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
    priceMonthly: 299,
    stripePriceId: process.env.STRIPE_PRICE_ENTERPRISE || null,
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
 * Helper to get plan config by key or price ID
 */
function getPlanConfig(planKeyOrPriceId) {
  if (!planKeyOrPriceId) return PLANS.FREE;
  
  const keyUpper = String(planKeyOrPriceId).toUpperCase();
  if (PLANS[keyUpper]) return PLANS[keyUpper];

  if (planKeyOrPriceId === PLANS.PRO.stripePriceId) return PLANS.PRO;
  if (planKeyOrPriceId === PLANS.ENTERPRISE.stripePriceId) return PLANS.ENTERPRISE;

  return PLANS.FREE;
}

module.exports = {
  PLANS,
  getPlanConfig
};
