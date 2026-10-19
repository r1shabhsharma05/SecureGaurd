import React from 'react';
import { Link } from 'react-router-dom';
import { motion, Variants } from 'framer-motion';
import { Check, Zap, Building } from 'lucide-react';
import './Pricing.css';

const MotionLink = motion.create(Link);

const PLANS = [
  {
    name: 'Starter',
    price: '$0',
    period: 'forever free',
    desc: 'Perfect for solo developers and open source projects.',
    icon: Zap,
    color: '#10b981',
    features: [
      '5 private repositories',
      'Basic vulnerability scanning',
      'GitHub & GitLab integration',
      'Community support',
      '100 scans / month',
    ],
    cta: 'Get Started Free',
    popular: false,
  },
  {
    name: 'Pro',
    price: '$29',
    period: 'per seat / month',
    desc: 'For professional teams who ship fast and stay secure.',
    icon: Check,
    color: '#2563eb',
    features: [
      'Unlimited repositories',
      'Full AI vulnerability suite',
      'Secret & SBOM detection',
      'Slack + Jira integration',
      'Priority support',
      'Compliance reports (SOC 2)',
      'PR block rules',
    ],
    cta: 'Start Free Trial',
    popular: true,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: 'volume pricing',
    desc: 'Tailored security for large teams with custom requirements.',
    icon: Building,
    color: '#8b5cf6',
    features: [
      'Everything in Pro',
      'SSO / SAML & SCIM',
      'Dedicated deployment',
      'Audit logs & SIEM export',
      'SLA guarantee',
      'Custom AI rules',
      '24/7 SRE support',
    ],
    cta: 'Contact Sales',
    popular: false,
  },
];

const cardVariants: Variants = {
  hidden: { opacity: 0, y: 40 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.12, duration: 0.5, ease: 'easeOut' },
  }),
};

export default function Pricing() {
  return (
    <section id="pricing" className="pricing-section section-padding">
      <div className="container">
        <div className="pricing-header">
          <span className="landing-section-eyebrow">Pricing</span>
          <h2 className="landing-section-title">
            Simple, Transparent<br />
            <span className="text-gradient">Pricing for Every Team</span>
          </h2>
          <p className="landing-section-sub">
            Start free. Scale as you grow. No hidden fees, no vendor lock-in.
          </p>
        </div>

        <div className="pricing-grid">
          {PLANS.map((plan, i) => {
            const Icon = plan.icon;

            const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
              const { currentTarget, clientX, clientY } = e;
              const { left, top } = currentTarget.getBoundingClientRect();
              const x = clientX - left;
              const y = clientY - top;
              currentTarget.style.setProperty('--mouse-x', `${x}px`);
              currentTarget.style.setProperty('--mouse-y', `${y}px`);
            };

            return (
                <motion.div
                  key={plan.name}
                  className={`pricing-card ${plan.popular ? 'pricing-card--popular' : ''}`}
                  custom={i}
                  initial="hidden"
                  whileInView="visible"
                  viewport={{ once: true, margin: '-60px' }}
                  variants={cardVariants}
                  onMouseMove={handleMouseMove}
                  whileHover={{ 
                    y: -8,
                    transition: { duration: 0.3 }
                  }}
                >
                <div className="pricing-spotlight" />
                {plan.popular && (
                  <div className="popular-badge">Most Popular</div>
                )}

                <div className="plan-top">
                  <div className="plan-icon">
                    <Icon size={20} />
                  </div>
                  <div>
                    <h3 className="plan-name">{plan.name}</h3>
                    <p className="plan-desc">{plan.desc}</p>
                  </div>
                </div>

                <div className="plan-price">
                  <span className="price-val">{plan.price}</span>
                  <span className="price-period">{plan.period}</span>
                </div>

                <ul className="plan-features">
                  {plan.features.map(f => (
                    <li key={f} className="plan-feature">
                      <Check size={14} className="check-icon" style={{ color: plan.color }} />
                      {f}
                    </li>
                  ))}
                </ul>

                <MotionLink
                  to="/signup"
                  className={`plan-cta ${plan.popular ? 'plan-cta--primary' : 'plan-cta--ghost'}`}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  {plan.cta}
                </MotionLink>
              </motion.div>
            );
          })}
        </div>

        <p className="pricing-note">
          All plans include a 14-day free trial. No credit card required.
        </p>
      </div>
    </section>
  );
}
