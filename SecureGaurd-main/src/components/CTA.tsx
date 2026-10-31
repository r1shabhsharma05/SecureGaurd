import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowRight, Shield } from 'lucide-react';
import './CTA.css';

const MotionLink = motion.create(Link);

export default function CTA() {
  return (
    <section className="cta-section section-padding">
      <div className="container">
        <motion.div
          className="cta-card"
          initial={{ opacity: 0, scale: 0.96 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        >
          <div className="cta-bg-orb cta-bg-orb--left" />
          <div className="cta-bg-orb cta-bg-orb--right" />

          <div className="cta-shield">
            <Shield size={40} />
            <div className="cta-pulse-ring" />
            <div className="cta-pulse-ring" style={{ animationDelay: '0.7s' }} />
          </div>

          <h2 className="cta-title">
            Ready to Ship<br />
            <span className="text-gradient">Vulnerability-Free?</span>
          </h2>

          <p className="cta-sub">
            Join 50,000+ developers who've made security part of their workflow.
            Set up in under 60 seconds. No credit card required.
          </p>

          <div className="cta-actions">
            <MotionLink
              to="/signup"
              className="cta-btn-main"
              onMouseMove={(e) => {
                const { currentTarget, clientX, clientY } = e;
                const { left, top, width, height } = currentTarget.getBoundingClientRect();
                const x = (clientX - (left + width / 2)) * 0.2;
                const y = (clientY - (top + height / 2)) * 0.2;
                currentTarget.style.transform = `translate(${x}px, ${y}px)`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = `translate(0px, 0px)`;
              }}
              whileHover={{ scale: 1.05, boxShadow: '0 0 40px rgba(37,99,235,0.6)' }}
              whileTap={{ scale: 0.95 }}
            >
              Start Free Trial
              <ArrowRight size={16} />
            </MotionLink>
            <Link to="/contact" className="cta-link">
              Talk to Sales →
            </Link>
          </div>

          <div className="cta-badges">
            {/* Day 8: badges name the compliance REPORTS the product generates,
                not certifications it does not hold. */}
            {['Compliance reports: SOC 2 · HIPAA · PCI DSS · GDPR', 'No data training'].map(b => (
              <span key={b} className="cta-badge">
                <span className="cta-badge-dot" />
                {b}
              </span>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
