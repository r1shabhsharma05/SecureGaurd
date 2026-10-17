import { motion } from 'framer-motion';
import { Star } from 'lucide-react';
import './Testimonials.css';

const QUOTES = [
  {
    name: 'Sarah Chen',
    role: 'Staff Engineer @ Stripe',
    avatar: 'SC',
    color: '#2563eb',
    quote: "SecureGuard caught a critical SQL injection in a PR that passed all our existing tests. It's now non-negotiable in our pipeline.",
    stars: 5,
  },
  {
    name: 'Marcus Webb',
    role: 'CTO @ Vercel',
    avatar: 'MW',
    color: '#10b981',
    quote: "We evaluated 6 tools. SecureGuard was the only one that scanned our monorepo in under a minute with zero false positives in the first week.",
    stars: 5,
  },
  {
    name: 'Priya Nair',
    role: 'Security Lead @ Linear',
    avatar: 'PN',
    color: '#8b5cf6',
    quote: "The secret detection alone paid for itself on day one. We found a leaked prod key from 18 months ago across a former developer's commits.",
    stars: 5,
  },
  {
    name: 'Tomas Havel',
    role: 'Platform Engineer',
    avatar: 'TH',
    color: '#f59e0b',
    quote: "I was skeptical about AI security tools, but SecureGuard's context-aware scanning is genuinely impressive. Low noise, high signal.",
    stars: 5,
  },
  {
    name: 'Anya Ivanova',
    role: 'DevSecOps @ Figma',
    avatar: 'AI',
    color: '#ef4444',
    quote: "Our SOC 2 audit went flawlessly this year. The automated compliance reports saved our team weeks of manual documentation work.",
    stars: 5,
  },
  {
    name: 'James Okonkwo',
    role: 'Lead Dev @ Notion',
    avatar: 'JO',
    color: '#06b6d4',
    quote: "The Jira integration is seamless. Vulnerabilities flow directly into our sprint backlog with severity labels. Security is now part of velocity.",
    stars: 5,
  },
];

const cardVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: i => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.08, duration: 0.5, ease: 'easeOut' },
  }),
};

export default function Testimonials() {
  return (
    <section id="testimonials" className="testimonials-section section-padding">
      <div className="container">
        <div className="testimonials-header">
          <span className="section-eyebrow">Social Proof</span>
          <h2 className="section-title">
            Loved by Security-First<br />
            <span className="text-gradient">Engineering Teams</span>
          </h2>
          <p className="section-sub">
            Join thousands of developers who ship safer code every day with SecureGuard.
          </p>
        </div>

        <div className="testimonials-grid">
          {QUOTES.map((q, i) => (
            <motion.div
              key={q.name}
              className="testimonial-card"
              custom={i}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true, margin: '-40px' }}
              variants={cardVariants}
              whileHover={{ y: -5, transition: { duration: 0.25 } }}
            >
              <div className="t-stars">
                {Array.from({ length: q.stars }).map((_, si) => (
                  <Star key={si} size={14} fill="#f59e0b" color="#f59e0b" />
                ))}
              </div>
              <p className="t-quote">"{q.quote}"</p>
              <div className="t-author">
                <div className="t-avatar" style={{ background: `${q.color}20`, color: q.color, borderColor: `${q.color}30` }}>
                  {q.avatar}
                </div>
                <div>
                  <div className="t-name">{q.name}</div>
                  <div className="t-role">{q.role}</div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
