import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, useInView, animate } from 'framer-motion';
import { gsap } from 'gsap';
import { prefersReducedMotion } from '../utils/reducedMotion';
import { Shield, ArrowRight, Play } from 'lucide-react';
import './Hero.css';

const MotionLink = motion.create(Link);

const SCAN_LINES = [
  { type: 'vuln', file: 'auth/login.js', msg: 'SQL Injection — HIGH', delay: 0.3 },
  { type: 'secret', file: 'config/db.js', msg: 'Exposed API Key — CRITICAL', delay: 0.6 },
  { type: 'ok', file: 'services/payment.js', msg: 'No vulnerabilities found', delay: 0.9 },
  { type: 'vuln', file: 'routes/user.js', msg: 'XSS Vulnerability — MEDIUM', delay: 1.2 },
  { type: 'ok', file: 'utils/validator.js', msg: 'Clean — 0 issues', delay: 1.5 },
];

const BADGE_VARIANTS = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' } },
};

// Animated count-up: 0 → target with easeOutExpo when scrolled into view
function CountUp({ to, decimals = 0, prefix = '', suffix = '', duration = 1.8 }: {
  to: number; decimals?: number; prefix?: string; suffix?: string; duration?: number;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: '-40px' });
  const [val, setVal] = useState(0);

  useEffect(() => {
    if (!inView) return;
    const controls = animate(0, to, {
      duration,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v: number) => setVal(v),
    });
    return () => controls.stop();
  }, [inView, to, duration]);

  return (
    <span ref={ref}>
      {prefix}
      {val.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}
      {suffix}
    </span>
  );
}

const STATS: { to: number; decimals?: number; prefix?: string; suffix?: string; lbl: string }[] = [
  { to: 10, suffix: 'M+', lbl: 'Vulnerabilities Found' },
  { to: 50, suffix: 'K+', lbl: 'Repos Protected' },
  { to: 99.9, decimals: 1, suffix: '%', lbl: 'Uptime SLA' },
  { to: 50, prefix: '<', suffix: 'ms', lbl: 'Avg Scan Time' },
];

export default function Hero() {
  const lineRef = useRef(null);
  const scanRef = useRef(null);

  useEffect(() => {
    // Day 8: under prefers-reduced-motion, skip the GSAP entrance + pulse
    // entirely — content renders in its final state. (framer-motion parts
    // are covered by <MotionConfig reducedMotion="user"> in App.tsx.)
    if (prefersReducedMotion()) return;
    const tl = gsap.timeline({ delay: 0.8 });
    tl.fromTo('.hero-badge', { opacity: 0, y: 20 }, { opacity: 1, y: 0, duration: 0.5, ease: 'back.out(1.7)' })
      .fromTo('.hero-headline', { opacity: 0, y: 40 }, { opacity: 1, y: 0, duration: 0.7, ease: 'power3.out' }, '-=0.2')
      .fromTo('.hero-sub', { opacity: 0, y: 30 }, { opacity: 1, y: 0, duration: 0.6, ease: 'power3.out' }, '-=0.4')
      .fromTo('.hero-cta', { opacity: 0, y: 20 }, { opacity: 1, y: 0, duration: 0.5, ease: 'power3.out', stagger: 0.1 }, '-=0.3');

    // Scan animation entrance
    gsap.fromTo(scanRef.current,
      { opacity: 0, x: 60, scale: 0.95 },
      { opacity: 1, x: 0, scale: 1, duration: 0.8, ease: 'power3.out', delay: 1.4 }
    );

    // Particle pulse on the shield
    gsap.to('.pulse-ring', {
      scale: 2,
      opacity: 0,
      duration: 2,
      ease: 'power2.out',
      repeat: -1,
      stagger: 0.7,
    });
  }, []);

  return (
    <section className="hero-section">
      {/* Radial background glow */}
      <div className="hero-bg-glow" />

      <div className="container hero-grid">
        {/* LEFT CONTENT */}
        <div className="hero-content">
          <div className="hero-badge">
            <span className="badge-dot" />
            AI-Powered Security · Real-Time Scanning
          </div>

          <h1 className="hero-headline">
            Secure Your Code<br />
            <span className="text-gradient">Before You Ship</span>
          </h1>

          <p className="hero-sub">
            SecureGuard uses advanced AI to scan every commit, detect vulnerabilities,
            exposed secrets, and misconfigurations in milliseconds — not hours.
          </p>

          <div className="hero-cta">
            <MotionLink
              to="/signup"
              className="cta-btn-primary"
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
              whileHover={{ scale: 1.05, boxShadow: '0 0 32px rgba(37,99,235,0.6)' }}
              whileTap={{ scale: 0.95 }}
            >
              <div className="btn-shimmer" />
              Start Free Trial
              <ArrowRight size={16} />
            </MotionLink>

            <motion.a
              href="#how-it-works"
              className="cta-btn-ghost"
              onMouseMove={(e) => {
                const { currentTarget, clientX, clientY } = e;
                const { left, top, width, height } = currentTarget.getBoundingClientRect();
                const x = (clientX - (left + width / 2)) * 0.15;
                const y = (clientY - (top + height / 2)) * 0.15;
                currentTarget.style.transform = `translate(${x}px, ${y}px)`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = `translate(0px, 0px)`;
              }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Play size={14} className="play-icon" />
              Watch Demo
            </motion.a>
          </div>
        </div>

        {/* RIGHT PANEL — SCAN TERMINAL */}
        <div className="hero-visual" ref={scanRef}>
          <div className="scan-card glass-card">
            {/* Scanning beam */}
            <div className="scan-beam" />
            <div className="scan-card-header">
              <div className="scan-dots">
                <span style={{ background: '#ef4444' }} />
                <span style={{ background: '#f59e0b' }} />
                <span style={{ background: '#10b981' }} />
              </div>
              <span className="scan-title">secureguard scan --watch</span>
              <div className="scan-live">
                <span className="live-dot" />
                LIVE
              </div>
            </div>

            <div className="scan-body">
              {SCAN_LINES.map((line, i) => (
                <motion.div
                  key={i}
                  className={`scan-row scan-row--${line.type}`}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 1.6 + line.delay, duration: 0.4, ease: 'easeOut' }}
                >
                  <span className="scan-indicator">
                    {line.type === 'ok' ? '✓' : line.type === 'vuln' ? '⚠' : '⛔'}
                  </span>
                  <span className="scan-file">{line.file}</span>
                  <span className="scan-msg">{line.msg}</span>
                </motion.div>
              ))}

              <motion.div
                className="scan-row scan-row--cursor"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 3.2 }}
              >
                <span className="scan-indicator">›</span>
                <span className="scan-cursor blink">Analyzing 1,247 files...</span>
              </motion.div>
            </div>

            <div className="scan-summary">
              <div className="summary-stat">
                <span className="stat-val" style={{ color: 'var(--accent-red)' }}>3</span>
                <span className="stat-lbl">Critical</span>
              </div>
              <div className="summary-divider" />
              <div className="summary-stat">
                <span className="stat-val" style={{ color: 'var(--accent-yellow)' }}>7</span>
                <span className="stat-lbl">Warnings</span>
              </div>
              <div className="summary-divider" />
              <div className="summary-stat">
                <span className="stat-val" style={{ color: 'var(--accent-green)' }}>1,237</span>
                <span className="stat-lbl">Clean</span>
              </div>
            </div>
          </div>

          {/* Floating badges */}
          <motion.div
            className="floating-badge fb-top"
            animate={{ y: [0, -8, 0] }}
            transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
          >
            <Shield size={14} />
            Zero-day protection
          </motion.div>

          <motion.div
            className="floating-badge fb-bottom"
            animate={{ y: [0, 8, 0] }}
            transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut', delay: 1 }}
          >
            ⚡ &lt;50ms scan time
          </motion.div>
        </div>
      </div>

      {/* Stats bar */}
      <motion.div
        className="hero-stats container"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 2.2, duration: 0.6 }}
      >
        {STATS.map(s => (
          <div key={s.lbl} className="stat-item">
            <span className="stat-value">
              <CountUp
                to={s.to}
                decimals={s.decimals ?? 0}
                prefix={s.prefix ?? ''}
                suffix={s.suffix ?? ''}
              />
            </span>
            <span className="stat-label">{s.lbl}</span>
          </div>
        ))}
      </motion.div>
    </section>
  );
}
