import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { GitCommit, ScanSearch, Bell, CheckCircle } from 'lucide-react';
import './HowItWorks.css';

gsap.registerPlugin(ScrollTrigger);

const STEPS = [
  {
    icon: GitCommit,
    num: '01',
    title: 'Connect Your Repo',
    desc: 'Install the SecureGuard GitHub App or CLI in under 60 seconds. No system access, no config files.',
    detail: 'Supports GitHub, GitLab, Bitbucket, and Azure DevOps. OAuth-based, zero friction.',
  },
  {
    icon: ScanSearch,
    num: '02',
    title: 'AI Scans Every Commit',
    desc: 'Our engine analyzes your diff, full history, and dependency tree on every push automatically.',
    detail: '17 vulnerability categories, SAST + SCA + secrets detection — all in one pass.',
  },
  {
    icon: Bell,
    num: '03',
    title: 'Get Actionable Alerts',
    desc: 'Receive prioritized findings in your PR as inline comments, Slack, or Jira tickets.',
    detail: 'Each alert includes a root-cause explanation, a code fix suggestion, and remediation docs.',
  },
  {
    icon: CheckCircle,
    num: '04',
    title: 'Ship With Confidence',
    desc: 'Gate your deployments with security quality checks. Merge only when the code is truly safe.',
    detail: 'Set thresholds by severity. Block, warn, or auto-remediate — your rules, your pipeline.',
  },
];

export default function HowItWorks() {
  const [activeStep, setActiveStep] = useState(0);
  const lineRef = useRef(null);

  useEffect(() => {
    gsap.fromTo('.how-header',
      { opacity: 0, y: 40 },
      {
        opacity: 1, y: 0, duration: 0.7, ease: 'power3.out',
        scrollTrigger: { trigger: '.how-header', start: 'top 85%' },
      }
    );

    // Progress line animation
    gsap.fromTo(lineRef.current,
      { scaleY: 0 },
      {
        scaleY: 1, duration: 1.5, ease: 'power2.out', transformOrigin: 'top',
        scrollTrigger: { trigger: '.how-steps', start: 'top 70%' },
      }
    );

    const interval = setInterval(() => {
      setActiveStep(s => (s + 1) % STEPS.length);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  return (
    <section id="how-it-works" className="how-section section-padding">
      <div className="container">
        <div className="how-header">
          <span className="landing-section-eyebrow">Simple by Design</span>
          <h2 className="landing-section-title">
            From Zero to<br />
            <span className="text-gradient">Fully Secured in 4 Steps</span>
          </h2>
        </div>

        <div className="how-layout">
          <div className="how-steps">
            <div className="steps-line-track">
              <div className="steps-line-fill" ref={lineRef} />
            </div>

            {STEPS.map((step, i) => {
              const Icon = step.icon;
              const isActive = activeStep === i;
              return (
                <motion.div
                  key={step.num}
                  className={`how-step ${isActive ? 'active' : ''}`}
                  onClick={() => setActiveStep(i)}
                  initial={{ opacity: 0, x: -30 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.15, duration: 0.5 }}
                >
                  <div className="step-icon-wrap">
                    <Icon size={18} />
                  </div>
                  <div className="step-content">
                    <span className="step-num">{step.num}</span>
                    <h3 className="step-title">{step.title}</h3>
                    <p className="step-desc">{step.desc}</p>
                  </div>
                </motion.div>
              );
            })}
          </div>

          <div className="how-visual">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeStep}
                className="how-visual-card"
                initial={{ opacity: 0, scale: 0.95, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95, y: -20 }}
                transition={{ duration: 0.4, ease: 'easeOut' }}
              >
                <div className="visual-step-num">{STEPS[activeStep].num}</div>
                <div className="visual-icon-large">
                  {(() => { const Icon = STEPS[activeStep].icon; return <Icon size={48} />; })()}
                </div>
                <h3 className="visual-title">{STEPS[activeStep].title}</h3>
                <p className="visual-detail">{STEPS[activeStep].detail}</p>

                <div className="step-indicator-dots">
                  {STEPS.map((_, i) => (
                    <button
                      key={i}
                      className={`indicator-dot ${i === activeStep ? 'active' : ''}`}
                      onClick={() => setActiveStep(i)}
                    />
                  ))}
                </div>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  );
}
