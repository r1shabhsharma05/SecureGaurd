import { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { Shield, Zap, Eye, Lock, GitBranch, Bell } from 'lucide-react';
import './Features.css';

gsap.registerPlugin(ScrollTrigger);

const FEATURES = [
  {
    icon: Zap,
    color: '#F59E0B',
    title: 'Real-Time AI Scanning',
    desc: 'Every commit triggers an instant AI-powered scan. Vulnerabilities are flagged before code ever merges.',
  },
  {
    icon: Eye,
    color: '#8B5CF6',
    title: 'Secret Detection',
    desc: 'Automatically identify exposed API keys, tokens, and credentials across your entire codebase history.',
  },
  {
    icon: Lock,
    color: '#10B981',
    title: 'Zero-Day Intelligence',
    desc: 'Our AI is trained on 50M+ CVEs and threat patterns, keeping you protected against emerging exploits.',
  },
  {
    icon: GitBranch,
    color: '#0055FF',
    title: 'CI/CD Integration',
    desc: 'Native plugins for GitHub Actions, GitLab CI, Jenkins, and CircleCI. Block merges on critical findings.',
  },
  {
    icon: Bell,
    color: '#EF4444',
    title: 'Intelligent Alerting',
    desc: 'Smart deduplication and severity scoring means no alert fatigue. Only what matters, when it matters.',
  },
  {
    icon: Shield,
    color: '#06B6D4',
    title: 'Compliance Reporting',
    desc: 'Auto-generate SOC 2, ISO 27001, and OWASP compliance reports with one click.',
  },
];

const cardVariants = {
  hidden: { opacity: 0, y: 40 },
  visible: i => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.1, duration: 0.5, ease: 'easeOut' },
  }),
};

export default function Features() {
  const sectionRef = useRef(null);

  useEffect(() => {
    gsap.fromTo('.features-header',
      { opacity: 0, y: 40 },
      {
        opacity: 1, y: 0, duration: 0.7, ease: 'power3.out',
        scrollTrigger: { trigger: '.features-header', start: 'top 85%' },
      }
    );
  }, []);

  return (
    <section id="features" className="features-section section-padding" ref={sectionRef}>
      <div className="container">
        <div className="features-header">
          <span className="landing-section-eyebrow">Why SecureGuard</span>
          <h2 className="landing-section-title">
            Security That Works<br />
            <span className="text-gradient">At the Speed of Code</span>
          </h2>
          <p className="landing-section-sub">
            Stop chasing vulnerabilities after the fact. SecureGuard integrates directly into
            your workflow so security is never an afterthought.
          </p>
        </div>

        <div className="features-grid">
          {FEATURES.map((f, i) => {
            const Icon = f.icon;
            
            const handleMouseMove = (e) => {
              const { currentTarget, clientX, clientY } = e;
              const { left, top } = currentTarget.getBoundingClientRect();
              const x = clientX - left;
              const y = clientY - top;
              currentTarget.style.setProperty('--mouse-x', `${x}px`);
              currentTarget.style.setProperty('--mouse-y', `${y}px`);
            };

            return (
              <motion.div
                key={f.title}
                className="feature-card glass-card"
                custom={i}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true, margin: '-60px' }}
                variants={cardVariants}
                onMouseMove={handleMouseMove}
                whileHover={{ 
                  y: -10,
                  rotateX: 2,
                  rotateY: -2,
                  transition: { duration: 0.3 }
                }}
                style={{
                  perspective: '1000px'
                }}
              >
                <div className="feature-spotlight" />
                
                <div className="feature-content">
                  <div className="feature-icon-wrap">
                    <Icon size={20} style={{ color: f.color }} />
                  </div>
                  <h3 className="feature-title">{f.title}</h3>
                  <p className="feature-desc">{f.desc}</p>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
