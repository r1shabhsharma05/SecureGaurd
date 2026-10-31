import { Link } from 'react-router-dom';
import { useConsent } from './CookieConsent';
import './Footer.css';

// Day 8 — footer links are all real destinations. The previous footer linked
// every item to "#" and claimed "SOC 2 Certified / ISO 27001" badges the
// product does not hold; both are fixed here. Privacy Policy and Terms of
// Service pages are Day 9's scope and are deliberately NOT linked until
// they exist — no dead links.
const GITHUB_REPO_URL = 'https://github.com/r1shabhsharma05/SecureGaurd';

const COLUMNS: Array<{ title: string; links: Array<{ label: string; to?: string; href?: string }> }> = [
  {
    title: 'Product',
    links: [
      { label: 'Features', to: '/#features' },
      { label: 'How It Works', to: '/#how-it-works' },
      { label: 'Pricing', to: '/#pricing' },
      { label: 'Contact', to: '/contact' },
    ],
  },
  {
    title: 'Account',
    links: [
      { label: 'Sign up', to: '/signup' },
      { label: 'Log in', to: '/login' },
      { label: 'Dashboard', to: '/dashboard' },
      { label: 'Get started', to: '/onboarding' },
    ],
  },
  {
    title: 'Developers',
    links: [
      { label: 'GitHub repository', href: GITHUB_REPO_URL },
      { label: 'Contact', to: '/contact' },
    ],
  },
];

export default function Footer() {
  const { openPreferences } = useConsent();

  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-top">
          <div className="footer-brand">
            <Link to="/" className="footer-logo">
              <picture>
                <source srcSet="/logo.webp" type="image/webp" />
                <img src="/logo.png" alt="SecureGuard Logo" className="logo-img" width={32} height={32} loading="lazy" decoding="async" />
              </picture>
              <span>Secure<strong>Guard</strong></span>
            </Link>
            <p className="footer-tagline">
              AI-powered security for modern engineering teams. Shift left, ship safe.
            </p>
            <div className="footer-socials">
              <a href={GITHUB_REPO_URL} target="_blank" rel="noreferrer" aria-label="SecureGuard on GitHub">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
              </a>
            </div>
          </div>

          <div className="footer-links-grid">
            {COLUMNS.map((col) => (
              <div key={col.title} className="footer-col">
                <h4 className="footer-col-title">{col.title}</h4>
                <ul>
                  {col.links.map((link) => (
                    <li key={link.label}>
                      {link.href ? (
                        <a href={link.href} target="_blank" rel="noreferrer">{link.label}</a>
                      ) : (
                        <Link to={link.to ?? '/'}>{link.label}</Link>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            <div className="footer-col">
              <h4 className="footer-col-title">Privacy</h4>
              <ul>
                <li>
                  <button type="button" className="footer-link-button" onClick={openPreferences}>
                    Cookie Settings
                  </button>
                </li>
                <li>
                  <Link to="/contact">Contact</Link>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div className="footer-bottom">
          <span className="footer-copy">© 2026 SecureGuard. All rights reserved.</span>
          <div className="footer-bottom-badges">
            <span>Compliance reports: SOC 2 · HIPAA · PCI DSS · GDPR</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
