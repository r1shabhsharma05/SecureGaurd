import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { gsap } from 'gsap';
import { useAuth } from '../context/AuthContext';
import './Navbar.css';

const NAV_LINKS = [
  { label: 'Features', href: '#features' },
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Pricing', href: '#pricing' },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const navRef = useRef(null);
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  useEffect(() => {
    gsap.fromTo(navRef.current,
      { y: -80, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.8, ease: 'power3.out', delay: 0.2 }
    );

    const handleScroll = () => setScrolled(window.scrollY > 50);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <nav ref={navRef} className={`navbar ${scrolled ? 'scrolled' : ''}`}>
      <div className="navbar-inner container">
        <a href="/" className="navbar-logo">
          <img src="/logo.png" alt="SecureGuard Logo" className="logo-img" />
          <span>Secure<strong>Guard</strong></span>
        </a>

        <ul className={`navbar-links ${menuOpen ? 'open' : ''}`}>
          {NAV_LINKS.map(link => (
            <li key={link.label}>
              <a href={link.href} onClick={() => setMenuOpen(false)}>{link.label}</a>
            </li>
          ))}
        </ul>

        <div className="navbar-actions">
          {user ? (
            <>
              <Link to="/dashboard" className="btn-ghost">
                <span className="nav-avatar">{user.firstName[0]}{user.lastName[0]}</span>
                Dashboard
              </Link>
              <button className="btn-logout" onClick={handleLogout}>Log out</button>
            </>
          ) : (
            <>
              <Link to="/login" className="btn-ghost">Log in</Link>
              <Link
                to="/signup"
                className="btn-primary"
                onMouseMove={(e) => {
                  const { currentTarget, clientX, clientY } = e;
                  const { left, top, width, height } = currentTarget.getBoundingClientRect();
                  const x = (clientX - (left + width / 2)) * 0.25;
                  const y = (clientY - (top + height / 2)) * 0.25;
                  currentTarget.style.transform = `translate(${x}px, ${y}px)`;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = `translate(0px, 0px)`;
                }}
              >
                Start Free Trial
              </Link>
            </>
          )}
        </div>

        <button
          className={`hamburger ${menuOpen ? 'open' : ''}`}
          onClick={() => setMenuOpen(v => !v)}
          aria-label="Toggle menu"
        >
          <span /><span /><span />
        </button>
      </div>
    </nav>
  );
}

