import React, { useState, useEffect } from 'react';
import { ArrowLeft, Check, Eye, EyeOff, Loader2, Mail, ArrowRight } from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { requestPasswordReset, resetPassword } from '../services/authService';
import { trackEvent } from '../utils/analytics';
import { apiUrl } from '../config/api';
import TurnstileWidget, { isTurnstileEnabled } from './TurnstileWidget';
import './AuthPage.css';

interface AuthPageProps {
  defaultMode: 'signup' | 'login' | 'forgot';
}

const AuthPage: React.FC<AuthPageProps> = ({ defaultMode }) => {
  const [mode, setMode]       = useState<'signup' | 'login' | 'forgot' | 'reset'>(defaultMode);
  const [agreed, setAgreed]   = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const [success, setSuccess] = useState('');

  // Form fields
  const [firstName, setFirstName] = useState('');
  const [lastName,  setLastName]  = useState('');
  const [email,     setEmail]     = useState('');
  const [password,  setPassword]  = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [resetToken,  setResetToken]  = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  // Day 9 — Turnstile token, tagged with the form mode that minted it: a
  // token minted for one mode must not leak into another (single-use, and
  // the widget remounts on mode change). Derived, not an effect.
  const [captcha, setCaptcha] = useState<{ mode: string; token: string } | null>(null);
  const captchaToken = captcha && captcha.mode === mode ? captcha.token : null;
  const [captchaKey, setCaptchaKey] = useState(0);
  const captchaEnabled = isTurnstileEnabled();

  // Day 10 — SSO providers configured on the server. The list comes from
  // the backend, so a button only ever renders for a provider that is
  // actually configured (no dead buttons). Empty list = no SSO section.
  // (Fetched by the effect below, after `location` is declared.)
  const [ssoProviders, setSsoProviders] = useState<{ provider: string; label: string }[]>([]);

  const location = useLocation();
  const navigate  = useNavigate();
  const { login, register, user } = useAuth();

  // Day 10 — OAuth error from a failed provider sign-in, derived from the
  // URL (no effect, no setState): the backend redirects here with
  // ?oauth_error=<code> when the provider flow fails.
  const oauthErrorMessages: Record<string, string> = {
    provider_error: 'Sign-in with your provider failed. Please try again, or use email and password.',
    failed: 'Sign-in with your provider failed. Please try again, or use email and password.',
    email_not_verified: 'Your provider account email is not verified. Verify it with your provider, then try again.',
    account_link_conflict: 'That email is already linked to a different provider account. Sign in with email and password instead.',
    invalid_state: 'Your sign-in session expired. Please try again.',
    provider_not_configured: 'That sign-in method is not configured yet.',
  };
  const oauthErrorCode = new URLSearchParams(location.search).get('oauth_error');
  const oauthErrorText = oauthErrorCode
    ? (oauthErrorMessages[oauthErrorCode] || 'Sign-in with your provider failed. Please try again.')
    : '';

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(apiUrl('/api/auth/oauth/providers'));
        if (res.ok && !cancelled) {
          const data = await res.json();
          setSsoProviders(Array.isArray(data.providers) ? data.providers : []);
        }
      } catch { /* SSO stays hidden when the list cannot load */ }
    })();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    setMode(defaultMode);
    setError('');
    setSuccess('');
  }, [defaultMode, location.pathname]);

  // Redirect after successful login based on onboarding status.
  // Honors a ?redirect= param (e.g. from an invite link) when it is a safe
  // same-origin path — protocol-relative or absolute URLs are never followed.
  useEffect(() => {
    if (user && success.includes('Login successful')) {
      const timer = setTimeout(() => {
        if (user.onboardingCompleted) {
          const redirect = new URLSearchParams(location.search).get('redirect');
          if (redirect && redirect.startsWith('/') && !redirect.startsWith('//')) {
            navigate(redirect);
          } else {
            navigate('/dashboard');
          }
        } else {
          navigate('/onboarding');
        }
      }, 800);
      return () => clearTimeout(timer);
    }
  }, [user, success, navigate, location.search]);

  // ── Login / Register ────────────────────────────────────────────────────────
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (mode === 'signup' && !agreed) {
      setError('You must agree to the Terms of Service to continue.');
      return;
    }

    if (mode === 'signup' && captchaEnabled && !captchaToken) {
      setError('Please complete the security check before continuing.');
      return;
    }

    setLoading(true);
    try {
      if (mode === 'login') {
        await login(email, password);
        setSuccess('Login successful! Redirecting…');
        // After login, user state is updated — use a small delay then check
        // Note: we navigate in useEffect below based on updated user state
      } else {
        await register(firstName, lastName, email, password, captchaToken ?? undefined);
        setSuccess('Account created! Redirecting to setup…');
        trackEvent('signup_completed');
        // New users always go to onboarding
        setTimeout(() => navigate('/onboarding'), 1000);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.');
      // The captcha token is single-use: mint a fresh one for the retry.
      setCaptcha(null);
      setCaptchaKey((k) => k + 1);
    } finally {
      setLoading(false);
    }
  };

  // ── Forgot Password ─────────────────────────────────────────────────────────
  const handleForgotSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (captchaEnabled && !captchaToken) {
      setError('Please complete the security check before continuing.');
      return;
    }
    setLoading(true);
    try {
      const data = await requestPasswordReset(email, captchaToken ?? undefined);
      setSuccess('Reset token generated! Check the response or your email.');
      // In dev: auto-fill token from response
      if (data.resetToken) setResetToken(data.resetToken);
      setTimeout(() => setMode('reset'), 1500);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.');
      setCaptcha(null);
      setCaptchaKey((k) => k + 1);
    } finally {
      setLoading(false);
    }
  };

  // ── Reset Password ──────────────────────────────────────────────────────────
  const handleResetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    setLoading(true);
    try {
      await resetPassword(resetToken, newPassword);
      setSuccess('Password reset! Redirecting to login…');
      setTimeout(() => { setMode('login'); setSuccess(''); }, 2000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong.');
    } finally {
      setLoading(false);
    }
  };

  // ── Titles ──────────────────────────────────────────────────────────────────
  const titles = {
    login:  { h: 'Welcome back',         sub: 'Enter your details to access your dashboard.' },
    signup: { h: 'Create an account',    sub: 'Start your 14-day free trial. No credit card required.' },
    forgot: { h: 'Forgot your password?',sub: 'Enter your email and we\'ll send a reset link.' },
    reset:  { h: 'Reset your password',  sub: 'Enter the reset token and your new password.' },
  };
  const { h, sub } = titles[mode];

  return (
    <div className="auth-container">
      <Link to="/" className="back-link">
        <ArrowLeft size={16} />
        <span>Return to Home</span>
      </Link>

      <div className="auth-card glass-card">
        <div className="auth-header">
          <Link to="/" className="auth-brand">SecureGuard</Link>
          <h1 className="auth-title">{h}</h1>
          <p className="auth-subtitle">{sub}</p>
        </div>

        {error   && <div className="auth-alert auth-alert--error">{error}</div>}
        {success && <div className="auth-alert auth-alert--success">{success}</div>}
        {!error && oauthErrorText && <div className="auth-alert auth-alert--error">{oauthErrorText}</div>}

        {/* ── Login / Register ─── */}
        {(mode === 'login' || mode === 'signup') && (
          <form className="auth-form" onSubmit={handleAuthSubmit} autoComplete="off">
            {mode === 'signup' && (
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="firstName">First Name</label>
                  <input type="text" id="firstName" placeholder="Jane" value={firstName}
                    onChange={e => setFirstName(e.target.value)} required autoComplete="off" />
                </div>
                <div className="form-group">
                  <label htmlFor="lastName">Last Name</label>
                  <input type="text" id="lastName" placeholder="Doe" value={lastName}
                    onChange={e => setLastName(e.target.value)} required autoComplete="off" />
                </div>
              </div>
            )}

            <div className="form-group">
              <label htmlFor="email">Work Email</label>
              <input type="email" id="email" placeholder="jane@company.com" value={email}
                onChange={e => setEmail(e.target.value)} required autoComplete="off" />
            </div>

            <div className="form-group">
              <div className="label-row">
                <label htmlFor="password">Password</label>
                {mode === 'login' && (
                  <button type="button" className="forgot-password" onClick={() => setMode('forgot')}>
                    Forgot password?
                  </button>
                )}
              </div>
              <div className="password-input-wrap">
                <input type={showPassword ? 'text' : 'password'} id="password" placeholder="••••••••" value={password}
                  onChange={e => setPassword(e.target.value)} required autoComplete="new-password"
                  minLength={8} />
                <button type="button" className="password-toggle" onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}>
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {mode === 'signup' && (
              <>
                <TurnstileWidget
                  key={`captcha-${mode}-${captchaKey}`}
                  onVerify={(token) => setCaptcha({ mode, token })}
                  onExpire={() => setCaptcha(null)}
                  onError={() => setCaptcha(null)}
                />
                <div className="checkbox-group" onClick={() => setAgreed(!agreed)}>
                  <div className={`checkbox ${agreed ? 'checked' : ''}`}>
                    {agreed && <Check size={12} strokeWidth={3} />}
                  </div>
                  <span className="checkbox-label">
                    I agree to the{' '}
                    <Link to="/terms" target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>Terms of Service</Link>
                    {' & '}
                    <Link to="/privacy" target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>Privacy Policy</Link>
                  </span>
                </div>
              </>
            )}

            <button type="submit" className="auth-submit-btn" disabled={loading}>
              {loading
                ? <span className="btn-loading"><Loader2 size={16} className="spin" /> Processing…</span>
                : mode === 'login' ? 'Sign In' : 'Start Free Trial'
              }
            </button>
          </form>
        )}

        {/* ── SSO (Day 10): only providers the backend reports configured ── */}
        {(mode === 'login' || mode === 'signup') && ssoProviders.length > 0 && (
          <div className="sso-section">
            <div className="sso-divider"><span>or continue with</span></div>
            <div className="sso-buttons">
              {ssoProviders.map((p) => (
                <a key={p.provider} className="sso-btn" href={apiUrl(`/api/auth/oauth/${p.provider}`)}>
                  Continue with {p.label}
                </a>
              ))}
            </div>
          </div>
        )}

        {/* ── Forgot Password ─── */}
        {mode === 'forgot' && (
          <form className="auth-form" onSubmit={handleForgotSubmit} autoComplete="off">
            <div className="form-group">
              <label htmlFor="forgot-email">Your Email</label>
              <input type="email" id="forgot-email" placeholder="jane@company.com" value={email}
                onChange={e => setEmail(e.target.value)} required />
            </div>
            <TurnstileWidget
              key={`captcha-${mode}-${captchaKey}`}
              onVerify={(token) => setCaptcha({ mode, token })}
              onExpire={() => setCaptcha(null)}
              onError={() => setCaptcha(null)}
            />
            <button type="submit" className="auth-submit-btn" disabled={loading}>
              {loading
                ? <span className="btn-loading"><Loader2 size={16} className="spin" /> Sending…</span>
                : <><Mail size={15} /> Send Reset Link</>
              }
            </button>
            <button type="button" className="toggle-mode-btn" style={{ marginTop: '0.5rem' }}
              onClick={() => setMode('login')}>
              ← Back to Login
            </button>
          </form>
        )}

        {/* ── Reset Password ─── */}
        {mode === 'reset' && (
          <form className="auth-form" onSubmit={handleResetSubmit} autoComplete="off">
            <div className="form-group">
              <label htmlFor="reset-token">Reset Token</label>
              <input type="text" id="reset-token" placeholder="Paste token from email" value={resetToken}
                onChange={e => setResetToken(e.target.value)} required />
            </div>
            <div className="form-group">
              <label htmlFor="new-password">New Password</label>
              <div className="password-input-wrap">
                <input type={showNewPassword ? 'text' : 'password'} id="new-password" placeholder="Min 8 characters" value={newPassword}
                  onChange={e => setNewPassword(e.target.value)} required minLength={8} />
                <button type="button" className="password-toggle" onClick={() => setShowNewPassword(!showNewPassword)}
                  aria-label={showNewPassword ? 'Hide new password' : 'Show new password'}>
                  {showNewPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>
            <button type="submit" className="auth-submit-btn" disabled={loading}>
              {loading
                ? <span className="btn-loading"><Loader2 size={16} className="spin" /> Resetting…</span>
                : <><ArrowRight size={15} /> Reset Password</>
              }
            </button>
          </form>
        )}

        {/* ── Footer toggle ─── */}
        {(mode === 'login' || mode === 'signup') && (
          <div className="auth-footer">
            <p>
              {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}
              <button className="toggle-mode-btn"
                onClick={() => { setMode(mode === 'login' ? 'signup' : 'login'); setError(''); setSuccess(''); }}>
                {mode === 'login' ? 'Sign up' : 'Log in'}
              </button>
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AuthPage;
