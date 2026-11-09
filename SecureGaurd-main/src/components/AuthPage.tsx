import React, { useState, useEffect } from 'react';
import { ArrowLeft, Eye, EyeOff, Loader2, Mail, ArrowRight } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { requestPasswordReset, resetPassword } from '../services/authService';
import TurnstileWidget, { isTurnstileEnabled } from './TurnstileWidget';
import NeonAuth from './NeonAuth';
import './AuthPage.css';

interface AuthPageProps {
  defaultMode: 'signup' | 'login' | 'forgot';
}

const AuthPage: React.FC<AuthPageProps> = ({ defaultMode }) => {
  const [mode, setMode]       = useState<'signup' | 'login' | 'forgot' | 'reset'>(defaultMode);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const [success, setSuccess] = useState('');

  // Form fields (forgot / reset modes only — login / signup live in NeonAuth)
  const [email,     setEmail]     = useState('');
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

  const location = useLocation();

  // Day 10 — OAuth error from a failed provider sign-in, derived from the
  // URL (no effect, no setState): the backend redirects here with
  // ?oauth_error=<code> when the provider flow fails. Passed to NeonAuth,
  // which renders it above the login / signup form.
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
    setMode(defaultMode);
    setError('');
    setSuccess('');
  }, [defaultMode, location.pathname]);

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

  // ── Titles (forgot / reset only — login / signup titles live in NeonAuth) ──
  const titles = {
    forgot: { h: 'Forgot your password?', sub: 'Enter your email and we\'ll send a reset link.' },
    reset: { h: 'Reset your password', sub: 'Enter the reset token and your new password.' },
  };
  const { h, sub } = titles[mode as 'forgot' | 'reset'];

  // ── Login / Signup: neon lamp design (NeonAuth) with real SecureGuard auth ──
  if (mode === 'login' || mode === 'signup') {
    return (
      <NeonAuth
        mode={mode}
        oauthErrorText={oauthErrorText}
        onModeChange={(m) => { setMode(m); setError(''); setSuccess(''); }}
        onForgot={() => setMode('forgot')}
      />
    );
  }

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
      </div>
    </div>
  );
};

export default AuthPage;
