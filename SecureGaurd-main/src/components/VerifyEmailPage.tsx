import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Mail, Loader2, CheckCircle2, XCircle } from 'lucide-react';
import { apiUrl } from '../config/api';
import { resendVerification } from '../services/authService';
import './AuthPage.css';

// SEC-09 — verification landing page. The email link points here (not at
// the backend API, which only returns JSON); this page POSTs the token and
// shows the result. An expired/invalid token offers a resend by email.
export default function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') || '';
  const [status, setStatus] = useState<'idle' | 'verifying' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const [email, setEmail] = useState('');
  const [resending, setResending] = useState(false);
  const [resendMessage, setResendMessage] = useState('');

  const verify = async () => {
    if (!token) {
      setStatus('error');
      setMessage('No verification token was provided. Request a new link below.');
      return;
    }
    setStatus('verifying');
    try {
      const res = await fetch(apiUrl('/api/auth/verify-email'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || 'Verification failed.');
      setStatus('success');
      setMessage(data.message || 'Email verified successfully.');
    } catch (err: unknown) {
      setStatus('error');
      setMessage(err instanceof Error ? err.message : 'Verification failed.');
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    setResending(true);
    setResendMessage('');
    try {
      const data = await resendVerification(email);
      setResendMessage(data.message);
    } catch (err: unknown) {
      setResendMessage(err instanceof Error ? err.message : 'Could not resend the verification email.');
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="auth-container">
      <Link to="/" className="back-link">← Return to Home</Link>
      <div className="auth-card glass-card">
        <div className="auth-header">
          <Link to="/" className="auth-brand">SecureGuard</Link>
          <h1 className="auth-title">Verify your email</h1>
          <p className="auth-subtitle">Confirm your email address to activate your account.</p>
        </div>

        {status === 'success' && (
          <div className="auth-alert auth-alert--success" role="status">
            <CheckCircle2 size={16} style={{ verticalAlign: '-3px', marginRight: '0.4rem' }} />
            {message} You can now sign in.
          </div>
        )}
        {status === 'error' && (
          <div className="auth-alert auth-alert--error" role="alert">{message}</div>
        )}

        {status === 'idle' && (
          <button type="button" className="auth-submit-btn" onClick={() => void verify()}>
            <Mail size={15} /> Verify my email
          </button>
        )}
        {status === 'verifying' && (
          <button type="button" className="auth-submit-btn" disabled>
            <span className="btn-loading"><Loader2 size={16} className="spin" /> Verifying…</span>
          </button>
        )}
        {status === 'success' && (
          <Link to="/login" className="auth-submit-btn" style={{ display: 'flex', justifyContent: 'center', textDecoration: 'none' }}>
            Sign in
          </Link>
        )}

        {status === 'error' && (
          <form className="auth-form" onSubmit={handleResend} style={{ marginTop: '1rem' }}>
            <div className="form-group">
              <label htmlFor="verify-resend-email">Request a new verification link</label>
              <input type="email" id="verify-resend-email" placeholder="jane@company.com" value={email}
                onChange={e => setEmail(e.target.value)} required />
            </div>
            <button type="submit" className="auth-submit-btn" disabled={resending}>
              {resending ? 'Sending…' : 'Resend verification email'}
            </button>
            {resendMessage && <p className="auth-alert auth-alert--success" role="status">{resendMessage}</p>}
            <Link to="/login" className="toggle-mode-btn" style={{ marginTop: '0.5rem', display: 'block', textAlign: 'center' }}>
              ← Back to Login
            </Link>
          </form>
        )}
      </div>
    </div>
  );
}
