import { useEffect, useState } from 'react';
import type { FC, FormEvent } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { AlertTriangle, Check, Eye, EyeOff, Loader2, ShieldCheck } from 'lucide-react';
import { resetPassword } from '../services/authService';
import { toErrorMessage } from '../services/ApiError';
import './ResetPasswordPage.css';

interface Props {
  token: string;
}

type Status = 'form' | 'submitting' | 'success' | 'error';

interface PasswordFieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  describedBy?: string;
}

function PasswordField({ id, label, value, onChange, describedBy }: PasswordFieldProps) {
  const [show, setShow] = useState(false);

  return (
    <div className="rp-field">
      <label htmlFor={id}>{label}</label>
      <div className="rp-input-wrap">
        <input
          type={show ? 'text' : 'password'}
          id={id}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder="••••••••"
          autoComplete="new-password"
          aria-required="true"
          aria-describedby={describedBy}
        />
        <button
          type="button"
          className="rp-toggle"
          onClick={() => setShow(!show)}
          aria-label={show ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}
          aria-pressed={show}
        >
          {show ? <EyeOff size={18} /> : <Eye size={18} />}
        </button>
      </div>
    </div>
  );
}

export const ResetPasswordPage: FC<Props> = ({ token }) => {
  const [status, setStatus] = useState<Status>('form');
  const [errorMessage, setErrorMessage] = useState('');
  const [pastedToken, setPastedToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const effectiveToken = token || pastedToken.trim();

  const requirements = [
    { label: 'At least 8 characters', ok: newPassword.length >= 8 },
    { label: 'Passwords match', ok: confirmPassword.length > 0 && confirmPassword === newPassword },
  ];
  const isValid = effectiveToken.length > 0 && requirements.every(r => r.ok);

  // Auto-redirect to login shortly after a successful reset.
  useEffect(() => {
    if (status !== 'success') return;
    const timer = setTimeout(() => {
      window.location.assign('/login');
    }, 3000);
    return () => clearTimeout(timer);
  }, [status]);

  const goToLogin = () => window.location.assign('/login');

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!isValid || status === 'submitting') return;

    setStatus('submitting');
    try {
      await resetPassword(effectiveToken, newPassword);
      setStatus('success');
    } catch (err: unknown) {
      setErrorMessage(toErrorMessage(err, 'Failed to reset password. Please try again.'));
      setStatus('error');
    }
  };

  const panelKey = status === 'success' ? 'success' : status === 'error' ? 'error' : 'form';

  return (
    <div className="rp-page">
      <motion.div
        className="rp-card"
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, ease: 'easeOut' }}
      >
        <AnimatePresence mode="wait">
          {panelKey === 'form' && (
            <motion.div
              key="form"
              className="rp-panel"
              initial={{ opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -24 }}
              transition={{ duration: 0.25, ease: 'easeOut' }}
            >
              <div className="rp-header">
                <motion.div
                  className="rp-icon-badge"
                  animate={{ scale: [1, 1.06, 1] }}
                  transition={{ duration: 2.6, repeat: Infinity, ease: 'easeInOut' }}
                >
                  <ShieldCheck size={26} />
                </motion.div>
                <h1 className="rp-title">Reset your password</h1>
                <p className="rp-subtitle">Choose a new password for your account.</p>
              </div>

              <form className="rp-form" onSubmit={handleSubmit} autoComplete="off">
                {!token && (
                  <div className="rp-field">
                    <label htmlFor="rp-token">Reset token</label>
                    <input
                      type="text"
                      id="rp-token"
                      value={pastedToken}
                      onChange={e => setPastedToken(e.target.value)}
                      placeholder="Paste the token from your email"
                      aria-required="true"
                    />
                  </div>
                )}

                <PasswordField
                  id="rp-new-password"
                  label="New password"
                  value={newPassword}
                  onChange={setNewPassword}
                  describedBy="rp-requirements"
                />
                <PasswordField
                  id="rp-confirm-password"
                  label="Confirm new password"
                  value={confirmPassword}
                  onChange={setConfirmPassword}
                  describedBy="rp-requirements"
                />

                <ul className="rp-reqs" id="rp-requirements" aria-label="Password requirements">
                  {requirements.map(req => (
                    <li key={req.label} className={`rp-req${req.ok ? ' rp-req--ok' : ''}`}>
                      <motion.span
                        className="rp-req-check"
                        key={String(req.ok)}
                        initial={{ scale: 0.6 }}
                        animate={{ scale: 1 }}
                        transition={{ type: 'spring', stiffness: 500, damping: 18 }}
                      >
                        <Check size={11} strokeWidth={3} />
                      </motion.span>
                      {req.label}
                    </li>
                  ))}
                </ul>

                <button type="submit" className="rp-btn" disabled={!isValid || status === 'submitting'}>
                  {status === 'submitting'
                    ? <span className="rp-btn-loading"><Loader2 size={16} className="rp-spin" /> Resetting…</span>
                    : 'Reset Password'}
                </button>
              </form>

              <button type="button" className="rp-link-btn" onClick={goToLogin}>
                Back to login
              </button>
            </motion.div>
          )}

          {panelKey === 'success' && (
            <motion.div
              key="success"
              className="rp-panel rp-panel--center"
              initial={{ opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -24 }}
              transition={{ duration: 0.25, ease: 'easeOut' }}
            >
              <svg className="rp-success-svg" viewBox="0 0 52 52" aria-hidden="true">
                <motion.circle
                  cx="26" cy="26" r="24" fill="none"
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 0.5, ease: 'easeOut' }}
                />
                <motion.path
                  d="M15 27l7.5 7.5L37 19" fill="none"
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 0.35, delay: 0.4, ease: 'easeOut' }}
                />
              </svg>
              <h1 className="rp-title">Password reset</h1>
              <p className="rp-message" aria-live="polite">
                Your password has been updated. Redirecting you to login…
              </p>
              <button type="button" className="rp-btn" onClick={goToLogin}>
                Go to login
              </button>
            </motion.div>
          )}

          {panelKey === 'error' && (
            <motion.div
              key="error"
              className="rp-panel rp-panel--center"
              initial={{ opacity: 0, x: 0 }}
              animate={{ opacity: 1, x: [0, -12, 12, -8, 8, 0] }}
              exit={{ opacity: 0, x: -24 }}
              transition={{ duration: 0.4, ease: 'easeOut' }}
            >
              <div className="rp-icon-badge rp-icon-badge--error">
                <AlertTriangle size={26} />
              </div>
              <h1 className="rp-title">Reset link problem</h1>
              <p className="rp-message" aria-live="polite">{errorMessage}</p>
              <button type="button" className="rp-btn" onClick={goToLogin}>
                Request a new reset link
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
};
