import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

/**
 * OAuth callback landing page (Day 10 SSO). The backend has already set the
 * refresh cookie and redirected here with no token in the URL; this page
 * restores the session via /refresh (same as a normal session restore) and
 * hands off to /dashboard — whose guard sends onboarding-incomplete users
 * on to /onboarding. A failed restore shows a plain error, never a token.
 */
export const OAuthCallbackPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { refreshSession } = useAuth();
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const ok = await refreshSession();
      if (cancelled) return;
      if (ok) {
        navigate('/dashboard', { replace: true });
      } else {
        setFailed(true);
      }
    })();
    return () => { cancelled = true; };
  }, [refreshSession, navigate]);

  const error = searchParams.get('oauth_error');

  return (
    <div className="auth-container">
      <div className="auth-card glass-card">
        <div className="auth-header">
          <Link to="/" className="auth-brand">SecureGuard</Link>
          <h1 className="auth-title">{failed ? 'Sign-in did not complete' : 'Signing you in…'}</h1>
          <p className="auth-subtitle">
            {failed
              ? 'Your provider sign-in could not be completed. Please try again, or sign in with email and password.'
              : 'Finishing your provider sign-in.'}
          </p>
        </div>
        {error && <div className="auth-alert auth-alert--error">Sign-in failed ({error}).</div>}
        {failed && (
          <div className="auth-footer">
            <p>
              <Link to="/login">Back to sign in</Link>
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default OAuthCallbackPage;
