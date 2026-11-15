import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { apiUrl } from '../config/api';

const API = apiUrl('/api/auth');

interface User {
  id: number;
  firstName: string;
  lastName: string;
  email: string;
  isEmailVerified: boolean;
  onboardingCompleted?: boolean;
}

interface AuthContextType {
  user: User | null;
  accessToken: string | null;
  loading: boolean;
  /** Email awaiting verification (SEC-09): set by login/register when the
      server gates on verification, so the UI can offer a resend. */
  pendingVerificationEmail: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (firstName: string, lastName: string, email: string, password: string, turnstileToken?: string) => Promise<{ requiresVerification: boolean }>;
  logout: () => Promise<void>;
  /** Returns the fresh access token, or null when the session is dead.
      Callers must use the returned token — the state value is stale inside
      the closure that called this (SEC-07 orgFetch bug). */
  refreshSession: () => Promise<string | null>;
  resendVerification: (email: string) => Promise<void>;
  completeOnboarding: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser]               = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [loading, setLoading]         = useState(true);
  const [pendingVerificationEmail, setPendingVerificationEmail] = useState<string | null>(null);

  // On mount — try restoring session from HTTP-only refresh cookie via /me
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API}/me`, { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          setUser(data.user);
          setAccessToken(data.accessToken);
        }
      } catch { /* no session */ }
      finally { setLoading(false); }
    })();
  }, []);

  const login = async (email: string, password: string) => {
    const res  = await fetch(`${API}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      // SEC-09 — remember the gated email so the UI can offer a resend
      // instead of a dead end; the throw still surfaces the message.
      if (data.code === 'email_not_verified') setPendingVerificationEmail(data.email || email);
      throw new Error(data.message || 'Login failed');
    }
    setPendingVerificationEmail(null);
    setUser(data.user);
    setAccessToken(data.accessToken);
  };

  const register = async (firstName: string, lastName: string, email: string, password: string, turnstileToken?: string) => {
    const res  = await fetch(`${API}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ firstName, lastName, email, password, ...(turnstileToken ? { turnstileToken } : {}) }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Registration failed');
    // SEC-09 — the server issues no session until the email is verified.
    if (data.requiresVerification) {
      setPendingVerificationEmail(data.email || email);
      return { requiresVerification: true };
    }
    setPendingVerificationEmail(null);
    setUser(data.user);
    setAccessToken(data.accessToken);
    return { requiresVerification: false };
  };

  const resendVerification = async (email: string) => {
    const res = await fetch(`${API}/resend-verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.message || 'Could not resend the verification email.');
  };

  const logout = async () => {
    try {
      await fetch(`${API}/logout`, { method: 'POST', credentials: 'include' });
    } catch { /* ignore */ }
    setUser(null);
    setAccessToken(null);
    // Also clear any old localStorage remnants
    localStorage.removeItem('sg_token');
    localStorage.removeItem('sg_user');
  };

  const refreshSession = useCallback(async (): Promise<string | null> => {
    try {
      const res = await fetch(`${API}/refresh`, { method: 'POST', credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setAccessToken(data.accessToken);
        return data.accessToken as string;
      }
    } catch { /* ignore */ }
    setUser(null);
    setAccessToken(null);
    return null;
  }, []);

  // SEC-07 — a failed completion must NOT mark onboarding done locally.
  // The old code set onboardingCompleted: true on any error, so a user
  // whose completion never reached the server was silently treated as
  // onboarded and never saw the wizard again. Now it throws and the
  // caller shows the error and stays put.
  const completeOnboarding = async () => {
    const res = await authFetch(`${API}/complete-onboarding`, { method: 'POST' }, accessToken, refreshSession);
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.message || 'Could not save onboarding progress. Please try again.');
    }
    const data = await res.json();
    setUser(data.user);
  };

  return (
    <AuthContext.Provider value={{ user, accessToken, loading, pendingVerificationEmail, login, register, logout, refreshSession, resendVerification, completeOnboarding }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

// Helper: make authenticated fetch — auto-refreshes on 401.
// SEC-07 — the retry must use the token refreshSession() RETURNS, not the
// `token` argument or a `newToken()` closure: both are stale by the time
// the refresh lands (state had not re-rendered), so every retry re-sent
// the expired token and failed again. `newToken` is kept only as a
// fallback for callers that pass one.
export async function authFetch(
  url: string,
  options: RequestInit = {},
  token: string | null,
  onRefresh: () => Promise<string | null>,
  newToken?: () => string | null
): Promise<Response> {
  const headers = {
    ...(options.headers || {}),
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  let res = await fetch(apiUrl(url), { ...options, headers, credentials: 'include' });

  if (res.status === 401) {
    const fresh = await onRefresh();
    const freshToken = fresh ?? (newToken ? newToken() : null);
    if (freshToken) {
      res = await fetch(apiUrl(url), {
        ...options,
        headers: { ...headers, Authorization: `Bearer ${freshToken}` },
        credentials: 'include',
      });
    }
  }
  return res;
}
