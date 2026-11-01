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
  login: (email: string, password: string) => Promise<void>;
  register: (firstName: string, lastName: string, email: string, password: string, turnstileToken?: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<boolean>;
  completeOnboarding: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser]               = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [loading, setLoading]         = useState(true);

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
    if (!res.ok) throw new Error(data.message || 'Login failed');
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
    setUser(data.user);
    setAccessToken(data.accessToken);
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

  const refreshSession = useCallback(async (): Promise<boolean> => {
    try {
      const res = await fetch(`${API}/refresh`, { method: 'POST', credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setAccessToken(data.accessToken);
        return true;
      }
    } catch { /* ignore */ }
    setUser(null);
    setAccessToken(null);
    return false;
  }, []);

  const completeOnboarding = async () => {
    try {
      const res = await authFetch(`${API}/complete-onboarding`, { method: 'POST' }, accessToken, refreshSession);
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
      } else {
        if (user) setUser({ ...user, onboardingCompleted: true });
      }
    } catch {
      if (user) setUser({ ...user, onboardingCompleted: true });
    }
  };

  return (
    <AuthContext.Provider value={{ user, accessToken, loading, login, register, logout, refreshSession, completeOnboarding }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

// Helper: make authenticated fetch — auto-refreshes on 401
export async function authFetch(
  url: string,
  options: RequestInit = {},
  token: string | null,
  onRefresh: () => Promise<boolean>,
  newToken?: () => string | null
): Promise<Response> {
  const headers = {
    ...(options.headers || {}),
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  let res = await fetch(apiUrl(url), { ...options, headers, credentials: 'include' });

  if (res.status === 401) {
    const ok = await onRefresh();
    if (ok && newToken) {
      const fresh = newToken();
      res = await fetch(apiUrl(url), {
        ...options,
        headers: { ...headers, ...(fresh ? { Authorization: `Bearer ${fresh}` } : {}) },
        credentials: 'include',
      });
    }
  }
  return res;
}
