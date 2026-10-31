// Day 8 — built-in product analytics (own database, no third party).
// Events are sent ONLY when the visitor granted analytics consent in the
// cookie banner (see CookieConsent.tsx) and Do Not Track is not set.
// Sending is fire-and-forget: analytics must never throw into UI code or
// delay navigation. No IP address or client-supplied identity is stored
// server-side; the session id is a random per-tab id, not a fingerprint.
import { apiUrl } from '../config/api';

export const CONSENT_STORAGE_KEY = 'secureguard-consent-v1';

export type ConsentChoice = { analytics: boolean; decidedAt: string };

export function readConsent(): ConsentChoice | null {
  try {
    const raw = window.localStorage.getItem(CONSENT_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as ConsentChoice;
    return typeof parsed.analytics === 'boolean' ? parsed : null;
  } catch {
    return null;
  }
}

export function canTrack(): boolean {
  if (typeof window === 'undefined') return false;
  if (navigator.doNotTrack === '1') return false;
  return readConsent()?.analytics === true;
}

function getSessionId(): string | null {
  try {
    let id = window.sessionStorage.getItem('sg-analytics-session');
    if (!id) {
      id = typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `sg-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      window.sessionStorage.setItem('sg-analytics-session', id);
    }
    return id;
  } catch {
    return null;
  }
}

export function trackEvent(event: string, props?: Record<string, string | number | boolean>): void {
  if (!canTrack()) return;
  try {
    void fetch(apiUrl('/api/analytics/events'), {
      method: 'POST',
      keepalive: true,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event, path: window.location.pathname, sessionId: getSessionId(), props: props ?? {} }),
    }).catch(() => { /* analytics failures are silent by design */ });
  } catch {
    // Never let analytics break the page.
  }
}

export function trackPageView(path: string): void {
  trackEvent('page_view', { path });
}
