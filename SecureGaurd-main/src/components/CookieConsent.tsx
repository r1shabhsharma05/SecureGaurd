import { createContext, useCallback, useContext, useState } from 'react';
import type { ReactNode } from 'react';
import { CONSENT_STORAGE_KEY, readConsent } from '../utils/analytics';
import type { ConsentChoice } from '../utils/analytics';
import './CookieConsent.css';

// Day 8 — cookie consent with real, stored state. Only two categories exist:
// necessary (the session cookie the app needs to stay signed in) and
// analytics (the built-in product events in utils/analytics.ts, which only
// fire when analytics consent is granted). The choice is stored in
// localStorage so the banner does not reappear on every visit; the footer
// "Cookie Settings" link re-opens preferences at any time.
type ConsentContextValue = {
  consent: ConsentChoice | null;
  saveConsent: (analytics: boolean) => void;
  openPreferences: () => void;
};

const ConsentContext = createContext<ConsentContextValue | null>(null);

export function useConsent() {
  const ctx = useContext(ConsentContext);
  if (!ctx) throw new Error('useConsent must be used inside ConsentProvider');
  return ctx;
}

export function ConsentProvider({ children }: { children: ReactNode }) {
  // Lazily read the stored choice at mount — no effect needed, so no
  // cascading render. Undecided visitors (null) see the banner.
  const [consent, setConsent] = useState<ConsentChoice | null>(() => readConsent());
  const [showPreferences, setShowPreferences] = useState(false);
  const [draftAnalytics, setDraftAnalytics] = useState(false);
  const showBanner = consent === null && !showPreferences;

  const saveConsent = useCallback((analytics: boolean) => {
    const choice: ConsentChoice = { analytics, decidedAt: new Date().toISOString() };
    try {
      window.localStorage.setItem(CONSENT_STORAGE_KEY, JSON.stringify(choice));
    } catch {
      // Storage unavailable: keep the in-memory choice for this visit.
    }
    setConsent(choice);
    setShowPreferences(false);
  }, []);

  const openPreferences = useCallback(() => {
    setDraftAnalytics(consent?.analytics ?? false);
    setShowPreferences(true);
  }, [consent]);

  return (
    <ConsentContext.Provider value={{ consent, saveConsent, openPreferences }}>
      {children}
      {showBanner && !showPreferences && (
        <div className="cookie-banner" role="region" aria-label="Cookie consent">
          <p className="cookie-banner-text">
            We use a necessary session cookie to keep you signed in, and optional analytics
            to understand which features get used. Analytics only runs if you accept it.
          </p>
          <div className="cookie-banner-actions">
            <button type="button" className="cookie-btn cookie-btn--primary" onClick={() => saveConsent(true)}>
              Accept all
            </button>
            <button type="button" className="cookie-btn" onClick={() => saveConsent(false)}>
              Reject analytics
            </button>
            <button type="button" className="cookie-btn cookie-btn--ghost" onClick={() => setShowPreferences(true)}>
              Customize
            </button>
          </div>
        </div>
      )}
      {showPreferences && (
        <div className="cookie-dialog-backdrop" role="presentation" onClick={() => setShowPreferences(false)}>
          <div
            className="cookie-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="cookie-dialog-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="cookie-dialog-title">Cookie preferences</h2>
            <div className="cookie-pref-row">
              <div>
                <strong>Necessary cookies</strong>
                <p>Required for sign-in sessions and security. Always on.</p>
              </div>
              <span className="cookie-pref-always">Always on</span>
            </div>
            <label className="cookie-pref-row cookie-pref-row--toggle">
              <div>
                <strong>Analytics</strong>
                <p>Anonymous product events (page views, scans started, fixes applied) stored in our own database. No third parties.</p>
              </div>
              <input
                type="checkbox"
                checked={draftAnalytics}
                onChange={(e) => setDraftAnalytics(e.target.checked)}
                aria-label="Allow analytics cookies"
              />
            </label>
            <div className="cookie-banner-actions">
              <button type="button" className="cookie-btn cookie-btn--primary" onClick={() => saveConsent(draftAnalytics)}>
                Save preferences
              </button>
              <button type="button" className="cookie-btn" onClick={() => setShowPreferences(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </ConsentContext.Provider>
  );
}
