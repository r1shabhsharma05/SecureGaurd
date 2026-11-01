import { useEffect, useRef, useState } from 'react';

// Day 9 — Cloudflare Turnstile widget (register / forgot-password /
// contact). Renders nothing until VITE_TURNSTILE_SITE_KEY is set: the
// captcha is inert until Rishabh creates the Turnstile widget in
// Cloudflare and sets the site key (Vercel) + secret key (Render).
// When a site key IS set, the token is required by the parent form and
// by the backend (utils/turnstile.js) — a missing/expired token blocks
// submit, so a bot cannot skip the check by posting without a token.
export const TURNSTILE_SITE_KEY = (import.meta.env.VITE_TURNSTILE_SITE_KEY as string | undefined)?.trim() || '';
export const isTurnstileEnabled = (): boolean => TURNSTILE_SITE_KEY.length > 0;

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      remove: (widgetId: string) => void;
      reset: (widgetId: string) => void;
    };
  }
}

const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/api.js?render=explicit';
let scriptPromise: Promise<void> | null = null;

function loadTurnstileScript(): Promise<void> {
  if (typeof window !== 'undefined' && window.turnstile) return Promise.resolve();
  if (scriptPromise) return scriptPromise;
  scriptPromise = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script');
    script.src = SCRIPT_URL;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => {
      scriptPromise = null;
      reject(new Error('Turnstile script failed to load'));
    };
    document.head.appendChild(script);
  });
  return scriptPromise;
}

interface TurnstileWidgetProps {
  onVerify: (token: string) => void;
  onExpire: () => void;
  onError?: () => void;
}

export default function TurnstileWidget({ onVerify, onExpire, onError }: TurnstileWidgetProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<string | null>(null);
  const callbacksRef = useRef({ onVerify, onExpire, onError });
  const [failed, setFailed] = useState(false);

  // Refs must not be written during render (react-hooks rule): refresh the
  // callbacks after every render so the widget always calls the latest one.
  useEffect(() => {
    callbacksRef.current = { onVerify, onExpire, onError };
  });

  useEffect(() => {
    if (!TURNSTILE_SITE_KEY) return;
    let cancelled = false;
    loadTurnstileScript()
      .then(() => {
        if (cancelled || !containerRef.current || !window.turnstile) return;
        widgetIdRef.current = window.turnstile.render(containerRef.current, {
          sitekey: TURNSTILE_SITE_KEY,
          theme: 'dark',
          callback: (token: string) => callbacksRef.current.onVerify(token),
          'expired-callback': () => callbacksRef.current.onExpire(),
          'error-callback': () => {
            setFailed(true);
            callbacksRef.current.onError?.();
          },
        });
      })
      .catch(() => {
        if (!cancelled) {
          setFailed(true);
          callbacksRef.current.onError?.();
        }
      });
    return () => {
      cancelled = true;
      if (widgetIdRef.current && window.turnstile) {
        try {
          window.turnstile.remove(widgetIdRef.current);
        } catch {
          // Widget already removed (StrictMode remount) — nothing to do.
        }
        widgetIdRef.current = null;
      }
    };
  }, []);

  if (!TURNSTILE_SITE_KEY) return null;
  if (failed) {
    return (
      <p className="turnstile-error" role="alert">
        The security check failed to load. Please refresh the page and try again.
      </p>
    );
  }
  return <div ref={containerRef} className="turnstile-widget" aria-label="Security check" />;
}
