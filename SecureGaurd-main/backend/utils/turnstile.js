'use strict';

// Cloudflare Turnstile (CAPTCHA) — server-side verification, Day 9.
// The widget lives in the frontend (TurnstileWidget.tsx); this module is
// the only place the secret key is used — it never leaves the server.
// Activation is env-gated, the same pattern as the other optional
// integrations in this codebase (see config/env.js): when
// TURNSTILE_SECRET_KEY is unset the guard passes requests through and
// warns once, so the forms keep working until Rishabh creates the
// Turnstile widget in Cloudflare and sets the keys (HIS STEP). When the
// secret IS set, a missing or invalid token is a hard 400 and a
// Cloudflare outage is a 503 — never a silent pass.
// shortcut: fail-open while unconfigured, upgrade: set TURNSTILE_SECRET_KEY
// (Render) + VITE_TURNSTILE_SITE_KEY (Vercel) and the check enforces.
const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

function isTurnstileConfigured(env = process.env) {
  return Boolean(env.TURNSTILE_SECRET_KEY);
}

function extractTurnstileToken(body) {
  if (!body || typeof body !== 'object') return null;
  for (const key of ['turnstileToken', 'cf-turnstile-response', 'cfTurnstileToken']) {
    const value = body[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

// Verifies one token against Cloudflare's siteverify API. `fetchImpl` is
// injectable so unit tests can stub Cloudflare; production always uses
// the global fetch. Tokens are single-use and ~5 minutes old at most —
// a replay returns `timeout-or-duplicate` and fails, which is the
// intended replay protection, not a bug to work around.
async function verifyTurnstileToken(token, { secret, remoteip, fetchImpl = globalThis.fetch } = {}) {
  if (!secret) throw new Error('TURNSTILE_SECRET_KEY is required to verify a Turnstile token');
  if (!token) return { ok: false, errorCodes: ['missing-input-response'] };
  const params = new URLSearchParams({ secret, response: token });
  if (remoteip) params.set('remoteip', remoteip);
  const res = await fetchImpl(VERIFY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`Turnstile siteverify responded ${res.status}`);
  const body = await res.json();
  return { ok: body && body.success === true, errorCodes: (body && body['error-codes']) || [] };
}

let warnedUnconfigured = false;

function requireTurnstile() {
  return async (req, res, next) => {
    const secret = process.env.TURNSTILE_SECRET_KEY;
    if (!secret) {
      if (!warnedUnconfigured) {
        warnedUnconfigured = true;
        console.warn('[turnstile] TURNSTILE_SECRET_KEY is not set — captcha check skipped. Set the key to activate.');
      }
      return next();
    }
    const token = extractTurnstileToken(req.body);
    if (!token) {
      return res.status(400).json({ message: 'Security check is required. Please complete the verification and try again.' });
    }
    try {
      const result = await verifyTurnstileToken(token, { secret, remoteip: req.ip });
      if (result.ok) return next();
      console.warn('[turnstile] verification failed:', result.errorCodes.join(',') || 'unknown');
      return res.status(400).json({ message: 'Security check failed. Please try again.' });
    } catch (err) {
      console.error('[turnstile] verification error:', err.message);
      return res.status(503).json({ message: 'Security check could not be verified right now. Please try again later.' });
    }
  };
}

module.exports = { VERIFY_URL, isTurnstileConfigured, extractTurnstileToken, verifyTurnstileToken, requireTurnstile };
