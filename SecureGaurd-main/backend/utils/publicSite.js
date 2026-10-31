'use strict';

// Day 8 — public-site helpers: product-analytics event allow-list, contact
// form validation, and the contact recipient resolution. Pure functions so
// the unit suite can prove them without a database or network. Nothing here
// invents data: an event outside the allow-list or a contact message that
// fails validation is rejected, never silently stored.

// Events the frontend is allowed to record. The list is closed on purpose:
// an open-ended event name would let any caller pollute the analytics table
// with arbitrary rows (and arbitrary prop keys).
const ALLOWED_ANALYTICS_EVENTS = new Set([
  'page_view',
  'signup_completed',
  'scan_started',
  'ai_fix_applied',
  'report_generated',
  'contact_sent',
]);

function isAllowedAnalyticsEvent(event) {
  return typeof event === 'string' && ALLOWED_ANALYTICS_EVENTS.has(event);
}

// Props must be a flat object of short strings — no nested objects, no PII
// fields (never accept email/name/token keys from the client).
const FORBIDDEN_PROP_KEYS = new Set(['email', 'name', 'token', 'password', 'authorization']);

function sanitizeAnalyticsProps(props) {
  if (props == null) return {};
  if (typeof props !== 'object' || Array.isArray(props)) return null;
  const keys = Object.keys(props);
  if (keys.length > 10) return null;
  const out = {};
  for (const key of keys) {
    if (FORBIDDEN_PROP_KEYS.has(key.toLowerCase())) return null;
    const value = props[key];
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') return null;
    const text = String(value);
    if (text.length > 200) return null;
    out[key] = value;
  }
  return out;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// Returns { ok: true, value } or { ok: false, message }. The honeypot field
// must stay empty: bots fill it, humans never see it. A filled honeypot is
// answered with the same success shape by the route (no signal to the bot),
// but validation still reports it here for the unit suite.
function validateContactInput(body) {
  if (!body || typeof body !== 'object') return { ok: false, message: 'Invalid request.' };
  if (typeof body.company === 'string' && body.company.trim() !== '') {
    return { ok: false, message: 'honeypot' };
  }
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const email = typeof body.email === 'string' ? body.email.trim() : '';
  const subject = typeof body.subject === 'string' ? body.subject.trim() : '';
  const message = typeof body.message === 'string' ? body.message.trim() : '';
  if (name.length < 2 || name.length > 100) return { ok: false, message: 'Name must be 2–100 characters.' };
  if (!EMAIL_RE.test(email) || email.length > 254) return { ok: false, message: 'A valid email address is required.' };
  if (subject.length > 140) return { ok: false, message: 'Subject must be at most 140 characters.' };
  if (message.length < 10 || message.length > 2000) return { ok: false, message: 'Message must be 10–2000 characters.' };
  return { ok: true, value: { name, email, subject, message } };
}

// Where a contact message goes: CONTACT_EMAIL when set, otherwise the
// address part of EMAIL_FROM (the Brevo sender — Rishabh's verified sender
// address). Returns null when neither is configured, so the route can say
// so honestly (503) instead of pretending the message was delivered.
function resolveContactRecipient(env) {
  const direct = (env.CONTACT_EMAIL || '').trim();
  if (direct) return direct;
  const from = (env.EMAIL_FROM || env.SMTP_USER || '').trim();
  const m = from.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  const addr = m ? m[2].trim() : from;
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(addr) ? addr : null;
}

module.exports = {
  ALLOWED_ANALYTICS_EVENTS,
  isAllowedAnalyticsEvent,
  sanitizeAnalyticsProps,
  validateContactInput,
  resolveContactRecipient,
};
