'use strict';

// Sentry error tracking, Day 9. Env-gated like every other optional
// integration here: no SENTRY_DSN, no tracking, no crash — the server
// boots and errors are only logged locally. With a DSN set (Render env
// for the backend, VITE_SENTRY_DSN for the frontend), exceptions are
// captured with no PII (sendDefaultPii: false) and no performance
// traces (tracesSampleRate: 0 — error tracking only, as ordered).
// The DSN itself is HIS STEP: Rishabh creates the free-tier Sentry
// project and sets the DSNs; until then this module is inert code.
// The forced test error lives behind SENTRY_TEST_ROUTE=enabled (see
// server.js) so it can never fire in a default production deploy.
let sentry = null;
let initialized = false;

function initSentry(env = process.env) {
  if (initialized) return sentry;
  initialized = true;
  const dsn = env.SENTRY_DSN;
  if (!dsn) {
    console.warn('[sentry] SENTRY_DSN is not set — error tracking disabled.');
    return null;
  }
  try {
    sentry = require('@sentry/node');
    sentry.init({
      dsn,
      environment: env.NODE_ENV || 'development',
      tracesSampleRate: 0,
      sendDefaultPii: false,
    });
    console.log('[sentry] error tracking enabled.');
    return sentry;
  } catch (err) {
    console.error('[sentry] failed to initialize:', err.message);
    return null;
  }
}

function captureError(err, context) {
  try {
    if (sentry) sentry.captureException(err, context ? { extra: context } : undefined);
  } catch { /* tracking must never break the request */ }
}

// Last error handler in server.js: captures, then answers with a generic
// 500 — stack traces never leak to clients (debug mode off in prod).
// Preserves a status the error already carries (e.g. 400 malformed JSON,
// 413 oversized body) instead of upgrading it to 500.
function sentryErrorHandler(err, req, res, next) {
  captureError(err, { path: req.path, method: req.method });
  if (res.headersSent) return next(err);
  const status = err.status || err.statusCode;
  if (status === 400) return res.status(400).json({ message: 'Invalid request body.' });
  if (status === 413) return res.status(413).json({ message: 'Request body too large.' });
  console.error('Unhandled error:', err);
  return res.status(500).json({ message: 'Server error' });
}

module.exports = { initSentry, captureError, sentryErrorHandler };
