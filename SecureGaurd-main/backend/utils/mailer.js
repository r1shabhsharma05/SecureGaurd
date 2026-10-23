'use strict';

// Minimal SMTP transport (nodemailer) driven entirely by env config:
//   SMTP_HOST (required to be "configured"), SMTP_PORT (default 587,
//   465 implies TLS), SMTP_USER / SMTP_PASS (optional — omitted for
//   unauthenticated relays / local sinks), EMAIL_FROM (default SMTP_USER).
// No credentials are hardcoded; without SMTP_HOST the feature is off and
// callers must say so honestly instead of claiming mail was sent.

let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch {
  nodemailer = null; // package missing -> treated as not configured, app still boots
}

function isMailConfigured() {
  return Boolean(nodemailer && process.env.SMTP_HOST);
}

async function sendMail({ to, subject, text, html }) {
  if (!isMailConfigured()) return false;
  const port = Number(process.env.SMTP_PORT) || 587;
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: port === 465,
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' }
      : undefined,
  });
  await transport.sendMail({
    from: process.env.EMAIL_FROM || process.env.SMTP_USER || 'no-reply@localhost',
    to,
    subject,
    text,
    html,
  });
  return true;
}

module.exports = { sendMail, isMailConfigured };
