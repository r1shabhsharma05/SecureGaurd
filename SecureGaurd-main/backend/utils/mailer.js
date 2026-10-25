'use strict';

// Mail delivery, two transports:
//   1. Brevo HTTP API (preferred when BREVO_API_KEY is set) — plain HTTPS,
//      works where outbound SMTP ports are blocked (e.g. Render free tier
//      blocks 25/465/587, which made every SMTP attempt time out).
//   2. SMTP via nodemailer, driven by env: SMTP_HOST (required to be
//      "configured"), SMTP_PORT (default 587, 465 implies TLS),
//      SMTP_USER / SMTP_PASS, EMAIL_FROM (default SMTP_USER).
// No credentials are hardcoded; with neither transport configured the
// feature is off and callers must say so honestly instead of claiming
// mail was sent. sendMail resolves to false when mail is not sent, true
// when sent without a provider id, or the provider message id string.

let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch {
  nodemailer = null; // package missing -> SMTP path treated as not configured
}

function isMailConfigured() {
  return Boolean(process.env.BREVO_API_KEY) || Boolean(nodemailer && process.env.SMTP_HOST);
}

function parseFrom() {
  const raw = process.env.EMAIL_FROM || process.env.SMTP_USER || 'no-reply@localhost';
  const m = raw.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  return m ? { name: m[1] || undefined, email: m[2] } : { email: raw };
}

async function sendViaBrevoApi({ to, subject, text, html }) {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      sender: parseFrom(),
      to: [{ email: to }],
      subject,
      textContent: text,
      htmlContent: html,
    }),
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`Brevo API responded ${res.status}`);
  // Surface the provider's message id so callers can prove acceptance.
  // Brevo returns { messageId } on success; fall back to true if absent.
  let messageId = true;
  try {
    const body = await res.json();
    if (body && typeof body.messageId === 'string' && body.messageId) messageId = body.messageId;
  } catch {
    // Non-JSON success body: acceptance already proven by res.ok.
  }
  return messageId;
}

async function sendMail({ to, subject, text, html }) {
  if (process.env.BREVO_API_KEY) return sendViaBrevoApi({ to, subject, text, html });
  if (!isMailConfigured()) return false;
  const port = Number(process.env.SMTP_PORT) || 587;
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: port === 465,
    // Fail fast: nodemailer's defaults (2 min connect) hang the request.
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
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
