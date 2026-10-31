'use strict';

// Day 8 — public site routes: product-analytics ingestion and the contact
// form. Both are deliberately public (no account needed to view the landing
// page or ask a question) and deliberately narrow:
//  - analytics: closed event allow-list, flat short-string props only, no
//    IP address and no client-supplied user identity stored. The frontend
//    only sends events when the visitor granted analytics consent.
//  - contact: validated + honeypot + rate-limited; the message is emailed
//    via the real Brevo route (mailer.js) to CONTACT_EMAIL (or the EMAIL_FROM
//    address) and stored only after the provider accepts it, so a stored
//    row always means a real email was sent. Nothing is faked on failure.
const express = require('express');
const rateLimit = require('express-rate-limit');
const prisma = require('../prismaClient');
const { sendMail, isMailConfigured } = require('../utils/mailer');
const {
  isAllowedAnalyticsEvent,
  sanitizeAnalyticsProps,
  validateContactInput,
  resolveContactRecipient,
} = require('../utils/publicSite');

const router = express.Router();

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const analyticsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  message: { message: 'Too many analytics events, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { message: 'Too many contact messages, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/analytics/events', analyticsLimiter, async (req, res) => {
  const { event, path, sessionId, props } = req.body || {};
  if (!isAllowedAnalyticsEvent(event)) {
    return res.status(400).json({ message: 'Unknown analytics event.' });
  }
  if (typeof path !== 'string' || !path.startsWith('/') || path.length > 500) {
    return res.status(400).json({ message: 'A valid page path is required.' });
  }
  const cleanProps = sanitizeAnalyticsProps(props);
  if (cleanProps === null) {
    return res.status(400).json({ message: 'Invalid event properties.' });
  }
  const cleanSession = typeof sessionId === 'string' && /^[A-Za-z0-9-]{8,64}$/.test(sessionId)
    ? sessionId
    : null;
  try {
    const row = await prisma.analyticsEvent.create({
      data: {
        event,
        path,
        sessionId: cleanSession,
        props: cleanProps,
        userAgent: typeof req.headers['user-agent'] === 'string'
          ? req.headers['user-agent'].slice(0, 200)
          : null,
      },
    });
    return res.status(201).json({ id: row.id });
  } catch (err) {
    console.error('Error storing analytics event:', err);
    return res.status(500).json({ message: 'Failed to record event.' });
  }
});

router.post('/contact', contactLimiter, async (req, res) => {
  const checked = validateContactInput(req.body || {});
  // Honeypot filled: answer success without sending or storing anything, so
  // a bot cannot tell it was caught — and no fake "message received" row
  // is ever created for it.
  if (!checked.ok && checked.message === 'honeypot') {
    return res.json({ message: 'Thanks — your message has been received.' });
  }
  if (!checked.ok) {
    return res.status(400).json({ message: checked.message });
  }
  const recipient = resolveContactRecipient(process.env);
  if (!recipient || !isMailConfigured()) {
    return res.status(503).json({
      message: 'Contact email is not configured on the server, so this message cannot be delivered yet.',
    });
  }
  const { name, email, subject, message } = checked.value;
  const mailSubject = `SecureGuard contact${subject ? `: ${subject}` : ''} — from ${name}`;
  try {
    const providerId = await sendMail({
      to: recipient,
      subject: mailSubject,
      text: `Contact form message from ${name} <${email}>\n\n${message}\n\nReply to: ${email}`,
      html: `<p>Contact form message from <strong>${escapeHtml(name)}</strong> &lt;${escapeHtml(email)}&gt;</p><p>${escapeHtml(message)}</p><p>Reply to: ${escapeHtml(email)}</p>`,
    });
    if (!providerId) {
      return res.status(502).json({ message: 'Email delivery failed. Please try again later.' });
    }
    const row = await prisma.contactMessage.create({
      data: {
        name, email, subject: subject || null, message,
        providerId: typeof providerId === 'string' ? providerId : null,
      },
    });
    return res.status(201).json({ id: row.id, message: 'Thanks — your message has been received.' });
  } catch (err) {
    console.error('Error sending contact message:', err);
    return res.status(502).json({ message: 'Email delivery failed. Please try again later.' });
  }
});

module.exports = router;
