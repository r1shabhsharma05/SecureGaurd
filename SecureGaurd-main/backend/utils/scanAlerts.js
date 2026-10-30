'use strict';

// Day 7 — scan-completion alert dispatcher.
// Best-effort by design: it NEVER throws into the scan path (a failed
// alert must not fail a completed scan). Every attempt is recorded in
// AlertLog with a masked target so delivery is provable after the fact.
// No alert row for an organization => no alerts sent, ever (opt-in).

const prisma = require('../prismaClient');
const { decrypt } = require('./cryptoUtils');
const { sendMail, isMailConfigured } = require('./mailer');
const { isValidSlackWebhookUrl, maskWebhookUrl, buildSlackPayload, buildEmailAlert } = require('./alertPayload');

async function logAttempt({ organizationId, channel, event, targetMasked, status, providerId, error }) {
  try {
    await prisma.alertLog.create({
      data: {
        organizationId,
        channel,
        event,
        targetMasked: targetMasked || null,
        status,
        providerId: providerId ? String(providerId).slice(0, 200) : null,
        error: error ? String(error).slice(0, 500) : null,
      },
    });
  } catch (err) {
    console.error('[scanAlerts] failed to write AlertLog:', err.message);
  }
}

async function postSlack(webhookUrl, payload) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const body = (await res.text()).slice(0, 200);
    return { ok: res.ok && body.trim() === 'ok', status: res.status, body };
  } finally {
    clearTimeout(timeout);
  }
}

// Shared by the scan-completion dispatch and the POST /api/alerts/test
// endpoint: returns a real provider outcome, never a fabricated success.
async function sendSlackAlert(webhookUrl, payload) {
  if (!isValidSlackWebhookUrl(webhookUrl)) {
    return { ok: false, status: null, body: 'invalid Slack webhook URL (must be https://hooks.slack.com/services/*)' };
  }
  try {
    return await postSlack(webhookUrl, payload);
  } catch (err) {
    return { ok: false, status: null, body: err.message };
  }
}

async function dispatchScanAlerts({ organizationId, scan, repository }) {
  const results = [];
  let setting;
  try {
    setting = await prisma.alertSetting.findUnique({ where: { organizationId } });
  } catch (err) {
    console.error('[scanAlerts] settings lookup failed:', err.message);
    return results;
  }
  if (!setting) return results;

  const criticalCount = scan.criticalCount || 0;
  const event = criticalCount > 0 && setting.notifyOnNewCritical
    ? 'new_critical'
    : (setting.notifyOnScanComplete ? 'scan_completed' : null);
  if (!event) return results;

  const org = await prisma.organization.findUnique({ where: { id: organizationId }, select: { name: true } });
  const base = {
    orgName: org ? org.name : `Organization ${organizationId}`,
    repoName: repository ? (repository.fullName || repository.name) : 'repository',
    scanId: scan.id,
    criticalCount,
    highCount: scan.highCount || 0,
    mediumCount: scan.mediumCount || 0,
    lowCount: scan.lowCount || 0,
    event,
  };

  if (setting.slackEnabled && setting.slackWebhookUrl) {
    const url = decrypt(setting.slackWebhookUrl);
    const outcome = await sendSlackAlert(url, buildSlackPayload(base));
    await logAttempt({
      organizationId,
      channel: 'slack',
      event,
      targetMasked: maskWebhookUrl(url),
      status: outcome.ok ? 'delivered' : 'failed',
      error: outcome.ok ? null : `Slack responded ${outcome.status} ${outcome.body}`,
    });
    results.push({ channel: 'slack', ok: outcome.ok });
  }

  if (setting.emailEnabled) {
    if (!isMailConfigured()) {
      await logAttempt({ organizationId, channel: 'email', event, status: 'failed', error: 'No mail transport configured (BREVO_API_KEY / SMTP)' });
      results.push({ channel: 'email', ok: false });
    } else {
      const members = await prisma.organizationMembership.findMany({
        where: { organizationId },
        include: { user: { select: { email: true } } },
      });
      const mail = buildEmailAlert(base);
      for (const m of members) {
        const to = m.user && m.user.email;
        if (!to) continue;
        try {
          const providerId = await sendMail({ to, subject: mail.subject, text: mail.text });
          const delivered = providerId !== false;
          await logAttempt({
            organizationId, channel: 'email', event, targetMasked: to,
            status: delivered ? 'delivered' : 'failed',
            providerId: delivered && providerId !== true ? providerId : null,
            error: delivered ? null : 'Mail transport refused the message',
          });
          results.push({ channel: 'email', ok: delivered, to });
        } catch (err) {
          await logAttempt({ organizationId, channel: 'email', event, targetMasked: to, status: 'failed', error: err.message });
          results.push({ channel: 'email', ok: false, to });
        }
      }
    }
  }
  return results;
}

module.exports = { dispatchScanAlerts, sendSlackAlert };
