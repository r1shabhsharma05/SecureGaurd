const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { encrypt, decrypt } = require('../utils/cryptoUtils');
const { sendMail, isMailConfigured } = require('../utils/mailer');
const { isValidSlackWebhookUrl, maskWebhookUrl } = require('../utils/alertPayload');
const { sendSlackAlert } = require('../utils/scanAlerts');

router.use(authMiddleware);
router.use(requireOrgContext);

// Public shape of a setting: the webhook URL itself is NEVER returned.
// Clients learn only whether one is stored, and its masked form.
function publicSetting(setting) {
  if (!setting) {
    return {
      configured: false,
      slackEnabled: false,
      emailEnabled: false,
      notifyOnScanComplete: true,
      notifyOnNewCritical: true,
      hasSlackWebhook: false,
      slackWebhookMasked: null,
    };
  }
  return {
    configured: true,
    slackEnabled: setting.slackEnabled,
    emailEnabled: setting.emailEnabled,
    notifyOnScanComplete: setting.notifyOnScanComplete,
    notifyOnNewCritical: setting.notifyOnNewCritical,
    hasSlackWebhook: Boolean(setting.slackWebhookUrl),
    slackWebhookMasked: setting.slackWebhookUrl ? maskWebhookUrl(decrypt(setting.slackWebhookUrl)) : null,
  };
}

// GET /api/alerts/settings — org-scoped; any member may read.
router.get('/settings', async (req, res) => {
  try {
    const setting = await prisma.alertSetting.findUnique({ where: { organizationId: req.organizationId } });
    res.json(publicSetting(setting));
  } catch (err) {
    console.error('Error fetching alert settings:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT /api/alerts/settings — OWNER/ADMIN only. A Slack URL is accepted
// only for hooks.slack.com/services/*; anything else is a 400, never stored.
router.put('/settings', requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const { slackWebhookUrl, slackEnabled, emailEnabled, notifyOnScanComplete, notifyOnNewCritical } = req.body || {};
  const bool = (v, d) => (typeof v === 'boolean' ? v : d);
  try {
    const existing = await prisma.alertSetting.findUnique({ where: { organizationId: req.organizationId } });
    let storedUrl = existing ? existing.slackWebhookUrl : null;
    if (slackWebhookUrl !== undefined) {
      const trimmed = typeof slackWebhookUrl === 'string' ? slackWebhookUrl.trim() : '';
      if (trimmed === '') {
        storedUrl = null;
      } else if (!isValidSlackWebhookUrl(trimmed)) {
        return res.status(400).json({ message: 'Slack webhook URL must be https://hooks.slack.com/services/*' });
      } else {
        storedUrl = encrypt(trimmed);
      }
    }
    const data = {
      slackWebhookUrl: storedUrl,
      slackEnabled: bool(slackEnabled, existing ? existing.slackEnabled : false),
      emailEnabled: bool(emailEnabled, existing ? existing.emailEnabled : false),
      notifyOnScanComplete: bool(notifyOnScanComplete, existing ? existing.notifyOnScanComplete : true),
      notifyOnNewCritical: bool(notifyOnNewCritical, existing ? existing.notifyOnNewCritical : true),
    };
    if (data.slackEnabled && !storedUrl) {
      return res.status(400).json({ message: 'Slack alerts cannot be enabled without a Slack webhook URL' });
    }
    const setting = existing
      ? await prisma.alertSetting.update({ where: { organizationId: req.organizationId }, data })
      : await prisma.alertSetting.create({ data: { organizationId: req.organizationId, ...data } });
    await createAuditLog(req.organizationId, req.userId, 'ALERT_SETTINGS_UPDATED', 'ORGANIZATION', String(req.organizationId), {
      slackEnabled: data.slackEnabled, emailEnabled: data.emailEnabled,
    });
    res.json(publicSetting(setting));
  } catch (err) {
    console.error('Error saving alert settings:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/alerts/test — OWNER/ADMIN only. Sends a REAL test message and
// returns the provider's actual outcome. A missing webhook, an unconfigured
// mail transport, or a provider rejection is reported as failure, never
// as a success.
router.post('/test', requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const { channel } = req.body || {};
  if (channel !== 'slack' && channel !== 'email') {
    return res.status(400).json({ message: 'channel must be "slack" or "email"' });
  }
  try {
    if (channel === 'slack') {
      const setting = await prisma.alertSetting.findUnique({ where: { organizationId: req.organizationId } });
      if (!setting || !setting.slackWebhookUrl) {
        await prisma.alertLog.create({ data: { organizationId: req.organizationId, channel: 'slack', event: 'test', status: 'failed', error: 'No Slack webhook configured' } });
        return res.status(400).json({ channel: 'slack', ok: false, error: 'No Slack webhook configured' });
      }
      const url = decrypt(setting.slackWebhookUrl);
      const outcome = await sendSlackAlert(url, { text: ':white_check_mark: SecureGuard test alert — your Slack alerts are wired up.' });
      await prisma.alertLog.create({
        data: { organizationId: req.organizationId, channel: 'slack', event: 'test', targetMasked: maskWebhookUrl(url), status: outcome.ok ? 'delivered' : 'failed', error: outcome.ok ? null : `Slack responded ${outcome.status} ${outcome.body}` },
      });
      if (!outcome.ok) return res.status(502).json({ channel: 'slack', ok: false, providerStatus: outcome.status, error: outcome.body });
      return res.json({ channel: 'slack', ok: true, providerStatus: outcome.status });
    }

    // Email test: to the caller's own address, via the real mail route.
    const user = await prisma.user.findUnique({ where: { id: req.userId }, select: { email: true } });
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (!isMailConfigured()) {
      await prisma.alertLog.create({ data: { organizationId: req.organizationId, channel: 'email', event: 'test', targetMasked: user.email, status: 'failed', error: 'No mail transport configured' } });
      return res.status(502).json({ channel: 'email', ok: false, error: 'Mail is not configured on this server (no Brevo/SMTP transport)' });
    }
    const providerId = await sendMail({ to: user.email, subject: '[SecureGuard] Test alert — email alerts are wired up', text: 'This is a SecureGuard test alert. If you received it, email alerts for your organization are working.' });
    const delivered = providerId !== false;
    await prisma.alertLog.create({
      data: { organizationId: req.organizationId, channel: 'email', event: 'test', targetMasked: user.email, status: delivered ? 'delivered' : 'failed', providerId: delivered && providerId !== true ? String(providerId) : null, error: delivered ? null : 'Mail transport refused the message' },
    });
    if (!delivered) return res.status(502).json({ channel: 'email', ok: false, error: 'Mail transport refused the message' });
    return res.json({ channel: 'email', ok: true, providerId: providerId === true ? null : providerId });
  } catch (err) {
    console.error('Error sending alert test:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/alerts/logs — last 50 delivery attempts, org-scoped.
router.get('/logs', async (req, res) => {
  try {
    const logs = await prisma.alertLog.findMany({
      where: { organizationId: req.organizationId },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
    res.json(logs);
  } catch (err) {
    console.error('Error fetching alert logs:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
