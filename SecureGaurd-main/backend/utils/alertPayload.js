'use strict';

// Day 7 — pure alert-payload helpers (no DB, no network: unit-testable).
// A Slack webhook URL is a bearer secret: it is stored encrypted, never
// returned by any API, and only a masked form ever reaches logs or clients.
// The URL is also NOT a generic POST oracle: only hooks.slack.com/services/*
// is accepted, so a stored value cannot be abused to probe other hosts.

function isValidSlackWebhookUrl(url) {
  if (typeof url !== 'string' || !url) return false;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' &&
      u.hostname === 'hooks.slack.com' &&
      u.pathname.startsWith('/services/');
  } catch {
    return false;
  }
}

// Masked form safe for API responses and AlertLog rows: host only, no
// token segments (a Slack webhook path IS the credential).
function maskWebhookUrl(url) {
  if (!isValidSlackWebhookUrl(url)) return null;
  return 'hooks.slack.com/services/***';
}

function scanSummaryText({ repoName, scanId, criticalCount, highCount, mediumCount, lowCount }) {
  return `${criticalCount} critical, ${highCount} high, ${mediumCount} medium, ${lowCount} low`;
}

function buildSlackPayload({ orgName, repoName, scanId, criticalCount, highCount, mediumCount, lowCount, event }) {
  const title = event === 'new_critical'
    ? `:rotating_light: SecureGuard: new critical findings in ${repoName}`
    : `:white_check_mark: SecureGuard scan completed for ${repoName}`;
  return {
    text: `${title}\nOrganization: ${orgName}\nScan #${scanId} — ${scanSummaryText({ repoName, scanId, criticalCount, highCount, mediumCount, lowCount })}`,
  };
}

function buildEmailAlert({ orgName, repoName, scanId, criticalCount, highCount, mediumCount, lowCount, event }) {
  const subject = event === 'new_critical'
    ? `[SecureGuard] New critical findings in ${repoName} (scan #${scanId})`
    : `[SecureGuard] Scan #${scanId} completed for ${repoName}`;
  const text = `${orgName} — ${repoName}\nScan #${scanId} completed.\nFindings: ${scanSummaryText({ repoName, scanId, criticalCount, highCount, mediumCount, lowCount })}.\n${event === 'new_critical' ? 'This scan contains new critical findings — review them in the SecureGuard dashboard.' : ''}`;
  return { subject, text };
}

module.exports = { isValidSlackWebhookUrl, maskWebhookUrl, buildSlackPayload, buildEmailAlert };
