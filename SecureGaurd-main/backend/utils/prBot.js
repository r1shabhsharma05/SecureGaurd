'use strict';

// Day 7 — pure PR-bot payload builders (no network: unit-testable).
// The old route returned a fabricated check ("simulated", prNumber || 42,
// a localhost report URL). The real route posts these exact payloads to
// the GitHub REST API with the user's connected PAT and returns only what
// GitHub itself returns (check-run id/url, comment id/url) — or an honest
// error. Nothing here is ever presented as a GitHub result unless GitHub
// produced it.

function parseRepoFullName(fullName) {
  if (typeof fullName !== 'string') return null;
  const parts = fullName.split('/');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  return { owner: parts[0], repo: parts[1] };
}

function buildCheckRunPayload({ commitSha, isClean, criticalCount, highCount, reportUrl }) {
  return {
    name: 'SecureGuard',
    head_sha: commitSha,
    status: 'completed',
    conclusion: isClean ? 'success' : 'failure',
    output: {
      title: isClean ? 'SecureGuard check passed' : 'SecureGuard found vulnerabilities',
      summary: isClean
        ? 'No critical or high findings in the latest SecureGuard scan.'
        : `${criticalCount} critical and ${highCount} high findings in the latest SecureGuard scan.`,
      text: reportUrl
        ? `Latest scan report: ${reportUrl}`
        : 'Latest SecureGuard scan for this repository.',
    },
  };
}

function buildPrCommentBody({ repoFullName, commitSha, isClean, criticalCount, highCount, mediumCount, lowCount, reportUrl }) {
  const lines = [
    `## SecureGuard report for \`${repoFullName}\``,
    `Commit: \`${commitSha}\``,
    '',
    isClean
      ? '✅ No critical or high findings in the latest scan.'
      : `⚠️ Latest scan: **${criticalCount} critical, ${highCount} high, ${mediumCount} medium, ${lowCount} low** findings.`,
  ];
  if (reportUrl) lines.push('', `Report: ${reportUrl}`);
  return lines.join('\n');
}

module.exports = { parseRepoFullName, buildCheckRunPayload, buildPrCommentBody };
