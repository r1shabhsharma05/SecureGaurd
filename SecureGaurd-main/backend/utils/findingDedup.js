'use strict';

// Finding dedup (E2E fix batch, 19 Nov 2026): a re-scan must not insert a
// second copy of a finding already open for this repo. Two findings are
// the same when (ruleId, filePath, lineStart) match — rule + file alone
// conflates distinct lines, which is also why the occurrence view showed
// contradictory statuses for "the same" finding.
//
// A finding fixed since the last scan is re-inserted (only OPEN rows are
// skipped), so a regression re-opens. Used by scanRunner (queued scans)
// and integration.js (webhook/push scans).
function dedupeFindings(findings, alreadyOpen) {
  const seen = new Set(
    (alreadyOpen || []).map((v) => `${v.ruleId}\0${v.filePath}\0${v.lineStart}`)
  );
  return findings.filter((f) => !seen.has(`${f.ruleId}\0${f.filePath}\0${f.lineStart}`));
}

module.exports = { dedupeFindings };
