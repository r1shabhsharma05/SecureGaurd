'use strict';

// Finding dedup (E2E fix batch, 19 Nov 2026; path normalisation +
// detection tracking added in the re-test fix batch, 19 Nov 2026).
//
// Two findings are the same when (ruleId, filePath, lineStart) match.
// filePath is compared NORMALISED: scanners have produced both
// repo-root-relative paths ("SecureGaurd-main/backend/...") and
// app-dir-relative ones ("backend/...") for the same file, and the raw
// comparison let those through as duplicates. Normalisation unifies
// separators, drops a leading "./", and drops a leading wrapper segment
// when the caller names it (the repo name and its "-main"/"-master"
// archive forms). Callers also store the normalised path so new rows
// are canonical.
//
// A finding fixed since the last scan is re-inserted (only OPEN rows are
// matched), so a regression re-opens. Used by scanRunner (queued scans)
// and integration.js (webhook/push scans).
function normalizePath(filePath, stripPrefixes) {
  let p = String(filePath || '').replace(/\\/g, '/');
  while (p.startsWith('./')) p = p.slice(2);
  const prefixes = (stripPrefixes || []).filter(Boolean);
  if (prefixes.length > 0 && p.includes('/')) {
    const first = p.split('/')[0];
    if (prefixes.some((pre) => String(pre).toLowerCase() === first.toLowerCase())) {
      p = p.slice(first.length + 1);
    }
  }
  return p;
}

function keyOf(f, stripPrefixes) {
  return `${f.ruleId}\0${normalizePath(f.filePath, stripPrefixes)}\0${f.lineStart}`;
}

// Split `findings` into the ones to insert (`fresh`) and the ones that
// match an already-open row (`matched`: { finding, existingId }). The
// matched half lets a scan record that it DETECTED a finding it did not
// insert (Vulnerability.detectedInScanIds) — without it, a re-scan that
// dedupes everything shows an empty findings list on its detail page.
function partitionFindings(findings, alreadyOpen, opts = {}) {
  const stripPrefixes = opts.stripPrefixes || [];
  const byKey = new Map();
  for (const v of alreadyOpen || []) {
    const k = keyOf(v, stripPrefixes);
    if (!byKey.has(k)) byKey.set(k, v);
  }
  const fresh = [];
  const matched = [];
  for (const f of findings || []) {
    const hit = byKey.get(keyOf(f, stripPrefixes));
    if (hit) matched.push({ finding: f, existingId: hit.id });
    else fresh.push(f);
  }
  return { fresh, matched };
}

function dedupeFindings(findings, alreadyOpen, opts = {}) {
  return partitionFindings(findings, alreadyOpen, opts).fresh;
}

module.exports = { dedupeFindings, partitionFindings, normalizePath };
