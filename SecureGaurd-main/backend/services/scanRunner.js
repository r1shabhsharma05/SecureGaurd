'use strict';
// Scan worker: runs one queued scan end to end (extracted verbatim from
// POST /api/scans/trigger, which used to run this inline in the request).
// The only behavioural change is the DB context: the request handler used
// withRequestOrgContext(req, fn), the worker uses withOrgContext(orgId,
// userId, fn) — same RLS boundary, no request object. Each DB segment gets
// its own short context (a scan interleaves minutes of scanning +
// classifier HTTP calls with writes, so no single transaction is held).
//
// Failure policy: every failure path marks the scan row 'failed' and
// returns { ok: false } — the worker never throws, so BullMQ never
// retries a scan blindly. A re-trigger creates a new scan row.
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);
const { createAuditLog } = require('../middleware/rbac');
const { runSecurityScan } = require('../utils/securityScanner');
// The synchronous scanner runs in a pooled worker thread, not on the
// event loop (see workers/scanThreadPool.js). A thread failure falls back
// to inline below — slow, but the scan still runs.
const { runScanInThread } = require('../workers/scanThreadPool');
const { storedRuleToParsed } = require('../utils/customRules');
const { mapRuleId } = require('../utils/ruleMap');
const { resolveScanTarget } = require('../utils/repoScanSource');
const { partitionFindings, normalizePath } = require('../utils/findingDedup');
const { withOrgContext } = require('../utils/rlsContext');
const { invalidateOrg } = require('../utils/cache');

// ─── ML feature: file change frequency from git history ─────────────────────
// The FP classifier was trained with file_change_frequency in 0..50
// (see backend/services/fp-classifier/generate_sample_data.py), but scans used
// to send a hardcoded 0, making the feature dead weight in production. Counting
// commits via `git log` keeps production inputs in-distribution. Falls back to
// 0 when git is unavailable or the scan target is not a git checkout.
//
// Async on purpose: the old execFileSync blocked the event loop ~20 ms per
// finding, so while a scan ran every HTTP response (including other scan
// submits) stalled behind it — at 100 concurrent triggers submit p95 was
// 5,543 ms. Async execFile + a bounded pool keeps the loop free.
const MAX_FILE_CHANGE_FREQUENCY = 50;
async function getFileChangeFrequency(scanRoot, relFilePath, cache) {
  const cacheKey = `${scanRoot}::${relFilePath}`;
  if (cache.has(cacheKey)) return cache.get(cacheKey);
  let count = 0;
  try {
    const { stdout } = await execFileAsync('git', ['-C', scanRoot, 'log', '--format=%H', '--', relFilePath], {
      encoding: 'utf8',
      timeout: 10000,
    });
    count = Math.min(stdout.split('\n').filter(Boolean).length, MAX_FILE_CHANGE_FREQUENCY);
  } catch (err) {
    count = 0;
  }
  cache.set(cacheKey, count);
  return count;
}

// Bounded concurrency map: at most `limit` git children at once, so a
// finding-heavy scan cannot fork-bomb the host.
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

// The synchronous scanner runs in a worker thread, not on the event loop:
// at 100 concurrent triggers the inline scan pushed submit p95 to ~2 s
// even after the git fix. A thread failure falls back to inline
// (slow, but the scan still runs) — never a failed scan for infra reasons.

async function markFailed(organizationId, userId, scanId, reason) {
  try {
    await withOrgContext(organizationId, userId, (tx) => tx.scan.update({
      where: { id: scanId },
      data: { status: 'failed', completedAt: new Date(), errorMessage: String(reason || 'Scan failed').slice(0, 1000) },
    }));
  } catch (err) {
    console.error('[scanRunner] could not mark scan failed:', err.message);
  }
  try {
    await createAuditLog(organizationId, userId, 'SCAN_FAILED', 'SCAN', String(scanId), { reason });
  } catch { /* audit failure must not mask the scan failure */ }
}

async function executeScan({ scanId, organizationId, userId, repositoryId }) {
  // P2028 = the interactive transaction could not START in time (pool
  // contention on the free-tier database) — nothing executed, so a
  // short retry is safe and keeps a contended moment from failing the
  // whole scan. Any other error propagates immediately.
  const ctx = async (fn) => {
    let lastErr;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        return await withOrgContext(organizationId, userId, fn);
      } catch (err) {
        lastErr = err;
        const isP2028 = err?.code === 'P2028' || /P2028/.test(err?.message || '');
        if (!isP2028 || attempt === 2) throw err;
        await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
      }
    }
    throw lastErr;
  };
  let scanTarget = null;
  try {
    const repo = await ctx((tx) => tx.repository.findFirst({
      where: { id: parseInt(repositoryId, 10), organizationId },
    }));
    if (!repo) {
      await markFailed(organizationId, userId, scanId, 'Repository not found in active organization');
      await invalidateOrg(organizationId);
      return { ok: false, error: 'Repository not found' };
    }

    // Scan the CONNECTED repository's own tree (clone/path resolution),
    // never SecureGaurd's own checkout. No reachable source → honest failure.
    try {
      scanTarget = resolveScanTarget(repo);
    } catch (resolveErr) {
      await markFailed(organizationId, userId, scanId, resolveErr.message);
      await invalidateOrg(organizationId);
      return { ok: false, error: resolveErr.message };
    }
    const scanPath = scanTarget.scanPath;

    await ctx((tx) => tx.scan.update({
      where: { id: scanId },
      data: { status: 'running' },
    }));

    // Day 10 — enabled org custom rules fire in this scan. Loading them
    // must never fail the scan: a missing table (pre-migration deploy) or
    // a bad row degrades to built-in rules only, and the scan still runs.
    let customRules = [];
    try {
      const customRows = await ctx((tx) => tx.customRule.findMany({
        where: { organizationId, enabled: true },
        orderBy: { ruleId: 'asc' },
      }));
      customRules = customRows.map(storedRuleToParsed);
    } catch (customErr) {
      console.error('Custom rules unavailable, scanning with built-in rules only:', customErr.message);
    }

    // Execute real security scan over the repository's tree (worker
    // thread — see runScanInThread; inline fallback if the thread fails).
    let scanResult;
    try {
      scanResult = await runScanInThread(scanPath, customRules);
    } catch (threadErr) {
      console.error('Scan worker thread failed, running inline:', threadErr.message);
      scanResult = runSecurityScan(scanPath, customRules);
    }

    // Per-scan cache for git-based file change frequency lookups.
    // All git lookups run up front with bounded concurrency (see
    // getFileChangeFrequency): the loop below must never block the loop.
    const freqCache = new Map();
    const mlFindings = scanResult.findings.filter((f) => f.mlFeatures);
    const freqByIndex = await mapLimit(mlFindings, 8, (f) => getFileChangeFrequency(scanPath, f.filePath, freqCache));

    // Append ML Features
    for (let i = 0; i < mlFindings.length; i++) {
      const finding = mlFindings[i];
      const seenCount = await ctx((tx) => tx.vulnerability.count({
        where: {
          ruleId: finding.ruleId,
          filePath: finding.filePath,
          scan: { repositoryId: repo.id }
        }
      }));
      finding.mlFeatures.same_finding_seen_before_count = seenCount;

      const dismissedCount = await ctx((tx) => tx.vulnerability.count({
        where: {
          ruleId: finding.ruleId,
          status: 'ignored',
          scan: { repositoryId: repo.id }
        }
      }));
      // Classifier schema field is 0/1 — send "was a similar finding ever
      // dismissed", not the raw dismissal count.
      finding.mlFeatures.developer_dismissed_similar_before = dismissedCount > 0 ? 1 : 0;
      finding.mlFeatures.file_change_frequency = freqByIndex[i];

      finding.mlFeatures.rule_id = mapRuleId(finding.ruleId);
      finding.mlFeatures.cwe_id = finding.cweId;
    }

    // ML Classifier Batch Query
    let finalFindings = scanResult.findings;
    const sastFindings = scanResult.findings.filter(f => f.mlFeatures);

    if (sastFindings.length > 0) {
      const BATCH_SIZE = 50;
      const results = [];
      const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || "http://localhost:8001";
      const headers = { 'Content-Type': 'application/json' };
      if (process.env.CLASSIFIER_API_KEY) {
        headers['X-SecureGuard-Key'] = process.env.CLASSIFIER_API_KEY;
      }

      for (let i = 0; i < sastFindings.length; i += BATCH_SIZE) {
        const chunk = sastFindings.slice(i, i + BATCH_SIZE);
        const payload = { findings: chunk.map(f => f.mlFeatures) };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        try {
          const response = await fetch(`${CLASSIFIER_URL}/classify/batch`, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload),
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          if (response.ok) {
            const batchResult = await response.json();
            results.push(...(batchResult.results || []));
          } else {
            results.push(...Array(chunk.length).fill(null));
          }
        } catch (err) {
          clearTimeout(timeoutId);
          results.push(...Array(chunk.length).fill(null));
        }
      }

      const processedSastFindings = sastFindings.map((f, idx) => {
        const classifierResult = results[idx];
        // The classifier was trained on SAST features only. IaC/API-spec
        // findings carry no SAST signals, so a model verdict on them is a
        // guess from neutral defaults — never let it suppress such a finding.
        const isNonSast = !!(f.mlFeatures.isIaC || f.mlFeatures.isApi);
        const pred = isNonSast ? 'REAL' : (classifierResult?.prediction || 'REAL');
        const explanations = classifierResult?.explanations || [];

        return {
          ...f,
          status: pred === 'FALSE_POSITIVE' ? 'ignored' : 'open',
          mlFeatures: {
            ...f.mlFeatures,
            ml_prediction: pred,
            // classifierResult is null when the classifier was unreachable or timed
            // out; keep the 1.0 fail-safe confidence in that case.
            ml_confidence: classifierResult?.confidence ?? 1.0,
            ml_explanation: explanations
          }
        };
      });

      finalFindings = [
        ...scanResult.findings.filter(f => !f.mlFeatures).map(f => ({ ...f, status: 'open' })),
        ...processedSastFindings
      ];
    }

    const critCount = finalFindings.filter(f => f.status === 'open' && f.severity === 'critical').length;
    const highCount = finalFindings.filter(f => f.status === 'open' && f.severity === 'high').length;
    const medCount  = finalFindings.filter(f => f.status === 'open' && f.severity === 'medium').length;
    const lowCount  = finalFindings.filter(f => f.status === 'open' && f.severity === 'low').length;
    const secrets   = finalFindings.filter(f => f.status === 'open' && f.type === 'secret').length;

    const scan = await ctx((tx) => tx.scan.update({
      where: { id: scanId },
      data: {
        status: 'completed',
        totalFiles: scanResult.totalFiles,
        totalLines: scanResult.totalLines,
        criticalCount: critCount,
        highCount: highCount,
        mediumCount: medCount,
        lowCount: lowCount,
        secretsFound: secrets,
        durationMs: scanResult.durationMs,
        completedAt: new Date(),
      },
    }));

    if (finalFindings.length > 0) {
      // Dedup: a re-scan must not insert a second copy of a finding that
      // is already open for this repo (same rule + file + line). Without
      // this every re-scan doubled the Vulnerability table and the counts
      // on every surface diverged. A finding fixed since the last scan is
      // re-inserted (only open rows are skipped), so a regression re-opens.
      // Paths are compared normalised (wrapper segment stripped) and
      // stored normalised, so "SecureGaurd-main/backend/..." and
      // "backend/..." are one finding, not two.
      const stripPrefixes = [repo.name, `${repo.name}-main`, `${repo.name}-master`];
      const alreadyOpen = await ctx((tx) => tx.vulnerability.findMany({
        where: { status: 'open', scan: { repositoryId: repo.id, organizationId } },
        select: { id: true, ruleId: true, filePath: true, lineStart: true },
      }));
      const { fresh: freshFindings, matched } = partitionFindings(finalFindings, alreadyOpen, { stripPrefixes });
      const dbFindings = freshFindings.map(f => ({
        scanId: scan.id,
        ruleId: f.ruleId,
        cweId: f.cweId,
        type: f.type,
        severity: f.severity,
        title: f.title,
        filePath: normalizePath(f.filePath, stripPrefixes),
        lineStart: f.lineStart,
        lineEnd: f.lineEnd,
        codeSnippet: f.codeSnippet,
        // Persist the classifier outcome: suppressed FPs stay 'ignored' so
        // list views and stats (which count open only) agree with counters.
        status: f.status || 'open',
        mlFeatures: f.mlFeatures ? f.mlFeatures : null,
        // The prod column is NOT NULL with no DB default, and createMany
        // omits unlisted fields — send it explicitly or every insert fails.
        detectedInScanIds: [scan.id]
      }));
      if (dbFindings.length > 0) await ctx((tx) => tx.vulnerability.createMany({ data: dbFindings }));
      // Record the re-detections: the scan-detail page lists findings by
      // scanId OR detectedInScanIds, so a scan that deduped everything
      // still shows what it found instead of an empty list.
      const matchedIds = [...new Set(matched.map((m) => m.existingId).filter(Boolean))];
      if (matchedIds.length > 0) {
        await ctx(async (tx) => {
          for (const vid of matchedIds) {
            await tx.vulnerability.update({
              where: { id: vid },
              data: { detectedInScanIds: { push: scan.id } },
            });
          }
        });
      }
    }

    const riskLevel = critCount > 0 ? 'critical' : highCount > 2 ? 'high' : medCount > 3 ? 'medium' : 'low';
    await ctx((tx) => tx.repository.update({
      where: { id: repo.id },
      data: { riskLevel, updatedAt: new Date() },
    }));

    // Generate & Store SPDX 2.3 + CycloneDX 1.6 Software Bills of Materials
    // (SBOM) — both from the same component list, so they cannot disagree.
    try {
      const { generateSpdxDocument } = require('../utils/spdxGenerator');
      const { validateSpdxDocument } = require('../utils/spdxValidator');
      const { generateCycloneDxDocument, validateCycloneDxDocument } = require('../utils/cycloneDxGenerator');

      const { spdxDocument, summaryStats: sbomStats } = generateSpdxDocument({
        repository: repo,
        scanId: scan.id,
        components: scanResult.sbomComponents || [],
        vulnerabilities: finalFindings
      });
      const { cycloneDxDocument } = generateCycloneDxDocument({
        repository: repo,
        scanId: scan.id,
        components: scanResult.sbomComponents || [],
      });
      // Never persist an invalid CycloneDX doc: log and store null (the
      // SPDX row still saves) rather than serving a broken download.
      const cycloneValid = validateCycloneDxDocument(cycloneDxDocument);
      if (!cycloneValid.isValid) console.error('CycloneDX invalid, not stored:', cycloneValid.errors);

      const validation = validateSpdxDocument(spdxDocument);
      // If SPDX is invalid, log the errors and still store the valid
      // CycloneDX document instead of silently dropping both formats.
      // spdxDoc is a required column, so the stored SPDX is a minimal
      // valid document (root package only) whose comment records the
      // validation failure; the generated invalid SPDX is never persisted.
      let spdxToStore = null;
      if (validation.isValid) {
        spdxToStore = spdxDocument;
      } else {
        console.error('SPDX invalid, storing CycloneDX only:', validation.errors);
        if (cycloneValid.isValid) {
          const rootPkg = spdxDocument.packages[0];
          spdxToStore = {
            ...spdxDocument,
            packages: [{ ...rootPkg, comment: `SPDX generation failed validation (${validation.errors.join('; ')}); see the stored CycloneDX document.` }],
            relationships: spdxDocument.relationships.filter((r) => r.relatedSpdxElement === rootPkg.SPDXID),
          };
        }
      }
      if (spdxToStore) {
        await ctx((tx) => tx.sbom.create({
          data: {
            organizationId,
            repositoryId: repo.id,
            scanId: scan.id,
            spdxVersion: 'SPDX-2.3',
            dataLicense: 'CC0-1.0',
            documentNamespace: spdxDocument.documentNamespace,
            name: spdxDocument.name,
            componentCount: sbomStats.componentCount,
            directCount: sbomStats.directCount,
            transitiveCount: sbomStats.transitiveCount,
            vulnerableCount: sbomStats.vulnerableCount,
            ecosystems: sbomStats.ecosystems,
            spdxDoc: spdxToStore,
            cycloneDxDoc: cycloneValid.isValid ? cycloneDxDocument : null
          }
        }));

        await createAuditLog(
          organizationId,
          userId,
          'SBOM_GENERATED',
          'SBOM',
          String(scan.id),
          { repoName: repo.name, componentCount: sbomStats.componentCount, vulnerableCount: sbomStats.vulnerableCount }
        );
      } else {
        console.error('SBOM not stored: both SPDX and CycloneDX documents are invalid');
      }
    } catch (sbomErr) {
      console.error('Error generating SBOM during scan:', sbomErr);
    }

    await createAuditLog(
      organizationId,
      userId,
      'SCAN_COMPLETED',
      'SCAN',
      String(scan.id),
      // findingsCount uses the same definition as the scan row counters
      // (open findings); totalDetected keeps the raw detection count
      // (open + classifier-suppressed) for anyone who needs it.
      { repoName: repo.name, findingsCount: critCount + highCount + medCount + lowCount, totalDetected: finalFindings.length, criticalCount: critCount }
    );

    // Day 7 — opt-in scan-completion alerts (Slack + email). Best-effort:
    // the dispatcher never throws, so a failed alert cannot fail a scan.
    try {
      const { dispatchScanAlerts } = require('../utils/scanAlerts');
      // Own short context: without it the AlertSetting lookup (an RLS
      // table) returns zero rows and no alert is ever sent.
      await withOrgContext(organizationId, userId, (tx) => dispatchScanAlerts({ organizationId, scan, repository: repo, tx }));
    } catch (alertErr) {
      console.error('Scan alert dispatch failed (scan itself succeeded):', alertErr.message);
    }

    if (scanTarget) scanTarget.cleanup();
    // Scan results changed: drop the org's cached lists/summary/detail.
    await invalidateOrg(organizationId);
    return { ok: true, scanId: scan.id, findings: finalFindings.length };
  } catch (err) {
    if (scanTarget) scanTarget.cleanup();
    console.error('Error running scan:', err);
    await markFailed(organizationId, userId, scanId, err.message || 'Unknown scan error');
    await invalidateOrg(organizationId);
    return { ok: false, error: err.message || 'Unknown scan error' };
  }
}

module.exports = { executeScan };
