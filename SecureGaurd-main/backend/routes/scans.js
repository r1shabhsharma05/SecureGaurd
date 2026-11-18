const express = require('express');
const router = express.Router();
const fs = require('fs');
const os = require('os');
const path = require('path');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { checkCanTriggerScan } = require('../services/billingService');
const { fetchPublicSpec, MAX_SPEC_BYTES } = require('../utils/ssrfGuard');
const { scanAPISpecFile } = require('../utils/apiSpecScanner');
const { validateBody, validateQuery, scanTriggerSchema, zPagination } = require('../utils/validation');
const { enqueueScan, getQueueStats } = require('../queues/scanQueue');
const cache = require('../utils/cache');
// SEC-31: Scan/Vulnerability/Sbom/CustomRule/Repository are RLS tables.
// Plain handlers run through withRequestOrgContext (tx replaces prisma).
// POST /trigger interleaves minutes of scanning + classifier HTTP calls
// with DB writes, so it does NOT hold one transaction open: each DB
// segment gets its own short context instead. dispatchScanAlerts takes
// the handler's tx when one exists (see the call site).
const { withRequestOrgContext, withUserContext, withOrgContext } = require('../utils/rlsContext');

// GET /api/scans/export-feedback — export user feedback labels for retraining.
// Two caller kinds: the classifier service (shared CLASSIFIER_API_KEY header,
// operator-level export) and an authenticated user, whose export is scoped to
// the organizations they belong to — never other tenants' labeled findings.
router.get('/export-feedback', validateQuery(zPagination), async (req, res, next) => {
  const apiKey = req.headers['x-secureguard-key'];
  if (process.env.CLASSIFIER_API_KEY && apiKey === process.env.CLASSIFIER_API_KEY) {
    req.serviceKeyCaller = true;
    return next();
  }
  authMiddleware(req, res, next);
}, async (req, res) => {
  try {
    // Unbounded export: cap the rows returned (default 1000, max 5000)
    // so one export cannot dump the whole labeled-findings table.
    // validateQuery(zPagination) already parsed/clamped ?limit=.
    const take = req.query.limit;
    let vulns;
    if (req.serviceKeyCaller) {
      // SEC-31: the operator export has no tenant context, and RLS
      // returns zero rows without one. Fail LOUD (503) rather than
      // silently exporting an empty dataset to the retraining pipeline.
      // The owner must pick the privileged path (a service-role client
      // or a SECURITY DEFINER export function) — see the gate report.
      console.error('[export-feedback] operator export unavailable under RLS (SEC-31): no service-role path configured');
      return res.status(503).json({ message: 'Feedback export is unavailable while RLS is being rolled out (SEC-31).' });
    }
    const memberships = await withUserContext(req.userId, (tx) => tx.organizationMembership.findMany({
      where: { userId: req.userId },
      select: { organizationId: true }
    }));
    // One short RLS transaction per org: a single context holds one org,
    // and the export spans every org the user belongs to. take applies to
    // the concatenated export (the original had no orderBy, so row order
    // was unspecified anyway).
    const perOrg = await Promise.all(memberships.map((m) =>
      withOrgContext(m.organizationId, req.userId, (tx) => tx.vulnerability.findMany({
        where: {
          userLabel: { not: null },
          mlFeatures: { not: null },
          scan: { organizationId: m.organizationId }
        },
        select: { userLabel: true, mlFeatures: true },
        take,
      }))
    ));
    vulns = perOrg.flat().slice(0, take);

    const formatted = vulns.map(v => {
      const features = typeof v.mlFeatures === 'string' ? JSON.parse(v.mlFeatures) : v.mlFeatures;
      return {
        rule_id: features.rule_id || '',
        cwe_id: features.cwe_id || '',
        is_string_concat: features.is_string_concat || 0,
        is_parameterized_query: features.is_parameterized_query || 0,
        has_sanitizer_nearby: features.has_sanitizer_nearby || 0,
        in_test_file: features.in_test_file || 0,
        is_in_vendor_or_generated_dir: features.is_in_vendor_or_generated_dir || 0,
        taint_source_distance: features.taint_source_distance || 5,
        function_complexity: features.function_complexity || 1,
        code_snippet_length: features.code_snippet_length || 0,
        variable_name_entropy: features.variable_name_entropy || 0.0,
        is_user_input_direct: features.is_user_input_direct || 0,
        has_type_validation: features.has_type_validation || 0,
        is_third_party_lib_call: features.is_third_party_lib_call || 0,
        same_finding_seen_before_count: features.same_finding_seen_before_count || 0,
        developer_dismissed_similar_before: features.developer_dismissed_similar_before ? 1 : 0,
        file_change_frequency: features.file_change_frequency || 0,
        is_authenticated_endpoint: features.is_authenticated_endpoint || 0,
        label: v.userLabel === 'real' ? 1 : 0
      };
    });

    res.json(formatted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

router.use(authMiddleware);
router.use(requireOrgContext);

// GET /api/scans/queue/stats — queue depth + cache hit rate (ops visibility).
// Defined BEFORE /:id so "queue" is not read as a scan id.
router.get('/queue/stats', async (req, res) => {
  try {
    const stats = await getQueueStats();
    res.json({ ...stats, cache: cache.getStats() });
  } catch (err) {
    console.error('Error fetching queue stats:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/scans — list scans for active organization (cached 60 s, org-scoped)
router.get('/', async (req, res) => {
  try {
    const { value: scans, hit } = await cache.getOrSet(cache.keys.scanList(req.organizationId), cache.TTL.list, () =>
      withRequestOrgContext(req, (tx) => tx.scan.findMany({
      where: { organizationId: req.organizationId },
      include: {
        repository: { select: { name: true, fullName: true, platform: true } },
        _count: { select: { vulnerabilities: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
    })));
    res.set('X-Cache', hit ? 'HIT' : 'MISS');
    res.json(scans);
  } catch (err) {
    console.error('Error listing scans:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/scans/:id — single scan with vulnerabilities.
// Only TERMINAL scans are cached: queued/running rows change every poll,
// and a cached "running" would lie to the dashboard's 2 s poller.
router.get('/:id', async (req, res) => {
  const scanId = parseInt(req.params.id);
  if (isNaN(scanId)) return res.status(400).json({ message: 'Invalid scan ID' });

  try {
    const found = await cache.get(cache.keys.scanDetail(req.organizationId, scanId));
    if (found.hit) {
      res.set('X-Cache', 'HIT');
      return res.json(found.value);
    }
    const scan = await withRequestOrgContext(req, (tx) => tx.scan.findFirst({
      where: { id: scanId, organizationId: req.organizationId },
      include: {
        repository: true,
        vulnerabilities: { orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }] },
      },
    }));
    if (!scan) return res.status(404).json({ message: 'Scan not found' });
    if (scan.status === 'completed' || scan.status === 'failed') {
      await cache.set(cache.keys.scanDetail(req.organizationId, scanId), scan, cache.TTL.terminalScan);
      res.set('X-Cache', 'MISS');
    } else {
      res.set('X-Cache', 'BYPASS');
    }
    res.json(scan);
  } catch (err) {
    console.error('Error fetching scan:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

const rateLimit = require('express-rate-limit');

const scanTriggerLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  message: { message: 'Too many scan requests triggered. Please wait before triggering another scan.' },
});

// POST /api/scans/trigger — enqueue a real SAST/Secret scan for an org repo.
// Async since the queue landed: the scan runs on a worker (BullMQ/Redis
// when REDIS_URL is set, in-process otherwise), so this returns 202 with
// the queued scan row instead of blocking the request for the whole scan.
// Poll GET /api/scans/:id for queued → running → completed/failed.
// Write operation: OWNER/ADMIN/DEVELOPER only (Auditor is read-only).
router.post('/trigger', scanTriggerLimiter, requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), validateBody(scanTriggerSchema), async (req, res) => {
  // validateBody(scanTriggerSchema) already proved repositoryId a positive
  // integer; it arrives here as a number, never "12abc".
  const { repositoryId } = req.body;

  try {
    // Entitlement Check: Monthly Scan Limit (own short RLS context —
    // the limit counts are tenant-table reads and must not run free).
    const limitCheck = await withRequestOrgContext(req, (tx) => checkCanTriggerScan(req.organizationId, tx));
    if (!limitCheck.allowed) {
      await createAuditLog(
        req.organizationId,
        req.userId,
        'USAGE_LIMIT_REACHED',
        'ORGANIZATION',
        String(req.organizationId),
        { resource: 'SCAN', limit: limitCheck.usage?.limit }
      );
      return res.status(403).json({
        error: limitCheck.reason,
        message: limitCheck.message,
        usage: limitCheck.usage
      });
    }

    // Verify repo belongs to active organization
    const repo = await withRequestOrgContext(req, (tx) => tx.repository.findFirst({
      where: { id: parseInt(repositoryId), organizationId: req.organizationId },
    }));
    if (!repo) return res.status(404).json({ message: 'Repository not found in active organization' });

    // Create the queued scan row first — the worker picks it up by id and
    // moves it queued → running → completed/failed. The row is the poll
    // handle: GET /api/scans/:id is what the dashboard already polls.
    const scan = await withRequestOrgContext(req, (tx) => tx.scan.create({
      data: {
        userId: req.userId,
        organizationId: req.organizationId,
        repositoryId: repo.id,
        status: 'queued',
        branch: 'main',
      },
    }));
    await createAuditLog(
      req.organizationId,
      req.userId,
      'SCAN_QUEUED',
      'SCAN',
      String(scan.id),
      { repoName: repo.name }
    );

    // Enqueue: the worker resolves the repo source (clone/local path),
    // scans, classifies, persists findings + SBOM, and invalidates the
    // cache on completion. A clone/resolve failure marks the scan
    // 'failed' in the worker — the trigger itself only fails if the job
    // cannot be queued at all.
    try {
      await enqueueScan({ scanId: scan.id, organizationId: req.organizationId, userId: req.userId, repositoryId: repo.id });
    } catch (queueErr) {
      console.error('Error queueing scan:', queueErr);
      await withRequestOrgContext(req, (tx) => tx.scan.update({
        where: { id: scan.id },
        data: { status: 'failed', completedAt: new Date(), errorMessage: 'Scan could not be queued. Please try again.' },
      }));
      return res.status(503).json({ message: 'Scan could not be queued. Please try again.', scanId: scan.id });
    }

    return res.status(202).json({ scan, message: `Scan queued. Poll GET /api/scans/${scan.id} for progress.` });
  } catch (err) {
    console.error('Error queueing scan:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/scans/api-spec — scan an OpenAPI/Swagger spec supplied by URL or
// pasted content (Day 5). URL fetches go through the SSRF guard: non-http(s)
// schemes, credential URLs, hosts resolving to non-public addresses, redirect
// hops to private hosts, and bodies over 2 MB are all rejected before any
// fetch of a private target. This is an on-demand check: findings are
// returned in the same shape the repo-scan pipeline persists (type 'api',
// CWE, mlFeatures.isApi); the repo-scan path is what persists findings and
// classifier-passes them (IaC/API findings are forced REAL there, never
// suppressed by the SAST-trained model).
router.post('/api-spec', scanTriggerLimiter, requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), async (req, res) => {
  try {
    const { specUrl, specContent, fileName } = req.body || {};
    if ((specUrl && specContent) || (!specUrl && !specContent)) {
      return res.status(400).json({ message: 'Provide exactly one of specUrl or specContent.' });
    }

    let content;
    let sourceName;
    let finalUrl = null;

    if (specUrl) {
      if (typeof specUrl !== 'string' || specUrl.length > 2048) {
        return res.status(400).json({ message: 'Invalid specUrl.' });
      }
      try {
        const fetched = await fetchPublicSpec(specUrl);
        content = fetched.content;
        finalUrl = fetched.finalUrl;
      } catch (err) {
        const msg = err.message || 'Failed to fetch spec URL.';
        const blocked = /blocked|Invalid|credentials|redirects|too large|does not resolve/.test(msg);
        return res.status(blocked ? 400 : 502).json({ message: msg });
      }
      try {
        const base = path.basename(new URL(finalUrl).pathname);
        sourceName = /\.(ya?ml|json)$/i.test(base) ? base : 'spec.yaml';
      } catch (e) {
        sourceName = 'spec.yaml';
      }
    } else {
      if (typeof specContent !== 'string' || specContent.length === 0 || specContent.length > MAX_SPEC_BYTES) {
        return res.status(400).json({ message: 'specContent must be a non-empty string under 2 MB.' });
      }
      content = specContent;
      const safeBase = typeof fileName === 'string' ? path.basename(fileName) : '';
      sourceName = /\.(ya?ml|json)$/i.test(safeBase) ? safeBase : 'spec.yaml';
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-spec-'));
    try {
      const tmpFile = path.join(tmpDir, sourceName);
      fs.writeFileSync(tmpFile, content, 'utf8');
      const findings = scanAPISpecFile(tmpFile, sourceName);
      const counts = {
        total: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      };
      return res.json({ source: specUrl ? 'url' : 'content', finalUrl, fileName: sourceName, findings, counts });
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  } catch (err) {
    console.error('Error scanning API spec:', err);
    return res.status(500).json({ message: 'Failed to scan API spec' });
  }
});

// GET /api/scans/stats/summary — dashboard summary stats for active organization (cached 30 s, org-scoped)
router.get('/stats/summary', async (req, res) => {
  try {
    const { value: summary, hit } = await cache.getOrSet(cache.keys.scanSummary(req.organizationId), cache.TTL.summary, async () => {
      const vulns = await withRequestOrgContext(req, (tx) => tx.vulnerability.findMany({
        where: {
          scan: { organizationId: req.organizationId },
          status: 'open',
        },
        select: { severity: true },
      }));

      const critical = vulns.filter(v => v.severity === 'critical').length;
      const high     = vulns.filter(v => v.severity === 'high').length;
      const medium   = vulns.filter(v => v.severity === 'medium').length;
      const low      = vulns.filter(v => v.severity === 'low').length;
      const total    = vulns.length;
      const health   = Math.max(0, 100 - critical * 15 - high * 8 - medium * 3 - low);

      const lastScan = await withRequestOrgContext(req, (tx) => tx.scan.findFirst({
        where: { organizationId: req.organizationId, status: 'completed' },
        orderBy: { createdAt: 'desc' },
        select: { durationMs: true, totalFiles: true, createdAt: true },
      }));

      return { critical, high, medium, low, total, health, lastScan };
    });
    res.set('X-Cache', hit ? 'HIT' : 'MISS');
    res.json(summary);
  } catch (err) {
    console.error('Error fetching summary stats:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
