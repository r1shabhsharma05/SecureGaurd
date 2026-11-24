const express = require('express');
const router = express.Router();
const { validateBody, vulnStatusSchema, vulnLabelSchema, parseIdParam } = require('../utils/validation');
const prisma = require('../prismaClient');
const { authenticateRequest } = require('../middleware/apiKeyAuth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
// SEC-31: Vulnerability is an RLS table — every read/write runs in a
// context. createAuditLog self-wraps, so the audit calls stay as-is.
const { withRequestOrgContext } = require('../utils/rlsContext');
const cache = require('../utils/cache');

router.use(authenticateRequest());
router.use(requireOrgContext);

// GET /api/vulnerabilities — list vulns for active organization (cached 60 s, org-scoped).
// Canonical definition, used by every surface: open findings only, unless
// ?status= is passed explicitly. ?page&limit paginate (default 100/page,
// max 200); X-Total-Count carries the unpaged total. Severity order is a
// rank (critical > high > medium > low), not alphabetical.
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
router.get('/', async (req, res) => {
  const { severity, status, scanId } = req.query;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 100));

  try {
    const cacheKey = cache.keys.vulnList(req.organizationId, JSON.stringify({ severity: severity || null, status: status || 'open', scanId: scanId || null, page, limit }));
    const { value: result, hit } = await cache.getOrSet(cacheKey, cache.TTL.list, async () => {
    // No ?status= means open only: the dashboard, the list and the
    // summary all count the same rows. ?status=all means every status.
    const statusFilter = !status ? 'open' : String(status).toLowerCase() === 'all' ? undefined : String(status).toLowerCase();
    const where = {
      scan: { organizationId: req.organizationId },
      ...(severity && { severity }),
      ...(statusFilter && { status: statusFilter }),
      ...(scanId && parseIdParam(scanId) !== null && { scanId: parseIdParam(scanId) }),
    };

    const rows = await withRequestOrgContext(req, (tx) => tx.vulnerability.findMany({
      where,
      include: {
        scan: { select: { id: true, repository: { select: { id: true, name: true, fullName: true, platform: true, language: true } } } },
      },
      orderBy: { createdAt: 'desc' },
    }));
    rows.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99));
    return { rows: rows.slice((page - 1) * limit, page * limit), total: rows.length, page, limit };
    });
    res.set('X-Cache', hit ? 'HIT' : 'MISS');
    res.set('X-Total-Count', String(result.total));
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching vulnerabilities:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/vulnerabilities/:id — fetch single vulnerability details with org ownership check (cached 120 s, org-scoped; 404s are never cached)
router.get('/:id', async (req, res) => {
  const vulnId = parseIdParam(req.params.id);
  if (vulnId === null) {
    return res.status(400).json({ message: 'Invalid vulnerability ID' });
  }

  try {
    const { value: detail, hit } = await cache.getOrSet(cache.keys.vulnDetail(req.organizationId, vulnId), cache.TTL.detail, async () => {
    // One transaction for both reads: two sequential transactions doubled
    // the round-trips (RLS set_config each) on every detail load.
    return withRequestOrgContext(req, async (tx) => {
    const vuln = await tx.vulnerability.findFirst({
      where: {
        id: vulnId,
        scan: { organizationId: req.organizationId }
      },
      include: {
        scan: {
          select: {
            id: true,
            status: true,
            branch: true,
            commitSha: true,
            createdAt: true,
            repository: {
              select: {
                id: true,
                name: true,
                fullName: true,
                url: true,
                platform: true,
                language: true,
                riskLevel: true,
              }
            }
          }
        }
      }
    });

    if (!vuln) {
      return null;
    }

    // Day 7 — occurrence history: the same finding (same rule + file +
    // LINE) in other scans of the same repository, org-scoped. Matching
    // rule + file only conflated distinct lines into one "finding" and
    // showed legitimately different statuses as a contradiction.
    let occurrences = [];
    if (vuln.ruleId && vuln.scan && vuln.scan.repository) {
      occurrences = await tx.vulnerability.findMany({
        where: {
          id: { not: vulnId },
          ruleId: vuln.ruleId,
          filePath: vuln.filePath,
          lineStart: vuln.lineStart,
          scan: { organizationId: req.organizationId, repositoryId: vuln.scan.repository.id },
        },
        select: {
          id: true, scanId: true, status: true, severity: true, createdAt: true,
          scan: { select: { createdAt: true, commitSha: true, branch: true } },
        },
        orderBy: { createdAt: 'desc' },
        take: 20,
      });
    }

    return { ...vuln, occurrences };
    });
    });
    if (!detail) return res.status(404).json({ message: 'Vulnerability not found' });
    res.set('X-Cache', hit ? 'HIT' : 'MISS');
    res.json(detail);
  } catch (err) {
    console.error('[Vulnerability Detail Error]', err);
    res.status(500).json({ message: 'Failed to fetch vulnerability details' });
  }
});

// GET /api/vulnerabilities/:id/explanation — live classifier reasoning.
// Re-scores the finding's STORED features through the classifier with
// include_explanation=true, so the SHAP top-5 reflects the serving model,
// not a snapshot. No stored features (non-SAST findings) => honest 404;
// classifier unreachable or rejecting the features => 502, never invented
// SHAP values. The stored at-scan-time prediction/reasons in mlFeatures
// remain the fallback the UI shows when this endpoint is unavailable.
router.get('/:id/explanation', async (req, res) => {
  const vulnId = parseIdParam(req.params.id);
  if (vulnId === null) {
    return res.status(400).json({ message: 'Invalid vulnerability ID' });
  }
  try {
    const vuln = await withRequestOrgContext(req, (tx) => tx.vulnerability.findFirst({
      where: { id: vulnId, scan: { organizationId: req.organizationId } },
      select: { mlFeatures: true },
    }));
    if (!vuln) {
      return res.status(404).json({ message: 'Vulnerability not found' });
    }
    const features = typeof vuln.mlFeatures === 'string' ? JSON.parse(vuln.mlFeatures) : vuln.mlFeatures;
    if (!features || !features.rule_id || !features.cwe_id) {
      return res.status(404).json({ message: 'No classifier features stored for this finding (it did not pass through the SAST classifier)' });
    }
    // Send exactly the classifier's 18 raw features; enrichment keys
    // (ml_prediction, ml_confidence, ml_explanation, isIaC/isApi) are not
    // model inputs and must not reach the scoring call.
    const RAW = ['rule_id', 'cwe_id', 'is_string_concat', 'is_parameterized_query', 'has_sanitizer_nearby', 'in_test_file', 'is_in_vendor_or_generated_dir', 'taint_source_distance', 'function_complexity', 'code_snippet_length', 'variable_name_entropy', 'is_user_input_direct', 'has_type_validation', 'is_third_party_lib_call', 'same_finding_seen_before_count', 'developer_dismissed_similar_before', 'file_change_frequency', 'is_authenticated_endpoint'];
    const payload = {};
    for (const key of RAW) {
      if (features[key] !== undefined && features[key] !== null) payload[key] = features[key];
    }
    const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || 'http://localhost:8001';
    const headers = { 'Content-Type': 'application/json' };
    if (process.env.CLASSIFIER_API_KEY) headers['X-SecureGuard-Key'] = process.env.CLASSIFIER_API_KEY;
    // 30 s, not 8 s: the classifier runs on Render's free tier and a cold
    // start can exceed 8 s; aborting that fast turned a slow-but-live
    // classifier into a false 502 (seen in the Day 7 live probe).
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    let clfRes;
    try {
      clfRes = await fetch(`${CLASSIFIER_URL}/classify?include_explanation=true`, {
        method: 'POST', headers, body: JSON.stringify(payload), signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
    if (!clfRes.ok) {
      return res.status(502).json({ message: `Classifier could not explain this finding (responded ${clfRes.status})` });
    }
    const data = await clfRes.json();
    const shap = Array.isArray(data.explanation) && data.explanation.length > 0 && !data.explanation[0].error
      ? data.explanation
      : null;
    const shapError = Array.isArray(data.explanation) && data.explanation[0] && data.explanation[0].error
      ? String(data.explanation[0].error)
      : null;
    return res.json({
      prediction: data.prediction,
      confidence: data.confidence,
      threshold_used: data.threshold_used,
      explanations: data.explanations || [],
      shap,
      shapError,
      model: 'fp-classifier (serving model)',
    });
  } catch (err) {
    console.error('[Vulnerability Explanation Error]', err);
    return res.status(502).json({ message: 'Classifier unreachable for explanation' });
  }
});

// PATCH /api/vulnerabilities/:id/status — mark status in active organization
// Write operation: OWNER/ADMIN/DEVELOPER only (Auditor is read-only).
router.patch('/:id/status', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), validateBody(vulnStatusSchema), async (req, res) => {
  const vulnId = parseIdParam(req.params.id);
  if (vulnId === null) {
    return res.status(400).json({ message: 'Invalid vulnerability ID' });
  }

  const { status } = req.body;
  const allowed = ['open', 'fixed', 'ignored', 'false_positive'];
  if (!allowed.includes(status)) return res.status(400).json({ message: 'Invalid status' });

  try {
    const vuln = await withRequestOrgContext(req, (tx) => tx.vulnerability.findFirst({
      where: { id: vulnId, scan: { organizationId: req.organizationId } },
    }));
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });

    let userLabel = undefined;
    if (status === 'ignored' || status === 'false_positive') {
      userLabel = 'false_positive';
    } else if (status === 'fixed') {
      userLabel = 'real';
    }

    const updated = await withRequestOrgContext(req, (tx) => tx.vulnerability.update({
      where: { id: vuln.id },
      data: {
        status,
        ...(userLabel && { userLabel })
      },
    }));

    await createAuditLog(
      req.organizationId,
      req.userId,
      'VULNERABILITY_STATUS_UPDATED',
      'VULNERABILITY',
      String(vuln.id),
      { title: vuln.title, previousStatus: vuln.status, newStatus: status }
    );

    // The row changed: drop the org's cached vuln lists/detail.
    await cache.invalidateOrg(req.organizationId);

    res.json(updated);
  } catch (err) {
    console.error('Error updating status:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/vulnerabilities/:id/label — explicit ML feedback
// Write operation: OWNER/ADMIN/DEVELOPER only (Auditor is read-only).
router.patch('/:id/label', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), validateBody(vulnLabelSchema), async (req, res) => {
  const vulnId = parseIdParam(req.params.id);
  if (vulnId === null) {
    return res.status(400).json({ message: 'Invalid vulnerability ID' });
  }

  const { label } = req.body;
  const allowed = ['real', 'false_positive'];
  if (!allowed.includes(label)) return res.status(400).json({ message: 'Invalid label. Must be "real" or "false_positive"' });

  try {
    const vuln = await withRequestOrgContext(req, (tx) => tx.vulnerability.findFirst({
      where: { id: vulnId, scan: { organizationId: req.organizationId } },
    }));
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });

    const updated = await withRequestOrgContext(req, (tx) => tx.vulnerability.update({
      where: { id: vuln.id },
      data: { userLabel: label },
    }));

    // Audit every label so retraining data is attributable to the labeler
    // (same shape as the status route above).
    await createAuditLog(
      req.organizationId,
      req.userId,
      'VULNERABILITY_LABEL_UPDATED',
      'VULNERABILITY',
      String(vuln.id),
      { title: vuln.title, previousLabel: vuln.userLabel, label, labeledAt: new Date().toISOString() }
    );

    // The row changed: drop the org's cached vuln lists/detail.
    await cache.invalidateOrg(req.organizationId);

    res.json({ success: true, id: updated.id, userLabel: updated.userLabel });
  } catch (err) {
    console.error('Error updating label:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
