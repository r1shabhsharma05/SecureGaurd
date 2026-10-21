const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');
const { requireOrgContext } = require('../middleware/rbac');
const prisma = require('../prismaClient');

// Versioned ML API (v2). v1 (/api/classifier) proxies the FP classifier's
// /classify endpoints; v2 serves the severity-priority ranker (/v2/rank).
const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || 'http://localhost:8001';
const CLASSIFIER_API_KEY = process.env.CLASSIFIER_API_KEY || '';

const classifierHeaders = {
  'Content-Type': 'application/json',
  ...(CLASSIFIER_API_KEY ? { 'X-SecureGuard-Key': CLASSIFIER_API_KEY } : {}),
};

// Mirrors backend/services/severity-ranker/severity_schema.py CWE_BASE_SCORE.
// The Python table is canonical; this copy exists ONLY for the degraded
// fallback below (classifier unreachable). Keep in sync when tiers change.
const CWE_BASE_SCORE = {
  'CWE-89': 85,   // SQL injection
  'CWE-918': 85,  // SSRF
  'CWE-502': 80,  // Insecure deserialization
  'CWE-22': 75,   // Path traversal
  'CWE-79': 70,   // XSS
  'CWE-798': 60,  // Hardcoded credentials
};
const DEFAULT_BASE_SCORE = 65;

function bandFor(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

// Helper: fetch from the Python ML service with a timeout.
async function fetchMl(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(`${CLASSIFIER_URL}${path}`, {
      headers: classifierHeaders,
      signal: controller.signal,
      ...options,
    });
    clearTimeout(timeout);
    return res;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// POST /api/v2/ml/rank — priority scores for the caller's vulnerabilities.
// Body: { vulnerabilityIds: number[] } (1..100). Returns the ranked list
// (highest priority first). Findings without stored mlFeatures cannot be
// scored and are omitted; the frontend keeps them in default order.
router.post('/rank', authMiddleware, requireOrgContext, async (req, res) => {
  const { vulnerabilityIds } = req.body || {};
  if (!Array.isArray(vulnerabilityIds) || vulnerabilityIds.length === 0 || vulnerabilityIds.length > 100) {
    return res.status(400).json({ message: 'vulnerabilityIds must be a non-empty array (max 100)' });
  }
  const ids = vulnerabilityIds.filter((n) => Number.isInteger(n));
  if (ids.length === 0) {
    return res.status(400).json({ message: 'vulnerabilityIds must contain integer ids' });
  }

  let vulns;
  try {
    vulns = await prisma.vulnerability.findMany({
      where: { id: { in: ids }, scan: { organizationId: req.organizationId } },
      select: { id: true, cweId: true, mlFeatures: true },
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error' });
  }

  // Only findings that went through the scan pipeline carry the 18 raw
  // features the ranker needs. The Python Finding schema ignores the extra
  // ml_prediction/ml_confidence enrichment keys, so pass-through is safe.
  const withFeatures = vulns.filter((v) => v.mlFeatures);
  const findings = withFeatures.map((v) =>
    typeof v.mlFeatures === 'string' ? JSON.parse(v.mlFeatures) : v.mlFeatures
  );

  try {
    const mlRes = await fetchMl('/v2/rank/batch', {
      method: 'POST',
      body: JSON.stringify({ findings }),
    });
    if (!mlRes.ok) throw new Error(`ranker responded ${mlRes.status}`);
    const data = await mlRes.json();
    const ranked = withFeatures
      .map((v, i) => ({ id: v.id, ...(data.results[i] || {}) }))
      .sort((a, b) => (b.priority_score ?? -1) - (a.priority_score ?? -1));
    return res.json({ ranked, degraded: false, model: 'severity-ranker/v0_heuristic' });
  } catch (err) {
    // Graceful degradation: classifier unreachable or errored — fall back to
    // static CWE-tier ordering, explicitly marked so the UI can say so.
    // Never leak the classifier error text to the client.
    const ranked = withFeatures
      .map((v) => {
        const score = CWE_BASE_SCORE[v.cweId] ?? DEFAULT_BASE_SCORE;
        return { id: v.id, priority_score: score, band: bandFor(score), fallback: true };
      })
      .sort((a, b) => b.priority_score - a.priority_score);
    return res.json({
      ranked,
      degraded: true,
      reason: 'classifier unreachable — tier-based fallback order',
    });
  }
});

module.exports = router;
