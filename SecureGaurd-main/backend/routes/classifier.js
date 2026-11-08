const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole } = require('../middleware/rbac');

const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || 'http://localhost:8001';
const CLASSIFIER_API_KEY = process.env.CLASSIFIER_API_KEY || '';

const classifierHeaders = {
  'Content-Type': 'application/json',
  ...(CLASSIFIER_API_KEY ? { 'X-SecureGuard-Key': CLASSIFIER_API_KEY } : {}),
};

// Helper: fetch from classifier with timeout
async function fetchClassifier(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const classifierResponse = await fetch(`${CLASSIFIER_URL}${path}`, {
      headers: classifierHeaders,
      signal: controller.signal,
      ...options,
    });
    clearTimeout(timeout);
    return classifierResponse;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// GET /api/classifier/status — coarse status only (org OWNER/ADMIN).
// Never returns the internal classifier URL or raw model-info.
router.get('/status', authMiddleware, requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  try {
    // Fetch health and metrics in parallel
    const [healthRes, metricsRes] = await Promise.allSettled([
      fetchClassifier('/health'),
      fetchClassifier('/metrics'),
    ]);

    const running = healthRes.status === 'fulfilled' && healthRes.value.ok;

    const metrics = metricsRes.status === 'fulfilled' && metricsRes.value.ok
      ? await metricsRes.value.json()
      : null;

    return res.json({
      running,
      metrics,
      checkedAt: new Date().toISOString(),
    });
  } catch (err) {
    return res.json({
      running: false,
      checkedAt: new Date().toISOString(),
    });
  }
});

// GET /api/classifier/health — public health probe (no auth), coarse
// { running: boolean } only; no upstream detail is re-served.
router.get('/health', async (req, res) => {
  try {
    const response = await fetchClassifier('/health');
    return res.json({ running: response.ok });
  } catch (err) {
    return res.json({ running: false });
  }
});

module.exports = router;
