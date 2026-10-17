const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');

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

// GET /api/classifier/status — health + metrics + model info (requires auth)
router.get('/status', authMiddleware, async (req, res) => {
  try {
    // Fetch health, metrics, and model-info in parallel
    const [healthRes, metricsRes, modelRes] = await Promise.allSettled([
      fetchClassifier('/health'),
      fetchClassifier('/metrics'),
      fetchClassifier('/model-info'),
    ]);

    const running = healthRes.status === 'fulfilled' && healthRes.value.ok;

    const metrics = metricsRes.status === 'fulfilled' && metricsRes.value.ok
      ? await metricsRes.value.json()
      : null;

    const modelInfo = modelRes.status === 'fulfilled' && modelRes.value.ok
      ? await modelRes.value.json()
      : null;

    return res.json({
      running,
      classifierUrl: CLASSIFIER_URL,
      metrics,
      modelInfo,
      checkedAt: new Date().toISOString(),
    });
  } catch (err) {
    return res.json({
      running: false,
      classifierUrl: CLASSIFIER_URL,
      error: err.message,
      checkedAt: new Date().toISOString(),
    });
  }
});

// GET /api/classifier/health — public health probe (no auth)
router.get('/health', async (req, res) => {
  try {
    const response = await fetchClassifier('/health');
    if (response.ok) {
      const healthData = await response.json();
      return res.json({ running: true, ...healthData });
    }
    return res.json({ running: false, status: response.status });
  } catch (err) {
    return res.json({ running: false, error: 'Classifier service unreachable' });
  }
});

module.exports = router;
