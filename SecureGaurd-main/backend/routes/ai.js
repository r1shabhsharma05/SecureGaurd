const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, createAuditLog } = require('../middleware/rbac');
const { generateAiFix } = require('../utils/aiFixEngine');

router.use(authMiddleware);
router.use(requireOrgContext);

// POST /api/ai/fix/:vulnId — Generate AI fix for a vulnerability
router.post('/fix/:vulnId', async (req, res) => {
  const vulnId = parseInt(req.params.vulnId);
  if (isNaN(vulnId)) return res.status(400).json({ message: 'Invalid vulnerability ID' });

  try {
    const vuln = await prisma.vulnerability.findFirst({
      where: {
        id: vulnId,
        scan: { organizationId: req.organizationId }
      }
    });
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });

    // If fix already cached, return it
    if (vuln.aiFix) {
      return res.json({
        vulnId: vuln.id,
        fixedCode: vuln.aiFix,
        cached: true,
        aiFixApplied: vuln.aiFixApplied
      });
    }

    // Generate AI fix
    const result = await generateAiFix(vuln);

    // Cache the fix in the database — only in aiFix.
    // Never overwrite description/cweId: they hold the scanner's
    // original finding and must survive AI-fix generation (F10).
    await prisma.vulnerability.update({
      where: { id: vuln.id },
      data: {
        aiFix: result.fixedCode,
      }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'AI_FIX_GENERATED',
      'VULNERABILITY',
      String(vuln.id),
      { title: vuln.title, engine: result.engine }
    );

    res.json({
      vulnId: vuln.id,
      fixedCode: result.fixedCode,
      explanation: result.explanation,
      confidence: result.confidence,
      cweId: result.cweId,
      cvssScore: result.cvssScore,
      references: result.references,
      engine: result.engine,
      cached: false
    });
  } catch (err) {
    console.error('[AI Fix]', err);
    res.status(500).json({ message: 'Failed to generate AI fix' });
  }
});

// PATCH /api/ai/fix/:vulnId/apply — Mark AI fix as applied + resolve vulnerability
router.patch('/fix/:vulnId/apply', async (req, res) => {
  const vulnId = parseInt(req.params.vulnId);
  if (isNaN(vulnId)) return res.status(400).json({ message: 'Invalid vulnerability ID' });

  try {
    const vuln = await prisma.vulnerability.findFirst({
      where: {
        id: vulnId,
        scan: { organizationId: req.organizationId }
      }
    });
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });
    if (!vuln.aiFix) return res.status(400).json({ message: 'Generate AI fix first before applying' });

    const updated = await prisma.vulnerability.update({
      where: { id: vuln.id },
      data: { aiFixApplied: true, status: 'fixed', userLabel: 'real' }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'AI_FIX_APPLIED',
      'VULNERABILITY',
      String(vuln.id),
      { title: vuln.title }
    );

    res.json({ message: 'AI fix applied successfully', vulnerability: updated });
  } catch (err) {
    console.error('[AI Apply]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/ai/false-positive/:vulnId — Mark as false positive
router.patch('/false-positive/:vulnId', async (req, res) => {
  const vulnId = parseInt(req.params.vulnId);
  if (isNaN(vulnId)) return res.status(400).json({ message: 'Invalid vulnerability ID' });

  try {
    const vuln = await prisma.vulnerability.findFirst({
      where: {
        id: vulnId,
        scan: { organizationId: req.organizationId }
      }
    });
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });

    const updated = await prisma.vulnerability.update({
      where: { id: vuln.id },
      data: { status: 'false_positive', userLabel: 'false_positive' }
    });

    res.json({ message: 'Marked as false positive', vulnerability: updated });
  } catch (err) {
    console.error('[False Positive]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/ai/status — Check if Gemini API is configured
router.get('/status', async (req, res) => {
  res.json({
    engine: process.env.GEMINI_API_KEY ? 'gemini-1.5-flash' : 'rule-based',
    geminiConfigured: !!process.env.GEMINI_API_KEY,
    capabilities: ['fix-generation', 'false-positive-detection', 'cvss-scoring', 'cwe-mapping']
  });
});

module.exports = router;
