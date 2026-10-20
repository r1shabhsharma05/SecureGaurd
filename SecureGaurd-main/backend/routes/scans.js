const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, createAuditLog } = require('../middleware/rbac');
const { checkCanTriggerScan } = require('../services/billingService');
const path = require('path');
const { execFileSync } = require('child_process');
const { runSecurityScan } = require('../utils/securityScanner');

// ─── ML feature: file change frequency from git history ─────────────────────
// The FP classifier was trained with file_change_frequency in 0..50
// (see backend/services/fp-classifier/generate_sample_data.py), but scans used
// to send a hardcoded 0, making the feature dead weight in production. Counting
// commits via `git log` keeps production inputs in-distribution. Falls back to
// 0 when git is unavailable or the scan target is not a git checkout.
const MAX_FILE_CHANGE_FREQUENCY = 50;
function getFileChangeFrequency(scanRoot, relFilePath, cache) {
  const cacheKey = `${scanRoot}::${relFilePath}`;
  if (cache.has(cacheKey)) return cache.get(cacheKey);
  let count = 0;
  try {
    const out = execFileSync('git', ['-C', scanRoot, 'log', '--format=%H', '--', relFilePath], {
      encoding: 'utf8',
      timeout: 10000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    count = Math.min(out.split('\n').filter(Boolean).length, MAX_FILE_CHANGE_FREQUENCY);
  } catch (err) {
    count = 0;
  }
  cache.set(cacheKey, count);
  return count;
}

// GET /api/scans/export-feedback — export all user feedback labels for retraining
router.get('/export-feedback', async (req, res, next) => {
  const apiKey = req.headers['x-secureguard-key'];
  if (process.env.CLASSIFIER_API_KEY && apiKey === process.env.CLASSIFIER_API_KEY) {
    return next();
  }
  authMiddleware(req, res, next);
}, async (req, res) => {
  try {
    const vulns = await prisma.vulnerability.findMany({
      where: {
        userLabel: { not: null },
        mlFeatures: { not: null }
      },
      select: {
        userLabel: true,
        mlFeatures: true
      }
    });

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
        developer_dismissed_similar_before: features.developer_dismissed_similar_before || 0,
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

// GET /api/scans — list scans for active organization
router.get('/', async (req, res) => {
  try {
    const scans = await prisma.scan.findMany({
      where: { organizationId: req.organizationId },
      include: {
        repository: { select: { name: true, fullName: true, platform: true } },
        _count: { select: { vulnerabilities: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
    res.json(scans);
  } catch (err) {
    console.error('Error listing scans:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/scans/:id — single scan with vulnerabilities
router.get('/:id', async (req, res) => {
  const scanId = parseInt(req.params.id);
  if (isNaN(scanId)) return res.status(400).json({ message: 'Invalid scan ID' });

  try {
    const scan = await prisma.scan.findFirst({
      where: { id: scanId, organizationId: req.organizationId },
      include: {
        repository: true,
        vulnerabilities: { orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }] },
      },
    });
    if (!scan) return res.status(404).json({ message: 'Scan not found' });
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

// POST /api/scans/trigger — trigger a real SAST/Secret scan for an organization repo
router.post('/trigger', scanTriggerLimiter, async (req, res) => {
  const { repositoryId } = req.body;
  if (!repositoryId || isNaN(parseInt(repositoryId))) return res.status(400).json({ message: 'Valid repositoryId is required' });

  try {
    // Entitlement Check: Monthly Scan Limit
    const limitCheck = await checkCanTriggerScan(req.organizationId);
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
    const repo = await prisma.repository.findFirst({
      where: { id: parseInt(repositoryId), organizationId: req.organizationId },
    });
    if (!repo) return res.status(404).json({ message: 'Repository not found in active organization' });

    // Path to scan is the project root folder
    const scanPath = path.join(__dirname, '..', '..');
    
    // Execute real security scan
    const scanResult = runSecurityScan(scanPath);

    // Per-scan cache for git-based file change frequency lookups
    const freqCache = new Map();

    // Append ML Features
    for (let finding of scanResult.findings) {
      if (finding.mlFeatures) {
        const seenCount = await prisma.vulnerability.count({
          where: {
            ruleId: finding.ruleId,
            filePath: finding.filePath,
            scan: { repositoryId: repo.id }
          }
        });
        finding.mlFeatures.same_finding_seen_before_count = seenCount;

        const dismissedCount = await prisma.vulnerability.count({
          where: {
            ruleId: finding.ruleId,
            status: 'ignored',
            scan: { repositoryId: repo.id }
          }
        });
        finding.mlFeatures.developer_dismissed_similar_before = dismissedCount;
        finding.mlFeatures.file_change_frequency = getFileChangeFrequency(scanPath, finding.filePath, freqCache);

        const RULE_MAP = {
          'SAST-001': 'sqli-concat',
          'SAST-002': 'xss-unescaped',
          'SAST-003': 'path-traversal',
          'SAST-004': 'hardcoded-secret',
          'SAST-005': 'insecure-deserialize',
          'SEC-001': 'hardcoded-secret',
          'SEC-002': 'hardcoded-secret',
          'SEC-003': 'hardcoded-secret',
        };
        finding.mlFeatures.rule_id = RULE_MAP[finding.ruleId] || finding.ruleId;
        finding.mlFeatures.cwe_id = finding.cweId;
      }
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
        const pred = classifierResult?.prediction || 'REAL';
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

    const scan = await prisma.scan.create({
      data: {
        userId: req.userId,
        organizationId: req.organizationId,
        repositoryId: repo.id,
        status: 'completed',
        branch: 'main',
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
    });

    if (finalFindings.length > 0) {
      const dbFindings = finalFindings.map(f => ({
        scanId: scan.id,
        ruleId: f.ruleId,
        cweId: f.cweId,
        type: f.type,
        severity: f.severity,
        title: f.title,
        filePath: f.filePath,
        lineStart: f.lineStart,
        lineEnd: f.lineEnd,
        codeSnippet: f.codeSnippet,
        status: 'open',
        mlFeatures: f.mlFeatures ? f.mlFeatures : null
      }));
      await prisma.vulnerability.createMany({ data: dbFindings });
    }

    const riskLevel = critCount > 0 ? 'critical' : highCount > 2 ? 'high' : medCount > 3 ? 'medium' : 'low';
    await prisma.repository.update({
      where: { id: repo.id },
      data: { riskLevel, updatedAt: new Date() },
    });

    // Generate & Store SPDX 2.3 Software Bill of Materials (SBOM)
    try {
      const { generateSpdxDocument } = require('../utils/spdxGenerator');
      const { validateSpdxDocument } = require('../utils/spdxValidator');

      const { spdxDocument, summaryStats: sbomStats } = generateSpdxDocument({
        repository: repo,
        scanId: scan.id,
        components: scanResult.sbomComponents || [],
        vulnerabilities: finalFindings
      });

      const validation = validateSpdxDocument(spdxDocument);
      if (validation.isValid) {
        await prisma.sbom.create({
          data: {
            organizationId: req.organizationId,
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
            spdxDoc: spdxDocument
          }
        });

        await createAuditLog(
          req.organizationId,
          req.userId,
          'SBOM_GENERATED',
          'SBOM',
          String(scan.id),
          { repoName: repo.name, componentCount: sbomStats.componentCount, vulnerableCount: sbomStats.vulnerableCount }
        );
      }
    } catch (sbomErr) {
      console.error('Error generating SBOM during scan:', sbomErr);
    }

    await createAuditLog(
      req.organizationId,
      req.userId,
      'SCAN_COMPLETED',
      'SCAN',
      String(scan.id),
      { repoName: repo.name, findingsCount: finalFindings.length, criticalCount: critCount }
    );

    res.status(201).json({ scan, message: `Scan completed. Evaluated ${scanResult.totalFiles} files. Found ${finalFindings.length} real issues.` });
  } catch (err) {
    console.error('Error running scan:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/scans/stats/summary — dashboard summary stats for active organization
router.get('/stats/summary', async (req, res) => {
  try {
    const vulns = await prisma.vulnerability.findMany({
      where: {
        scan: { organizationId: req.organizationId },
        status: 'open',
      },
      select: { severity: true },
    });

    const critical = vulns.filter(v => v.severity === 'critical').length;
    const high     = vulns.filter(v => v.severity === 'high').length;
    const medium   = vulns.filter(v => v.severity === 'medium').length;
    const low      = vulns.filter(v => v.severity === 'low').length;
    const total    = vulns.length;
    const health   = Math.max(0, 100 - critical * 15 - high * 8 - medium * 3 - low);

    const lastScan = await prisma.scan.findFirst({
      where: { organizationId: req.organizationId, status: 'completed' },
      orderBy: { createdAt: 'desc' },
      select: { durationMs: true, totalFiles: true, createdAt: true },
    });

    res.json({ critical, high, medium, low, total, health, lastScan });
  } catch (err) {
    console.error('Error fetching summary stats:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
