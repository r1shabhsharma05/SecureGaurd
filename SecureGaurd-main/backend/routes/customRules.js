const express = require('express');
const router = express.Router();
const path = require('path');
const rateLimit = require('express-rate-limit');
const { Worker } = require('worker_threads');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { parseCustomRuleYaml, publicCustomRule, storedRuleToParsed } = require('../utils/customRules');
const { runSecurityScan, BUILTIN_RULES } = require('../utils/securityScanner');
const { IAC_RULES } = require('../utils/rules/iacRules');
const { API_RULES } = require('../utils/rules/apiRules');
const { resolveScanTarget } = require('../utils/repoScanSource');

router.use(authMiddleware);
router.use(requireOrgContext);

const MAX_RULES_PER_ORG = 50;
const WRITE_ROLES = ['OWNER', 'ADMIN', 'DEVELOPER'];

// Same budget as the scan trigger limiter (routes/scans.js): the test
// endpoint executes author-supplied regexes, so it is rate-limited like a
// scan trigger and restricted to WRITE_ROLES — a read-only AUDITOR must
// not be able to trigger a rule authored by someone else.
const customRuleTestLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  message: { message: 'Too many rule test requests. Please wait before testing another rule.' },
});

const RULE_TEST_TIMEOUT_MS = 5000;

/**
 * Run one stored rule's matching in a worker thread so a pathological
 * pattern (e.g. one stored before the write-time nested-quantifier guard)
 * can stall only the worker, never this process's event loop. The worker
 * is terminated on timeout; the caller gets a 503, not a hung process.
 */
function testRuleInWorker(rule, relPath, lines) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn, value) => { if (!settled) { settled = true; clearTimeout(timer); fn(value); } };
    const worker = new Worker(
      `
      const { parentPort, workerData } = require('worker_threads');
      const { compileCustomRules, matchCustomRules } = require(${JSON.stringify(require.resolve('../utils/customRules'))});
      const compiled = compileCustomRules([workerData.rule]);
      const matches = [];
      // A rule skipped at compile time (e.g. a pathological pattern
      // stored before the write-time guard) compiles to nothing: the
      // test honestly reports zero matches instead of crashing.
      if (compiled.length > 0) {
        workerData.lines.forEach((line, idx) => {
          matches.push(...matchCustomRules(compiled, workerData.relPath, line, idx + 1));
        });
      }
      parentPort.postMessage(matches);
      `,
      { eval: true, workerData: { rule, relPath, lines } },
    );
    const timer = setTimeout(() => {
      worker.terminate().catch(() => {});
      settle(reject, new Error('Rule test timed out: the pattern took too long to evaluate'));
    }, RULE_TEST_TIMEOUT_MS);
    worker.on('message', (matches) => { worker.terminate().catch(() => {}); settle(resolve, matches); });
    worker.on('error', (err) => settle(reject, err));
    worker.on('exit', (code) => {
      if (code !== 0) settle(reject, new Error(`Rule test worker exited with code ${code}`));
    });
  });
}

// GET /api/custom-rules/library — built-in rule library (read-only reference
// for authors writing custom rules). Any org member may read it.
router.get('/library', async (req, res) => {
  const builtin = BUILTIN_RULES.map((r) => ({
    id: r.id,
    title: r.title,
    severity: r.severity,
    type: r.type,
    description: r.description,
    pattern: r.regex.source,
    source: 'built-in',
    framework: 'SAST/Secrets',
  }));
  const iac = Object.values(IAC_RULES).map((r) => ({
    id: r.ruleId,
    title: r.title,
    severity: r.severity,
    type: 'iac',
    description: r.description,
    remediation: r.remediation,
    cweId: r.cweId,
    pattern: null,
    source: 'built-in',
    framework: r.framework,
  }));
  const api = Object.values(API_RULES).map((r) => ({
    id: r.ruleId,
    title: r.title,
    severity: r.severity,
    type: 'api',
    description: r.description,
    remediation: r.remediation,
    cweId: r.cweId,
    pattern: null,
    source: 'built-in',
    framework: r.framework,
  }));
  res.json({ builtin: [...builtin, ...iac, ...api], total: builtin.length + iac.length + api.length });
});

// GET /api/custom-rules — list this org's rules (any member).
router.get('/', async (req, res) => {
  try {
    const rows = await prisma.customRule.findMany({
      where: { organizationId: req.organizationId },
      orderBy: { ruleId: 'asc' },
    });
    res.json(rows.map(publicCustomRule));
  } catch (err) {
    console.error('Error listing custom rules:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/custom-rules/:id — one rule (any member).
router.get('/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ message: 'Invalid rule ID' });
  try {
    const row = await prisma.customRule.findFirst({ where: { id, organizationId: req.organizationId } });
    if (!row) return res.status(404).json({ message: 'Custom rule not found' });
    res.json(publicCustomRule(row));
  } catch (err) {
    console.error('Error fetching custom rule:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

async function loadRule(req, res) {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    res.status(400).json({ message: 'Invalid rule ID' });
    return null;
  }
  const row = await prisma.customRule.findFirst({ where: { id, organizationId: req.organizationId } });
  if (!row) {
    res.status(404).json({ message: 'Custom rule not found' });
    return null;
  }
  return row;
}

function ruleDataFromParsed(parsed, organizationId, createdById) {
  return {
    organizationId,
    ruleId: parsed.id,
    title: parsed.title,
    severity: parsed.severity,
    type: parsed.type,
    pattern: parsed.pattern,
    ignoreCase: parsed.ignoreCase,
    filePattern: parsed.filePattern,
    excludePattern: parsed.excludePattern,
    description: parsed.description,
    remediation: parsed.remediation,
    cweId: parsed.cweId,
    enabled: parsed.enabled,
    createdById,
  };
}

// POST /api/custom-rules — create from YAML. OWNER/ADMIN/DEVELOPER only.
router.post('/', requireOrgRole(WRITE_ROLES), async (req, res) => {
  const { yaml: yamlText } = req.body || {};
  let parsed;
  try {
    parsed = parseCustomRuleYaml(yamlText);
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }
  try {
    const count = await prisma.customRule.count({ where: { organizationId: req.organizationId } });
    if (count >= MAX_RULES_PER_ORG) {
      return res.status(400).json({ message: `Organization already has the maximum of ${MAX_RULES_PER_ORG} custom rules` });
    }
    const existing = await prisma.customRule.findFirst({
      where: { organizationId: req.organizationId, ruleId: parsed.id },
    });
    if (existing) return res.status(409).json({ message: `A rule with id ${parsed.id} already exists in this organization` });
    const row = await prisma.customRule.create({
      data: ruleDataFromParsed(parsed, req.organizationId, req.userId),
    });
    await createAuditLog(req.organizationId, req.userId, 'CUSTOM_RULE_CREATED', 'CUSTOM_RULE', String(row.id), { ruleId: row.ruleId, title: row.title });
    res.status(201).json(publicCustomRule(row));
  } catch (err) {
    console.error('Error creating custom rule:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/custom-rules/:id — full replace from YAML, or {enabled} toggle.
// A YAML replace must carry the same id as the stored rule (ids are immutable).
router.patch('/:id', requireOrgRole(WRITE_ROLES), async (req, res) => {
  try {
    const row = await loadRule(req, res);
    if (!row) return;
    const { yaml: yamlText, enabled } = req.body || {};
    if (yamlText !== undefined) {
      let parsed;
      try {
        parsed = parseCustomRuleYaml(yamlText);
      } catch (err) {
        return res.status(400).json({ message: err.message });
      }
      if (parsed.id !== row.ruleId) {
        return res.status(400).json({ message: `Rule id is immutable: YAML id ${parsed.id} does not match stored rule ${row.ruleId}` });
      }
      const updated = await prisma.customRule.update({
        where: { id: row.id },
        data: ruleDataFromParsed(parsed, req.organizationId, row.createdById),
      });
      await createAuditLog(req.organizationId, req.userId, 'CUSTOM_RULE_UPDATED', 'CUSTOM_RULE', String(row.id), { ruleId: row.ruleId });
      return res.json(publicCustomRule(updated));
    }
    if (typeof enabled === 'boolean') {
      const updated = await prisma.customRule.update({ where: { id: row.id }, data: { enabled } });
      await createAuditLog(req.organizationId, req.userId, 'CUSTOM_RULE_UPDATED', 'CUSTOM_RULE', String(row.id), { ruleId: row.ruleId, enabled });
      return res.json(publicCustomRule(updated));
    }
    return res.status(400).json({ message: 'Provide yaml (full rule) or enabled (true/false)' });
  } catch (err) {
    console.error('Error updating custom rule:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/custom-rules/:id — OWNER/ADMIN/DEVELOPER only. Past findings
// keep the ruleId; only future scans stop firing this rule.
router.delete('/:id', requireOrgRole(WRITE_ROLES), async (req, res) => {
  try {
    const row = await loadRule(req, res);
    if (!row) return;
    await prisma.customRule.delete({ where: { id: row.id } });
    await createAuditLog(req.organizationId, req.userId, 'CUSTOM_RULE_DELETED', 'CUSTOM_RULE', String(row.id), { ruleId: row.ruleId });
    res.status(204).end();
  } catch (err) {
    console.error('Error deleting custom rule:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/custom-rules/:id/test — test against pasted sample code.
// OWNER/ADMIN/DEVELOPER only, rate-limited like a scan trigger. Matching
// runs in a worker thread with a timeout (see testRuleInWorker), so a
// pathological stored pattern cannot block the main event loop. Body:
// { code: string, filePath?: string }.
router.post('/:id/test', customRuleTestLimiter, requireOrgRole(WRITE_ROLES), async (req, res) => {
  try {
    const row = await loadRule(req, res);
    if (!row) return;
    const { code, filePath } = req.body || {};
    if (typeof code !== 'string' || code.length === 0 || code.length > 200000) {
      return res.status(400).json({ message: 'code must be a non-empty string under 200 KB' });
    }
    const relPath = typeof filePath === 'string' && filePath ? path.basename(filePath) : 'sample.js';
    let matches;
    try {
      matches = await testRuleInWorker(storedRuleToParsed(row), relPath, code.split('\n'));
    } catch (workerErr) {
      if (/timed out/.test(workerErr.message)) {
        return res.status(503).json({ message: workerErr.message });
      }
      throw workerErr;
    }
    res.json({ ruleId: row.ruleId, filePath: relPath, matchCount: matches.length, matches });
  } catch (err) {
    console.error('Error testing custom rule:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/custom-rules/:id/test-scan — test against a past scan's
// repository. OWNER/ADMIN/DEVELOPER only. The repository tree is re-scanned
// as it exists NOW (a past scan's frozen tree is not stored) with ONLY this
// rule enabled, so the match list proves the rule fires in the real engine.
// Body: { scanId: number }.
router.post('/:id/test-scan', requireOrgRole(WRITE_ROLES), async (req, res) => {
  let scanTarget = null;
  try {
    const row = await loadRule(req, res);
    if (!row) return;
    const scanId = parseInt(req.body?.scanId, 10);
    if (isNaN(scanId)) return res.status(400).json({ message: 'scanId is required' });
    const scan = await prisma.scan.findFirst({
      where: { id: scanId, organizationId: req.organizationId },
      include: { repository: true },
    });
    if (!scan) return res.status(404).json({ message: 'Scan not found in this organization' });
    try {
      scanTarget = resolveScanTarget(scan.repository);
    } catch (resolveErr) {
      return res.status(422).json({ message: `Scan failed: ${resolveErr.message}` });
    }
    const result = runSecurityScan(scanTarget.scanPath, [storedRuleToParsed(row)]);
    const matches = result.findings.filter((f) => f.ruleId === row.ruleId);
    res.json({
      ruleId: row.ruleId,
      scanId: scan.id,
      repository: scan.repository.fullName,
      scannedFiles: result.totalFiles,
      matchCount: matches.length,
      matches,
      note: 'Re-scanned the repository tree as it exists now, with only this rule enabled. A past scan\'s frozen tree is not stored.',
    });
  } catch (err) {
    console.error('Error test-scanning custom rule:', err);
    res.status(500).json({ message: 'Server error' });
  } finally {
    if (scanTarget) scanTarget.cleanup();
  }
});

module.exports = router;
