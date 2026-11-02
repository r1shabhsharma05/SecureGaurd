/**
 * Custom detection rules (Day 10, PRD §4.2.1) — pure functions, no DB.
 *
 * An organization writes a rule as YAML, tests it against sample code or a
 * past scan's repository, and enables it; enabled rules fire in real scans
 * alongside the built-in rules. Rules are line-oriented regular expressions
 * over the same code files the built-in SAST/secret scanner already reads —
 * they never see file contents the scanner would not already read, and they
 * carry no ML features, so the SAST-trained FP classifier can never
 * suppress a custom-rule finding (findings without mlFeatures stay open
 * in routes/scans.js).
 *
 * shortcut: no ReDoS sandboxing — a rule author is an OWNER/ADMIN/DEVELOPER
 * of their own organization (a trusted author, not an anonymous input), and
 * patterns are length-capped. A pathological pattern can slow that org's
 * own scans; it cannot affect other orgs' data.
 */
const yaml = require('js-yaml');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const TYPES = ['sast', 'secret', 'iac', 'dependency', 'api'];
const MAX_YAML_BYTES = 8000;
const MAX_PATTERN_LENGTH = 2000;
const RULE_ID_RE = /^CUSTOM-[A-Z0-9][A-Z0-9_-]*$/;
const CWE_RE = /^CWE-\d+$/;

const ALLOWED_KEYS = new Set([
  'id', 'title', 'severity', 'type', 'pattern', 'ignoreCase', 'filePattern',
  'excludePattern', 'description', 'remediation', 'cweId', 'enabled',
]);

function fail(message) {
  throw new Error(message);
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function asText(value, field, { min = 1, max = 2000, required = true } = {}) {
  if (value === undefined || value === null) {
    if (required) fail(`${field} is required`);
    return '';
  }
  if (typeof value !== 'string') fail(`${field} must be a string`);
  const text = value.trim();
  if (text.length < min) fail(`${field} must be at least ${min} character(s)`);
  if (text.length > max) fail(`${field} must be at most ${max} characters`);
  return text;
}

function compilePattern(source, field) {
  try {
    return new RegExp(source);
  } catch (err) {
    fail(`${field} is not a valid regular expression: ${err.message}`);
    return null;
  }
}

/**
 * Parse + validate one rule written as YAML. Returns the normalized rule
 * (plain JSON). Throws Error with a field-specific message on any problem.
 * Example:
 *   id: CUSTOM-001
 *   title: No eval on request data
 *   severity: high
 *   type: sast
 *   pattern: 'eval\s*\(.*req\.'
 *   filePattern: '\.(js|ts|jsx|tsx)$'
 *   description: ...
 *   remediation: ...
 *   cweId: CWE-95
 */
function parseCustomRuleYaml(yamlText) {
  if (typeof yamlText !== 'string' || yamlText.trim().length === 0) {
    fail('yaml is required (a rule written in YAML)');
  }
  if (yamlText.length > MAX_YAML_BYTES) {
    fail(`yaml must be at most ${MAX_YAML_BYTES} characters`);
  }
  let doc;
  try {
    doc = yaml.load(yamlText);
  } catch (err) {
    fail(`Invalid YAML: ${err.message}`);
  }
  if (!isPlainObject(doc)) fail('Rule YAML must be a single mapping (one rule per document)');
  for (const key of Object.keys(doc)) {
    if (!ALLOWED_KEYS.has(key)) fail(`Unknown rule field: ${key}`);
  }

  const id = asText(doc.id, 'id', { max: 64 });
  if (!RULE_ID_RE.test(id)) {
    fail('id must look like CUSTOM-001 (CUSTOM- prefix, capitals/digits/_/- only)');
  }
  const title = asText(doc.title, 'title', { max: 120, min: 3 });
  const severity = asText(doc.severity, 'severity', { max: 16 });
  if (!SEVERITIES.includes(severity)) {
    fail(`severity must be one of: ${SEVERITIES.join(', ')}`);
  }
  const type = doc.type === undefined ? 'sast' : asText(doc.type, 'type', { max: 16 });
  if (!TYPES.includes(type)) fail(`type must be one of: ${TYPES.join(', ')}`);
  const pattern = asText(doc.pattern, 'pattern', { max: MAX_PATTERN_LENGTH });
  compilePattern(pattern, 'pattern');
  const ignoreCase = doc.ignoreCase === undefined ? false : doc.ignoreCase;
  if (typeof ignoreCase !== 'boolean') fail('ignoreCase must be true or false');
  const filePattern = doc.filePattern === undefined
    ? '.*'
    : asText(doc.filePattern, 'filePattern', { max: 500 });
  compilePattern(filePattern, 'filePattern');
  const excludePattern = doc.excludePattern === undefined || doc.excludePattern === null
    ? null
    : asText(doc.excludePattern, 'excludePattern', { max: MAX_PATTERN_LENGTH });
  if (excludePattern) compilePattern(excludePattern, 'excludePattern');
  const description = asText(doc.description, 'description', { max: 2000, required: false });
  const remediation = asText(doc.remediation, 'remediation', { max: 2000, required: false });
  const cweId = doc.cweId === undefined || doc.cweId === null || doc.cweId === ''
    ? null
    : asText(doc.cweId, 'cweId', { max: 16 });
  if (cweId && !CWE_RE.test(cweId)) fail('cweId must look like CWE-95');
  const enabled = doc.enabled === undefined ? true : doc.enabled;
  if (typeof enabled !== 'boolean') fail('enabled must be true or false');

  return {
    id, title, severity, type, pattern, ignoreCase, filePattern,
    excludePattern, description, remediation, cweId, enabled,
  };
}

/**
 * Compile normalized rules into matchers. A rule that fails to compile is
 * skipped (callers log it) so one bad stored rule can never fail a scan —
 * rules are validated at write time, so this is defense in depth only.
 */
function compileCustomRules(rules) {
  const compiled = [];
  for (const rule of rules || []) {
    try {
      compiled.push({
        ...rule,
        regex: new RegExp(rule.pattern, rule.ignoreCase ? 'i' : ''),
        fileRegex: new RegExp(rule.filePattern || '.*'),
        excludeRegex: rule.excludePattern ? new RegExp(rule.excludePattern) : null,
      });
    } catch (err) {
      console.error(`Skipping custom rule ${rule && rule.id}: ${err.message}`);
    }
  }
  return compiled;
}

/** Match compiled rules against one line. Returns finding-shaped objects. */
function matchCustomRules(compiledRules, relPath, lineContent, lineNum) {
  const findings = [];
  for (const rule of compiledRules || []) {
    if (!rule.fileRegex.test(relPath)) continue;
    if (!rule.regex.test(lineContent)) continue;
    if (rule.excludeRegex && rule.excludeRegex.test(lineContent)) continue;
    findings.push({
      ruleId: rule.id || rule.ruleId,
      cweId: rule.cweId || 'CWE-Other',
      type: rule.type,
      severity: rule.severity,
      title: rule.title,
      filePath: relPath,
      lineStart: lineNum,
      lineEnd: lineNum,
      codeSnippet: lineContent.trim(),
      status: 'open',
    });
  }
  return findings;
}

/** Shape a stored CustomRule row as the API returns it. */
function publicCustomRule(row) {
  return {
    id: row.id,
    ruleId: row.ruleId,
    title: row.title,
    severity: row.severity,
    type: row.type,
    pattern: row.pattern,
    ignoreCase: row.ignoreCase,
    filePattern: row.filePattern,
    excludePattern: row.excludePattern,
    description: row.description,
    remediation: row.remediation,
    cweId: row.cweId,
    enabled: row.enabled,
    createdById: row.createdById,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

/** Convert a stored CustomRule row back to the parsed-rule shape the
 * scanner consumes (id = the CUSTOM-xxx rule id, not the DB row id). */
function storedRuleToParsed(row) {
  return {
    id: row.ruleId,
    title: row.title,
    severity: row.severity,
    type: row.type,
    pattern: row.pattern,
    ignoreCase: row.ignoreCase,
    filePattern: row.filePattern,
    excludePattern: row.excludePattern,
    description: row.description,
    remediation: row.remediation,
    cweId: row.cweId,
    enabled: row.enabled,
  };
}

module.exports = {
  parseCustomRuleYaml,
  compileCustomRules,
  matchCustomRules,
  publicCustomRule,
  storedRuleToParsed,
  SEVERITIES,
  TYPES,
};
