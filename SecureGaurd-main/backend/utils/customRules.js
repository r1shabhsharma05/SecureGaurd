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
 *
 * That shortcut is WRONG and is fixed here: the backend runs as a single
 * Node process, so one catastrophic pattern stalls every tenant's scans.
 * Defense in depth, in order:
 *  1. Write time (parseCustomRuleYaml → compilePattern): a structural
 *     nested-quantifier check rejects patterns such as (a+)+, (a*)* and
 *     (a|ab)+ before they can be stored.
 *  2. Test endpoint (routes/customRules.js): matching runs in a worker
 *     thread with a timeout, so a pre-existing stored pattern can never
 *     block the main event loop.
 *  3. Real scans rely on (1): only patterns that passed the write-time
 *     check can be stored, and compileCustomRules re-checks stored rules
 *     and skips any that fail, so one bad stored rule can never fail or
 *     stall a scan.
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

/**
 * Structural nested-quantifier check (write-time ReDoS guard). Rejects a
 * quantified group whose content ends in a quantified atom — (a+)+, (a*)*,
 * ((a+))+, ([\w]+)+ — or whose top-level alternatives overlap so one
 * branch is a literal prefix of another — (a|ab)+, (ab|a)+. Either shape
 * can backtrack exponentially on a non-matching input (e.g. (a+)+$ against
 * 'a'*30 + '!'). This is structural, not a timing check: it runs before
 * the pattern is stored, so it cannot be evaded by input size, and it
 * never executes the pattern. Legitimate patterns are unaffected: a
 * quantified group with unquantified, non-overlapping branches — e.g.
 * (foo|bar)+ or \.(js|ts|jsx|tsx)$ — passes, as do quantified atoms that
 * are not groups ((\d+\.)+ is allowed: only a trailing quantified atom
 * inside a quantified group is rejected).
 */
function quantifierLengthAt(s, i) {
  const c = s[i];
  if (c === '+' || c === '*' || c === '?') {
    return i + 1 < s.length && s[i + 1] === '?' ? 2 : 1;
  }
  if (c === '{') {
    const m = /^\{\d+(,\d*)?\}/.exec(s.slice(i));
    if (m) {
      const end = i + m[0].length;
      return end < s.length && s[end] === '?' ? m[0].length + 1 : m[0].length;
    }
  }
  return 0;
}

function literalPrefix(branchText) {
  let out = '';
  for (let i = 0; i < branchText.length; i++) {
    const c = branchText[i];
    if (c === '\\' && i + 1 < branchText.length) { out += branchText[i + 1]; i++; continue; }
    if (/[A-Za-z0-9]/.test(c)) { out += c; continue; }
    break;
  }
  return out;
}

function assertSafePattern(source, field) {
  const failMsg = `${field} uses a nested quantifier that can backtrack catastrophically `
    + '(e.g. (a+)+, (a*)* or (a|ab)+) — rewrite the pattern without a quantified group '
    + 'containing a quantified atom or overlapping alternatives';
  // closeInfo: index of ')' -> { branches: [{ text, endsQuantified }], quantified }
  const closeInfo = new Map();
  // Each open group: { branches: [], curText: '', curEndsQuantified: false }
  const stack = [{ branches: [], curText: '', curEndsQuantified: false }];
  let inClass = false;
  // prev atom kind: 'none' | 'open' | 'alt' | 'char' | 'class' | 'group' | 'quantifier'
  let prevKind = 'none';
  let prevCloseIndex = -1;

  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    const frame = stack[stack.length - 1];
    if (c === '\\' && i + 1 < source.length) {
      frame.curText += source.slice(i, i + 2);
      i++;
      frame.curEndsQuantified = false;
      prevKind = 'char';
      continue;
    }
    if (inClass) {
      frame.curText += c;
      if (c === ']') { inClass = false; prevKind = 'class'; frame.curEndsQuantified = false; }
      continue;
    }
    if (c === '[') {
      inClass = true;
      frame.curText += c;
      prevKind = 'class';
      frame.curEndsQuantified = false;
      continue;
    }
    if (c === '(') {
      frame.curText += c;
      stack.push({ branches: [], curText: '', curEndsQuantified: false });
      prevKind = 'open';
      continue;
    }
    if (c === ')') {
      const closed = stack.pop();
      if (!closed) fail(`${field} is not a valid regular expression: unmatched )`);
      closed.branches.push({ text: closed.curText, endsQuantified: closed.curEndsQuantified });
      const endsQuantified = closed.branches.some((b) => b.endsQuantified);
      closeInfo.set(i, { branches: closed.branches, quantified: false, endsQuantified });
      const parent = stack[stack.length - 1];
      if (!parent) fail(`${field} is not a valid regular expression: unmatched )`);
      parent.curText += c;
      parent.curEndsQuantified = endsQuantified;
      prevKind = 'group';
      prevCloseIndex = i;
      continue;
    }
    if (c === '|' && stack.length > 1) {
      frame.branches.push({ text: frame.curText, endsQuantified: frame.curEndsQuantified });
      frame.curText = '';
      frame.curEndsQuantified = false;
      prevKind = 'alt';
      continue;
    }
    const qLen = (prevKind === 'char' || prevKind === 'class' || prevKind === 'group' || prevKind === 'quantifier')
      ? quantifierLengthAt(source, i)
      : 0;
    if (qLen > 0) {
      if (prevKind === 'group') {
        const info = closeInfo.get(prevCloseIndex);
        if (info) {
          if (info.branches.some((b) => b.endsQuantified)) fail(failMsg);
          const prefixes = info.branches.map((b) => literalPrefix(b.text)).filter(Boolean);
          for (let a = 0; a < prefixes.length; a++) {
            for (let b = 0; b < prefixes.length; b++) {
              if (a !== b && prefixes[b].startsWith(prefixes[a]) && prefixes[b].length > prefixes[a].length) {
                fail(failMsg);
              }
            }
          }
          info.quantified = true;
        }
      }
      frame.curText += source.slice(i, i + qLen);
      frame.curEndsQuantified = true;
      prevKind = 'quantifier';
      i += qLen - 1;
      continue;
    }
    frame.curText += c;
    frame.curEndsQuantified = false;
    prevKind = 'char';
  }
  if (stack.length !== 1) fail(`${field} is not a valid regular expression: unmatched (`);
}

function compilePattern(source, field) {
  assertSafePattern(source, field);
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
      // Re-check stored rules: a rule stored before the write-time guard
      // (or inserted by any other path) must never stall a scan.
      assertSafePattern(rule.pattern, 'pattern');
      if (rule.filePattern) assertSafePattern(rule.filePattern, 'filePattern');
      if (rule.excludePattern) assertSafePattern(rule.excludePattern, 'excludePattern');
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
    if (!rule || !rule.fileRegex || !rule.regex) continue;
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
  assertSafePattern,
  publicCustomRule,
  storedRuleToParsed,
  SEVERITIES,
  TYPES,
};
