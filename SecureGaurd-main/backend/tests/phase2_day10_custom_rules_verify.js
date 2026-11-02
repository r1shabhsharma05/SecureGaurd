/**
 * Day 10 — unit verification for custom rules (offline, no database).
 * Proves the pure pieces the custom-rules routes + scanner depend on:
 *  - YAML parsing/validation (valid doc, defaults, and every rejection),
 *  - compile + line matching (file filter, exclude, ignoreCase),
 *  - runSecurityScan applies a custom rule to a real fixture tree and
 *    the finding carries no mlFeatures (classifier can never suppress it).
 * Live API behaviour is proven separately against production.
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  parseCustomRuleYaml,
  compileCustomRules,
  matchCustomRules,
  publicCustomRule,
  storedRuleToParsed,
} = require('../utils/customRules');
const { runSecurityScan } = require('../utils/securityScanner');

let passed = 0, total = 0;
function test(name, fn) {
  total++;
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; console.log(`  ✓ PASS: ${name}`); })
    .catch((e) => { console.error(`  ✗ FAIL: ${name}\n    ${e.message}`); });
}

function rejects(name, yamlText, pattern) {
  return test(name, () => {
    assert.throws(() => parseCustomRuleYaml(yamlText), (e) => pattern.test(e.message));
  });
}

const VALID_YAML = `
id: CUSTOM-001
title: No eval on request data
severity: high
type: sast
pattern: 'eval\\s*\\(.*req\\.'
filePattern: '\\.(js|ts)$'
description: Eval on request data is code injection.
remediation: Avoid eval; parse input explicitly.
cweId: CWE-95
`;

(async () => {
  await test('parse valid YAML with defaults', () => {
    const r = parseCustomRuleYaml(VALID_YAML);
    assert.strictEqual(r.id, 'CUSTOM-001');
    assert.strictEqual(r.severity, 'high');
    assert.strictEqual(r.ignoreCase, false);
    assert.strictEqual(r.enabled, true);
    assert.strictEqual(r.excludePattern, null);
  });

  await test('parse applies type/ignoreCase/enabled overrides', () => {
    const yamlText = VALID_YAML.replace('type: sast', 'type: secret').replace('cweId: CWE-95', 'cweId: CWE-95\nignoreCase: true\nenabled: false');
    const r = parseCustomRuleYaml(yamlText);
    assert.strictEqual(r.type, 'secret');
    assert.strictEqual(r.ignoreCase, true);
    assert.strictEqual(r.enabled, false);
  });

  await rejects('reject bad rule id', VALID_YAML.replace('CUSTOM-001', 'EVAL-1'), /id must/);
  await rejects('reject bad severity', VALID_YAML.replace('high', 'urgent'), /severity must/);
  await rejects('reject bad regex', VALID_YAML.replace(/pattern:.*/, "pattern: '[unclosed'"), /not a valid regular expression/);
  await rejects('reject unknown field', `${VALID_YAML}\n Surprise: 1\n`.replace(' Surprise', 'surprise'), /Unknown rule field/);
  await rejects('reject non-mapping YAML', '- a\n- b\n', /single mapping/);
  await rejects('reject bad CWE', VALID_YAML.replace('CWE-95', 'CWE95'), /cweId must/);
  await rejects('reject empty YAML', '', /yaml is required/);

  await test('match: fires on matching file+line, skips others', () => {
    const [c] = compileCustomRules([parseCustomRuleYaml(VALID_YAML)]);
    const hits = matchCustomRules([c], 'app.js', '  eval(req.body.code);', 7);
    assert.strictEqual(hits.length, 1);
    assert.strictEqual(hits[0].ruleId, 'CUSTOM-001');
    assert.strictEqual(hits[0].lineStart, 7);
    assert.strictEqual(hits[0].cweId, 'CWE-95');
    assert.strictEqual(matchCustomRules([c], 'notes.md', 'eval(req.body.code);', 1).length, 0);
    assert.strictEqual(matchCustomRules([c], 'app.js', 'const x = 1;', 1).length, 0);
  });

  await test('match: excludePattern and ignoreCase honored', () => {
    const rule = parseCustomRuleYaml(`${VALID_YAML}\nexcludePattern: 'SAFE-EVAL'\nignoreCase: true\n`);
    const [c] = compileCustomRules([rule]);
    assert.strictEqual(matchCustomRules([c], 'app.js', 'EVAL(req.body.code); // SAFE-EVAL', 1).length, 0);
    assert.strictEqual(matchCustomRules([c], 'app.js', 'EVAL(req.body.code);', 1).length, 1);
  });

  await test('storedRuleToParsed / publicCustomRule round-trip', () => {
    const row = {
      id: 9, ruleId: 'CUSTOM-001', title: 'T', severity: 'high', type: 'sast',
      pattern: 'x', ignoreCase: false, filePattern: '.*', excludePattern: null,
      description: '', remediation: '', cweId: null, enabled: true,
      createdById: 1, createdAt: new Date(), updatedAt: new Date(),
    };
    assert.strictEqual(storedRuleToParsed(row).id, 'CUSTOM-001');
    assert.strictEqual(publicCustomRule(row).ruleId, 'CUSTOM-001');
  });

  await test('runSecurityScan fires custom rule on fixture tree, no mlFeatures', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-custom-rule-'));
    try {
      fs.writeFileSync(path.join(dir, 'app.js'), 'const a = eval(req.body.code);\nconst b = 1;\n');
      fs.writeFileSync(path.join(dir, 'clean.js'), 'const b = 1;\n');
      const result = runSecurityScan(dir, [parseCustomRuleYaml(VALID_YAML)]);
      const custom = result.findings.filter((f) => f.ruleId === 'CUSTOM-001');
      assert.strictEqual(custom.length, 1);
      assert.strictEqual(custom[0].filePath, 'app.js');
      assert.strictEqual(custom[0].lineStart, 1);
      assert.strictEqual(custom[0].mlFeatures, undefined);
      // Built-in rules still run in the same pass.
      assert.ok(result.totalFiles >= 2);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  console.log(`\n${passed}/${total} custom-rules unit tests passed`);
  process.exit(passed === total ? 0 : 1);
})();
