'use strict';

// Re-test #2 fix-batch regressions (19 Nov 2026, evening E2E re-test).
// Offline: no Redis, no Postgres.
// Run: node --test backend/tests/retest2Fixes.test.js
//   from SecureGaurd-main.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { createRlsContext } = require('../utils/rlsContext');
const { evaluateCompliance } = require('../services/complianceEngine');

const ROOT = path.join(__dirname, '..', '..');
const readSrc = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

// ── RLS context: P2028-start retry + single set_config round trip ─────

function fakeClient(failures) {
  let calls = 0;
  let rawCalls = 0;
  return {
    calls: () => calls,
    rawCalls: () => rawCalls,
    $transaction: async (fn) => {
      calls++;
      if (calls <= failures.length) throw failures[calls - 1];
      const tx = { $executeRaw: async () => { rawCalls++; } };
      return fn(tx);
    },
  };
}

const startError = () => Object.assign(
  new Error('Transaction API error: Unable to start a transaction in the given time.'),
  { code: 'P2028' }
);

test('withOrgContext retries a transaction that could not start (P2028)', async () => {
  const client = fakeClient([startError(), startError()]);
  const { withOrgContext } = createRlsContext(client);
  const out = await withOrgContext(1, 1, async () => 'ok');
  assert.equal(out, 'ok');
  assert.equal(client.calls(), 3);
});

test('withOrgContext gives up after 3 start failures', async () => {
  const client = fakeClient([startError(), startError(), startError()]);
  const { withOrgContext } = createRlsContext(client);
  await assert.rejects(() => withOrgContext(1, 1, async () => 'ok'), /Unable to start/);
  assert.equal(client.calls(), 3);
});

test('withOrgContext does not retry non-start errors', async () => {
  const client = fakeClient([Object.assign(new Error('boom'), { code: 'P2002' })]);
  const { withOrgContext } = createRlsContext(client);
  await assert.rejects(() => withOrgContext(1, 1, async () => 'ok'), /boom/);
  assert.equal(client.calls(), 1);
});

test('withOrgContext does not retry a P2028 raised after start', async () => {
  const closed = Object.assign(
    new Error('Transaction API error: Transaction already closed.'),
    { code: 'P2028' }
  );
  const client = fakeClient([closed]);
  const { withOrgContext } = createRlsContext(client);
  await assert.rejects(() => withOrgContext(1, 1, async () => 'ok'), /already closed/);
  assert.equal(client.calls(), 1);
});

test('setOrgContext sets both variables in one statement', async () => {
  const client = fakeClient([]);
  const { withOrgContext } = createRlsContext(client);
  await withOrgContext(1, 1, async () => 'ok');
  assert.equal(client.rawCalls(), 1);
});

// ── Compliance mapping: CWE-first, type only as no-CWE fallback ───────

test('SQLi (CWE-89) maps to CC6.8, not to access-control CC6.1', () => {
  const report = evaluateCompliance({
    framework: 'SOC2',
    vulnerabilities: [
      { id: 1, cweId: 'CWE-89', type: 'sast', severity: 'critical', status: 'open', title: 'SQLi', filePath: 'a.js', lineStart: 1 },
    ],
    repository: { name: 'r' },
  });
  const byId = Object.fromEntries(report.controls.map((c) => [c.id, c]));
  assert.equal(byId['SOC2-CC6.8'].findingsCount, 1);
  assert.equal(byId['SOC2-CC6.1'].findingsCount, 0);
  assert.match(byId['SOC2-CC6.8'].evidence, /mapped to this control/);
});

test('a finding without CWE still maps by type', () => {
  const report = evaluateCompliance({
    framework: 'SOC2',
    vulnerabilities: [
      { id: 2, cweId: null, type: 'secret', severity: 'high', status: 'open', title: 'Secret', filePath: 'b.js', lineStart: 2 },
    ],
    repository: { name: 'r' },
  });
  const byId = Object.fromEntries(report.controls.map((c) => [c.id, c]));
  // secret is in CC6.1/CC6.3/CC7.1 type lists, not in CC6.6's.
  assert.equal(byId['SOC2-CC6.1'].findingsCount, 1);
  assert.equal(byId['SOC2-CC7.1'].findingsCount, 1);
  assert.equal(byId['SOC2-CC6.6'].findingsCount, 0);
});

// ── Source assertions for the frontend/backend fixes ──────────────────

test('dashboard loads its five data sets in parallel', () => {
  const src = readSrc('src/components/Dashboard.tsx');
  assert.match(src, /Promise\.all\(\[/);
  assert.doesNotMatch(src, /if \(!user\) return null;/);
});

test('auth guards render a loading screen, not a black page', () => {
  const app = readSrc('src/App.tsx');
  assert.doesNotMatch(app, /if \(loading\) return null;/);
  assert.match(app, /Loading SecureGuard/);
});

test('vuln search matches displayed IDs (V-0068)', () => {
  const src = readSrc('src/utils/vulnFilters.ts');
  assert.match(src, /padStart\(4, '0'\)/);
  assert.match(src, /id\?: number/);
});

test('compliance generate includes re-detected findings in range', () => {
  const src = readSrc('backend/routes/compliance.js');
  assert.match(src, /detectedInScanIds: \{ hasSome: scanIdsInRange \}/);
  // The engine takes flat fromDate/toDate — a nested dateRange object
  // silently fell back to a default 30-day window.
  assert.match(src, /fromDate,\s*\n\s*toDate,\s*\n\s*dateRangeOption/);
});

test('keepalive workflow pings the backend health endpoint', () => {
  const wf = fs.readFileSync(path.join(ROOT, '..', '.github', 'workflows', 'keepalive.yml'), 'utf8');
  assert.match(wf, /securegaurd\.onrender\.com\/health/);
  assert.match(wf, /cron: '\*\/10 1-20 \* \* \*'/);
});

// ── AI engine: model not hardcoded to a retired one; status probes ───

test('Gemini model comes from GEMINI_MODEL, defaulting to a current model', () => {
  const src = readSrc('backend/utils/aiFixEngine.js');
  assert.match(src, /process\.env\.GEMINI_MODEL \|\| 'gemini-3\.8-flash'/);
  assert.doesNotMatch(src, /models\/gemini-1\.5-flash:generateContent/);
  assert.doesNotMatch(src, /engine: 'gemini-1\.5-flash/);
});

test('Gemini generation disables thinking and joins all text parts', () => {
  // Thinking models blew the 30 s abort in prod ("This operation was
  // aborted", 19 Nov 2026) and may put a thought part before the text.
  const src = readSrc('backend/utils/aiFixEngine.js');
  assert.match(src, /thinkingConfig: \{ thinkingBudget: 0 \}/);
  assert.match(src, /parts\.filter\(\(p\) => !p\.thought && p\.text\)/);
});

test('AI status probes Gemini instead of trusting key presence', () => {
  const src = readSrc('backend/routes/ai.js');
  assert.match(src, /geminiAvailable\(\)/);
  assert.match(src, /v1beta\/models\/\$\{GEMINI_MODEL\}/);
  assert.doesNotMatch(src, /engine: process\.env\.GEMINI_API_KEY \? 'gemini-1\.5-flash'/);
});

test('AI status probe exercises generation, not just the model catalog', () => {
  // GET /models/{id} answers 200 for any valid key even when
  // :generateContent 404s for that key's project (live, 19 Nov 2026) —
  // the probe must generate to be honest.
  const src = readSrc('backend/routes/ai.js');
  assert.match(src, /models\/\$\{GEMINI_MODEL\}:generateContent/);
  assert.match(src, /maxOutputTokens: 1/);
});

test('Gemini failures log Google\'s error body, not just the status code', () => {
  const src = readSrc('backend/utils/aiFixEngine.js');
  assert.match(src, /Gemini API error: \$\{response\.status\} \$\{detail\}/);
});

test('AI engine label derives the Gemini version from the engine string', () => {
  const src = readSrc('src/components/VulnerabilityDetailsPage.tsx');
  assert.match(src, /gemini-\(\[\\d\.\]\+\)-flash/);
  assert.doesNotMatch(src, /'Google Gemini 1\.5 Flash'/);
});
