'use strict';

// Re-test fix-batch regressions (19 Nov 2026, afternoon E2E re-test).
// Offline: no Redis, no Postgres.
// Run: node --test backend/tests/retestFixes.test.js
//   from SecureGaurd-main.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { partitionFindings, dedupeFindings, normalizePath } = require('../utils/findingDedup');
const { computeHealthScore } = require('../utils/healthScore');

const ROOT = path.join(__dirname, '..', '..');
const readSrc = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

// ── Dedup: partition + path normalisation ─────────────────────────────

test('partitionFindings splits fresh from matched with existing ids', () => {
  const open = [
    { id: 10, ruleId: 'SQLI', filePath: 'backend/a.js', lineStart: 5 },
    { id: 11, ruleId: 'XSS', filePath: 'backend/b.js', lineStart: 9 },
  ];
  const findings = [
    { ruleId: 'SQLI', filePath: 'backend/a.js', lineStart: 5 },   // matched → 10
    { ruleId: 'SQLI', filePath: 'backend/a.js', lineStart: 12 },  // fresh (different line)
    { ruleId: 'NEW', filePath: 'backend/c.js', lineStart: 1 },    // fresh
  ];
  const { fresh, matched } = partitionFindings(findings, open);
  assert.equal(fresh.length, 2);
  assert.equal(matched.length, 1);
  assert.equal(matched[0].existingId, 10);
  // dedupeFindings stays the fresh-only wrapper other callers expect.
  assert.equal(dedupeFindings(findings, open).length, 2);
});

test('path variants of the same file dedupe (wrapper prefix, slashes, ./)', () => {
  const stripPrefixes = ['SecureGaurd', 'SecureGaurd-main', 'SecureGaurd-master'];
  const open = [
    { id: 27, ruleId: 'SQLI', filePath: 'backend/tests/fixtures/sqli_variants.js', lineStart: 35 },
  ];
  const findings = [
    { ruleId: 'SQLI', filePath: 'SecureGaurd-main/backend/tests/fixtures/sqli_variants.js', lineStart: 35 },
    { ruleId: 'SQLI', filePath: './backend/tests/fixtures/sqli_variants.js', lineStart: 35 },
    { ruleId: 'SQLI', filePath: 'backend\\tests\\fixtures\\sqli_variants.js', lineStart: 35 },
  ];
  const { fresh, matched } = partitionFindings(findings, open, { stripPrefixes });
  assert.equal(fresh.length, 0);
  assert.equal(matched.length, 3);
  assert.ok(matched.every((m) => m.existingId === 27));
});

test('normalizePath only strips a named wrapper segment', () => {
  assert.equal(normalizePath('SecureGaurd-main/backend/a.js', ['SecureGaurd-main']), 'backend/a.js');
  assert.equal(normalizePath('frontend/src/a.js', ['SecureGaurd-main']), 'frontend/src/a.js');
  assert.equal(normalizePath('backend/a.js', []), 'backend/a.js');
  // A bare filename is never stripped into nothing.
  assert.equal(normalizePath('SecureGaurd-main', ['SecureGaurd-main']), 'SecureGaurd-main');
});

// ── Health score: severity mix, not saturating absolute counts ────────

test('computeHealthScore pins', () => {
  assert.equal(computeHealthScore({ critical: 0, high: 0, medium: 0, low: 0 }), 100);
  assert.equal(computeHealthScore({ critical: 5, high: 0, medium: 0, low: 0 }), 0);
  assert.equal(computeHealthScore({ critical: 0, high: 0, medium: 0, low: 10 }), 93);
  // The live dashboard mix at re-test time (110C/62H/9M) scored 0 under
  // the old absolute formula; the mix formula gives 20.
  assert.equal(computeHealthScore({ critical: 110, high: 62, medium: 9, low: 0 }), 20);
});

// ── Source pins: the wiring these fixes depend on ─────────────────────

test('scan detail lists detected findings, not only inserted rows', () => {
  const scans = readSrc('backend/routes/scans.js');
  assert.match(scans, /detectedInScanIds: \{ has: scanId \}/);
  const runner = readSrc('backend/services/scanRunner.js');
  assert.match(runner, /detectedInScanIds: \{ push: scan\.id \}/);
  const integration = readSrc('backend/routes/integration.js');
  assert.match(integration, /detectedInScanIds: \{ push: scan\.id \}/);
});

test('audit findingsCount uses the open-count definition', () => {
  const runner = readSrc('backend/services/scanRunner.js');
  assert.match(runner, /findingsCount: critCount \+ highCount \+ medCount \+ lowCount/);
  assert.match(runner, /totalDetected: finalFindings\.length/);
});

test('AI fix engine is persisted and returned for cached fixes', () => {
  const ai = readSrc('backend/routes/ai.js');
  assert.match(ai, /aiFixEngine: result\.engine/);
  assert.match(ai, /engine: vuln\.aiFixEngine \|\| null/);
  const page = readSrc('src/components/VulnerabilityDetailsPage.tsx');
  assert.match(page, /engine: data\.aiFixEngine \|\| undefined/);
});

test('no native window.confirm call sites remain in the UI', () => {
  for (const rel of [
    'src/components/Dashboard.tsx',
    'src/components/ComplianceReports.tsx',
    'src/components/OrganizationSettingsModal.tsx',
  ]) {
    const code = readSrc(rel)
      .split('\n')
      .filter((l) => !/^\s*(\/\/|\*)/.test(l))
      .join('\n');
    assert.ok(!code.includes('window.confirm('), `${rel} still calls window.confirm`);
  }
});

test('SBOM page loads the org-wide list, not the per-repo latest', () => {
  const page = readSrc('src/components/SbomPage.tsx');
  assert.match(page, /orgFetch\('\/api\/sboms'\)/);
  assert.ok(!page.includes('/api/sboms/repository/'), 'per-repo latest-only endpoint still used');
});

test('RLS transactions wait longer than the Prisma defaults', () => {
  const rls = readSrc('backend/utils/rlsContext.js');
  assert.match(rls, /TX_OPTIONS = \{ maxWait: 10000, timeout: 30000 \}/);
  const runner = readSrc('backend/services/scanRunner.js');
  assert.match(runner, /err\?\.code === 'P2028'/);
});
