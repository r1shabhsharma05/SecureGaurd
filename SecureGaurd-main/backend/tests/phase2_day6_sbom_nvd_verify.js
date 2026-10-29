/**
 * Day 6 — CycloneDX SBOM + live-NVD enrichment unit verification.
 * No network, no database: NVD responses are stubbed with the real
 * lodash CVE shapes returned by services.nvd.nist.gov (CVE-2018-3721
 * ends at 4.17.5, CVE-2018-16487 ends at 4.17.11) so the version-range
 * matcher is proven against real data shapes, not invented ones.
 */
const assert = require('assert');
const { generateCycloneDxDocument, validateCycloneDxDocument } = require('../utils/cycloneDxGenerator');
const { parseNvdResponse, versionInRange, enrichComponent, clearNvdCache } = require('../utils/nvdEnrichment');

let passed = 0, total = 0;
function test(name, fn) {
  total++;
  try { const r = fn(); if (r && typeof r.then === 'function') return r.then(() => { console.log(`  ✓ PASS: ${name}`); passed++; }).catch((e) => { console.error(`  ✗ FAIL: ${name}\n    ${e.message}`); });
    console.log(`  ✓ PASS: ${name}`); passed++; } catch (e) { console.error(`  ✗ FAIL: ${name}\n    ${e.message}`); }
}
async function testAsync(name, fn) {
  total++;
  try { await fn(); console.log(`  ✓ PASS: ${name}`); passed++; } catch (e) { console.error(`  ✗ FAIL: ${name}\n    ${e.message}`); }
}

const COMPONENTS = [
  { name: 'express', version: '4.18.2', ecosystem: 'npm', packageManager: 'npm', dependencyType: 'direct', manifestSource: 'package.json', purl: 'pkg:npm/express@4.18.2', license: 'MIT', dependencies: ['body-parser'] },
  { name: 'body-parser', version: '1.20.1', ecosystem: 'npm', packageManager: 'npm', dependencyType: 'transitive', manifestSource: 'package-lock.json', purl: 'pkg:npm/body-parser@1.20.1', license: 'MIT', dependencies: [] },
  { name: 'requests', version: '2.28.1', ecosystem: 'pypi', packageManager: 'pip', dependencyType: 'direct', manifestSource: 'requirements.txt', purl: 'pkg:pypi/requests@2.28.1', license: 'Apache-2.0', dependencies: [] },
  { name: 'github.com/gin-gonic/gin', version: '1.8.1', ecosystem: 'golang', packageManager: 'go', dependencyType: 'direct', manifestSource: 'go.mod', purl: 'pkg:golang/github.com/gin-gonic/gin@1.8.1', license: 'NOASSERTION', dependencies: [] },
];

(async () => {
  console.log('\n=== Day 6: CycloneDX + NVD unit verification ===\n');

  test('CycloneDX doc: bomFormat/specVersion/metadata root', () => {
    const { cycloneDxDocument } = generateCycloneDxDocument({ repository: { id: 1, name: 'demo' }, scanId: 9, components: COMPONENTS });
    assert.strictEqual(cycloneDxDocument.bomFormat, 'CycloneDX');
    assert.strictEqual(cycloneDxDocument.specVersion, '1.6');
    assert.strictEqual(cycloneDxDocument.components.length, 4);
    assert.strictEqual(cycloneDxDocument.metadata.component.name, 'demo');
    assert.ok(cycloneDxDocument.serialNumber.startsWith('urn:uuid:'));
  });

  test('CycloneDX: license summary counts MIT x2, Apache-2.0 x1, NOASSERTION x1; NOASSERTION emits no license', () => {
    const { summaryStats, cycloneDxDocument } = generateCycloneDxDocument({ repository: { id: 1, name: 'demo' }, scanId: 9, components: COMPONENTS });
    assert.deepStrictEqual(summaryStats.licenseSummary, { MIT: 2, 'Apache-2.0': 1, NOASSERTION: 1 });
    const gin = cycloneDxDocument.components.find((c) => c.name === 'github.com/gin-gonic/gin');
    assert.strictEqual(gin.licenses, undefined);
    const express = cycloneDxDocument.components.find((c) => c.name === 'express');
    assert.deepStrictEqual(express.licenses, [{ license: { id: 'MIT' } }]);
  });

  test('CycloneDX: direct=required, transitive=optional; root depends on direct only; name-dependency resolves to bom-ref', () => {
    const { cycloneDxDocument } = generateCycloneDxDocument({ repository: { id: 1, name: 'demo' }, scanId: 9, components: COMPONENTS });
    const byName = Object.fromEntries(cycloneDxDocument.components.map((c) => [c.name, c]));
    assert.strictEqual(byName.express.scope, 'required');
    assert.strictEqual(byName['body-parser'].scope, 'optional');
    const root = cycloneDxDocument.dependencies.find((d) => d.ref.startsWith('secureguard-root-'));
    assert.deepStrictEqual([...root.dependsOn].sort(), ['pkg:golang/github.com/gin-gonic/gin@1.8.1', 'pkg:npm/express@4.18.2', 'pkg:pypi/requests@2.28.1']);
    const expDeps = cycloneDxDocument.dependencies.find((d) => d.ref === 'pkg:npm/express@4.18.2');
    assert.deepStrictEqual(expDeps.dependsOn, ['pkg:npm/body-parser@1.20.1']);
  });

  test('CycloneDX validator accepts a generated doc and rejects duplicates / wrong format', () => {
    const { cycloneDxDocument } = generateCycloneDxDocument({ repository: { id: 1, name: 'demo' }, scanId: 9, components: COMPONENTS });
    assert.strictEqual(validateCycloneDxDocument(cycloneDxDocument).isValid, true);
    const dup = JSON.parse(JSON.stringify(cycloneDxDocument));
    dup.components.push(dup.components[0]);
    assert.strictEqual(validateCycloneDxDocument(dup).isValid, false);
    assert.strictEqual(validateCycloneDxDocument({ bomFormat: 'SPDX', specVersion: '1.6', components: [] }).isValid, false);
  });

  // ── NVD parsing / version-range matching (real lodash CVE shapes) ──
  const nvdBody = { totalResults: 2, vulnerabilities: [
    { cve: { id: 'CVE-2018-3721', vulnStatus: 'Modified', published: '2018-07-02T00:00:00.000', lastModified: '2018-07-02T00:00:00.000',
      descriptions: [{ lang: 'en', value: 'lodash before 4.17.5 MAID' }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 6.5, baseSeverity: 'MEDIUM', vectorString: 'CVSS:3.1/AV:N/AC:L' } }] },
      configurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*', versionEndExcluding: '4.17.5' }] }] }] } },
    { cve: { id: 'CVE-2018-16487', vulnStatus: 'Modified', published: '2018-10-29T00:00:00.000', lastModified: '2018-10-29T00:00:00.000',
      descriptions: [{ lang: 'en', value: 'lodash <4.17.11 prototype pollution' }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 5.6, baseSeverity: 'MEDIUM', vectorString: 'CVSS:3.1/AV:N/AC:H' } }] },
      configurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*', versionEndExcluding: '4.17.11' }] }] }] } },
  ] };

  test('NVD parse: CVE id, CVSS score/severity, published date, CPE range preserved', () => {
    const { totalResults, cves } = parseNvdResponse(nvdBody);
    assert.strictEqual(totalResults, 2);
    assert.strictEqual(cves[0].cveId, 'CVE-2018-3721');
    assert.strictEqual(cves[0].cvssScore, 6.5);
    assert.strictEqual(cves[0].cvssSeverity, 'MEDIUM');
    assert.ok(cves[0].published.startsWith('2018-07-02'));
    assert.strictEqual(cves[0].cpeMatches[0].versionEndExcluding, '4.17.5');
  });

  test('Version-range matcher: 4.17.10 matches CVE-2018-16487 only, not CVE-2018-3721; 4.17.11 matches neither', () => {
    const { cves } = parseNvdResponse(nvdBody);
    assert.strictEqual(versionInRange('4.17.10', cves[0].cpeMatches[0]), false);
    assert.strictEqual(versionInRange('4.17.10', cves[1].cpeMatches[0]), true);
    assert.strictEqual(versionInRange('4.17.11', cves[1].cpeMatches[0]), false);
    assert.strictEqual(versionInRange('4.17.4', cves[0].cpeMatches[0]), true);
  });

  await testAsync('enrichComponent (stubbed fetch): matches only in-range CVE, caches second call without fetching', async () => {
    clearNvdCache();
    let calls = 0;
    const stubFetch = async () => { calls++; return { ok: true, status: 200, json: async () => nvdBody }; };
    const first = await enrichComponent({ name: 'lodash', version: '4.17.10' }, stubFetch);
    assert.strictEqual(first.cached, false);
    assert.deepStrictEqual(first.cves.map((c) => c.cveId), ['CVE-2018-16487']);
    assert.ok(first.fetchedAt);
    const second = await enrichComponent({ name: 'lodash', version: '4.17.10' }, stubFetch);
    assert.strictEqual(second.cached, true);
    assert.strictEqual(calls, 1);
  });

  await testAsync('enrichComponent surfaces NVD 429 as an error, never as empty data', async () => {
    clearNvdCache();
    const stubFetch = async () => ({ ok: false, status: 429, json: async () => ({}) });
    await assert.rejects(() => enrichComponent({ name: 'lodash', version: '4.17.10' }, stubFetch), /rate limited/);
  });

  console.log(`\nDay 6 unit summary: ${passed}/${total} passed.`);
  if (passed !== total) process.exit(1);
})();
