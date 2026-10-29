/**
 * CycloneDX 1.6 SBOM generator — Day 6.
 *
 * Companion to the existing SPDX 2.3 generator (utils/spdxGenerator.js):
 * the same scan components (npm / pypi / golang / maven / cargo / composer /
 * rubygems, as extracted by utils/sbomExtractor.js) are rendered as a
 * CycloneDX bill of materials, stored per scan in Sbom.cycloneDxDoc, and
 * served by GET /api/sboms/:id/cyclonedx. SPDX stays the canonical stored
 * document; CycloneDX is a second, derived format, not a second pipeline —
 * both generators consume the identical component list, so they cannot
 * disagree about what a scan contained.
 *
 * License summary: counts components per declared license. NOASSERTION
 * (the extractor's fallback for manifests without license metadata) is
 * counted under "NOASSERTION" and omitted from the component's licenses
 * array — CycloneDX has no NOASSERTION license id, and inventing one
 * would misstate the manifest.
 */
const { randomUUID } = require('crypto');
const { generatePurl } = require('./sbomExtractor');

function sanitizeBomRef(str) {
  return String(str || 'unknown').replace(/[^a-zA-Z0-9.\-_/]/g, '-');
}

function licenseEntry(license) {
  if (!license || license === 'NOASSERTION') return null;
  // A single SPDX-id-shaped token goes in `id`; anything else (e.g. a
  // multi-license expression) goes in `name` verbatim — never rewritten.
  if (/^[A-Za-z0-9.+\-]+$/.test(license)) return { license: { id: license } };
  return { license: { name: license } };
}

function hashEntry(integrity) {
  if (!integrity || typeof integrity !== 'string') return null;
  const m = integrity.match(/^(sha512|sha384|sha256|sha1|md5)-(.+)$/);
  if (!m) return null;
  return { alg: m[1].toUpperCase().replace('SHA1', 'SHA-1'), content: m[2] };
}

function generateCycloneDxDocument({ repository, scanId, components = [] }) {
  const repoName = repository?.name || repository?.fullName || 'Repository';
  const repoId = repository?.id || 0;
  const rootRef = `secureguard-root-${repoId}-${scanId || 0}`;

  const licenseSummary = {};
  const byName = new Map();
  const cycloneComponents = components.map((comp) => {
    const license = comp.license || 'NOASSERTION';
    licenseSummary[license] = (licenseSummary[license] || 0) + 1;
    const bomRef = comp.purl || generatePurl(comp.ecosystem || 'generic', comp.name, comp.version);
    const entry = {
      type: 'library',
      'bom-ref': bomRef,
      name: comp.name,
      version: comp.version || 'unknown',
      scope: comp.dependencyType === 'direct' ? 'required' : 'optional',
      purl: bomRef,
    };
    const lic = licenseEntry(license);
    if (lic) entry.licenses = [lic];
    const hash = hashEntry(comp.integrity);
    if (hash) entry.hashes = [hash];
    const sources = comp.manifestSources || (comp.manifestSource ? [comp.manifestSource] : []);
    if (sources.length) entry.properties = [{ name: 'secureguard:manifestSources', value: sources.join(',') }];
    if (!byName.has(comp.name)) byName.set(comp.name, bomRef);
    return entry;
  });

  // Dependencies: the root depends on direct components; each component
  // depends on the components its lockfile lists by name (first name match
  // wins — lockfile dependency lists carry names, not purls). Names with
  // no match in this document are dropped, never invented as bom-refs.
  const dependencies = [{ ref: rootRef, dependsOn: cycloneComponents
    .filter((_, i) => components[i].dependencyType === 'direct')
    .map((c) => c['bom-ref']) }];
  components.forEach((comp, i) => {
    const deps = (comp.dependencies || [])
      .map((depName) => byName.get(depName))
      .filter(Boolean);
    dependencies.push({ ref: cycloneComponents[i]['bom-ref'], dependsOn: [...new Set(deps)] });
  });

  const document = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'SecureGuard', name: 'SecureGuard-SBOMEngine', version: '2.0' }],
      component: {
        type: 'application',
        'bom-ref': rootRef,
        name: repoName,
        version: repository?.branch || 'main',
      },
    },
    components: cycloneComponents,
    dependencies,
  };

  return {
    cycloneDxDocument: document,
    summaryStats: {
      componentCount: components.length,
      directCount: components.filter((c) => c.dependencyType === 'direct').length,
      transitiveCount: components.filter((c) => c.dependencyType === 'transitive').length,
      licenseSummary,
    },
  };
}

function validateCycloneDxDocument(doc) {
  const errors = [];
  if (!doc || doc.bomFormat !== 'CycloneDX') errors.push('bomFormat must be "CycloneDX"');
  if (doc?.specVersion !== '1.6') errors.push('specVersion must be "1.6"');
  if (!Array.isArray(doc?.components)) errors.push('components must be an array');
  else {
    const refs = new Set();
    doc.components.forEach((c, i) => {
      if (!c['bom-ref']) errors.push(`component ${i} missing bom-ref`);
      else if (refs.has(c['bom-ref'])) errors.push(`duplicate bom-ref: ${c['bom-ref']}`);
      else refs.add(c['bom-ref']);
      if (!c.name) errors.push(`component ${i} missing name`);
      if (!c.purl) errors.push(`component ${i} missing purl`);
    });
  }
  return { isValid: errors.length === 0, errors };
}

module.exports = { generateCycloneDxDocument, validateCycloneDxDocument, sanitizeBomRef };
