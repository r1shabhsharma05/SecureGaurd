/**
 * SPDX 2.3 Specification Document Generator & SCA Vulnerability Matcher
 * 
 * Constructs valid SPDX 2.3 JSON documents containing metadata, packages, PURLs,
 * dependency relationships, and associated SCA vulnerability references.
 */

const crypto = require('crypto');
const v4 = () => Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

/**
 * Sanitizes string for use as SPDXID ref token.
 */
function sanitizeSpdxIdToken(str) {
  return (str || 'unknown').replace(/[^a-zA-Z0-9.\-]/g, '-');
}

/**
 * Generates an SPDX 2.3 JSON Document from extracted components and scan findings.
 */
function generateSpdxDocument({ repository, scanId, components = [], vulnerabilities = [] }) {
  const repoName = repository?.name || repository?.fullName || 'Repository';
  const repoId = repository?.id || 0;
  const docUuid = v4();
  const createdTimestamp = new Date().toISOString();

  const docNamespace = `https://secureguard.io/spdxdocs/${repoId}-${scanId || 0}-${docUuid}`;
  const documentSpdxId = 'SPDXRef-DOCUMENT';

  // 1. Map components into SPDX 2.3 package structures
  const spdxPackages = [];
  const relationships = [];
  const vulnerableComponentsSet = new Set();
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  // Filter SCA / Dependency findings
  const scaFindings = vulnerabilities.filter(v => v.type === 'dependency' || (v.ruleId && v.ruleId.startsWith('SEC-')));

  const rootPkgId = `SPDXRef-Package-Root-${sanitizeSpdxIdToken(repoName)}`;

  // Root Package representing the repository
  spdxPackages.push({
    SPDXID: rootPkgId,
    name: repoName,
    versionInfo: repository?.branch || 'main',
    downloadLocation: repository?.url || 'NOASSERTION',
    filesAnalyzed: false,
    supplier: 'Organization: SecureGuard',
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    comment: 'Root application repository scanned by SecureGuard'
  });

  relationships.push({
    spdxElementId: documentSpdxId,
    relationshipType: 'DESCRIBES',
    relatedSpdxElement: rootPkgId
  });

  // Track ecosystem set
  const ecosystemsSet = new Set();

  // SPDXIDs must be unique in the document: sanitisation is lossy
  // ('foo_bar' and 'foo-bar' both sanitise to 'foo-bar'), so a colliding
  // ID is disambiguated with a short hash of the ORIGINAL
  // ecosystem/name/version. Declared ONCE, outside the loop — a
  // per-iteration set could never see a collision.
  const seenSpdxIds = new Set([rootPkgId]);

  components.forEach((comp, idx) => {
    ecosystemsSet.add(comp.ecosystem);
    let spdxPkgId = `SPDXRef-Package-${sanitizeSpdxIdToken(comp.ecosystem)}-${sanitizeSpdxIdToken(comp.name)}-${sanitizeSpdxIdToken(comp.version)}`;
    if (seenSpdxIds.has(spdxPkgId)) {
      spdxPkgId = `${spdxPkgId}-${crypto.createHash('sha256').update(comp.ecosystem + ':' + comp.name + '@' + comp.version).digest('hex').slice(0, 8)}`;
    }
    seenSpdxIds.add(spdxPkgId);

    // Cross-reference with SCA Vulnerabilities
    const matchedVulns = scaFindings.filter(v => {
      const titleMatch = v.title && v.title.toLowerCase().includes(comp.name.toLowerCase());
      const snippetMatch = v.codeSnippet && v.codeSnippet.toLowerCase().includes(comp.name.toLowerCase());
      return titleMatch || snippetMatch;
    });

    const hasVulns = matchedVulns.length > 0;
    if (hasVulns) {
      vulnerableComponentsSet.add(spdxPkgId);
      matchedVulns.forEach(v => {
        const s = (v.severity || 'low').toLowerCase();
        if (s === 'critical') criticalCount++;
        else if (s === 'high') highCount++;
        else if (s === 'medium') mediumCount++;
        else lowCount++;
      });
    }

    const pkgObject = {
      SPDXID: spdxPkgId,
      name: comp.name,
      versionInfo: comp.version || 'unknown',
      downloadLocation: 'NOASSERTION',
      packageSupplier: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: comp.license || 'NOASSERTION',
      licenseDeclared: comp.license || 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: comp.purl || `pkg:generic/${comp.name}@${comp.version}`
        }
      ],
      comment: JSON.stringify({
        dependencyType: comp.dependencyType || 'direct',
        packageManager: comp.packageManager || comp.ecosystem,
        manifestSources: comp.manifestSources || [comp.manifestSource],
        vulnerabilitiesCount: matchedVulns.length,
        vulnerabilities: matchedVulns.map(v => ({
          id: v.id,
          cweId: v.cweId || 'N/A',
          severity: v.severity,
          title: v.title
        }))
      })
    };

    if (comp.integrity) {
      pkgObject.checksums = [
        {
          algorithm: comp.integrity.startsWith('sha512-') ? 'SHA512' : 'SHA256',
          checksumValue: comp.integrity.replace(/^sha[0-9]+-/, '')
        }
      ];
    }

    spdxPackages.push(pkgObject);

    // Add Root -> Component Relationship
    relationships.push({
      spdxElementId: rootPkgId,
      relationshipType: comp.dependencyType === 'direct' ? 'DEPENDS_ON' : 'DEPENDENCY_MANIFEST_OF',
      relatedSpdxElement: spdxPkgId
    });
  });

  const directCount = components.filter(c => c.dependencyType === 'direct').length;
  const transitiveCount = components.filter(c => c.dependencyType === 'transitive').length;

  const spdxDocument = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: documentSpdxId,
    name: `SBOM-${repoName}-${scanId || 'latest'}`,
    documentNamespace: docNamespace,
    creationInfo: {
      creators: [
        'Tool: SecureGuard-SBOMEngine-v2.0',
        'Organization: SecureGuard Security Platform'
      ],
      created: createdTimestamp,
      licenseListVersion: '3.19'
    },
    documentDescribes: [rootPkgId],
    packages: spdxPackages,
    relationships: relationships
  };

  return {
    spdxDocument,
    summaryStats: {
      componentCount: components.length,
      directCount,
      transitiveCount,
      vulnerableCount: vulnerableComponentsSet.size,
      ecosystems: Array.from(ecosystemsSet),
      vulnerabilityBreakdown: {
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount
      }
    }
  };
}

module.exports = {
  generateSpdxDocument,
  sanitizeSpdxIdToken
};
