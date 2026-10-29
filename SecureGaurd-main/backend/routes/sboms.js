const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');

router.use(authMiddleware);
router.use(requireOrgContext);

// GET /api/sboms — list all SBOMs for active organization
router.get('/', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']), async (req, res) => {
  try {
    const sboms = await prisma.sbom.findMany({
      where: { organizationId: req.organizationId },
      include: {
        repository: { select: { id: true, name: true, fullName: true, platform: true } },
        scan: { select: { id: true, branch: true, commitSha: true, createdAt: true } }
      },
      orderBy: { createdAt: 'desc' },
      take: 50
    });

    res.json(sboms);
  } catch (err) {
    console.error('Error listing SBOMs:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/sboms/:id — get single SBOM details with SPDX document
router.get('/:id', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']), async (req, res) => {
  const sbomId = parseInt(req.params.id);
  if (isNaN(sbomId)) return res.status(400).json({ message: 'Invalid SBOM ID' });

  try {
    const sbom = await prisma.sbom.findFirst({
      where: { id: sbomId, organizationId: req.organizationId },
      include: {
        repository: { select: { id: true, name: true, fullName: true, platform: true, url: true } },
        scan: { select: { id: true, branch: true, commitSha: true, createdAt: true } }
      }
    });

    if (!sbom) {
      return res.status(404).json({ message: 'SBOM not found in active organization' });
    }

    await createAuditLog(
      req.organizationId,
      req.userId,
      'SBOM_VIEWED',
      'SBOM',
      String(sbom.id),
      { sbomName: sbom.name, repositoryId: sbom.repositoryId }
    );

    res.json(sbom);
  } catch (err) {
    console.error('Error fetching SBOM details:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/sboms/:id/download — download valid SPDX 2.3 JSON file
router.get('/:id/download', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']), async (req, res) => {
  const sbomId = parseInt(req.params.id);
  if (isNaN(sbomId)) return res.status(400).json({ message: 'Invalid SBOM ID' });

  try {
    const sbom = await prisma.sbom.findFirst({
      where: { id: sbomId, organizationId: req.organizationId }
    });

    if (!sbom) {
      return res.status(404).json({ message: 'SBOM not found in active organization' });
    }

    await createAuditLog(
      req.organizationId,
      req.userId,
      'SBOM_DOWNLOADED',
      'SBOM',
      String(sbom.id),
      { sbomName: sbom.name, repositoryId: sbom.repositoryId }
    );

    const filename = `${sbom.name || 'sbom'}.spdx.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(JSON.stringify(sbom.spdxDoc, null, 2));
  } catch (err) {
    console.error('Error downloading SBOM:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/sboms/:id/cyclonedx — download the CycloneDX 1.6 document
// stored for this scan (Day 6). SBOMs generated before Day 6 have no
// CycloneDX doc — that is a 404 with an honest message, not a regenerated
// claim: rescan the repo to get one.
router.get('/:id/cyclonedx', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']), async (req, res) => {
  const sbomId = parseInt(req.params.id);
  if (isNaN(sbomId)) return res.status(400).json({ message: 'Invalid SBOM ID' });

  try {
    const sbom = await prisma.sbom.findFirst({
      where: { id: sbomId, organizationId: req.organizationId }
    });
    if (!sbom) return res.status(404).json({ message: 'SBOM not found in active organization' });
    if (!sbom.cycloneDxDoc) {
      return res.status(404).json({ message: 'No CycloneDX document stored for this SBOM (generated before CycloneDX support — rescan to create one)' });
    }

    await createAuditLog(
      req.organizationId,
      req.userId,
      'SBOM_DOWNLOADED',
      'SBOM',
      String(sbom.id),
      { sbomName: sbom.name, repositoryId: sbom.repositoryId, format: 'cyclonedx-1.6' }
    );

    const filename = `${sbom.name || 'sbom'}.cyclonedx.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(JSON.stringify(sbom.cycloneDxDoc, null, 2));
  } catch (err) {
    console.error('Error downloading CycloneDX SBOM:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/sboms/:id/threat-intel?component=<name> — live NVD enrichment
// for ONE component of this SBOM (Day 6). Without ?component, no NVD call
// is made: the response lists the SBOM's components so the caller can pick
// one. One component per call keeps this inside NVD's unauthenticated
// rate limit; the util caches name@version for 24 h and stamps fetchedAt.
router.get('/:id/threat-intel', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']), async (req, res) => {
  const sbomId = parseInt(req.params.id);
  if (isNaN(sbomId)) return res.status(400).json({ message: 'Invalid SBOM ID' });

  try {
    const sbom = await prisma.sbom.findFirst({
      where: { id: sbomId, organizationId: req.organizationId }
    });
    if (!sbom) return res.status(404).json({ message: 'SBOM not found in active organization' });

    // Component list: CycloneDX when stored, else the SPDX packages
    // (legacy SBOMs keep working for threat intel — only the CycloneDX
    // download itself requires a rescan).
    let components = [];
    if (sbom.cycloneDxDoc && Array.isArray(sbom.cycloneDxDoc.components)) {
      components = sbom.cycloneDxDoc.components.map((c) => ({ name: c.name, version: c.version, purl: c.purl || null }));
    } else if (sbom.spdxDoc && Array.isArray(sbom.spdxDoc.packages)) {
      components = sbom.spdxDoc.packages
        .filter((p) => p.SPDXID && !p.SPDXID.includes('Root'))
        .map((p) => ({
          name: p.name,
          version: p.versionInfo || 'unknown',
          purl: (p.externalRefs || []).find((r) => r.referenceType === 'purl')?.referenceLocator || null,
        }));
    }

    const wanted = typeof req.query.component === 'string' ? req.query.component.trim() : '';
    if (!wanted) {
      return res.json({ sbomId: sbom.id, components, hint: 'Pass ?component=<name> to query live NVD data for one component.' });
    }
    const comp = components.find((c) => c.name.toLowerCase() === wanted.toLowerCase());
    if (!comp) return res.status(404).json({ message: `Component '${wanted}' not in this SBOM`, components: components.map((c) => c.name) });

    const { enrichComponent } = require('../utils/nvdEnrichment');
    try {
      const enrichment = await enrichComponent({ name: comp.name, version: comp.version });
      return res.json({ sbomId: sbom.id, component: comp, enrichment });
    } catch (err) {
      return res.status(502).json({ message: err.message || 'Threat-intel lookup failed' });
    }
  } catch (err) {
    console.error('Error fetching threat intel:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/repositories/:id/sbom — get latest SBOM for a repository
router.get('/repository/:repositoryId', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']), async (req, res) => {
  const repositoryId = parseInt(req.params.repositoryId);
  if (isNaN(repositoryId)) return res.status(400).json({ message: 'Invalid repository ID' });

  try {
    const sbom = await prisma.sbom.findFirst({
      where: { repositoryId, organizationId: req.organizationId },
      include: {
        repository: { select: { id: true, name: true, fullName: true, platform: true } },
        scan: { select: { id: true, branch: true, commitSha: true, createdAt: true } }
      },
      orderBy: { createdAt: 'desc' }
    });

    if (!sbom) {
      return res.status(404).json({ message: 'No SBOM found for this repository' });
    }

    res.json(sbom);
  } catch (err) {
    console.error('Error fetching repository SBOM:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
