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
