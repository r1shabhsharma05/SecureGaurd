const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');

router.use(authMiddleware);
router.use(requireOrgContext);

// GET /api/vulnerabilities — list open vulns for active organization with filters
router.get('/', async (req, res) => {
  const { severity, status, scanId } = req.query;

  try {
    const where = {
      scan: { organizationId: req.organizationId },
      ...(severity && { severity }),
      ...(status  && { status  }),
      ...(scanId && !isNaN(parseInt(scanId)) && { scanId: parseInt(scanId) }),
    };

    const vulns = await prisma.vulnerability.findMany({
      where,
      include: {
        scan: { select: { id: true, repository: { select: { id: true, name: true, fullName: true, platform: true, language: true } } } },
      },
      orderBy: [
        { severity: 'asc' },
        { createdAt: 'desc' },
      ],
      take: 100,
    });

    res.json(vulns);
  } catch (err) {
    console.error('Error fetching vulnerabilities:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/vulnerabilities/:id — fetch single vulnerability details with org ownership check
router.get('/:id', async (req, res) => {
  const vulnId = Number(req.params.id);
  if (!vulnId || isNaN(vulnId)) {
    return res.status(400).json({ message: 'Invalid vulnerability ID' });
  }

  try {
    const vuln = await prisma.vulnerability.findFirst({
      where: {
        id: vulnId,
        scan: { organizationId: req.organizationId }
      },
      include: {
        scan: {
          select: {
            id: true,
            status: true,
            branch: true,
            commitSha: true,
            createdAt: true,
            repository: {
              select: {
                id: true,
                name: true,
                fullName: true,
                url: true,
                platform: true,
                language: true,
                riskLevel: true,
              }
            }
          }
        }
      }
    });

    if (!vuln) {
      return res.status(404).json({ message: 'Vulnerability not found' });
    }

    res.json(vuln);
  } catch (err) {
    console.error('[Vulnerability Detail Error]', err);
    res.status(500).json({ message: 'Failed to fetch vulnerability details' });
  }
});

// PATCH /api/vulnerabilities/:id/status — mark status in active organization
// Write operation: OWNER/ADMIN/DEVELOPER only (Auditor is read-only).
router.patch('/:id/status', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), async (req, res) => {
  const vulnId = Number(req.params.id);
  if (!vulnId || isNaN(vulnId)) {
    return res.status(400).json({ message: 'Invalid vulnerability ID' });
  }

  const { status } = req.body;
  const allowed = ['open', 'fixed', 'ignored', 'false_positive'];
  if (!allowed.includes(status)) return res.status(400).json({ message: 'Invalid status' });

  try {
    const vuln = await prisma.vulnerability.findFirst({
      where: { id: vulnId, scan: { organizationId: req.organizationId } },
    });
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });

    let userLabel = undefined;
    if (status === 'ignored' || status === 'false_positive') {
      userLabel = 'false_positive';
    } else if (status === 'fixed') {
      userLabel = 'real';
    }

    const updated = await prisma.vulnerability.update({
      where: { id: vuln.id },
      data: {
        status,
        ...(userLabel && { userLabel })
      },
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'VULNERABILITY_STATUS_UPDATED',
      'VULNERABILITY',
      String(vuln.id),
      { title: vuln.title, previousStatus: vuln.status, newStatus: status }
    );

    res.json(updated);
  } catch (err) {
    console.error('Error updating status:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/vulnerabilities/:id/label — explicit ML feedback
// Write operation: OWNER/ADMIN/DEVELOPER only (Auditor is read-only).
router.patch('/:id/label', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), async (req, res) => {
  const vulnId = Number(req.params.id);
  if (!vulnId || isNaN(vulnId)) {
    return res.status(400).json({ message: 'Invalid vulnerability ID' });
  }

  const { label } = req.body;
  const allowed = ['real', 'false_positive'];
  if (!allowed.includes(label)) return res.status(400).json({ message: 'Invalid label. Must be "real" or "false_positive"' });

  try {
    const vuln = await prisma.vulnerability.findFirst({
      where: { id: vulnId, scan: { organizationId: req.organizationId } },
    });
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });

    const updated = await prisma.vulnerability.update({
      where: { id: vuln.id },
      data: { userLabel: label },
    });
    res.json({ success: true, id: updated.id, userLabel: updated.userLabel });
  } catch (err) {
    console.error('Error updating label:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
