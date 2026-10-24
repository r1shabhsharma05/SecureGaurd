const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { evaluateCompliance } = require('../services/complianceEngine');
const { generateCompliancePdf } = require('../utils/pdfGenerator');

// All compliance routes require authentication & organization context
router.use(authMiddleware);
router.use(requireOrgContext);

/**
 * Helper to compute date range
 */
function parseDateRange(dateRangeOption, customFrom, customTo) {
  const now = new Date();
  let fromDate = new Date();
  let toDate = now;

  if (dateRangeOption === '7d') {
    fromDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  } else if (dateRangeOption === '90d') {
    fromDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
  } else if (dateRangeOption === 'custom' && customFrom && customTo) {
    fromDate = new Date(customFrom);
    toDate = new Date(customTo);
  } else {
    // Default 30d
    fromDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  }

  if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
    throw new Error('Invalid date range specified');
  }

  return { fromDate, toDate };
}

// POST /api/compliance/generate — Generate a new compliance report for active organization
// Write operation: OWNER/ADMIN/DEVELOPER only (Auditor is read-only; auditors read via GET /reports).
router.post('/generate', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), async (req, res) => {
  try {
    const { repositoryId, framework, dateRangeOption, customFromDate, customToDate, reportName } = req.body;

    if (!repositoryId || isNaN(Number(repositoryId))) {
      return res.status(400).json({ message: 'repositoryId is required and must be a valid number' });
    }

    const sanitizedReportName = reportName ? String(reportName).slice(0, 200) : undefined;

    const validFrameworks = ['SOC2', 'HIPAA', 'PCI-DSS', 'GDPR'];
    const normalizedFramework = (framework || 'SOC2').toUpperCase();
    const frameworkKey = normalizedFramework === 'PCI_DSS' ? 'PCI-DSS' : normalizedFramework;

    if (!validFrameworks.includes(frameworkKey)) {
      return res.status(400).json({ message: `Invalid framework. Supported options: ${validFrameworks.join(', ')}` });
    }

    // Authorization check: repository must belong to active organization
    const parsedRepoId = Number(repositoryId);
    const repo = await prisma.repository.findFirst({
      where: {
        id: parsedRepoId,
        organizationId: req.organizationId
      }
    });

    if (!repo) {
      return res.status(404).json({ message: 'Repository not found or unauthorized' });
    }

    let fromDate, toDate;
    try {
      const parsed = parseDateRange(dateRangeOption, customFromDate, customToDate);
      fromDate = parsed.fromDate;
      toDate = parsed.toDate;
    } catch (dateErr) {
      return res.status(400).json({ message: dateErr.message });
    }

    const vulnerabilities = await prisma.vulnerability.findMany({
      where: {
        scan: {
          repositoryId: repo.id,
          createdAt: {
            gte: fromDate,
            lte: toDate
          }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    const reportData = evaluateCompliance({
      framework: frameworkKey,
      vulnerabilities,
      repository: repo,
      reportName: sanitizedReportName,
      dateRange: { fromDate, toDate, option: dateRangeOption || '30d' }
    });

    const finalReportName = sanitizedReportName || `${frameworkKey} Compliance Report - ${repo.name}`;

    const report = await prisma.complianceReport.create({
      data: {
        userId: req.userId,
        organizationId: req.organizationId,
        repositoryId: repo.id,
        name: finalReportName,
        framework: frameworkKey,
        dateRangeOption: dateRangeOption || '30d',
        fromDate,
        toDate,
        status: 'completed',
        complianceScore: reportData.summary.score,
        totalFindings: reportData.summary.totalFindings,
        criticalCount: reportData.summary.critical,
        highCount: reportData.summary.high,
        mediumCount: reportData.summary.medium,
        lowCount: reportData.summary.low,
        passedControls: reportData.summary.passedControls,
        partialControls: reportData.summary.partialControls,
        failedControls: reportData.summary.failedControls,
        reportData
      },
      include: {
        repository: {
          select: { id: true, name: true, fullName: true, platform: true }
        }
      }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'COMPLIANCE_REPORT_GENERATED',
      'COMPLIANCE_REPORT',
      String(report.id),
      { framework: frameworkKey, score: reportData.summary.score, repoName: repo.name }
    );

    res.status(201).json(report);
  } catch (err) {
    console.error('Compliance Report Generation Error:', err);
    res.status(500).json({ message: 'Failed to generate compliance report' });
  }
});

// GET /api/compliance/reports — List all compliance reports for active organization
router.get('/reports', async (req, res) => {
  try {
    const reports = await prisma.complianceReport.findMany({
      where: {
        organizationId: req.organizationId
      },
      include: {
        repository: {
          select: { id: true, name: true, fullName: true, platform: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(reports);
  } catch (err) {
    console.error('Error fetching compliance reports:', err);
    res.status(500).json({ message: 'Failed to fetch compliance reports' });
  }
});

// GET /api/compliance/reports/:id — Fetch single compliance report with org check
router.get('/reports/:id', async (req, res) => {
  const reportId = Number(req.params.id);
  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Invalid report ID' });
  }

  try {
    const report = await prisma.complianceReport.findFirst({
      where: {
        id: reportId,
        organizationId: req.organizationId
      },
      include: {
        repository: {
          select: { id: true, name: true, fullName: true, platform: true, url: true }
        }
      }
    });

    if (!report) {
      return res.status(404).json({ message: 'Compliance report not found' });
    }

    res.json(report);
  } catch (err) {
    console.error('Error fetching single compliance report:', err);
    res.status(500).json({ message: 'Failed to fetch compliance report' });
  }
});

// GET /api/compliance/reports/:id/pdf — Download PDF report
router.get('/reports/:id/pdf', async (req, res) => {
  const reportId = Number(req.params.id);
  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Invalid report ID' });
  }

  try {
    const report = await prisma.complianceReport.findFirst({
      where: {
        id: reportId,
        organizationId: req.organizationId
      },
      include: {
        repository: true
      }
    });

    if (!report) {
      return res.status(404).json({ message: 'Compliance report not found' });
    }

    const pdfBuffer = await generateCompliancePdf(report);

    const safeFilename = `${report.framework}_Report_${report.id}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);

    res.send(pdfBuffer);
  } catch (err) {
    console.error('Error generating PDF download:', err);
    res.status(500).json({ message: 'Failed to generate PDF report' });
  }
});

// GET /api/compliance/reports/:id/json — Download JSON export
router.get('/reports/:id/json', async (req, res) => {
  const reportId = Number(req.params.id);
  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Invalid report ID' });
  }

  try {
    const report = await prisma.complianceReport.findFirst({
      where: {
        id: reportId,
        organizationId: req.organizationId
      },
      include: {
        repository: {
          select: { id: true, name: true, fullName: true, platform: true }
        }
      }
    });

    if (!report) {
      return res.status(404).json({ message: 'Compliance report not found' });
    }

    const safeFilename = `${report.framework}_Report_${report.id}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);

    res.send(JSON.stringify(report, null, 2));
  } catch (err) {
    console.error('Error exporting report JSON:', err);
    res.status(500).json({ message: 'Failed to export compliance report JSON' });
  }
});

// DELETE /api/compliance/reports/:id — Delete report (OWNER or ADMIN)
router.delete('/reports/:id', requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const reportId = Number(req.params.id);
  if (!reportId || isNaN(reportId)) {
    return res.status(400).json({ message: 'Invalid report ID' });
  }

  try {
    const report = await prisma.complianceReport.findFirst({
      where: {
        id: reportId,
        organizationId: req.organizationId
      }
    });

    if (!report) {
      return res.status(404).json({ message: 'Compliance report not found' });
    }

    await prisma.complianceReport.delete({
      where: { id: report.id }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'COMPLIANCE_REPORT_DELETED',
      'COMPLIANCE_REPORT',
      String(report.id),
      { reportName: report.name }
    );

    res.json({ message: 'Compliance report deleted successfully' });
  } catch (err) {
    console.error('Error deleting compliance report:', err);
    res.status(500).json({ message: 'Failed to delete compliance report' });
  }
});

module.exports = router;
