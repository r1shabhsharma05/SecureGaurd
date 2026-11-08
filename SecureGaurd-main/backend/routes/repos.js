const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { checkCanAddRepository } = require('../services/billingService');
const { getPlanConfig } = require('../config/plans');

// Remote git URLs only: https://, http://, git://, or ssh git@host:path.
// Anything else (notably a server-local filesystem path) is rejected here
// so it can never be stored as a repository url.
const REMOTE_GIT_URL_RE = /^(?:https?:\/\/|git:\/\/)[^\s]+$|^git@[^\s/:]+:[^\s]+$/i;
// Repository names flow into SBOM download filenames (Content-Disposition),
// so control characters, quotes and CR/LF are rejected at creation.
const INVALID_REPO_NAME_RE = /["'\x00-\x1F\x7F]/;
const MAX_REPO_NAME_LENGTH = 100;

// All repo routes require auth and organization context
router.use(authMiddleware);
router.use(requireOrgContext);

// GET /api/repos — list all repos for the active organization
router.get('/', async (req, res) => {
  try {
    const repos = await prisma.repository.findMany({
      where: { organizationId: req.organizationId },
      include: {
        scans: {
          orderBy: { createdAt: 'desc' },
          take: 1, // last scan only
        },
        _count: { select: { scans: true } },
      },
      orderBy: { updatedAt: 'desc' },
    });
    res.json(repos);
  } catch (err) {
    console.error('Error fetching repos:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/repos — add a new repository to the organization
router.post('/', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), async (req, res) => {
  const { name, fullName, url, platform, language } = req.body;
  if (!name || !url || typeof name !== 'string' || typeof url !== 'string') return res.status(400).json({ message: 'name and url are required' });

  const trimmedName = name.trim();
  const trimmedUrl = url.trim();
  if (!trimmedName || trimmedName.length > MAX_REPO_NAME_LENGTH || INVALID_REPO_NAME_RE.test(trimmedName)) {
    return res.status(400).json({ message: 'name must be 1-100 characters and must not contain control characters or quotes' });
  }
  if (!REMOTE_GIT_URL_RE.test(trimmedUrl)) {
    return res.status(400).json({ message: 'url must be a remote git URL (https://, http://, git://, or git@host:path)' });
  }

  try {
    // Entitlement Check: Repository Limit (fast path; the authoritative
    // check is re-run under the per-org lock inside the transaction below).
    const limitCheck = await checkCanAddRepository(req.organizationId);
    if (!limitCheck.allowed) {
      await createAuditLog(
        req.organizationId,
        req.userId,
        'USAGE_LIMIT_REACHED',
        'ORGANIZATION',
        String(req.organizationId),
        { resource: 'REPOSITORY', limit: limitCheck.usage?.limit }
      );
      return res.status(403).json({
        error: limitCheck.reason,
        message: limitCheck.message,
        usage: limitCheck.usage
      });
    }
    // Serialize count+create per organization: hold a per-org advisory lock
    // across the re-check and the insert inside one transaction. A plain
    // $transaction alone is NOT enough under Read Committed — two concurrent
    // transactions could both count below the limit before either inserts;
    // the lock is what makes the check atomic.
    const repo = await prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT pg_advisory_xact_lock(${req.organizationId}::bigint)`;
      const sub = await tx.subscription.findUnique({
        where: { organizationId: req.organizationId },
      });
      const plan = getPlanConfig(
        sub && (sub.status === 'active' || sub.status === 'trialing') ? sub.plan : 'FREE'
      );
      const used = await tx.repository.count({
        where: { organizationId: req.organizationId },
      });
      if (used >= plan.maxRepositories) {
        const err = new Error('Repository limit reached');
        err.code = 'REPOSITORY_LIMIT_REACHED';
        err.limit = plan.maxRepositories;
        err.planName = plan.name;
        throw err;
      }
      return tx.repository.create({
        data: {
          userId: req.userId,
          organizationId: req.organizationId,
          name: trimmedName,
          fullName: fullName || trimmedName,
          url: trimmedUrl,
          platform: platform || 'manual',
          language: language || null,
        },
      });
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'REPOSITORY_ADDED',
      'REPOSITORY',
      String(repo.id),
      { name: repo.name, fullName: repo.fullName, platform: repo.platform }
    );

    res.status(201).json(repo);
  } catch (err) {
    if (err.code === 'REPOSITORY_LIMIT_REACHED') {
      await createAuditLog(
        req.organizationId,
        req.userId,
        'USAGE_LIMIT_REACHED',
        'ORGANIZATION',
        String(req.organizationId),
        { resource: 'REPOSITORY', limit: err.limit }
      );
      return res.status(403).json({
        error: 'REPOSITORY_LIMIT_REACHED',
        message: `Your organization has reached the limit of ${err.limit} repositories on the ${err.planName} plan. Upgrade to Pro for up to 25 repositories.`,
        usage: { used: err.limit, limit: err.limit, remaining: 0 },
      });
    }
    if (err.code === 'P2002') {
      return res.status(400).json({ message: 'Repository already connected' });
    }
    console.error('Error creating repo:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/repos/:id — remove a repository (OWNER or ADMIN only)
router.delete('/:id', requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const repoId = parseInt(req.params.id);
  if (isNaN(repoId)) return res.status(400).json({ message: 'Invalid repository ID' });

  try {
    const repo = await prisma.repository.findFirst({
      where: { id: repoId, organizationId: req.organizationId },
    });
    if (!repo) return res.status(404).json({ message: 'Repository not found' });

    await prisma.repository.delete({ where: { id: repo.id } });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'REPOSITORY_REMOVED',
      'REPOSITORY',
      String(repo.id),
      { name: repo.name, fullName: repo.fullName }
    );

    res.json({ message: 'Repository removed' });
  } catch (err) {
    console.error('Error removing repo:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
