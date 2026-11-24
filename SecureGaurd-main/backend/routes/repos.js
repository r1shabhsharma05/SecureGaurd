const express = require('express');
const router = express.Router();
const { validateBody, createRepoSchema, parseIdParam } = require('../utils/validation');
const { execFile } = require('child_process');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
// SEC-31: every Repository/AuditLog query must run with RLS context set.
// Plain reads/writes go through withRequestOrgContext (tx replaces prisma);
// the POST handler's existing $transaction sets the context inside it
// instead (no nested transactions). createAuditLog self-wraps when called
// without a tx.
const { withRequestOrgContext, setOrgContext } = require('../utils/rlsContext');
const { checkCanAddRepository } = require('../services/billingService');
const { getPlanConfig } = require('../config/plans');
const { generateWebhookSecret } = require('./integration');

// Remote git URLs only: https://, http://, git://, or ssh git@host:path.
// Anything else (notably a server-local filesystem path) is rejected here
// so it can never be stored as a repository url.
const REMOTE_GIT_URL_RE = /^(?:https?:\/\/|git:\/\/)[^\s]+$|^git@[^\s/:]+:[^\s]+$/i;
// Repository names flow into SBOM download filenames (Content-Disposition),
// so control characters, quotes and CR/LF are rejected at creation.
const INVALID_REPO_NAME_RE = /["'\x00-\x1F\x7F]/;
const MAX_REPO_NAME_LENGTH = 100;

// The scanner clones anonymously, so a URL that does not resolve to a
// public repo can never produce a scan — reject it at connect time instead
// of storing a dead repo that fails every scan at clone. `git ls-remote`
// is the cheapest reachability probe (no clone, no credentials). SSH
// remotes are checked in their anonymous-HTTPS form, the same form the
// scanner clones; non-HTTP(S) URLs were already rejected above.
function checkRepoReachable(rawUrl) {
  return new Promise((resolve) => {
    let url = rawUrl.trim();
    const sshMatch = url.match(/^git@([^:]+):(.+)$/);
    if (sshMatch) url = `https://${sshMatch[1]}/${sshMatch[2]}`;
    if (!/^https?:\/\//i.test(url)) return resolve(true);
    execFile('git', ['ls-remote', url, 'HEAD'], { timeout: 15000 }, (err) => resolve(!err));
  });
}

// All repo routes require auth and organization context
router.use(authMiddleware);
router.use(requireOrgContext);

// GET /api/repos — list all repos for the active organization
router.get('/', async (req, res) => {
  try {
    const repos = await withRequestOrgContext(req, (tx) => tx.repository.findMany({
      where: { organizationId: req.organizationId },
      include: {
        scans: {
          orderBy: { createdAt: 'desc' },
          take: 1, // last scan only
        },
        _count: { select: { scans: true } },
      },
      orderBy: { updatedAt: 'desc' },
    }));
    // Never leak the per-repo webhook secret in the list response: it is
    // returned once, at creation, and is a credential after that.
    res.json(repos.map(({ webhookSecret, ...repo }) => repo));
  } catch (err) {
    console.error('Error fetching repos:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/repos — add a new repository to the organization
router.post('/', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), validateBody(createRepoSchema), async (req, res) => {
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
  if (!(await checkRepoReachable(trimmedUrl))) {
    return res.status(400).json({ message: 'repository URL is not reachable (git ls-remote found no such public repository). Connect a public repository URL.' });
  }

  try {
    // Entitlement Check: Repository Limit (fast path; the authoritative
    // check is re-run under the per-org lock inside the transaction below).
    // Runs in its own short RLS transaction — the limit counts are
    // tenant-table reads and must not run context-free.
    const limitCheck = await withRequestOrgContext(req, (tx) =>
      checkCanAddRepository(req.organizationId, tx));
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
      // RLS context inside the existing transaction (no nesting):
      // the advisory lock + re-check + insert below all need it.
      await setOrgContext(tx, req.organizationId, req.userId);
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(${req.organizationId}::bigint)`;
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
          // Per-repo webhook secret (returned once in the 201 response;
          // never in list/detail responses). Existing repos keep NULL and
          // verify against the shared WEBHOOK_SECRET until backfilled.
          webhookSecret: generateWebhookSecret(),
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
  const repoId = parseIdParam(req.params.id);
  if (repoId === null) return res.status(400).json({ message: 'Invalid repository ID' });

  try {
    const repo = await withRequestOrgContext(req, async (tx) => {
      const found = await tx.repository.findFirst({
        where: { id: repoId, organizationId: req.organizationId },
      });
      if (!found) return null;
      await tx.repository.delete({ where: { id: found.id } });
      return found;
    });
    if (!repo) return res.status(404).json({ message: 'Repository not found' });

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
