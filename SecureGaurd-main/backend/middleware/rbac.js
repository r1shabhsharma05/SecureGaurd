/**
 * Multi-Tenant RBAC Middleware & Audit Logging Utility
 *
 * Enforces organization membership, extracts active organization context,
 * checks role-based permissions (OWNER, ADMIN, DEVELOPER), and records
 * audit logs for sensitive operations.
 */

const { ensureDefaultOrganization } = require('../utils/orgMigration');
// SEC-31: tenant-table reads must run inside an RLS transaction context.
// requireOrgContext discovers the org by user id only, so its lookups run
// inside withUserContext (the OrganizationMembership policy lets a
// user-only session see its OWN memberships). createAuditLog writes
// AuditLog, which needs the org variable — it opens its own
// withOrgContext unless the caller passes a tx it already runs in.
const { withUserContext, withOrgContext } = require('../utils/rlsContext');
const { membershipCache } = require('../utils/membershipCache');

/**
 * Require valid Organization Membership and set req.organizationId & req.orgRole
 */
async function requireOrgContext(req, res, next) {
  if (!req.userId) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  let requestedOrgId = req.headers['x-organization-id'] || req.query.organizationId || req.body?.organizationId;

  // An API key pins its own org: the key's org wins over the creator's
  // default org, and the membership lookup below still verifies the
  // creator still belongs to it (a key dies with the membership).
  if (req.apiKeyOrgId) requestedOrgId = req.apiKeyOrgId;
  // If route param contains orgId or id (on /api/organizations/:id routes)
  if (!requestedOrgId && req.params && req.params.organizationId) {
    requestedOrgId = req.params.organizationId;
  }

  // Membership cache (60 s): the lookup below costs a full RLS
  // transaction across regions on every request. Only successful
  // resolutions are stored, and membership mutations clear the cache
  // (routes/organizations.js), so revocation is still immediate. A
  // malformed org id simply misses the cache and hits the 400 below.
  const cacheKey = `${req.userId}:${requestedOrgId ? String(requestedOrgId).trim() : ''}`;
  const cachedMembership = membershipCache.get(cacheKey);
  if (cachedMembership) {
    req.organizationId = cachedMembership.organizationId;
    req.organization = cachedMembership.organization;
    req.orgMembership = cachedMembership;
    req.orgRole = cachedMembership.role;
    return next();
  }

  try {
    let membership = null;

    // A supplied org id must be a plain integer. The old
    // `!isNaN(parseInt(...))` gate coerced "12abc" to 12 and then silently
    // fell back to the caller's first org when the lookup missed, so a
    // malformed id could return another org's data. Malformed ids are a
    // 400; only an absent id takes the default-org path below.
    if (requestedOrgId) {
      const rawOrgId = String(requestedOrgId).trim();
      if (!/^\d+$/.test(rawOrgId)) {
        return res.status(400).json({ message: 'Invalid organization id' });
      }
      const orgIdNum = parseInt(rawOrgId, 10);
      // User-only context: the caller proves membership by user id; the
      // policy's user disjunct makes exactly this row visible.
      membership = await withUserContext(req.userId, (tx) =>
        tx.organizationMembership.findUnique({
          where: {
            userId_organizationId: {
              userId: req.userId,
              organizationId: orgIdNum,
            }
          },
          include: { organization: true }
        }));

      if (!membership) {
        return res.status(403).json({ message: 'Access denied: You are not a member of this organization' });
      }
    } else {
      // Find default or first membership for user
      membership = await withUserContext(req.userId, (tx) =>
        tx.organizationMembership.findFirst({
          where: { userId: req.userId },
          include: { organization: true },
          orderBy: { createdAt: 'asc' }
        }));

      // Auto-migrate if no membership exists yet
      if (!membership) {
        const defaultOrg = await ensureDefaultOrganization(req.userId);
        if (!defaultOrg) {
          return res.status(400).json({ message: 'No valid organization context found' });
        }
        membership = await withUserContext(req.userId, (tx) =>
          tx.organizationMembership.findUnique({
            where: {
              userId_organizationId: {
                userId: req.userId,
                organizationId: defaultOrg.id,
              }
            },
            include: { organization: true }
          }));
      }
    }

    membershipCache.set(cacheKey, membership);

    req.organizationId = membership.organizationId;
    req.organization = membership.organization;
    req.orgMembership = membership;
    req.orgRole = membership.role;

    next();
  } catch (err) {
    console.error('RBAC Context Middleware Error:', err);
    return res.status(500).json({ message: 'Error processing organization authorization' });
  }
}

/**
 * Higher-order middleware to enforce specific role permissions
 * Example: requireOrgRole(['OWNER', 'ADMIN'])
 */
function requireOrgRole(allowedRoles = []) {
  return (req, res, next) => {
    // API keys carry no role: their scopes were already enforced at auth
    // (authenticateRequest), and keys never reach a write route.
    if (req.apiKey) return next();
    if (!req.orgRole) {
      return res.status(403).json({ message: 'Organization context missing' });
    }

    if (!allowedRoles.includes(req.orgRole)) {
      return res.status(403).json({
        message: `Access denied: Role '${req.orgRole}' lacks required permission (${allowedRoles.join(', ')})`
      });
    }

    next();
  };
}

/**
 * Log Audit Event
 *
 * SEC-31: AuditLog is RLS-protected (org match only), so the insert must
 * run with the org variable set. Pass `tx` when the caller already runs
 * inside a withOrgContext/withUserContext transaction (the write then
 * reuses that transaction's context); otherwise this opens its own
 * short withOrgContext. A missing actorId cannot satisfy the context
 * helpers — the row is skipped with a loud log instead of failing the
 * caller's request (no call site passes a null actor today).
 */
async function createAuditLog(organizationId, actorId, action, targetType = null, targetId = null, details = null, tx = null) {
  const row = {
    organizationId: parseInt(organizationId),
    actorId: actorId ? parseInt(actorId) : null,
    action: String(action),
    targetType: targetType ? String(targetType) : null,
    targetId: targetId ? String(targetId) : null,
    details: details || {},
  };
  try {
    if (tx) {
      await tx.auditLog.create({ data: row });
      return;
    }
    if (row.actorId === null || Number.isNaN(row.actorId)) {
      console.error('Audit Log Error: refusing audit write without actorId (no RLS context can be set)', { organizationId, action });
      return;
    }
    await withOrgContext(row.organizationId, row.actorId, (t) => t.auditLog.create({ data: row }));
  } catch (err) {
    console.error('Audit Log Error:', err);
  }
}

/**
 * Audit-log an auth event (login, logout, password change/reset).
 *
 * AuditLog.organizationId is required, but auth events happen outside
 * any org context. Resolution: the user's primary (earliest)
 * membership's org — the same default-org rule requireOrgContext
 * uses. A user with no membership yet (pre-onboarding) has no org to
 * attach the row to, so the event is skipped. Never throws into the
 * auth handler: an audit failure must not break sign-in.
 */
async function logAuthEvent(userId, action, details = null) {
  try {
    const uid = parseInt(userId, 10);
    if (!uid || Number.isNaN(uid)) return;
    const membership = await withUserContext(uid, (tx) =>
      tx.organizationMembership.findFirst({
        where: { userId: uid },
        orderBy: { createdAt: 'asc' },
        select: { organizationId: true },
      }));
    if (!membership) return;
    await createAuditLog(membership.organizationId, uid, action, 'USER', String(uid), details || {});
  } catch (err) {
    console.error('Auth Audit Log Error:', err);
  }
}

module.exports = {
  requireOrgContext,
  requireOrgRole,
  createAuditLog,
  logAuthEvent,
  // Test hook + mutation invalidation: membership changes clear the
  // whole cache so a removed/demoted member loses access immediately.
  clearMembershipCache: () => membershipCache.clear(),
};
