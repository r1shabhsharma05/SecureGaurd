/**
 * Multi-Tenant RBAC Middleware & Audit Logging Utility
 *
 * Enforces organization membership, extracts active organization context,
 * checks role-based permissions (OWNER, ADMIN, DEVELOPER), and records
 * audit logs for sensitive operations.
 */

const prisma = require('../prismaClient');
const { ensureDefaultOrganization } = require('../utils/orgMigration');

/**
 * Require valid Organization Membership and set req.organizationId & req.orgRole
 */
async function requireOrgContext(req, res, next) {
  if (!req.userId) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  let requestedOrgId = req.headers['x-organization-id'] || req.query.organizationId || req.body?.organizationId;
  
  // If route param contains orgId or id (on /api/organizations/:id routes)
  if (!requestedOrgId && req.params && req.params.organizationId) {
    requestedOrgId = req.params.organizationId;
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
      membership = await prisma.organizationMembership.findUnique({
        where: {
          userId_organizationId: {
            userId: req.userId,
            organizationId: orgIdNum,
          }
        },
        include: { organization: true }
      });

      if (!membership) {
        return res.status(403).json({ message: 'Access denied: You are not a member of this organization' });
      }
    } else {
      // Find default or first membership for user
      membership = await prisma.organizationMembership.findFirst({
        where: { userId: req.userId },
        include: { organization: true },
        orderBy: { createdAt: 'asc' }
      });

      // Auto-migrate if no membership exists yet
      if (!membership) {
        const defaultOrg = await ensureDefaultOrganization(req.userId);
        if (!defaultOrg) {
          return res.status(400).json({ message: 'No valid organization context found' });
        }
        membership = await prisma.organizationMembership.findUnique({
          where: {
            userId_organizationId: {
              userId: req.userId,
              organizationId: defaultOrg.id,
            }
          },
          include: { organization: true }
        });
      }
    }

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
 */
async function createAuditLog(organizationId, actorId, action, targetType = null, targetId = null, details = null) {
  try {
    await prisma.auditLog.create({
      data: {
        organizationId: parseInt(organizationId),
        actorId: actorId ? parseInt(actorId) : null,
        action: String(action),
        targetType: targetType ? String(targetType) : null,
        targetId: targetId ? String(targetId) : null,
        details: details || {},
      }
    });
  } catch (err) {
    console.error('Audit Log Error:', err);
  }
}

module.exports = {
  requireOrgContext,
  requireOrgRole,
  createAuditLog,
};
