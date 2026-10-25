const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { checkCanInviteMember } = require('../services/billingService');
const { sendMail } = require('../utils/mailer');

// All organization endpoints require logged-in user
router.use(authMiddleware);

function slugify(text) {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^\w\-]+/g, '')
    .replace(/\-\-+/g, '-');
}

// ── GET /api/organizations — List user's organizations ───────────────────────
router.get('/', async (req, res) => {
  try {
    const memberships = await prisma.organizationMembership.findMany({
      where: { userId: req.userId },
      include: {
        organization: {
          include: {
            _count: { select: { memberships: true, repositories: true } }
          }
        }
      },
      orderBy: { createdAt: 'asc' }
    });

    const orgs = memberships.map(m => ({
      id: m.organization.id,
      name: m.organization.name,
      slug: m.organization.slug,
      role: m.role,
      memberCount: m.organization._count.memberships,
      repositoryCount: m.organization._count.repositories,
      createdAt: m.organization.createdAt,
    }));

    res.json(orgs);
  } catch (err) {
    console.error('Error fetching organizations:', err);
    res.status(500).json({ message: 'Server error fetching organizations' });
  }
});

// ── POST /api/organizations — Create new organization ────────────────────────
router.post('/', async (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ message: 'Organization name must be at least 2 characters' });
  }

  const cleanName = name.trim();
  let slug = slugify(cleanName);
  
  if (!slug) slug = `org-${Date.now()}`;

  // Ensure unique slug
  let suffix = 0;
  while (await prisma.organization.findUnique({ where: { slug } })) {
    suffix++;
    slug = `${slugify(cleanName)}-${suffix}`;
  }

  try {
    const org = await prisma.$transaction(async (tx) => {
      const newOrg = await tx.organization.create({
        data: { name: cleanName, slug }
      });

      await tx.organizationMembership.create({
        data: {
          userId: req.userId,
          organizationId: newOrg.id,
          role: 'OWNER'
        }
      });

      return newOrg;
    });

    await createAuditLog(org.id, req.userId, 'ORGANIZATION_CREATED', 'ORGANIZATION', String(org.id), { name: org.name, slug: org.slug });

    res.status(201).json({
      id: org.id,
      name: org.name,
      slug: org.slug,
      role: 'OWNER',
      createdAt: org.createdAt
    });
  } catch (err) {
    console.error('Error creating organization:', err);
    res.status(500).json({ message: 'Server error creating organization' });
  }
});

// ── GET /api/organizations/:id — Get details of an organization ─────────────
router.get('/:organizationId', requireOrgContext, async (req, res) => {
  try {
    const org = await prisma.organization.findUnique({
      where: { id: req.organizationId },
      include: {
        _count: { select: { memberships: true, repositories: true, scans: true } }
      }
    });

    if (!org) return res.status(404).json({ message: 'Organization not found' });

    res.json({
      id: org.id,
      name: org.name,
      slug: org.slug,
      role: req.orgRole,
      createdAt: org.createdAt,
      stats: {
        membersCount: org._count.memberships,
        repositoriesCount: org._count.repositories,
        scansCount: org._count.scans
      }
    });
  } catch (err) {
    console.error('Error fetching org detail:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── PATCH /api/organizations/:id — Update organization name ─────────────────
router.patch('/:organizationId', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ message: 'Organization name must be at least 2 characters' });
  }

  try {
    const updated = await prisma.organization.update({
      where: { id: req.organizationId },
      data: { name: name.trim() }
    });

    await createAuditLog(req.organizationId, req.userId, 'ORGANIZATION_UPDATED', 'ORGANIZATION', String(req.organizationId), { newName: updated.name });

    res.json({ id: updated.id, name: updated.name, slug: updated.slug });
  } catch (err) {
    console.error('Error updating organization:', err);
    res.status(500).json({ message: 'Server error updating organization' });
  }
});

// ── DELETE /api/organizations/:id — Delete organization (OWNER ONLY) ────────
router.delete('/:organizationId', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  try {
    // Audit before delete
    await createAuditLog(req.organizationId, req.userId, 'ORGANIZATION_DELETED', 'ORGANIZATION', String(req.organizationId), { name: req.organization.name });

    await prisma.organization.delete({
      where: { id: req.organizationId }
    });

    res.json({ message: 'Organization deleted successfully' });
  } catch (err) {
    console.error('Error deleting organization:', err);
    res.status(500).json({ message: 'Server error deleting organization' });
  }
});

// ── GET /api/organizations/:id/members — List org members ────────────────────
router.get('/:organizationId/members', requireOrgContext, async (req, res) => {
  try {
    const members = await prisma.organizationMembership.findMany({
      where: { organizationId: req.organizationId },
      include: {
        user: {
          select: { id: true, firstName: true, lastName: true, email: true, createdAt: true }
        }
      },
      orderBy: { createdAt: 'asc' }
    });

    const result = members.map(m => ({
      id: m.id,
      userId: m.user.id,
      firstName: m.user.firstName,
      lastName: m.user.lastName,
      email: m.user.email,
      role: m.role,
      joinedAt: m.createdAt
    }));

    res.json(result);
  } catch (err) {
    console.error('Error listing members:', err);
    res.status(500).json({ message: 'Server error listing members' });
  }
});

// ── PATCH /api/organizations/:id/members/:memberId — Update member role ────
router.patch('/:organizationId/members/:memberId', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const targetMemberId = parseInt(req.params.memberId);
  const { role } = req.body;

  if (isNaN(targetMemberId)) return res.status(400).json({ message: 'Invalid member ID' });
  if (!['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR'].includes(role)) {
    return res.status(400).json({ message: 'Invalid role. Must be OWNER, ADMIN, DEVELOPER, or AUDITOR' });
  }

  try {
    const targetMembership = await prisma.organizationMembership.findFirst({
      where: { id: targetMemberId, organizationId: req.organizationId },
      include: { user: true }
    });

    if (!targetMembership) {
      return res.status(404).json({ message: 'Member not found in this organization' });
    }

    // Role restrictions:
    // 1. ADMIN cannot change an OWNER's role or promote someone to OWNER
    if (req.orgRole === 'ADMIN') {
      if (targetMembership.role === 'OWNER' || role === 'OWNER') {
        return res.status(403).json({ message: 'Only Organization Owners can assign or change Owner roles' });
      }
    }

    // 2. Prevent demoting the LAST owner of the organization
    if (targetMembership.role === 'OWNER' && role !== 'OWNER') {
      const ownerCount = await prisma.organizationMembership.count({
        where: { organizationId: req.organizationId, role: 'OWNER' }
      });
      if (ownerCount <= 1) {
        return res.status(400).json({ message: 'Cannot demote the final Owner. Assign another Owner first.' });
      }
    }

    const updated = await prisma.organizationMembership.update({
      where: { id: targetMembership.id },
      data: { role }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'MEMBER_ROLE_CHANGED',
      'USER',
      String(targetMembership.userId),
      { previousRole: targetMembership.role, newRole: role, targetEmail: targetMembership.user.email }
    );

    res.json({
      id: updated.id,
      userId: updated.userId,
      role: updated.role,
      updatedAt: updated.updatedAt
    });
  } catch (err) {
    console.error('Error updating member role:', err);
    res.status(500).json({ message: 'Server error updating member role' });
  }
});

// ── DELETE /api/organizations/:id/members/:memberId — Remove member ────────
router.delete('/:organizationId/members/:memberId', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const targetMemberId = parseInt(req.params.memberId);
  if (isNaN(targetMemberId)) return res.status(400).json({ message: 'Invalid member ID' });

  try {
    const targetMembership = await prisma.organizationMembership.findFirst({
      where: { id: targetMemberId, organizationId: req.organizationId },
      include: { user: true }
    });

    if (!targetMembership) {
      return res.status(404).json({ message: 'Member not found in this organization' });
    }

    // Role restrictions:
    // ADMIN cannot remove an OWNER or another ADMIN
    if (req.orgRole === 'ADMIN' && (targetMembership.role === 'OWNER' || targetMembership.role === 'ADMIN')) {
      return res.status(403).json({ message: 'Admins cannot remove Owners or other Admins' });
    }

    // Prevent removing the final OWNER
    if (targetMembership.role === 'OWNER') {
      const ownerCount = await prisma.organizationMembership.count({
        where: { organizationId: req.organizationId, role: 'OWNER' }
      });
      if (ownerCount <= 1) {
        return res.status(400).json({ message: 'Cannot remove the final Owner of the organization' });
      }
    }

    await prisma.organizationMembership.delete({
      where: { id: targetMembership.id }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'MEMBER_REMOVED',
      'USER',
      String(targetMembership.userId),
      { removedRole: targetMembership.role, removedEmail: targetMembership.user.email }
    );

    res.json({ message: 'Member removed from organization' });
  } catch (err) {
    console.error('Error removing member:', err);
    res.status(500).json({ message: 'Server error removing member' });
  }
});

// ── POST /api/organizations/:id/leave — Leave organization (any member) ─────
router.post('/:organizationId/leave', requireOrgContext, async (req, res) => {
  try {
    // The sole OWNER may not leave: the org would be left ownerless.
    if (req.orgRole === 'OWNER') {
      const ownerCount = await prisma.organizationMembership.count({
        where: { organizationId: req.organizationId, role: 'OWNER' }
      });
      if (ownerCount <= 1) {
        return res.status(400).json({ message: 'Cannot leave as the sole owner — transfer ownership first' });
      }
    }

    await prisma.organizationMembership.delete({
      where: { id: req.orgMembership.id }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'MEMBER_LEFT',
      'USER',
      String(req.userId),
      { leftRole: req.orgRole }
    );

    res.json({ message: 'Left organization successfully' });
  } catch (err) {
    console.error('Error leaving organization:', err);
    res.status(500).json({ message: 'Server error leaving organization' });
  }
});

// ── POST /api/organizations/:id/transfer-ownership — OWNER only ─────────────
router.post('/:organizationId/transfer-ownership', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  const targetMemberId = parseInt(req.body?.memberId);
  if (isNaN(targetMemberId)) return res.status(400).json({ message: 'Invalid member ID' });

  try {
    const targetMembership = await prisma.organizationMembership.findFirst({
      where: { id: targetMemberId, organizationId: req.organizationId },
      include: { user: { select: { id: true, email: true, firstName: true, lastName: true } } }
    });

    if (!targetMembership) {
      return res.status(404).json({ message: 'Member not found in this organization' });
    }

    if (targetMembership.userId === req.userId) {
      return res.status(400).json({ message: 'Cannot transfer ownership to yourself' });
    }

    const caller = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { id: true, email: true }
    });

    // Atomic swap: target becomes OWNER, caller steps down to ADMIN.
    await prisma.$transaction([
      prisma.organizationMembership.update({
        where: { id: targetMembership.id },
        data: { role: 'OWNER' }
      }),
      prisma.organizationMembership.update({
        where: { id: req.orgMembership.id },
        data: { role: 'ADMIN' }
      })
    ]);

    await createAuditLog(
      req.organizationId,
      req.userId,
      'OWNERSHIP_TRANSFERRED',
      'USER',
      String(targetMembership.userId),
      {
        previousOwnerId: req.userId,
        previousOwnerEmail: caller ? caller.email : null,
        newOwnerId: targetMembership.userId,
        newOwnerEmail: targetMembership.user.email
      }
    );

    res.json({
      message: 'Ownership transferred successfully',
      previousOwnerId: req.userId,
      newOwnerId: targetMembership.userId
    });
  } catch (err) {
    console.error('Error transferring ownership:', err);
    res.status(500).json({ message: 'Server error transferring ownership' });
  }
});

// ── POST /api/organizations/:id/invitations — Invite member ─────────────────
router.post('/:organizationId/invitations', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const { email, role } = req.body;
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ message: 'Valid email address is required' });
  }

  // Roles the inviter may grant: Owners can invite anyone (incl. Owner and
  // the read-only Auditor); Admins can invite up to Admin. The targetRole is
  // validated server-side — a client-supplied role is never trusted.
  const inviteableRoles = req.orgRole === 'OWNER'
    ? ['OWNER', 'ADMIN', 'DEVELOPER', 'AUDITOR']
    : ['ADMIN', 'DEVELOPER', 'AUDITOR'];
  const targetRole = role && inviteableRoles.includes(role) ? role : 'DEVELOPER';

  const cleanEmail = email.trim().toLowerCase();

  try {
    // Entitlement Check: Member Limit
    const limitCheck = await checkCanInviteMember(req.organizationId);
    if (!limitCheck.allowed) {
      await createAuditLog(
        req.organizationId,
        req.userId,
        'USAGE_LIMIT_REACHED',
        'ORGANIZATION',
        String(req.organizationId),
        { resource: 'MEMBER', limit: limitCheck.usage?.limit }
      );
      return res.status(403).json({
        error: limitCheck.reason,
        message: limitCheck.message,
        usage: limitCheck.usage
      });
    }

    // Check if user is already a member
    const existingUser = await prisma.user.findUnique({ where: { email: cleanEmail } });
    if (existingUser) {
      const existingMember = await prisma.organizationMembership.findUnique({
        where: {
          userId_organizationId: {
            userId: existingUser.id,
            organizationId: req.organizationId
          }
        }
      });
      if (existingMember) {
        return res.status(400).json({ message: 'User is already a member of this organization' });
      }
    }

    // Generate cryptographically secure random token and SHA-256 hash
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    const invitation = await prisma.organizationInvitation.create({
      data: {
        organizationId: req.organizationId,
        invitedEmail: cleanEmail,
        role: targetRole,
        tokenHash: tokenHash,
        expiresAt: expiresAt,
        invitedById: req.userId,
        status: 'PENDING'
      }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'MEMBER_INVITED',
      'INVITATION',
      String(invitation.id),
      { invitedEmail: cleanEmail, role: targetRole }
    );

    // Real invite email (Brevo HTTPS API via utils/mailer). Mail failure must
    // never break invitation creation: report it honestly instead.
    const invitationUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/accept-invite?token=${rawToken}`;
    let mailSent = false;
    let mailMessageId = null;
    try {
      const inviter = await prisma.user.findUnique({
        where: { id: req.userId },
        select: { firstName: true, lastName: true, email: true }
      });
      const inviterName = inviter
        ? `${inviter.firstName || ''} ${inviter.lastName || ''}`.trim() || inviter.email
        : 'A team member';
      const orgName = req.organization ? req.organization.name : 'SecureGaurd';
      const mailResult = await sendMail({
        to: cleanEmail,
        subject: `${inviterName} invited you to join ${orgName} on SecureGaurd`,
        text: `${inviterName} has invited you to join the "${orgName}" organization on SecureGaurd as ${targetRole}.\n\nAccept the invitation here: ${invitationUrl}\n\nThis invitation expires in 7 days. If you were not expecting this invitation, you can ignore this email.`,
        html: `<p>${inviterName} has invited you to join the "<strong>${orgName}</strong>" organization on SecureGaurd as <strong>${targetRole}</strong>.</p><p><a href="${invitationUrl}">Accept the invitation</a></p><p>This invitation expires in 7 days. If you were not expecting this invitation, you can ignore this email.</p>`
      });
      mailSent = mailResult !== false;
      mailMessageId = typeof mailResult === 'string' ? mailResult : null;
    } catch (mailErr) {
      console.error('Failed to send invitation email:', mailErr);
      mailSent = false;
      mailMessageId = null;
    }

    res.status(201).json({
      id: invitation.id,
      invitedEmail: invitation.invitedEmail,
      role: invitation.role,
      expiresAt: invitation.expiresAt,
      token: rawToken,
      invitationUrl,
      mailSent,
      mailMessageId
    });
  } catch (err) {
    console.error('Error creating invitation:', err);
    res.status(500).json({ message: 'Server error creating invitation' });
  }
});

// ── GET /api/organizations/:id/invitations — List pending invitations ───────
router.get('/:organizationId/invitations', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  try {
    const invitations = await prisma.organizationInvitation.findMany({
      where: {
        organizationId: req.organizationId,
        status: 'PENDING'
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(invitations.map(i => ({
      id: i.id,
      invitedEmail: i.invitedEmail,
      role: i.role,
      status: i.status,
      expiresAt: i.expiresAt,
      createdAt: i.createdAt
    })));
  } catch (err) {
    console.error('Error listing invitations:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ── DELETE /api/organizations/:id/invitations/:invitationId — Revoke ───────
router.delete('/:organizationId/invitations/:invitationId', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const invId = parseInt(req.params.invitationId);
  if (isNaN(invId)) return res.status(400).json({ message: 'Invalid invitation ID' });

  try {
    const inv = await prisma.organizationInvitation.findFirst({
      where: { id: invId, organizationId: req.organizationId }
    });

    if (!inv) return res.status(404).json({ message: 'Invitation not found' });

    await prisma.organizationInvitation.update({
      where: { id: inv.id },
      data: { status: 'REVOKED' }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'INVITATION_REVOKED',
      'INVITATION',
      String(inv.id),
      { revokedEmail: inv.invitedEmail }
    );

    res.json({ message: 'Invitation revoked successfully' });
  } catch (err) {
    console.error('Error revoking invitation:', err);
    res.status(500).json({ message: 'Server error revoking invitation' });
  }
});

// ── GET /api/organizations/:id/audit-logs — Get audit log ────────────────────
router.get('/:organizationId/audit-logs', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  try {
    const logs = await prisma.auditLog.findMany({
      where: { organizationId: req.organizationId },
      include: {
        actor: { select: { id: true, firstName: true, lastName: true, email: true } }
      },
      orderBy: { createdAt: 'desc' },
      take: 100
    });

    res.json(logs);
  } catch (err) {
    console.error('Error fetching audit logs:', err);
    res.status(500).json({ message: 'Server error fetching audit logs' });
  }
});

module.exports = router;
