const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { createAuditLog } = require('../middleware/rbac');
const { PLANS, getPlanConfig } = require('../config/plans');

// ── GET /api/invitations/:token — Inspect invitation ─────────────────────────
router.get('/:token', async (req, res) => {
  const rawToken = req.params.token;
  if (!rawToken) return res.status(400).json({ message: 'Token is required' });

  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  try {
    const invitation = await prisma.organizationInvitation.findUnique({
      where: { tokenHash },
      include: {
        organization: { select: { id: true, name: true, slug: true } },
        invitedBy: { select: { firstName: true, lastName: true, email: true } }
      }
    });

    if (!invitation) {
      return res.status(404).json({ message: 'Invalid or non-existent invitation' });
    }

    if (invitation.status !== 'PENDING') {
      return res.status(400).json({ message: `Invitation has already been ${invitation.status.toLowerCase()}` });
    }

    if (invitation.expiresAt < new Date()) {
      await prisma.organizationInvitation.update({
        where: { id: invitation.id },
        data: { status: 'EXPIRED' }
      });
      return res.status(400).json({ message: 'Invitation has expired' });
    }

    res.json({
      organization: invitation.organization,
      invitedEmail: invitation.invitedEmail,
      role: invitation.role,
      invitedBy: invitation.invitedBy,
      expiresAt: invitation.expiresAt
    });
  } catch (err) {
    console.error('Error inspecting invitation:', err);
    res.status(500).json({ message: 'Server error inspecting invitation' });
  }
});

// ── POST /api/invitations/:token/accept — Accept invitation ──────────────────
router.post('/:token/accept', authMiddleware, async (req, res) => {
  const rawToken = req.params.token;
  if (!rawToken) return res.status(400).json({ message: 'Token is required' });

  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  try {
    const invitation = await prisma.organizationInvitation.findUnique({
      where: { tokenHash },
      include: { organization: true }
    });

    if (!invitation) {
      return res.status(404).json({ message: 'Invalid or non-existent invitation' });
    }

    // The invitation is addressed to one email: only the account holding
    // that email may accept it. The token alone is not sufficient.
    const acceptor = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { email: true }
    });
    if (!acceptor || acceptor.email.trim().toLowerCase() !== invitation.invitedEmail.trim().toLowerCase()) {
      return res.status(403).json({ message: 'This invitation was sent to a different email address' });
    }

    if (invitation.status !== 'PENDING') {
      return res.status(400).json({ message: `Invitation has already been ${invitation.status.toLowerCase()}` });
    }

    if (invitation.expiresAt < new Date()) {
      await prisma.organizationInvitation.update({
        where: { id: invitation.id },
        data: { status: 'EXPIRED' }
      });
      return res.status(400).json({ message: 'Invitation has expired' });
    }

    // Check if user is already a member
    const existingMembership = await prisma.organizationMembership.findUnique({
      where: {
        userId_organizationId: {
          userId: req.userId,
          organizationId: invitation.organizationId
        }
      }
    });

    if (existingMembership) {
      await prisma.organizationInvitation.update({
        where: { id: invitation.id },
        data: { status: 'ACCEPTED' }
      });
      return res.json({
        message: 'You are already a member of this organization',
        organization: invitation.organization,
        membership: existingMembership
      });
    }

    // Accept invitation and create membership atomically
    const result = await prisma.$transaction(async (tx) => {
      // Conditional claim: only one accept may consume the invitation.
      // A concurrent accept flips the row first, so this update matches
      // zero rows and the second accept aborts instead of creating a
      // second membership from the same token.
      const claimed = await tx.organizationInvitation.updateMany({
        where: { id: invitation.id, status: 'PENDING' },
        data: { status: 'ACCEPTED' }
      });
      if (claimed.count === 0) {
        const err = new Error('This invitation has already been accepted');
        err.statusCode = 409;
        throw err;
      }

      // Member limit is enforced at this sink, inside the same
      // transaction, so pre-issued invitations cannot grow the org
      // past its plan limit. Mirrors getOrgPlan's fallback: an
      // inactive or missing subscription means the FREE plan.
      const sub = await tx.subscription.findUnique({
        where: { organizationId: invitation.organizationId }
      });
      const plan = sub && ['active', 'trialing'].includes(sub.status)
        ? getPlanConfig(sub.plan)
        : PLANS.FREE;
      const memberCount = await tx.organizationMembership.count({
        where: { organizationId: invitation.organizationId }
      });
      if (memberCount >= plan.maxMembers) {
        const err = new Error(
          `Your organization has reached the limit of ${plan.maxMembers} team members on the ${plan.name} plan. Upgrade to Pro for up to 15 members.`
        );
        err.statusCode = 403;
        err.reason = 'MEMBER_LIMIT_REACHED';
        throw err;
      }

      const membership = await tx.organizationMembership.create({
        data: {
          userId: req.userId,
          organizationId: invitation.organizationId,
          role: invitation.role
        }
      });

      return membership;
    });

    await createAuditLog(
      invitation.organizationId,
      req.userId,
      'MEMBER_ACCEPTED',
      'USER',
      String(req.userId),
      { role: invitation.role, invitedEmail: invitation.invitedEmail }
    );

    res.json({
      message: 'Invitation accepted successfully',
      organization: {
        id: invitation.organization.id,
        name: invitation.organization.name,
        slug: invitation.organization.slug
      },
      membership: {
        id: result.id,
        role: result.role,
        createdAt: result.createdAt
      }
    });
  } catch (err) {
    // Sentinel errors thrown inside the transaction (409 double-accept,
    // 403 member limit) carry their status; anything else is a 500.
    if (err.statusCode) {
      return res.status(err.statusCode).json({
        message: err.message,
        ...(err.reason ? { error: err.reason } : {})
      });
    }
    console.error('Error accepting invitation:', err);
    res.status(500).json({ message: 'Server error accepting invitation' });
  }
});

module.exports = router;
