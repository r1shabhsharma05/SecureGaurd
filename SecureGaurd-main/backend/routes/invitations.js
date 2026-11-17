const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { createAuditLog } = require('../middleware/rbac');
const { PLANS, getPlanConfig } = require('../config/plans');
// SEC-31: OrganizationInvitation is an RLS table, and these handlers run
// BEFORE any org context exists — the org comes from the token itself.
// resolveOrgIdForInvitationAny (SECURITY DEFINER, keyed by the secret
// token hash, returns the org id only) resolves the tenant; the PENDING
// statuses are then told apart inside the context. Inspect has no
// authenticated user, so it uses org-only context (rule 6); accept has
// req.userId, so it uses withOrgContext.
const { withOrgContext, withOrgOnlyContext, resolveOrgIdForInvitationAny } = require('../utils/rlsContext');

// ── GET /api/invitations/:token — Inspect invitation ─────────────────────────
router.get('/:token', async (req, res) => {
  const rawToken = req.params.token;
  if (!rawToken) return res.status(400).json({ message: 'Token is required' });

  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  try {
    // Resolve the tenant from the secret first (no org context exists yet).
    const organizationId = await prisma.$transaction((tx) => resolveOrgIdForInvitationAny(tx, tokenHash));
    if (!organizationId) {
      return res.status(404).json({ message: 'Invalid or non-existent invitation' });
    }

    const outcome = await withOrgOnlyContext(organizationId, async (tx) => {
      const found = await tx.organizationInvitation.findUnique({
        where: { tokenHash },
        include: {
          organization: { select: { id: true, name: true, slug: true } },
          invitedBy: { select: { firstName: true, lastName: true, email: true } }
        }
      });
      if (!found) return null;
      if (found.status === 'PENDING' && found.expiresAt < new Date()) {
        await tx.organizationInvitation.update({
          where: { id: found.id },
          data: { status: 'EXPIRED' }
        });
        return { invitation: found, justExpired: true };
      }
      return { invitation: found, justExpired: false };
    });

    if (!outcome) {
      return res.status(404).json({ message: 'Invalid or non-existent invitation' });
    }
    const invitation = outcome.invitation;

    if (invitation.status !== 'PENDING') {
      return res.status(400).json({ message: `Invitation has already been ${invitation.status.toLowerCase()}` });
    }

    if (outcome.justExpired) {
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
    // Resolve the tenant from the secret first (no org context exists yet).
    const organizationId = await prisma.$transaction((tx) => resolveOrgIdForInvitationAny(tx, tokenHash));
    if (!organizationId) {
      return res.status(404).json({ message: 'Invalid or non-existent invitation' });
    }

    // The whole accept runs in ONE RLS transaction (the old $transaction
    // is inlined here — Prisma forbids nesting). Early returns become
    // outcome values: a res.json inside the callback would double-send,
    // because the handler continues after the wrapper returns.
    const outcome = await withOrgContext(organizationId, req.userId, async (tx) => {
      const invitation = await tx.organizationInvitation.findUnique({
        where: { tokenHash },
        include: { organization: true }
      });

      if (!invitation) return { kind: 'not-found' };

      // The invitation is addressed to one email: only the account holding
      // that email may accept it. The token alone is not sufficient.
      const acceptor = await tx.user.findUnique({
        where: { id: req.userId },
        select: { email: true }
      });
      if (!acceptor || acceptor.email.trim().toLowerCase() !== invitation.invitedEmail.trim().toLowerCase()) {
        return { kind: 'forbidden' };
      }

      if (invitation.status !== 'PENDING') {
        return { kind: 'status', status: invitation.status };
      }

      if (invitation.expiresAt < new Date()) {
        await tx.organizationInvitation.update({
          where: { id: invitation.id },
          data: { status: 'EXPIRED' }
        });
        return { kind: 'expired' };
      }

      // Check if user is already a member
      const existingMembership = await tx.organizationMembership.findUnique({
        where: {
          userId_organizationId: {
            userId: req.userId,
            organizationId: invitation.organizationId
          }
        }
      });

      if (existingMembership) {
        await tx.organizationInvitation.update({
          where: { id: invitation.id },
          data: { status: 'ACCEPTED' }
        });
        return { kind: 'already-member', organization: invitation.organization, membership: existingMembership };
      }

      // Accept invitation and create membership atomically
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

      return {
        kind: 'accepted',
        organization: invitation.organization,
        membership,
        role: invitation.role,
        invitedEmail: invitation.invitedEmail,
      };
    });

    if (outcome.kind === 'not-found') {
      return res.status(404).json({ message: 'Invalid or non-existent invitation' });
    }
    if (outcome.kind === 'forbidden') {
      return res.status(403).json({ message: 'This invitation was sent to a different email address' });
    }
    if (outcome.kind === 'status') {
      return res.status(400).json({ message: `Invitation has already been ${outcome.status.toLowerCase()}` });
    }
    if (outcome.kind === 'expired') {
      return res.status(400).json({ message: 'Invitation has expired' });
    }
    if (outcome.kind === 'already-member') {
      return res.json({
        message: 'You are already a member of this organization',
        organization: outcome.organization,
        membership: outcome.membership
      });
    }

    await createAuditLog(
      outcome.organization.id,
      req.userId,
      'MEMBER_ACCEPTED',
      'USER',
      String(req.userId),
      { role: outcome.role, invitedEmail: outcome.invitedEmail }
    );

    res.json({
      message: 'Invitation accepted successfully',
      organization: {
        id: outcome.organization.id,
        name: outcome.organization.name,
        slug: outcome.organization.slug
      },
      membership: {
        id: outcome.membership.id,
        role: outcome.membership.role,
        createdAt: outcome.membership.createdAt
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
