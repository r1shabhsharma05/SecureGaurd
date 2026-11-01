'use strict';

// Account-deletion handoff planner, Day 9. Pure function (no DB) so the
// ownership rules are unit-tested without a database:
//  - sole OWNER with other members -> ownership transfers to the oldest
//    ADMIN, else the oldest remaining member (createdAt, then lowest id).
//  - sole OWNER and sole member -> the organization is deleted with the
//    account (nothing survives ownerless; its data cascades in Prisma).
//  - another OWNER exists -> the user simply leaves; the org survives.
//  - non-owner -> the user simply leaves.
// `memberships`: [{ organizationId, role, members: [{ userId, role,
// createdAt }] }] — members includes the departing user.
function bySeniority(a, b) {
  const ta = new Date(a.createdAt || 0).getTime();
  const tb = new Date(b.createdAt || 0).getTime();
  if (ta !== tb) return ta - tb;
  return a.userId - b.userId;
}

function planAccountDeletion(userId, memberships) {
  const transfers = [];
  const deletions = [];
  const leaves = [];
  for (const m of memberships || []) {
    const others = (m.members || []).filter((x) => x.userId !== userId);
    if (m.role === 'OWNER') {
      if (others.some((x) => x.role === 'OWNER')) {
        leaves.push(m.organizationId);
        continue;
      }
      if (others.length === 0) {
        deletions.push(m.organizationId);
        continue;
      }
      const admins = others.filter((x) => x.role === 'ADMIN').sort(bySeniority);
      const successor = admins[0] || [...others].sort(bySeniority)[0];
      transfers.push({ organizationId: m.organizationId, newOwnerId: successor.userId });
    } else {
      leaves.push(m.organizationId);
    }
  }
  return { transfers, deletions, leaves };
}

module.exports = { planAccountDeletion };
