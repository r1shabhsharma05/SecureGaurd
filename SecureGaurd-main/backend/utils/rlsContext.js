/**
 * RLS session context — backend/utils/rlsContext.js
 *
 * SEC-31: the app connects to Postgres with ONE DATABASE_URL credential,
 * so Postgres cannot tell users apart by role. Tenant isolation at the
 * database layer works through two per-transaction session variables
 * (see migration 20261116_rls_policies):
 *   app.current_org_id   — active organization id
 *   app.current_user_id  — authenticated user id
 *
 * HOW TO USE (the only supported pattern):
 *   const { withOrgContext } = require('../utils/rlsContext');
 *   // inside a route handler, AFTER requireOrgContext has run:
 *   const rows = await withOrgContext(req.organizationId, req.userId, (tx) =>
 *     tx.scan.findMany({ where: { organizationId: req.organizationId } }));
 *
 * RULES — read before touching this file:
 * 1. The variables are set with set_config(..., true) == SET LOCAL, so
 *    they live ONLY inside the interactive transaction opened here. A
 *    plain `prisma.*` call outside withOrgContext sees no variables and
 *    the RLS policies return ZERO rows (fail closed, by design). Every
 *    org-scoped query must receive the `tx` client and use it.
 * 2. Never set the variables with a bare `prisma.$executeRaw('SET ...')`
 *    outside a transaction: each Prisma query may run on a different
 *    pooled connection, so the value would land on the wrong connection
 *    or leak into the next request on that connection. SET LOCAL inside
 *    the transaction is the only correct scope (this also holds under
 *    PgBouncer transaction pooling, which Supabase uses).
 * 3. `withUserContext` (user id only, no org) exists for exactly two
 *    flows: org discovery in requireOrgContext (findFirst membership by
 *    userId) and org creation (the bootstrap INSERT policy allows an
 *    org insert only with user context set and org unset). After the
 *    insert, set the org variable to the NEW org id in the same
 *    transaction before inserting the OWNER membership / audit row —
 *    see `createOrgWithContext` in the rollout doc.
 * 4. Unauthenticated / webhook flows have no req.userId. They must
 *    resolve the tenant FIRST via the SECURITY DEFINER functions in the
 *    migration (resolveOrgIdForInvitation / resolveOrgIdForRazorpaySubscription
 *    / resolveOrgIdForStripeSubscription / resolveOrgIdForRepository),
 *    then call withOrgContext with the resolved id. Never call these
 *    resolvers with a caller-supplied org id — the input is the secret
 *    (token hash / provider subscription id / repo fullName+platform).
 * 5. `rlsContextMiddleware` only carries the ids in AsyncLocalStorage so
 *    nested helpers can read them; it does NOT set the DB variables and
 *    must never be mistaken for enforcement. Enforcement happens only
 *    inside withOrgContext/withUserContext transactions.
 * 6. Resolver flows with NO authenticated user (invitation inspect,
 *    provider webhooks) use withOrgOnlyContext: the org id comes from a
 *    SECURITY DEFINER resolver keyed by a secret, and the policies that
 *    matter there check the org variable only. Never use it where a user
 *    id exists — withOrgContext is the rule then.
 *
 * ROLLOUT ORDER (see the migration header): deploy this file + convert
 * call sites FIRST, then apply the migration. Applying the migration
 * first makes every org-scoped query return zero rows.
 */

const { AsyncLocalStorage } = require('node:async_hooks');

const prisma = require('../prismaClient');

const storage = new AsyncLocalStorage();

/**
 * Parse an org/user id the way the policies need it: a plain integer.
 * Rejects the parseInt-coercion trap (parseInt("12abc") === 12 — the
 * SEC-15/S3 bug class): only strings of digits, real integers, and
 * values >= 1 pass. Anything else is null (fail closed).
 */
function parseContextId(value) {
  if (typeof value === 'number') {
    return Number.isInteger(value) && value >= 1 ? value : null;
  }
  if (typeof value === 'string' && /^[0-9]+$/.test(value)) {
    const n = Number(value);
    return Number.isSafeInteger(n) && n >= 1 ? n : null;
  }
  return null;
}

function assertContextId(value, name) {
  const parsed = parseContextId(value);
  if (parsed === null) {
    throw new Error(`Invalid RLS context: ${name} must be a positive integer`);
  }
  return parsed;
}

/**
 * Set both session variables on the transaction's connection. `tx` must
 * be the interactive-transaction client from prisma.$transaction — never
 * the global prisma client (see rule 2 above).
 */
async function setOrgContext(tx, orgId, userId) {
  const org = parseContextId(orgId);
  const user = parseContextId(userId);
  if (org === null) throw new Error('Invalid RLS context: organizationId must be a positive integer');
  if (user === null) throw new Error('Invalid RLS context: userId must be a positive integer');
  await tx.$executeRaw`SELECT set_config('app.current_org_id', ${String(org)}, true)`;
  await tx.$executeRaw`SELECT set_config('app.current_user_id', ${String(user)}, true)`;
}

/** Set only the user variable (org discovery / org creation bootstrap). */
async function setUserContext(tx, userId) {
  const user = parseContextId(userId);
  if (user === null) throw new Error('Invalid RLS context: userId must be a positive integer');
  await tx.$executeRaw`SELECT set_config('app.current_user_id', ${String(user)}, true)`;
}

/** Set only the org variable (resolver flows with no authenticated user — rule 6). */
async function setOrgOnlyContext(tx, orgId) {
  const org = parseContextId(orgId);
  if (org === null) throw new Error('Invalid RLS context: organizationId must be a positive integer');
  await tx.$executeRaw`SELECT set_config('app.current_org_id', ${String(org)}, true)`;
}

/**
 * Run `fn(tx)` inside an interactive transaction with both RLS variables
 * set. `fn` receives the transaction client — use it for every query.
 * Returns whatever `fn` returns. Rolls back on any throw (Prisma default).
 */
function createRlsContext(client) {
  async function withOrgContext(orgId, userId, fn) {
    const org = assertContextId(orgId, 'organizationId');
    const user = assertContextId(userId, 'userId');
    return client.$transaction(async (tx) => {
      await setOrgContext(tx, org, user);
      return fn(tx);
    });
  }

  async function withUserContext(userId, fn) {
    const user = assertContextId(userId, 'userId');
    return client.$transaction(async (tx) => {
      await setUserContext(tx, user);
      return fn(tx);
    });
  }

  /** Run `fn(tx)` with only the org variable set (rule 6 — no user). */
  async function withOrgOnlyContext(orgId, fn) {
    const org = assertContextId(orgId, 'organizationId');
    return client.$transaction(async (tx) => {
      await setOrgOnlyContext(tx, org);
      return fn(tx);
    });
  }

  /** Convenience wrapper reading the ids off the request (after auth + requireOrgContext). */
  async function withRequestOrgContext(req, fn) {
    return withOrgContext(req.organizationId, req.userId, fn);
  }

  // -- SECURITY DEFINER resolvers (migration §5). Each runs inside the
  // caller's transaction and returns an integer id or null. The caller
  // then re-enters withOrgContext with the resolved id; these functions
  // never return row contents.
  async function resolveOrgIdForInvitation(tx, tokenHash) {
    if (typeof tokenHash !== 'string' || tokenHash.length === 0) return null;
    const rows = await tx.$queryRaw`SELECT app_org_id_for_invitation(${tokenHash}) AS "orgId"`;
    const id = rows?.[0]?.orgId;
    return parseContextId(id);
  }

  // Any-status variant (migration §5): resolves the org for an invitation
  // in ANY status — the inspect/accept handlers must tell PENDING apart
  // from ACCEPTED/EXPIRED, and the PENDING-only resolver collapses those
  // to "not found". Same secret key, same return shape (org id only).
  async function resolveOrgIdForInvitationAny(tx, tokenHash) {
    if (typeof tokenHash !== 'string' || tokenHash.length === 0) return null;
    const rows = await tx.$queryRaw`SELECT app_org_id_for_invitation_any(${tokenHash}) AS "orgId"`;
    const id = rows?.[0]?.orgId;
    return parseContextId(id);
  }

  async function resolveOrgIdForRazorpaySubscription(tx, subscriptionId) {
    if (typeof subscriptionId !== 'string' || subscriptionId.length === 0) return null;
    const rows = await tx.$queryRaw`SELECT app_org_id_for_razorpay_subscription(${subscriptionId}) AS "orgId"`;
    return parseContextId(rows?.[0]?.orgId);
  }

  async function resolveOrgIdForStripeSubscription(tx, subscriptionId) {
    if (typeof subscriptionId !== 'string' || subscriptionId.length === 0) return null;
    const rows = await tx.$queryRaw`SELECT app_org_id_for_stripe_subscription(${subscriptionId}) AS "orgId"`;
    return parseContextId(rows?.[0]?.orgId);
  }

  async function resolveOrgIdForRepository(tx, fullName, platform) {
    if (typeof fullName !== 'string' || typeof platform !== 'string') return null;
    const rows = await tx.$queryRaw`SELECT app_org_id_for_repository(${fullName}, ${platform}) AS "orgId"`;
    return parseContextId(rows?.[0]?.orgId);
  }

  async function resolveUserIdForRepository(tx, fullName, platform) {
    if (typeof fullName !== 'string' || typeof platform !== 'string') return null;
    const rows = await tx.$queryRaw`SELECT app_user_id_for_repository(${fullName}, ${platform}) AS "userId"`;
    return parseContextId(rows?.[0]?.userId);
  }

  return {
    withOrgContext,
    withUserContext,
    withOrgOnlyContext,
    withRequestOrgContext,
    resolveOrgIdForInvitation,
    resolveOrgIdForInvitationAny,
    resolveOrgIdForRazorpaySubscription,
    resolveOrgIdForStripeSubscription,
    resolveOrgIdForRepository,
    resolveUserIdForRepository,
  };
}

/**
 * Express middleware: carries { userId, organizationId } for the request
 * in AsyncLocalStorage. Mount AFTER authMiddleware + requireOrgContext
 * (the values only exist then). Carriage only — NOT enforcement (rule 5).
 */
function rlsContextMiddleware(req, res, next) {
  const ctx = {
    userId: parseContextId(req.userId),
    organizationId: parseContextId(req.organizationId),
  };
  storage.run(ctx, () => next());
}

/** Read the ids carried by rlsContextMiddleware for the current request (or nulls outside a request). */
function getRequestContext() {
  return storage.getStore() || { userId: null, organizationId: null };
}

module.exports = {
  parseContextId,
  assertContextId,
  setOrgContext,
  setUserContext,
  setOrgOnlyContext,
  createRlsContext,
  rlsContextMiddleware,
  getRequestContext,
  // Default instance bound to the app's singleton Prisma client.
  ...createRlsContext(prisma),
};
