-- 20261128: SECURITY DEFINER resolvers, NULL on no match (F-03/F-04).
--
-- The §5 definitions in the 20261116_rls_policies bundle already return
-- NULL on no match (plain SELECT, no RAISE) — the live 500s on
-- invitation inspect/accept and on unauthenticated webhooks were for
-- unknown AND real tokens alike, which is the signature of the functions
-- being ABSENT in prod: that bundle is untracked and was never applied
-- (SEC-31 Step E pending), so every resolver call raised
-- "function ... does not exist" before the handlers' 404/401 branches
-- could run. The billing webhook never showed it because it verifies
-- its signature before touching any resolver.
--
-- This tracked migration carries the four unauthenticated-path resolvers
-- (invitation inspect/accept + push webhooks) into the normal
-- `prisma migrate deploy` chain, with the same NULL-on-miss bodies as
-- §5. CREATE OR REPLACE: safe to apply over the §5 definitions, or on
-- a database that never got them. It touches no tables and changes no
-- policies. The billing resolvers (razorpay/stripe) are NOT duplicated
-- here — they ride with the Step E bundle.
--
-- The app layer additionally fails closed to null when a resolver errors
-- (utils/rlsContext.js: nullOnResolverError), so even before this
-- migration is applied, a missing function answers 404/401 instead of
-- 500. Applying this migration is what restores the feature itself
-- (real invitations become acceptable, registered webhooks resolve) —
-- that apply step is a deployment decision for the owner (SEC-31 Step
-- E), not part of this local change.
-- Verified by tests/rlsMigration.test.js ('resolver migration
-- 20261128 ...' — PGlite, NULL on miss, ids on hit).

CREATE OR REPLACE FUNCTION app_org_id_for_invitation(p_token_hash text)
RETURNS integer LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT "organizationId" FROM "OrganizationInvitation"
  WHERE "tokenHash" = p_token_hash
    AND status = 'PENDING'
    AND "expiresAt" > now();
$$;

CREATE OR REPLACE FUNCTION app_org_id_for_invitation_any(p_token_hash text)
RETURNS integer LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT "organizationId" FROM "OrganizationInvitation"
  WHERE "tokenHash" = p_token_hash;
$$;

-- Push-webhook lookup key is (fullName, platform) — see
-- routes/integration.js (shared-secret verification now runs first;
-- the resolvers below only run for the per-repo-secret path).
CREATE OR REPLACE FUNCTION app_org_id_for_repository(p_full_name text, p_platform text)
RETURNS integer LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT "organizationId" FROM "Repository"
  WHERE "fullName" = p_full_name AND platform = p_platform;
$$;

CREATE OR REPLACE FUNCTION app_user_id_for_repository(p_full_name text, p_platform text)
RETURNS integer LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT "userId" FROM "Repository"
  WHERE "fullName" = p_full_name AND platform = p_platform;
$$;
