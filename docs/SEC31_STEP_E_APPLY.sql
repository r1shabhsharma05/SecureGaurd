-- SEC-31 Step E — pre-steps + verification + rollback.
-- RUN ONLY after Rishabh picks "Pre-steps ke saath apply karo" on the
-- SEC-31 options widget. Run in the Supabase SQL Editor signed in as
-- rishabhsharma144289@gmail.com, BEFORE migration.sql
-- (backend/prisma/migrations/20261116_rls_policies/migration.sql).
--
-- WHY THE PRE-STEPS EXIST: the migration's §7 self-check requires
-- pg_policies on the 14 tenant tables to be EXACTLY 17. The 20
-- permissive `app_full_access` policies (fix-forward, 22 Nov) would
-- push the count to 31 and the migration would raise + roll back.
-- And the migration puts NO policy on the 6 non-tenant tables — prod
-- has RLS ENABLED on all 20, so dropping their permissive policies
-- without disabling RLS there would break login + webhooks (repeat of
-- the 22 Nov outage). Order below is mandatory: pre-steps, then the
-- migration, then the verification queries.
--
-- WARNING: between Step 1 and the migration, the app role has NO
-- policies on the tenant tables. Keep the window short (run the
-- migration immediately after) and do NOT deploy anything in between.
-- If the migration fails, run the ROLLBACK block at once — do not
-- leave prod in the pre-step state.

-- ── Step 1: drop the 20 permissive policies ──────────────────────────
DROP POLICY IF EXISTS "app_full_access" ON public."AlertLog";
DROP POLICY IF EXISTS "app_full_access" ON public."AlertSetting";
DROP POLICY IF EXISTS "app_full_access" ON public."AnalyticsEvent";
DROP POLICY IF EXISTS "app_full_access" ON public."ApiKey";
DROP POLICY IF EXISTS "app_full_access" ON public."AuditLog";
DROP POLICY IF EXISTS "app_full_access" ON public."ComplianceReport";
DROP POLICY IF EXISTS "app_full_access" ON public."ContactMessage";
DROP POLICY IF EXISTS "app_full_access" ON public."CustomRule";
DROP POLICY IF EXISTS "app_full_access" ON public."Organization";
DROP POLICY IF EXISTS "app_full_access" ON public."OrganizationInvitation";
DROP POLICY IF EXISTS "app_full_access" ON public."OrganizationMembership";
DROP POLICY IF EXISTS "app_full_access" ON public."RazorpayWebhookEvent";
DROP POLICY IF EXISTS "app_full_access" ON public."Repository";
DROP POLICY IF EXISTS "app_full_access" ON public."Sbom";
DROP POLICY IF EXISTS "app_full_access" ON public."Scan";
DROP POLICY IF EXISTS "app_full_access" ON public."StripeWebhookEvent";
DROP POLICY IF EXISTS "app_full_access" ON public."Subscription";
DROP POLICY IF EXISTS "app_full_access" ON public."User";
DROP POLICY IF EXISTS "app_full_access" ON public."Vulnerability";
DROP POLICY IF EXISTS "app_full_access" ON public."WebhookDelivery";

-- ── Step 2: disable RLS on the 6 non-tenant tables (migration has no
--    policy for these; leaving RLS on with zero policies blocks login
--    lookups + webhook inserts) ───────────────────────────────────────
ALTER TABLE public."User" DISABLE ROW LEVEL SECURITY;
ALTER TABLE public."StripeWebhookEvent" DISABLE ROW LEVEL SECURITY;
ALTER TABLE public."RazorpayWebhookEvent" DISABLE ROW LEVEL SECURITY;
ALTER TABLE public."WebhookDelivery" DISABLE ROW LEVEL SECURITY;
ALTER TABLE public."AnalyticsEvent" DISABLE ROW LEVEL SECURITY;
ALTER TABLE public."ContactMessage" DISABLE ROW LEVEL SECURITY;

-- ── Step 3: run migration.sql now (whole file, same SQL Editor
--    session). It creates the 17 tenant policies, sets FORCE RLS on
--    the 14 tenant tables, and self-checks the count.
--    GUARD (Day 12 dry-run finding): run `SET search_path TO public;`
--    FIRST in the same session. The migration's §1 creates the
--    app_current_org_id()/app_current_user_id() helpers unqualified;
--    a session with an empty search_path fails there with "no schema
--    has been selected to create in". A fresh SQL Editor session has
--    the default path, so this is a precaution, not a migration bug. ──

-- ── Step 4: verification (run after the migration; all three must pass)
-- a) exactly 17 policies, all tenant-scoped:
SELECT count(*) AS policy_count FROM pg_policies WHERE schemaname = 'public';
-- expected: 17
-- b) list them (names end _tenant_isolation / _tenant_update /
--    _tenant_delete / _create_bootstrap):
SELECT tablename, policyname FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename, policyname;
-- c) RLS enabled + forced on the 14 tenant tables, disabled on the 6:
SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
  JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
  WHERE nspname = 'public' AND relkind = 'r' ORDER BY relname;
-- expected: 14 tables relrowsecurity=t, relforcerowsecurity=t;
--   6 tables (User, StripeWebhookEvent, RazorpayWebhookEvent,
--   WebhookDelivery, AnalyticsEvent, ContactMessage) both = f.
-- d) live smoke after: login as rishabhsharma14426, dashboard loads,
--    fresh scan completes (S-0024+). Export-feedback 503 under RLS is
--    a KNOWN accepted breakage until its design is decided.

-- ── ROLLBACK (only if the migration fails after Steps 1–2) ──────────
-- Re-create the 20 permissive policies exactly as the 22 Nov
-- fix-forward had them, and re-enable RLS on the 6 tables. Run at once.
-- CREATE POLICY "app_full_access" ON public."AlertLog" FOR ALL TO secureguard_app USING (true) WITH CHECK (true);
-- (repeat for: AlertSetting, AnalyticsEvent, ApiKey, AuditLog,
--  ComplianceReport, ContactMessage, CustomRule, Organization,
--  OrganizationInvitation, OrganizationMembership, RazorpayWebhookEvent,
--  Repository, Sbom, Scan, StripeWebhookEvent, Subscription, User,
--  Vulnerability, WebhookDelivery)
-- ALTER TABLE public."User" ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE public."StripeWebhookEvent" ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE public."RazorpayWebhookEvent" ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE public."WebhookDelivery" ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE public."AnalyticsEvent" ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE public."ContactMessage" ENABLE ROW LEVEL SECURITY;
-- Then verify: SELECT count(*) FROM pg_policies WHERE schemaname='public';
-- expected: 20, and login smoke must pass before anything else.
