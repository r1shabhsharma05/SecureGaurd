-- Webhook idempotency + per-repo webhook secrets + Razorpay ordering
-- guard + email-verification token expiry. Additive only: all new columns
-- are nullable and the new table is empty, so this applies cleanly to
-- existing deployments. Applied automatically on Render by the
-- preDeployCommand (npx prisma migrate deploy) in render.yaml.
-- NOTE: not executed locally — no Postgres on this VM. Validate with
-- `npx prisma migrate deploy` against a staging database before relying
-- on it, and run `prisma generate` (npm run build) so the client picks
-- up WebhookDelivery / the new columns.

-- 1. WebhookDelivery: one row per accepted GitHub/GitLab push delivery.
--    deliveryId is UNIQUE so the check-then-insert in
--    routes/integration.js is atomic (redelivery -> P2002 -> 200 no-op).
CREATE TABLE IF NOT EXISTS "WebhookDelivery" (
  "id"           SERIAL PRIMARY KEY,
  "deliveryId"   TEXT NOT NULL,
  "platform"     TEXT NOT NULL,
  "repositoryId" INTEGER NOT NULL,
  "commitSha"    TEXT,
  "receivedAt"   TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS "WebhookDelivery_deliveryId_key" ON "WebhookDelivery"("deliveryId");
CREATE INDEX IF NOT EXISTS "WebhookDelivery_repositoryId_commitSha_idx" ON "WebhookDelivery"("repositoryId", "commitSha");

-- 2. Razorpay ordering guard: event time of the last applied event per
--    subscription. Events older than (or equal to) this are ignored.
ALTER TABLE "Subscription" ADD COLUMN IF NOT EXISTS "lastWebhookEventAt" TIMESTAMP(3);

-- 3. Per-repository webhook secret (NULL for pre-existing repos, which
--    keep verifying against the shared WEBHOOK_SECRET until they get one).
ALTER TABLE "Repository" ADD COLUMN IF NOT EXISTS "webhookSecret" TEXT;

-- 4. Email-verification token expiry (set/read by routes/auth.js).
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "emailVerifyTokenExpiresAt" TIMESTAMP(3);
