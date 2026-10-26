-- Razorpay billing (Day 3 switch from Stripe): additive only. The Stripe
-- columns and StripeWebhookEvent table are kept untouched — existing linkage
-- records are preserved, the new code simply stops using them.
ALTER TABLE "Subscription" ADD COLUMN IF NOT EXISTS "razorpayCustomerId" TEXT;
ALTER TABLE "Subscription" ADD COLUMN IF NOT EXISTS "razorpaySubscriptionId" TEXT;
ALTER TABLE "Subscription" ADD COLUMN IF NOT EXISTS "razorpayPlanId" TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS "Subscription_razorpaySubscriptionId_key" ON "Subscription"("razorpaySubscriptionId");
CREATE INDEX IF NOT EXISTS "Subscription_razorpayCustomerId_idx" ON "Subscription"("razorpayCustomerId");
CREATE TABLE IF NOT EXISTS "RazorpayWebhookEvent" (
    "id" SERIAL NOT NULL,
    "razorpayEventId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "processedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "RazorpayWebhookEvent_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX IF NOT EXISTS "RazorpayWebhookEvent_razorpayEventId_key" ON "RazorpayWebhookEvent"("razorpayEventId");
