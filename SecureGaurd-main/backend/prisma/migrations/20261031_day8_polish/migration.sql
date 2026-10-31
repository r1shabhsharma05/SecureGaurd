-- Day 8: product-analytics events (own DB) + contact-form messages.
-- Additive only. AnalyticsEvent stores no IP and no client-supplied user
-- identity. ContactMessage rows are written only after Brevo accepts the
-- email, so a row always means a real message was delivered.
CREATE TABLE IF NOT EXISTS "AnalyticsEvent" (
  "id"        SERIAL PRIMARY KEY,
  "event"     TEXT NOT NULL,
  "path"      TEXT NOT NULL,
  "sessionId" TEXT,
  "props"     JSONB,
  "userAgent" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS "AnalyticsEvent_event_createdAt_idx" ON "AnalyticsEvent"("event", "createdAt");
CREATE INDEX IF NOT EXISTS "AnalyticsEvent_createdAt_idx" ON "AnalyticsEvent"("createdAt");
CREATE TABLE IF NOT EXISTS "ContactMessage" (
  "id"         SERIAL PRIMARY KEY,
  "name"       TEXT NOT NULL,
  "email"      TEXT NOT NULL,
  "subject"    TEXT,
  "message"    TEXT NOT NULL,
  "providerId" TEXT,
  "createdAt"  TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS "ContactMessage_createdAt_idx" ON "ContactMessage"("createdAt");
