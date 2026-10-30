-- Day 7: scan-completion alert settings + delivery log. Additive only.
CREATE TABLE IF NOT EXISTS "AlertSetting" (
  "id"                   SERIAL PRIMARY KEY,
  "organizationId"       INTEGER NOT NULL UNIQUE,
  "slackWebhookUrl"      TEXT,
  "slackEnabled"         BOOLEAN NOT NULL DEFAULT false,
  "emailEnabled"         BOOLEAN NOT NULL DEFAULT false,
  "notifyOnScanComplete" BOOLEAN NOT NULL DEFAULT true,
  "notifyOnNewCritical"  BOOLEAN NOT NULL DEFAULT true,
  "createdAt"            TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"            TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AlertSetting_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX IF NOT EXISTS "AlertSetting_organizationId_idx" ON "AlertSetting"("organizationId");
CREATE TABLE IF NOT EXISTS "AlertLog" (
  "id"             SERIAL PRIMARY KEY,
  "organizationId" INTEGER NOT NULL,
  "channel"        TEXT NOT NULL,
  "event"          TEXT NOT NULL,
  "targetMasked"   TEXT,
  "status"         TEXT NOT NULL,
  "providerId"     TEXT,
  "error"          TEXT,
  "createdAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AlertLog_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX IF NOT EXISTS "AlertLog_organizationId_createdAt_idx" ON "AlertLog"("organizationId", "createdAt");
