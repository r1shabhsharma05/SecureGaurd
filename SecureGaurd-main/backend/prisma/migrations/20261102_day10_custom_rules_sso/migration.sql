-- Day 10: org custom detection rules + SSO/OIDC provider identities.
-- Additive only. CustomRule rows cascade with their organization; OAuth
-- identity columns are nullable + unique (multiple NULLs allowed).
CREATE TABLE IF NOT EXISTS "CustomRule" (
  "id"             SERIAL PRIMARY KEY,
  "organizationId" INTEGER NOT NULL,
  "ruleId"         TEXT NOT NULL,
  "title"          TEXT NOT NULL,
  "severity"       TEXT NOT NULL,
  "type"           TEXT NOT NULL DEFAULT 'sast',
  "pattern"        TEXT NOT NULL,
  "ignoreCase"     BOOLEAN NOT NULL DEFAULT false,
  "filePattern"    TEXT NOT NULL DEFAULT '.*',
  "excludePattern" TEXT,
  "description"    TEXT NOT NULL DEFAULT '',
  "remediation"    TEXT NOT NULL DEFAULT '',
  "cweId"          TEXT,
  "enabled"        BOOLEAN NOT NULL DEFAULT true,
  "createdById"    INTEGER,
  "createdAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "CustomRule_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS "CustomRule_organizationId_ruleId_key" ON "CustomRule"("organizationId", "ruleId");
CREATE INDEX IF NOT EXISTS "CustomRule_organizationId_idx" ON "CustomRule"("organizationId");
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "oauthGoogleId" TEXT;
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "oauthGithubId" TEXT;
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "oauthGitlabId" TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS "User_oauthGoogleId_key" ON "User"("oauthGoogleId");
CREATE UNIQUE INDEX IF NOT EXISTS "User_oauthGithubId_key" ON "User"("oauthGithubId");
CREATE UNIQUE INDEX IF NOT EXISTS "User_oauthGitlabId_key" ON "User"("oauthGitlabId");
