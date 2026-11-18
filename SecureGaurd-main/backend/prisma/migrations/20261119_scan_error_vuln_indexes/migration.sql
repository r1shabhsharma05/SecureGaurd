-- 20261119_scan_error_vuln_indexes
-- E2E fix batch (19 Nov 2026):
--   1. Scan.errorMessage — clone/resolve failure reason, stored on the scan
--      row so a FAILED scan shows WHY in scan history instead of failing
--      silently (the reason previously lived only in the audit log).
--   2. Vulnerability indexes — the occurrence-history query (ruleId +
--      filePath) and per-scan lookups were sequential scans; the table has
--      zero indexes today.
ALTER TABLE "Scan" ADD COLUMN IF NOT EXISTS "errorMessage" TEXT;
CREATE INDEX IF NOT EXISTS "Vulnerability_scanId_idx" ON "Vulnerability"("scanId");
CREATE INDEX IF NOT EXISTS "Vulnerability_ruleId_filePath_idx" ON "Vulnerability"("ruleId", "filePath");
