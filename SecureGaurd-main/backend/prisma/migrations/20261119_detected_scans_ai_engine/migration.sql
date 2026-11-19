-- 20261119_detected_scans_ai_engine
-- Re-test fix batch (19 Nov 2026):
--  * detectedInScanIds: every scan that detected this finding, including
--    re-detections deduped against the already-open row. The scan-detail
--    page lists findings by scanId OR detectedInScanIds, so a re-scan
--    that inserted nothing no longer shows an empty findings list.
--  * aiFixEngine: the engine that actually generated the cached aiFix
--    ('rule-based' | 'gemini-1.5-flash' | ...), so the UI label stops
--    claiming Gemini for fixes the rule engine produced.
ALTER TABLE "Vulnerability" ADD COLUMN IF NOT EXISTS "detectedInScanIds" INTEGER[] NOT NULL DEFAULT '{}';
ALTER TABLE "Vulnerability" ADD COLUMN IF NOT EXISTS "aiFixEngine" TEXT;
