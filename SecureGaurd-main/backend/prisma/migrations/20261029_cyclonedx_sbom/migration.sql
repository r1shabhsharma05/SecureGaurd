-- CycloneDX SBOM (Day 6): additive only. Existing SPDX rows keep working;
-- cycloneDxDoc is null for them until a rescan stores a CycloneDX doc.
ALTER TABLE "Sbom" ADD COLUMN IF NOT EXISTS "cycloneDxDoc" JSONB;
