# Changelog — SecureGuard 7-day improvement run

All notable changes from the October 2026 improvement week (10 small, verified
commits per day; every change kept `vite build` green and passed the daily
auth/security scan before pushing to `origin/main`).

## Day 7 — 2026-10-22 — Final polish
- Removed a hardcoded fake workspace API token (`sg_live_token_…`) shown in the
  Dashboard settings tab — the backend has no API-token mechanism, so the
  displayed "token" was a dead credential that also tripped secret scanners.
- Lazy-loaded the Compliance Reports and SBOM tab components (`React.lazy` +
  `Suspense`); they now ship as separate chunks instead of riding the initial
  Dashboard bundle (main chunk 670 kB → 573 kB).
- Fixed the last `react-hooks/exhaustive-deps` warning (missing `authLoading`
  dep in the VulnerabilityDetailsPage session guard) — `npm run lint` is clean.
- Removed dangling custom-cursor `url()` references to PNG assets that don't
  exist in `public/cursors/` (browsers were already falling back; this kills
  the 404s the build warned about).
- Accessibility: added `aria-label="Log out"` to the icon-only sidebar logout
  button (`title` alone isn't reliably announced).
- README: added a tech-stack badge row (only verifiable facts — no CI workflow
  or license exists in the repo yet, so no build/license badges were claimed).
- Verified: `render.yaml`/`vercel.json` still match the backend scripts and the
  `/health` endpoint; every docs link resolves; `.env.example` files cover all
  required/optional vars from `backend/config/env.js`.

## Day 6 — 2026-10-21 — New ML model + README visualization
- New severity-priority ranker served by the FastAPI service (`/v2/rank`,
  `/v2/rank/batch`; 0.6/0.4 blend of classifier signal and heuristic score),
  proxied by a versioned Node route (`/api/v2/ml/rank`).
- Dashboard "AI Priority" toggle (behind `VITE_ENABLE_SEVERITY_RANK`) to sort
  by ranker score.
- 12 stdlib-only unit tests pinning the severity-schema label formula and
  bands; honest `v0_heuristic` label-source caveat recorded in
  `severity_metadata.json`, LIMITATIONS.md, and `custom_model_guide.md`.
- README gained mermaid system-architecture and scan data-flow diagrams.

## Day 5 — 2026-10-20 — Upscale ML model
- Documented the FP classifier (`docs/fp-classifier.md`): architecture,
  18-feature table, training/calibration/versioning, serving contract.
- Pydantic range validation on classifier inputs; `/classify/batch` capped at
  200; `/health` reports service and model versions.
- Single source of truth for the feature schema (`feature_schema.py`); new
  `evaluate.py` (accuracy, precision/recall/F1, confusion matrix); 9 stdlib
  unit tests pinning the training/serving contract.
- Fixed `ml_confidence` (was reading a property off the Express response) and
  made `file_change_frequency` real (from `git log`, memoized) instead of a
  hardcoded 0; `scale_pos_weight` now derived from the actual label skew.

## Day 4 — 2026-10-19 — Bug hunt & fixes
- `react-hooks/exhaustive-deps` warnings 10 → 0 via `useCallback` memoization
  and completed dep arrays (no refetch loops).
- Removed a redundant Dashboard effect that fired the full fetch sequence
  twice on every mount.
- Fixed the broken invite flow: `?redirect=` is now honored after login
  (same-origin guarded, target URL-encoded).
- `dotenv.config()` + `validateEnv()` now run before route requires in
  `server.js` (cryptoUtils reads `JWT_SECRET` at require time).

## Day 3 — 2026-10-18 — Error handling + env/security
- New `ApiError` class (status-carrying) + `statusMessage()`/`toErrorMessage()`
  helpers; `apiClient` throws typed errors; all 14 `catch (err: any)` sites
  now `catch (err: unknown)`.
- `ErrorBoundary` wired around all routes in `App.tsx`.
- Dashboard webhook example URLs derive from configured `apiUrl()` (no more
  hardcoded `localhost:5000`); `VITE_API_URL` documented in `.env.example`.
- Removed the bogus `'sk-gemini'` placeholder bearer fallback and the
  hardcoded encryption-key default; new `backend/config/env.js` fails fast on
  missing `JWT_SECRET`/`DATABASE_URL`; `backend/.env.example` documents every
  variable.

## Day 2 — 2026-10-17 — Duplicates, dead code & naming
- Removed 18 unused lucide-react icon imports, 2 unused eslint-disable
  directives, and 3 unreferenced assets; renamed Navbar `onScroll` →
  `handleScroll` and ambiguous `res`/`data` vars in backend routes.
- Verified `backend/generated/prisma/` is required by `prismaClient.js`
  (not removed).

## Day 1 — 2026-10-17 — Clean structure, logic separated from UI
- New `src/services/` layer (`apiClient`, `authService`, `invitationService`)
  and `src/utils/` (`vulnFilters`, `vulnStats`); `AuthPage`,
  `AcceptInvitePage`, and `Dashboard` refactored to consume them.

## Next
- **Day 8 (2026-10-23):** real-data retrain of the FP classifier
  (`v1_synthetic` → trained on real labeled findings; held-out test metrics
  vs the synthetic baseline; deploy only if it wins). Spec: Day 8 section of
  `IMPROVEMENT_PLAN.md`.
