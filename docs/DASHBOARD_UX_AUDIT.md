# Day 14 — Dashboard & UX audit (screenshot 04: "20 UX Patterns Every SaaS Needs")

Date: 2026-11-27 (Day 14 of 20). Remote HEAD at audit time: `9d9593f`
(Day 13). Audit base = that commit; no code changed since Day 13.

## Gate status first (unchanged)

**Security gate: STILL NOT PASSED — 29 PASS / 12 PARTIAL / 2 FAIL /
0 BLOCKED / 3 N/A.** Remote HEAD is the Day 13 commit, no owner decisions
recorded since Day 13, so no item crossed and no recount was needed.
Phase 4 implementation (Day 14 dashboard + UX build) did **not** start.
This document is a read-only audit of the Day 14 scope, in the same
posture as the Day 13 audit. Nothing below is built; the post-gate build
order is recorded at the end.

Live probes this run: frontend `https://secureguard-main.vercel.app` 200;
backend `/health` 200 `{"status":"ok","db":"up"}`; classifier `/health`
200, `model_loaded: true`, v2.2.1 / `v3_real` (after a Render cold start).

Run limitation (stated plainly): no local test, build, OSV or Gitleaks
run happened this turn — the same execution-risk check on the local
clone that limited Day 13 recurred, so no git/npm command ran inside
`~/workspace/SecureGaurd`. Test counts cited anywhere here are Day 12's
fresh evidence (25 Nov), labelled as such, not re-measured today.

## Method

Each of screenshot 04's 20 patterns was checked against the actual
dashboard code (`SecureGaurd-main/src/components/Dashboard.tsx`,
2,460 lines) and the shared components it uses, at remote HEAD
`9d9593f`. Verdicts: PRESENT (in the dashboard, working from real data),
PARTIAL (exists but incomplete or unverified live), MISSING (no
implementation found). No verdict is copied from the reel — the reel's
list is a pattern catalogue, not a status claim about SecureGaurd.

## Scoreboard — 9 PRESENT / 2 PARTIAL / 9 MISSING

| # | Pattern | Verdict | Evidence |
|---|---------|---------|----------|
| 1 | Optimistic UI updates | MISSING | No optimistic update in Dashboard.tsx. Only mention in the app is a code comment in `SbomPage.tsx:271` ("Optimistic: select the list item now…"). Mutations (save name, revoke key, change password) wait for the server, then toast. |
| 2 | Skeleton loaders | PRESENT | `Skeleton.tsx` (`PageSkeleton`); used in Dashboard (`:1205`, `:1838`, `:2247–2272` lazy `Suspense` fallbacks) and 7 other pages (AlertsSettings, CustomRulesPage, ProductInsights, ComplianceReports, ScanDetailPage, OrganizationSettingsModal, SbomPage). |
| 3 | Command palette | MISSING | No palette component, no `cmdk`, no Ctrl/Cmd+K handler anywhere in `src/`. |
| 4 | Persistent sidebar navigation | PRESENT | `dash-sidebar` in Dashboard.tsx `:985–1087`, persistent across all dashboard tabs; collapses to a mobile drawer ≤768px (`dash-sidebar--open`, `:163` SEC-39 note). |
| 5 | Loading and empty states | PRESENT | `EmptyState.tsx` used in Dashboard `:1680` (scan history), CustomRulesPage, ProductInsights, ComplianceReports; loading text + `apiKeysLoading` states in settings; `PageSkeleton` while tabs load. |
| 6 | Autosave functions | MISSING | All edits are explicit-save (Save name, Create key, Change password buttons with `disabled` until valid). No autosave anywhere in `src/`. |
| 7 | Debouncing | MISSING | Finding/repo search (`searchQuery`, `:393`, `:1163`) filters on every keystroke via `filterVulns`/`filterRepos` (`:883`, `:945`). No debounce utility in `src/`. |
| 8 | Throttling | MISSING | No throttle utility or throttled handler in `src/`. |
| 9 | Smart form validation | PRESENT | ContactForm: length/range checks with specific messages (`Name must be 2–100 characters`, email, subject ≤140, message 10–2000) + Turnstile gate; AuthPage error state; dashboard name-save disabled until changed-and-valid. |
| 10 | Bulk actions on list | MISSING | Findings list has per-row selection only (`selectedVuln`, `:360`); no multi-select, no select-all, no bulk dismiss/assign. The only checkbox in Dashboard.tsx (`:1998`) is API-key scope selection in Settings, not a list bulk action. |
| 11 | Reusable data table | PARTIAL | No shared table component exists. Three hand-rolled tables: `vuln-table` (`:1338`), `scan-history-table` (`:1689`, `:1788`). Sorting/pagination/filtering are re-implemented per table instead of shared. |
| 12 | Advanced data filtering | PRESENT | Severity + type + lifecycle-status filters, full-text search, sort, and an AI-priority toggle (`filterOptions.ts`, `utils/vulnFilters.ts`; Dashboard `:384–393`, `:882–895`, `:1324–1327`). |
| 13 | Keyboard shortcuts | MISSING | No `keydown` handler in app code (only a comment in `PageMeta.tsx:182`). No shortcut help, no `/` to focus search, no `j/k` navigation. |
| 14 | Tier-based UI indicator | MISSING | No plan/tier badge anywhere in the dashboard chrome. "Billing & Usage" (`:1066–1069`) opens the org-settings billing tab, but the dashboard never surfaces the current tier or usage against its limit. |
| 15 | Onboarding data capture | PRESENT | `OnboardingWizard` at `/onboarding` (`App.tsx:146`); replayable from dashboard settings (`navigate('/onboarding?replay=1')`, `:1961`). |
| 16 | Referral and affiliate pages | MISSING | No referral/affiliate code, route, or UI anywhere in `src/`. |
| 17 | Custom 404 page | PRESENT | `NotFound.tsx` + route in App.tsx; also referenced by screenshot 01/06 items already verified. |
| 18 | Mobile-optimized SaaS layouts | PRESENT (code-verified) | `@media` breakpoints at 1100px and 768px in `Dashboard.css:766,797`; sidebar becomes a drawer; scan-confirm modal is in-page (no `window.confirm`, which mobile browsers auto-dismiss — Dashboard `:668`). Live mobile rendering was not re-probed this run. |
| 19 | Destructive action protection | PRESENT | `ConfirmModal.tsx` in-page confirm for Disconnect, Revoke key, Delete account (Dashboard `:2440`, ComplianceReports `:801`, OrganizationSettingsModal `:844`). |
| 20 | Graceful error recovery | PARTIAL | ErrorBoundary wraps the app (`App.tsx:136`) but only logs locally — no error-tracking service is wired (Day 12). Scan timeout shows a specific recovery message with the next step (`:761`: "check scan history before retrying"); toasts report failures with retry wording. No automatic retry anywhere. |

## Dashboard scope check (plan Day 14: overview, findings, risk, history, orgs)

What the dashboard already does, from real data (not re-measured live
this run; behaviour as implemented at `9d9593f`):

- **Security overview:** Health Score / Security Health stats
  (`:1242`, `:1890`) computed from stored findings; Overview tab with
  repo list, scan trigger, and vulnerability remediation health card.
- **Findings:** vulnerability table, 25/page pagination (`:390–392`),
  severity/type/status/search filters, per-finding detail panel with
  file path, severity badge, and ML explanation (`:1390–1453`).
- **Risk prioritization:** severity ordering by default; AI-priority
  ranker behind a feature flag (`rankMode`, `:356`, `:886–943`),
  with a visible fallback notice when the classifier is unreachable
  (`:1297`). The ranker is off by default (Day 6 flag).
- **Scan history:** "Scan Log History" tab (`:861`, `:1123`) with a
  history table and an empty state prompting the first scan (`:1683`).
- **Organization workflows:** org switcher, org settings modal
  (members / invitations / audit / billing / settings tabs, `:167`),
  API-key management with one-time secret display (`:1970–2020`).

Gaps inside the dashboard scope itself (beyond the 20 patterns):
no per-finding bulk workflow (see #10); no shared table means the
three tables drift independently (see #11); the AI ranker is
feature-flagged off, so the default prioritization is severity-only;
the Health Score formula is not explained in the UI (no "why this
score" affordance).

## Post-gate build order (smallest first, none started)

1. **Debounce search** (#7) — one utility + two call sites; kills
   per-keystroke refilters on large finding lists.
2. **Bulk actions on findings** (#10) — multi-select + bulk
   dismiss/assign, reusing the existing lifecycle-status API.
3. **Reusable data table** (#11) — extract the vuln + scan-history
   tables into one component (sort, filter, pagination, empty state),
   then migrate the three call sites.
4. **Keyboard shortcuts** (#13) — `/` focuses search, `Esc` closes
   panels, then `j/k` navigation; document in a shortcuts popover.
5. **Command palette** (#3) — after #13; jump to repo/scan/finding,
   run common actions (new scan, invite, billing).
6. **Optimistic UI** (#1) — status changes on findings first
   (revert on failure with toast), then name/settings saves.
7. **Autosave** (#6) — settings forms only, with an explicit
   "saved HH:MM" indicator; never for destructive actions.
8. **Tier indicator** (#14) — current plan + usage vs limit in the
   sidebar footer, fed by the existing billing endpoint.
9. **Throttling** (#8) — only where a handler fires at high frequency
   (resize/scroll listeners); not needed until a concrete case appears.
10. **Referral/affiliate** (#16) — last; a product decision, not a UX
    fix. Needs his call on whether referral exists at all.

## What this audit does NOT claim

- No pattern above was verified by clicking through the live
  dashboard — there are no probe credentials, and the audit is
  code-based at `9d9593f`. Live interaction (including mobile
  rendering) is an open verification step for the post-gate build.
- The 9 PRESENT verdicts mean the pattern exists in code, not that
  its UX is good: e.g. filtering is present but un-debounced, and
  the mobile layout is present in CSS but not re-probed live.
- The gate still blocks all of it. The build order above is a plan,
  not work done.
