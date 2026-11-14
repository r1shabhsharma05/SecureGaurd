# SecureGaurd — Master Project Audit (Day 1, 20-Day Transformation)

**Audit date:** 2026-11-14 (Day 1 of the 20-day program)
**Audited commit:** `bf49b47` — "fix text cursor showing arrow instead of i-beam" (2026-11-13 12:12 IST)
**Repo:** `r1shabhsharma05/SecureGaurd` — canonical app root `SecureGaurd-main/` (the git repo root holds only an entry README, `.github/`, `docs/` and `graphify-out/`)
**Auditors:** Day 1 repository-intelligence run — three parallel source inspections (frontend, backend, deployment/tests/docs) plus live probes and a build-at-HEAD check.
**Method:** read-only source inspection of every substantive file; counts taken from live files; claims checked against code, not README copy. Live probes are read-only safe endpoints only. No destructive workflow was run against production. No secrets were read or printed anywhere in this audit (env var names only).

## Verdict in one paragraph

SecureGaurd is a real, substantial product — not a demo shell. A React 19 SPA talks to an Express 5 API on Prisma/PostgreSQL, with a Python XGBoost false-positive classifier and severity ranker, real Razorpay billing, real GitHub/GitLab webhooks, OIDC SSO and SBOM/compliance generation. The auth core is unusually careful for a solo project (rotating refresh tokens with reuse detection, hashed reset tokens, org-scoped queries throughout). The single biggest architectural fact is that **scans run synchronously inside the HTTP request** — clone (up to 180 s) + scan + classifier, no queue, no worker — which is both the main performance bottleneck and the main availability risk. The second fact is that **the platform's headline claims outrun its wiring**: Stripe billing, SAML/SCIM, Jira, Jenkins/CircleCI/GitLab CI plugins and private-repo scanning are presented as live on the landing page or in docs, but Stripe is dead code, SAML is an explicit 501, and private repos cannot be cloned. There is **no test/build/deploy CI at all** (only a gitleaks secret scan), no frontend tests, and `npm audit` could not run from this VM, so the dependency-vulnerability posture is unknown, not clean. Prior audits (2026-09-03, 2026-09-07, 2026-11-08) are stale or superseded; this document replaces them as the Day 1 baseline.

## 1. Repository map

| Area | Count / fact | Evidence |
|---|---|---|
| Total tracked files in `SecureGaurd-main/` (excl. node_modules) | 506 | `find` count at HEAD |
| Source files (`.ts/.tsx/.js/.py`, excl. node_modules) | 223 | `find` count at HEAD |
| Git history | 227 commits, all by one author (Rishabh Sharma); first 2026-04-16, 213 commits in the last 30 days | `git log` |
| Frontend `src/` | 79 files, 36 `.tsx`, ~11,727 lines; 13 routes; 0 test files | `src/` listing |
| Backend | 17 route files, 88 router routes + `GET /health`; 19 Prisma models; 7 migrations | `backend/routes/`, `backend/prisma/schema.prisma` (422 lines) |
| ML | 2 classifier copies + severity ranker; 6 Python test files | `backend/services/fp-classifier/`, `classifier model/files/` |
| Backend tests | 5 real `.test.js` + 2 fixture files; 24 verify/helper scripts | `backend/tests/` |
| Docs in `docs/` | 8 files + `SecureGuard_PRD_v2.docx` + `superpowers/plans/` | `docs/` listing |
| `dist/` | build output, not tracked | `git ls-files` |

### Directory layout (`SecureGaurd-main/`)

- `src/` — React/Vite frontend (components, context, services, config, utils)
- `backend/` — Express API: `server.js`, `api/index.js` (Vercel entry, re-exports server), `routes/` (17 files), `middleware/`, `config/`, `services/`, `utils/`, `prisma/`, `tests/`, `scripts/`
- `backend/services/fp-classifier/` — live Python FastAPI classifier (XGBoost) + retrain scheduler
- `backend/services/severity-ranker/` — heuristic-trained ranker served by the same FastAPI process
- `classifier model/files/` — stale original classifier copy (Oct 16; model 489 KB vs 296 KB retrained Oct 23)
- `public/` — static assets incl. `cursors/`
- `docs/` — readiness/operational docs (see §10)
- Root: `Dockerfile`, `docker-compose.yml`, `nginx.conf`, `render.yaml`, `vercel.json`, `package.json`, `CHANGELOG.md`, `LIMITATIONS.md`, `README.md`, `SECURITY_AUDIT.md`, `custom_model_guide.md`, `project_status.md`, `walkthrough.md`
- `backend/generated/prisma/` — generated Prisma client **committed** (incl. ~4.9 MB `query_compiler_fast_bg.wasm-base64.js` + ~3.7 MB `.wasm`)
- `graphify-out/` — code-graph cache (not audited in depth)

## 2. Architecture

**Frontend:** React 19.2.4 + TypeScript + react-router-dom 7.18.3 + Vite 8.0.4 + Tailwind 4.2.2, framer-motion 12, GSAP 3.15, lucide-react. State is React Context only (`AuthContext`, `OrganizationContext`) — no Redux/Zustand/React Query/axios. All data fetching is raw `fetch` via three wrappers: `authFetch` (Bearer + cookie, retries once after `/refresh` on 401), `orgFetch` (adds `x-organization-id`), `apiRequest` (unauthenticated callers only). Sentry is env-gated (`main.tsx:10-16`).

**Backend:** Express 5.3.0 (CommonJS), entry `backend/server.js` (132 lines). Middleware: `trust proxy` (`TRUST_PROXY_HOPS`, default 1), helmet (CORP relaxed to `cross-origin`), CORS allow-list (`backend/config/cors.js` — localhost + `FRONTEND_URL`/`FRONTEND_URLS` + Vercel-preview regex, `credentials: true`, deny-without-error), billing webhook mounted before `express.json` (raw-body HMAC), `express.json`/`urlencoded` 1 MB with `req.rawBody`, `cookie-parser`, Sentry error handler last, generic 500 with no stack leak. `GET /health` public. Startup `validateEnv()` fail-fasts on missing `JWT_SECRET`, `JWT_REFRESH_SECRET`, `ENCRYPTION_KEY` (64-hex), `DATABASE_URL`.

**Data flow (verified in code):** SPA (Vercel) → REST `/api` (Render; in prod same-origin relative paths via `vercel.json` rewrite to `https://securegaurd.onrender.com/api/:path*`, so the session cookie stays first-party) → Express → Prisma → PostgreSQL (Supabase project `wkvvxqlflhjiqkhwxrsl`, ap-southeast-1). Scan path: `POST /api/scans/trigger` → entitlement check → clone (anonymous HTTPS, `--depth 1`) → `runSecurityScan` (regex SAST/secrets + Babel AST features) → classifier batch (`POST /classify/batch`, chunks of 50, 5 s timeout) → persist Scan + Vulnerability rows (+ `mlFeatures` JSON) + SBOM + alerts — all synchronously in the request. AI fix: rule templates first, then Gemini 1.5-flash (official API or Web2API proxy). Billing: Razorpay REST + HMAC webhook. Mail: Brevo or SMTP.

**ML service:** Python 3.12 FastAPI on port 8001, XGBoost + scikit-learn, endpoints `GET /health`, `GET /model-info`, `POST /classify`, `POST /classify/batch`, `POST /v2/rank`, `POST /v2/rank/batch`, `GET /metrics`. Auth `X-SecureGuard-Key` vs `CLASSIFIER_API_KEY`, fail-closed unless `CLASSIFIER_ALLOW_UNAUTHENTICATED=1`. Model files are tracked in git (see §7).

## 3. Existing functionality — actual vs claimed

Status key: **WORKING** = code exists and is wired end-to-end with evidence; **PARTIAL** = implemented but with a known gap; **BROKEN** = code present but demonstrably not working as claimed; **MISSING** = claimed or expected but absent.

### 3.1 Workflows verified wired (frontend → backend → DB)

| Workflow | Status | Evidence |
|---|---|---|
| Register / login / logout / session restore | WORKING | `AuthContext.tsx`, `routes/auth.js`; bcrypt(12); rotating refresh + 60 s grace + reuse detection (`auth.js:259-317`) |
| Password reset (hashed single-use token, 1 h; clears all sessions) | WORKING | `routes/auth.js:345-411`; frontend `services/authService.ts:28-48` |
| Email verification (token, 24 h, single-use) | PARTIAL | Backend endpoints exist (`GET\|POST /api/auth/verify-email`); **no UI anywhere references verification** — users can never verify/resend from the frontend; and login has **no `isEmailVerified` check** (`auth.js:190-228`), so verification is cosmetic |
| Organizations CRUD, members, roles, invites, audit logs, leave, transfer-ownership | WORKING | `routes/organizations.js` (14 routes); frontend `OrganizationContext.tsx`, `OrganizationSettingsModal.tsx` |
| Repos: add manual / GitHub / GitLab import, delete | WORKING | `Dashboard.tsx:346-438`; `routes/repos.js` |
| Scan trigger (manual) | PARTIAL | Wired (`POST /api/scans/trigger`), but **synchronous in-request** (see §6) and the frontend shows a **fake progress bar**: `Dashboard.tsx:459-492` runs a 2.4 s interval cycling random filenames from a hardcoded `SCAN_FILES` list and animates 0→100% *before* the real trigger fires |
| SAST / secret / IaC scanning | WORKING | `utils/securityScanner.js` (3 secret, 5 SAST, 2 IaC regex rules), `utils/iac*Scanner.js`, `utils/apiSpecScanner.js`; AST features via `@babel/parser` + `@babel/traverse` (`utils/astExtractor.js`, 18 features) |
| Findings list / detail / status change / explanation | WORKING | `Dashboard.tsx:497-508`, `VulnerabilityDetailsPage.tsx`; `routes/vulnerabilities.js` |
| FP classifier (REAL vs FALSE_POSITIVE) | WORKING (fail-open) | `scans.js:280-340`; classifier down/timeout → findings stay REAL; SEC-* rules skip ML entirely by design (`LIMITATIONS.md` §0) |
| Severity ranker / AI Priority toggle | PARTIAL | Wired behind `VITE_ENABLE_SEVERITY_RANK` (default off); on failure degrades to static CWE-tier ordering flagged `degraded: true`; ranker trained on heuristic labels, not analyst labels (`LIMITATIONS.md` §10) |
| AI fix generate / apply / mark false-positive | PARTIAL | Generate + cache works (`routes/ai.js`, `utils/aiFixEngine.js`); **apply only flips `aiFixApplied=true` + status `fixed` — it never writes to the repository**. No branch/PR creation from a fix. Guard rejects fixes identical to the vulnerable snippet |
| SBOM (SPDX 2.3 + CycloneDX 1.6) + NVD enrichment | WORKING | `utils/sbomExtractor.js` (801 lines, npm/Python/Java/Go/Rust/PHP/Ruby), `scans.js:391-455`; NVD live, 6 s throttle, in-memory cache |
| Compliance reports (SOC2/HIPAA/PCI-DSS/GDPR) | WORKING | `services/complianceEngine.js` (deterministic score = 100 − weighted deductions, explicit not-a-certification disclaimer); PDF via `pdfkit` |
| Custom rules (library, CRUD, test, test-scan) | WORKING | `routes/customRules.js` (8 routes); `CustomRulesPage.tsx` |
| Alerts (Slack webhook + email) | WORKING | `routes/alerts.js`; `utils/scanAlerts.js` (Slack URL validated, encrypted at rest, masked in logs) |
| GitHub/GitLab webhooks + PR bot | WORKING | HMAC-SHA256 / GitLab token, per-repo secret first then shared fallback, timing-safe compare, fail-closed; idempotency via `WebhookDelivery`; PR bot posts real check-runs + PR comments (`routes/integration.js:430-540`, `utils/prBot.js`) |
| Razorpay billing + webhooks | WORKING | `utils/razorpay.js` (fail-closed on placeholder creds, HMAC verify, ordering guard, idempotency); plan activates only via `subscription.activated` webhook |
| SSO / OIDC (Google, GitHub, GitLab) | PARTIAL | Real auth-code + PKCE, HMAC-signed state (`utils/oauth.js:89-115`); **docs/OAUTH_SSO.md states no provider is live** — code shipped, providers not configured in production (verify on Day 12) |
| Onboarding wizard (connect repo, first scan, invite) | WORKING | `OnboardingWizard.tsx` polls `GET /api/scans/:id` |
| Contact form | WORKING | `POST /api/contact` (Brevo); Turnstile-gated when configured |
| Account deletion | WORKING | `DELETE /api/auth/account` (password + typed `DELETE`); cascade handled (`accountDeletion.js`) |
| Analytics / Product Insights | WORKING | `GET /api/analytics/summary`, `POST /api/analytics/events` |
| Legal pages, cookie consent, custom 404, loading/empty/error states, toasts | WORKING | `LegalPages.tsx`, `CookieConsent.tsx`, `NotFound.tsx`, `Skeleton.tsx`, `EmptyState.tsx`, `Toast.tsx`, `ErrorBoundary` |

### 3.2 Incomplete functionality

- **Private-repo scanning:** clone is anonymous HTTPS only — SSH remotes rewritten to HTTPS, credentials in URL rejected, host allowlist `github.com`/`gitlab.com` (+ `EXTRA_GIT_HOSTS`), PAT never passed to git (`utils/repoScanSource.js:17-157`). Private repos cannot be cloned/scanned. Public repos only, in practice.
- **Email verification:** backend done, frontend absent (see §3.1).
- **Password change:** no UI and no endpoint call anywhere, despite Dashboard Settings subtitle "Manage passwords and workspace configurations" (`Dashboard.tsx:824`).
- **Background jobs / queue:** none. Scans, webhooks and SBOM all run in-request (see §6).
- **File upload:** none (no multer); API-spec scan is URL/paste only.
- **Dashboard deep-linking:** all 10 app tabs are `activeNav` state inside the single `/dashboard` route (`Dashboard.tsx:149`); no routes for `/settings`, `/billing`, `/repos`, `/scans`, `/compliance`, `/sbom`. Refresh always lands on Overview; browser back/forward do nothing inside the dashboard.
- **Onboarding guard:** `/onboarding` redirects only if `onboardingCompleted` is true; it has **no logged-out guard** — an anonymous user can open it.
- **No route-level auth guard:** each protected page re-implements its guard (`Dashboard.tsx:232-238`, `VulnerabilityDetailsPage.tsx:132-138`); `/signup` and `/login` do not redirect an already-logged-in user away.

### 3.3 Broken functionality (code present, not working as claimed)

1. **Fake scan progress** — `Dashboard.tsx:453-492`: cosmetic 0–100% with random filenames before the real trigger. This is mock UX presented as a live scan; the plan's rule 11 (never replace real integrations with mocked responses) and rule 6 (never mark complete without evidence) both bite here.
2. **`orgFetch` stale-token 401 retry** — `OrganizationContext.tsx:130-145`: after `refreshSession()` succeeds it re-fires with the old captured `accessToken`, not the fresh one. `authFetch` does this correctly via its `newToken` callback; `orgFetch` never uses that pattern. Org-scoped calls after token expiry retry with the expired token.
3. **`completeOnboarding` 401 retry is a no-op** — `AuthContext.tsx:100-113`: calls `authFetch` without the `newToken` callback, then silently marks onboarding complete locally (`:107`, `:111`) even when the server call failed.
4. **`apiRequest` drops the session cookie** — `src/services/apiClient.ts` never sets `credentials:'include'`; harmless today (only unauthenticated callers) but any future authenticated use silently drops the cookie.
5. **Webhook scan path calls the classifier without its API key** — `routes/integration.js:206-213` sends only `Content-Type`, no `X-SecureGuard-Key`, unlike `routes/scans.js:280-294`. With the classifier fail-closed (default), every webhook-triggered scan's classifier call 401s, so FP suppression silently never runs on that path (fails safe to REAL, but inconsistent and invisible).
6. **`index.html:59` references `/src/main.jsx`; the real file is `src/main.tsx`.** Build-at-HEAD check (this audit) passes — Vite resolves the extension — so this is latent fragility, not a broken build. Fix to `/src/main.tsx` on a later day.

### 3.4 Missing functionality (claimed or expected, absent)

| Item | Evidence |
|---|---|
| Stripe billing | No SDK installed, no Stripe code paths; only legacy `stripeCustomerId`/`stripeSubscriptionId` columns. Orgs with a live Stripe sub can **never be deleted** via the API (502, `routes/organizations.js:33-38`) — manual Stripe-dashboard action required |
| SAML / SCIM | Explicit 501-by-design (`routes/auth.js:469`); yet Pricing page sells "SSO / SAML & SCIM" on Enterprise |
| MFA (TOTP / WebAuthn) | Nowhere in `auth.js` or the frontend |
| Jira integration | Appears only in Pricing (`Pricing.tsx`) and one HowItWorks sentence; no code, no endpoint |
| Jenkins / CircleCI / GitLab CI plugins | Features page claims "Native plugins for GitHub Actions, GitLab CI, Jenkins, CircleCI"; only a GitHub Actions YAML template is actually shown (Dashboard Settings CI/CD section) |
| "50M+ CVEs" / "Zero-Day Intelligence" | Features-page copy with no evidence in UI or code |
| "in milliseconds" scan claim | Hero copy; unmeasured; scans are synchronous and can take minutes on large repos |
| Email-verification UI, password-change UI | See §3.2 |
| Frontend tests | 0 test files in `src/`; no jest/vitest/playwright config |
| CI for tests/build/deploy | See §8 |

## 4. Security vulnerabilities and weaknesses

Prior context: a 2026-11-08 audit run pushed 25 fixes (SSRF DNS-rebinding pinning, symlink containment, secret redaction, fail-closed classifier auth, per-repo webhook secrets, hashed reset/verify tokens, webhook quota + idempotency, Razorpay ordering). The findings below are what remains **at HEAD `bf49b47`**, verified in current source. Severity is assigned only to confirmed, source-grounded findings (per the security-audit skill); items needing live verification are marked UNVERIFIED, not given a severity.

### 4.1 Confirmed (source evidence)

| # | Finding | Severity | Evidence |
|---|---|---|---|
| S1 | **Email verification is cosmetic.** Register returns an access token immediately; login has no `isEmailVerified` check. An attacker registering with someone else's email gets a working session. | High | `routes/auth.js:98-152`, `:190-228` |
| S2 | **Turnstile fails open when unconfigured.** With `TURNSTILE_SECRET_KEY` unset, register / forgot-password / contact run with no captcha. If the key was never set in production, there is no bot protection on signup or password reset at all. Documented as a deliberate tradeoff in `utils/turnstile.js`. | Medium | `utils/turnstile.js`; `backend/.env.example` ("inert until set") |
| S3 | **`requireOrgContext` silently falls back to the caller's first org on a bad org id.** A non-numeric `x-organization-id`/query/body value is ignored (`!isNaN(parseInt(...))` gate; `parseInt("12abc")` coerces to 12) and the request is served against the oldest membership instead of 400ing. Wrong-org data can be returned for a malformed header. | Medium | `middleware/rbac.js:36-57` |
| S4 | **No rate limit on `POST /api/auth/refresh` and `GET /api/auth/me`.** Refresh-token guessing is bcrypt-bound per attempt, but unlimited attempts are allowed; `/me` mints a fresh access token per call with no rotation. | Low | `routes/auth.js:259,426` |
| S5 | **Razorpay webhook idempotency check is outside the transaction.** Two concurrent duplicate deliveries can both pass the check; the loser hits P2002 inside the tx → 500 instead of an idempotent 200 (retried, not double-applied — ordering guard still holds). | Low | `routes/billingWebhook.js:141-155` |
| S6 | **Synchronous scans are a DoS surface.** Full clone (180 s) + sync scan + classifier in-request on both `POST /api/scans/trigger` and the webhook endpoint; no queue, no per-scan HTTP-side timeout. The 10/10-min trigger limiter is per-IP (trust-proxy dependent); an authenticated user can pin the single Node process with a few large-repo scans. | Medium | `routes/scans.js:167-505`, `routes/integration.js:66-313` |
| S7 | **Webhook classifier call missing API key** (see §3.3.5) — FP suppression silently never runs on webhook-triggered scans. Safe direction (fail-open to REAL), but a silent inconsistency. | Low | `routes/integration.js:206-213` |
| S8 | **A dev MongoDB credential string is printed in a repo doc.** `SECURITY_AUDIT.md` §8 lists a `glanexus_admin` dev connection string with password in plain text. It is a dev credential, not production, but it does not belong in a tracked doc. | Low | `SECURITY_AUDIT.md` §8 |
| S9 | **Legacy Stripe subscriptions are un-cancellable and block org deletion** (see §3.4). Billing-orphan trap; the Subscription row cascade-deletes with the org while the Stripe sub lives on. | Medium | `routes/organizations.js:21-38` |

### 4.2 Verified good (do not re-litigate without new evidence)

- Tenant isolation: every `:id` lookup checked scopes by org (`scans.js:137-144`, `vulnerabilities.js:42-56`, `repos.js:154-164`, `compliance.js`, `sboms.js`, `customRules.js`, `ai.js`, `ml.js`). No unscoped `:id` fetch found in routes.
- Passwords bcrypt(12); refresh tokens bcrypt-hashed, rotating, reuse detection with atomic compare-and-swap.
- Reset/verify tokens `crypto.randomBytes(32)`, SHA-256 hash stored only, single-use, 24 h / 1 h expiry.
- PATs AES-256-GCM encrypted at rest (`utils/cryptoUtils.js:11-51`); legacy-plaintext passthrough for pre-encryption values (lines 36-42) — a migration gap, not a live leak.
- SSRF: pinned-IP socket fetch, single DNS resolution, redirect re-validation, 2 MB cap (`utils/ssrfGuard.js`); clone path notes its own TOCTOU residual, bounded by host allowlist.
- Webhook HMAC (GitHub SHA-256 over raw body / GitLab token), per-repo secret first, timing-safe compare, fail-closed; idempotency via `WebhookDelivery`.
- CORS allow-listed, no wildcard; helmet; 1 MB body limits; generic 500s, no stack leak.
- No `.env` tracked in git; `.env` ignored at both levels. Committed-secret history: `backend/.env` was added in `e1e3dc9` (2026-04-16) and removed in `0204134`; the secret-scan workflow comment confirms a real `JWT_SECRET` was in that commit. Rotation is recorded as done; **history purge is still pending and needs the user's word** (standing flag).
- Secrets scan of current tree (this audit, pattern grep): only test-fixture values (fake AWS-key patterns in `backend/tests/fixtures/secrets_variants.js` and `generateFixtures.js`, which exist to trigger SEC-001/SEC-002) and token placeholders in UI copy. No real secret values found in HEAD.

### 4.3 UNVERIFIED (needs live verification — Day 3/7 work, not assumed)

- Whether `TURNSTILE_SECRET_KEY`, `SENTRY_DSN`, OAuth provider credentials, `GEMINI_API_KEY`, `BREVO_API_KEY` / SMTP are actually set in production Render/Vercel env. Procedure: inspect Render + Vercel dashboards (owner-only); never print values.
- Cross-tenant IDOR / RBAC matrix against the live API (requires test orgs + test users; `backend/tests/security_audit_test.js` and `phase2_rbac_multitenancy_verify.js` exist but need a live server + DB).
- Production security headers beyond what `vercel.json` declares (no CSP header — see §8).
- Whether the Supabase project `wkvvxqlflhjiqkhwxrsl` has backups / PITR enabled (docs/BACKUP_AND_RESTORE.md states honestly that **no backup has ever been taken and no trial restore performed**).
- Whether the classifier's live model is the Oct 23 retrain (`v3_real` per live `/health`) — probe says yes; the stale `classifier model/` copy must not be mistaken for the live one.

## 5. Performance bottlenecks

1. **Synchronous scan execution in the request lifecycle** (S6 above) — the dominant bottleneck and the Day 13 fix. Clone up to 180 s + scan + classifier, single Node process, no concurrency limit, no cancellation.
2. **Render free-tier cold starts:** backend root took **32.9 s** on first hit (cold start), classifier root **62.8 s**; subsequent calls ~1–3 s. Every first scan/webhook of the day pays this. No keep-alive is configured.
3. **Main JS chunk 741.5 kB (231.6 kB gzip)** — Vite build warns "Some chunks are larger than 500 kB"; limited code-splitting (5 lazy tab pages exist, but the Dashboard core is one big chunk). Build itself is fast (1.76 s, 2815 modules).
4. **NVD enrichment is unauthenticated, 6 s throttle, in-memory cache** (`utils/nvdEnrichment.js:22-24,125-137`) — per-process cache means every Render restart re-pays NVD latency; unauthenticated NVD rate limits can stall SBOM enrichment on large dependency sets.
5. **Classifier 5 s timeout per 50-finding chunk** — large scans make many sequential chunk calls; a slow classifier serialises the whole scan.
6. **No CDN/caching strategy beyond `/assets/*` immutable 1-year cache** in `vercel.json`; API responses have no cache headers noted.

## 6. Technical debt

| Debt | Location / evidence |
|---|---|
| No queue/worker; scans in-request | `routes/scans.js:167-505`, `routes/integration.js:66-313` (Day 13) |
| Dead dependency `mongoose@^9.11.4` declared, never imported | `backend/package.json` |
| Stale duplicate classifier copy (`classifier model/files/`, Oct 16) alongside live `backend/services/fp-classifier/` (Oct 23 retrain); `sample_findings.csv` exists in 3 copies (same blob) | repo tree |
| Generated Prisma client committed (~8.6 MB of wasm + base64 JS) | `backend/generated/prisma/` |
| Legacy Stripe columns + org-delete 502 trap | `routes/organizations.js:33-38`, schema |
| Legacy plaintext PAT passthrough in decrypt path | `utils/cryptoUtils.js:36-42` |
| Stale `backend/vercel.json` (deprecated `builds` + `@vercel/node` syntax; backend actually deploys on Render) | `backend/vercel.json` |
| `index.html` references `/src/main.jsx` (real file `main.tsx`) — works only via Vite extension resolution | `index.html:59` |
| `src/App.css` exists but `App.tsx` imports only `index.css` (likely unreferenced) | `src/App.css` |
| Per-component CSS files (30, no CSS modules) — global-scope collision risk | `src/components/*.css` |
| All dashboard navigation is tab-state, not routes (§3.2) | `Dashboard.tsx:149` |
| `parseInt` org-id coercion in `requireOrgContext` (S3) | `middleware/rbac.js:36-57` |
| Test fixtures committed with realistic-looking secret patterns (fine as fixtures, but they trip naive secret scanners) | `backend/tests/fixtures/secrets_variants.js`, `generateFixtures.js` |
| 227 commits by one author; 213 in the last 30 days — velocity concentrated in bursts (181 in Oct 2026); no CODEOWNERS / review process in repo | `git log` |
| Docs dated Sep–Oct 2026 describing a pre-Phase-2/3 product (see §10) | `docs/`, `SECURITY_AUDIT.md` |

## 7. Dependency relationships

**Frontend (11 deps):** React 19.2.4, react-dom, react-router-dom 7.18.3, framer-motion 12.38.0, gsap 3.15.0, lucide-react, @sentry/react 11.10.0, @radix-ui/react-slot, class-variance-authority, clsx, tailwind-merge; dev: Vite 8.0.4, Tailwind 4.2.2, TypeScript 6.0.2, ESLint 9.39.4. **15 outdated** (`npm outdated`); 6 major bumps available incl. `typescript` 6→7, `eslint` 9→10, `framer-motion` 12→14.

**Backend (17 deps):** Express 5.3.0, @prisma/client 7.8.0 + adapter-pg, pg 8.23.1, jsonwebtoken 9.0.3, bcryptjs 3.0.3, helmet 8.3.0, express-rate-limit 8.7.2, cors 2.8.6, dotenv 17.4.2, nodemailer 10.3.1, pdfkit 0.20.2, @babel/parser + traverse 8.0.10, js-yaml 5.5.0, @sentry/node 11.10.0, cookie-parser 1.4.7, mongoose 9.11.4 (dead). Dev: prisma 7.8.0, tsx. **10 outdated**; 2 major: `dotenv` 17→18, `prisma` 7.10.0→8.0.0-rc.33.

**Classifier (pinned, `--require-hashes`):** fastapi 0.162.2, uvicorn 0.54.0, pandas 3.1.1, scikit-learn 1.9.1, xgboost 3.4.1, shap, etc. (`requirements.txt`).

**Vulnerability posture: UNKNOWN, not clean.** `npm audit --json` is **blocked on this VM in both packages** (registry policy `zz_managed_internal_spaces_package_registries`, `POST /-/npm/v1/security/audits/quick` rejected). No counts obtainable here. The 2026-09-07 readiness report records 4 high vulnerabilities in the Prisma 7 tooling chain (`@prisma/config`, `deepmerge-ts`, `mysql2`, `prisma`) with a downgrade-to-6.19.3 fix deliberately not applied — that claim is from Sep 2026 and must be re-measured on Day 4 from a machine where `npm audit` works. The stack sits on bleeding-edge majors throughout (React 19, Vite 8, Express 5, Prisma 7, TS 6) — upgrade risk concentrates in the next major bumps, not the current pins.

**Env vars (names only):** backend reads 32 `process.env.*` names in JS (`JWT_SECRET`, `JWT_REFRESH_SECRET`, `ENCRYPTION_KEY`, `DATABASE_URL`, `FRONTEND_URL`, `FRONTEND_URLS`, `WEBHOOK_SECRET`, `FP_CLASSIFIER_URL`, `CLASSIFIER_API_KEY`, `GEMINI_API_KEY`, `GEMINI_WEB2API_URL/KEY`, `RAZORPAY_KEY_ID/SECRET`, `RAZORPAY_PLAN_PRO/ENTERPRISE`, `RAZORPAY_WEBHOOK_SECRET`, `BREVO_API_KEY`, `EMAIL_FROM`, `CONTACT_EMAIL`, `SMTP_HOST/PORT/USER/PASS`, `TURNSTILE_SECRET_KEY`, `SENTRY_DSN`, `GOOGLE/GITHUB/GITLAB_CLIENT_ID/SECRET`, `BACKEND_URL`, `EXTRA_GIT_HOSTS`, `SCAN_CLONE_DIR`, `SCAN_LOCAL_BASE`, `MAX_ORGS_PER_USER`, `PORT`, `TRUST_PROXY_HOPS`, `SENTRY_TEST_ROUTE`, `TEST_BASE_URL`, `NODE_ENV`, `RETRAIN_SCHEDULE_HOURS`, `MIN_FEEDBACK_TO_RETRAIN`); Python reads `CLASSIFIER_API_KEY`, `CLASSIFIER_ALLOW_UNAUTHENTICATED`. Frontend: `VITE_API_URL`, `VITE_ENABLE_SEVERITY_RANK`, `VITE_TURNSTILE_SITE_KEY`, `VITE_SENTRY_DSN`. Full list with sources in the Day 1 run log.

## 8. Tests, CI/CD, deployment

### Tests — counts from live files

| Suite | Files | Run this audit | Result |
|---|---|---|---|
| Backend JS unit tests (`backend/tests/*.test.js`) | 5 real: `aiFixEngine`, `astExtraction`, `compliance`, `deployment_config`, `startup_routes` (+ 2 fixture files `fixtures/mock.test.js`, `fixtures/mock_sast.test.js` — deliberately vulnerable sample code, not runnable tests) | `node --test aiFixEngine + startup_routes` → **8 pass, 0 fail**; `node tests/astExtraction.test.js` → **4 pass, 0 fail** | 12/12 offline-pass |
| `deployment_config.test.js` | 1 | `node --test` → **0 pass, 1 fail** — fails at import: `server.js` calls `validateEnv()` and throws for missing `JWT_SECRET, JWT_REFRESH_SECRET, ENCRYPTION_KEY, DATABASE_URL`. Env-gated, not a code failure | BLOCKED without secrets |
| `compliance.test.js` | 1 | Not run — targets a live server at `TEST_BASE_URL` (needs DB + JWT) | Not run |
| Verify/helper scripts (`backend/tests/*.js`, non-`.test.js`) | 24 — mostly one-off `phase2_*_verify.js` (RBAC, billing, SBOM/NVD, IaC, OAuth, custom rules, Days 6–10) + `e2e_onboarding_test.js`, `run_e2e_with_server.js`, `security_audit_test.js`, `verify_db_schema.js` | Not run — need live server/DB/network | Not run |
| Python tests | 6 — `test_conformal`, `test_feature_schema`, `test_iac_batch_regression`, `test_shap`, `test_shap_diag`, `test_severity_schema` | Not run — no `pytest`, no `scikit-learn` on this VM; installing was out of scope | Not run |
| Frontend tests | **0** | — | Missing |
| **Total runnable-offline result** | | | **12 pass, 0 fail; 1 env-gated fail; rest not runnable here** |

Neither `package.json` (root nor backend) defines a `test` script. Tests are run manually via `node --test`. No coverage measurement exists.

### CI/CD

- **No test/build/deploy CI exists.** `SecureGaurd-main/.github/` does not exist. The only workflow in the repo is clone-root `.github/workflows/secret-scan.yml`: gitleaks on PRs + push to `main` (full history, `fetch-depth: 0`), added after a real `JWT_SECRET` was committed in history (`e1e3dc9`).
- Deploys are Vercel/Render auto-deploy from git pushes (inferred from hosting, not from any workflow file). There is no gate between a push to `main` and production.

### Deployment

- **Vercel (frontend):** `vercel.json` — SPA, `/api/:path*` rewritten to hardcoded `https://securegaurd.onrender.com/api/:path*`, SPA fallback, headers `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` — **no Content-Security-Policy header**. `/assets/*` immutable 1-year cache. No env vars referenced in the file (Vite vars baked at build).
- **Render (backend):** `render.yaml` — exactly one service `secureguard-api`, Node, `rootDir: SecureGaurd-main/backend`, build `npm install && npm run build` (Prisma generate), `preDeployCommand: npx prisma migrate deploy`, start `npm start`, `healthCheckPath: /health`. Env (names only, all `sync: false`): `NODE_ENV=production`, `FRONTEND_URL`, `DATABASE_URL`, `JWT_SECRET`, `JWT_REFRESH_SECRET`, `ENCRYPTION_KEY`, `WEBHOOK_SECRET`, `GEMINI_API_KEY`, `CLASSIFIER_API_KEY`. **Flag: no classifier service is defined here** — the classifier has a Dockerfile and a compose service but no Render service, so its hosted deployment is not described by this file.
- **Docker (on-prem):** root `Dockerfile` (node:22-alpine build → nginx:alpine, serves `dist/`, port 80); `backend/Dockerfile` (node:22-alpine, full `npm ci` incl. dev deps for Prisma generate, port 5000, migrations at container start); `docker-compose.yml` (4 services: `db` postgres:16-alpine with `pg_isready` healthcheck, `classifier` port 8001, `backend` port 5000, `frontend` port 80; `nginx.conf` plain HTTP, no TLS — on-prem only). `docs/ON_PREM.md` states the compose setup was **statically verified only, never smoke-tested**. Flag: compose uses `env_file: .env` (`SecureGaurd-main/.env`), which does not exist in the repo (only `.env.example` / `.env.onprem.example`) — Compose fails without a manually created `.env`.
- **Classifier hosting:** live at `https://secureguard-classifier.onrender.com` (verified by probe, §9) but not represented in `render.yaml` — deployment source of truth for it is undocumented.

### Build verification (this audit)

`npx vite build --mode production` at HEAD: **passes** — 2815 modules, 1.76 s, main chunk 741.50 kB (gzip 231.61 kB), chunk-size warning (>500 kB). `dist/index.html` correctly references the built bundle despite the `main.jsx` source reference (§3.3.6). Frontend lint was not re-run (readiness report Sep 2026 recorded 10 React-hooks warnings, 0 errors — stale, re-measure on Day 18/19).

## 9. Live probe results (2026-11-14 ~01:05–01:15 IST, read-only GETs)

| Endpoint | Result |
|---|---|
| `GET https://secureguard-main.vercel.app/` | **200**, 1.06 s, 4,203 B HTML, title "SecureGuard — AI-Powered Code Security Platform" |
| `GET https://securegaurd.onrender.com/` | **404** `Cannot GET /` (no root route — expected), 32.9 s (Render cold start) |
| `GET https://securegaurd.onrender.com/health` | **200** `{"status":"ok"}`, 1.03 s |
| `GET https://securegaurd.onrender.com/api/health` | **404** `Cannot GET /api/health` — no such route |
| `GET https://secureguard-classifier.onrender.com/` | **404** `{"detail":"Not Found"}` (FastAPI, no root route — expected), 62.8 s (cold start) |
| `GET https://secureguard-classifier.onrender.com/health` | **200**, 3.09 s — `{"status":"ok","service":"SecureGuard FP Classifier","version":"2.2.1","model_version":"v3_real","model_loaded":true,"severity_ranker_ready":true,"severity_ranker_version":"v0_heuristic"}` |

All three services respond. Cold-start latency (33 s backend, 63 s classifier) is a Render free-tier fact, not a code defect — but it means the first scan/webhook of the day waits over a minute before any work starts.

**Not probed:** any authenticated endpoint, any write, any scan trigger, any webhook — those need test credentials / would mutate production state. Procedure for Day 7 verification: create a throwaway test org + user, run the §4.3 checks, then delete the test org.

## 10. Documentation accuracy

| Doc | Status |
|---|---|
| `README.md` (144 lines) | Mostly accurate on architecture and setup; mermaid diagrams describe the intended scan flow correctly. Claims "Stripe" in the billing line — Stripe is dead (§3.4). |
| `LIMITATIONS.md` (112 lines) | **The most honest doc in the repo.** Documents 12 real limitations (secrets skip ML, intra-procedural taint, synthetic training data, heuristic ranker labels, fail-open classifier, ranker 503 without weights). Trust it over marketing copy. |
| `docs/route-auth-matrix.md` (audited 2026-10-24) | Claims every route is exactly one of AUTH+ORG / AUTH / PUBLIC-DELIBERATE. 32 commits have landed since; the backend inspector's route inventory (88 routes) was not fully re-checked against this matrix — **treat as stale until Day 5 re-verifies it**. |
| `docs/production-readiness-report.md` (2026-09-07) | Pre-Phase 2/3; verdict "READY FOR STAGED DEPLOYMENT" with blockers listed. Stale. |
| `SECURITY_AUDIT.md` (2026-09-03) | Pre-Phase 2/3; contains the dev-credential string flagged as S8; its IDOR claim ("queries include `where: {userId: req.userId}`") does not match current org-scoped code — stale. |
| `docs/BACKUP_AND_RESTORE.md` | Honest: no backup ever taken, no trial restore performed. |
| `docs/OAUTH_SSO.md` | Honest: code shipped, no provider live. |
| `docs/ON_PREM.md` | Honest: statically verified only, never smoke-tested. |
| `docs/fp-classifier.md`, `docs/severity-ranker.md` | Architecture/metrics docs; consistent with code as inspected. |
| `CHANGELOG.md`, `project_status.md` (rewritten to true state 2026-11-02), `walkthrough.md`, `custom_model_guide.md` | Historical / guide material; not re-verified line-by-line. |
| `docs/superpowers/plans/` | Two plan files, both 2026-09-07. Historical. |

## 11. Database

- **Schema:** 19 models (`backend/prisma/schema.prisma`, 422 lines): User, Organization, Subscription, StripeWebhookEvent, RazorpayWebhookEvent, WebhookDelivery, OrganizationMembership, OrganizationInvitation, AuditLog, Repository, Scan, Vulnerability, ComplianceReport, Sbom, AlertSetting, AlertLog, AnalyticsEvent, ContactMessage, CustomRule.
- **Migrations:** 7 — `20261024_refresh_grace_window`, `20261026_razorpay_billing`, `20261029_cyclonedx_sbom`, `20261030_day7_alerts`, `20261031_day8_polish`, `20261102_day10_custom_rules_sso`, `20261108_webhook_idempotency_billing_ordering`. `render.yaml` runs `prisma migrate deploy` pre-deploy.
- **Raw SQL:** only `pg_advisory_xact_lock` in `organizations.js:307,380` and `repos.js:85` (parameterized template tags — safe) plus test-only `$queryRaw` in `tests/verify_db_schema.js`. No raw SQL in app code paths.
- **Notable schema facts:** `User.refreshToken/previousRefreshToken/refreshGraceExpiresAt` (bcrypt-hashed); `githubToken/gitlabToken` encrypted; `Repository.organizationId` nullable (legacy personal repos); `Vulnerability.mlFeatures` (Json), `userLabel`, `aiFix`, `aiFixApplied`; `Sbom.spdxDoc/cycloneDxDoc` (Json); `CustomRule @@unique([organizationId, ruleId])`; org-scoped tables cascade on org delete.
- **Backups: NONE ever taken, none tested** (`docs/BACKUP_AND_RESTORE.md`). This is a Day 7 production blocker.

## 12. Production blockers (must clear before a real launch)

1. **No CI gate** — pushes to `main` auto-deploy with no test/build check. One bad push is production.
2. **Synchronous scans** — availability/DoS risk on the single Render instance (S6).
3. **Backups never taken or restore-tested** (Supabase `wkvvxqlflhjiqkhwxrsl`).
4. **Dependency vulnerabilities unknown** — `npm audit` blocked on this VM; Sep 2026 report's 4 high Prisma advisories unresolved/accepted.
5. **Email verification cosmetic (S1)** + Turnstile fail-open (S2) — account-takeover-by-registration and bot-signup exposure.
6. **Private-repo scanning does not work** — a headline feature (GitHub/GitLab integration) only works for public repos.
7. **AI "apply fix" never touches the repo** — the remediation story is half-built; a user who clicks Apply gets a status flip, not a patch.
8. **Landing-page overclaims** (Stripe, SAML/SCIM, Jira, CI plugins, "50M+ CVEs", "milliseconds") — marketing claims that do not match the product; fix copy or ship the features (Days 16–17).
9. **No CSP header** on the Vercel deployment.
10. **Classifier has no deployment definition** (`render.yaml` covers only the API) — its hosting is undocumented and unverifiable from the repo.
11. **Fake scan progress** (§3.3.1) — mock UX in a production flow.
12. **History contains a real committed `JWT_SECRET`** (`e1e3dc9`); rotation recorded done, history purge still pending the user's word.

## 13. Recommended changes (prioritised; mapped to plan days)

| # | Change | Plan day |
|---|---|---|
| 1 | Add CI: test + lint + build on PR/push to `main` (block merge on failure) | 19 |
| 2 | Move scans to a background queue/worker with timeouts, retries, cancellation, resource limits | 13 |
| 3 | Gate login/registration on email verification; add verification + resend UI; add password-change UI | 5 |
| 4 | Set Turnstile keys in production (owner action) or remove the fail-open and require the key at startup | 4 |
| 5 | Fix `requireOrgContext` to 400 on malformed org id instead of falling back to the first org | 5 |
| 6 | Fix `orgFetch` stale-token retry; fix `completeOnboarding` silent local completion; add `credentials:'include'` to `apiRequest` | 5 / 14 |
| 7 | Pass `X-SecureGuard-Key` on the webhook classifier call | 6 |
| 8 | Authenticated private-repo clone via PAT (least-privilege, redacted, cleaned up) | 12 |
| 9 | Real AI remediation: generate diff → human approval → branch → patch → tests → rescan → PR | 11 |
| 10 | Take + test-restore a Supabase backup; document the procedure | 7 |
| 11 | Re-run `npm audit` where it works; resolve/accept the Prisma advisories | 4 |
| 12 | Correct landing-page copy to match wiring (or ship the claimed integrations) | 16–17 |
| 13 | Remove the fake scan progress; show real scan status polling | 14 |
| 14 | Add CSP header; define the classifier service in `render.yaml` (or document its hosting) | 19 / 4 |
| 15 | Remove stale `classifier model/` duplicate, committed generated Prisma client, dead `mongoose` dep, stale `backend/vercel.json` (with a documented reason each; model files need the plan's approval rule) | 19 |
| 16 | Add frontend tests (component + routing + auth flow) and a `test` script in both packages | 18 |
| 17 | Fix `index.html` entry to `/src/main.tsx`; fix `SECURITY_AUDIT.md` credential string (S8) | 14 / 3 |
| 18 | Make the route-auth matrix current again and re-verify it against the 88-route inventory | 5 |

## 14. What this audit did NOT verify (open, with procedure)

- **Live auth flows end-to-end** (register → verify → login → org → scan → fix → SBOM → compliance → billing → logout). Procedure: throwaway test account + test org on production, or a disposable local stack (`docker-compose.yml` + test DB); never use real user data. Target: Day 7 / Day 18.
- **Cross-tenant isolation under live traffic** (IDOR/RBAC matrix). Procedure: two test orgs, attempt cross-org reads/writes on every `:id` route; expect 404. Target: Day 5/7.
- **Production env var presence** (Turnstile, Sentry, OAuth, Gemini, Brevo/SMTP). Procedure: owner checks Render + Vercel dashboards; values never printed. Target: Day 4.
- **Classifier model quality** (precision/recall/F1 on independent data, data-leakage check). The live `/health` reports `v3_real` loaded; the Day 8 evaluation reports in `datasets/day8/` were not independently re-run. Target: Day 10.
- **NVD enrichment under load / rate limits; SBOM accuracy on a real multi-ecosystem repo.** Target: Day 9.
- **On-prem Docker Compose smoke test.** Target: Day 19.
- **Mobile responsiveness and accessibility beyond static attributes** (28 `@media` queries exist; no device verification done). Target: Day 14/18.

## 15. Evidence index

- Inspection reports (this run): backend — 88 routes, 19 models, 7 migrations, env-var inventory, security findings S1–S9; frontend — 79 files, 13 routes, 36 `.tsx`, workflow wiring table, auth bugs; deployment/tests/docs — CI inventory, test counts + runs, `npm audit` block, git history (227 commits), ML classifier inventory.
- Live probes: §9 table (timestamps ~01:05–01:15 IST, 2026-11-14).
- Build check: `npx vite build --mode production` at HEAD — pass, 1.76 s, 2815 modules, main chunk 741.50 kB / 231.61 kB gzip.
- Test runs: `node --test backend/tests/aiFixEngine.test.js backend/tests/startup_routes.test.js` → 8/8; `node backend/tests/astExtraction.test.js` → 4/4; `deployment_config.test.js` → env-gated fail (missing secrets).
- Secret-pattern scan of HEAD: no real secret values; only test fixtures + UI placeholders.
- Run log (commands, probes, open questions): `~/workspace/goals/securegaurd-20-day-transformation/hidden_files/day01-run-log.md`
- Audited commit: `bf49b47` (`git log` HEAD at audit time). Any code change after this commit is outside this audit's scope.
