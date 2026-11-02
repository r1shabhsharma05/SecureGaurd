# SecureGuard — Project Status Report
> PRD v2 & ML Architecture Status Report — rewritten to the true state on **2026-11-02**, at the end of the 10-day Phase 2 + Phase 3 completion program (2026-10-24 → 2026-11-02). The previous version of this file was stale (it showed Team/RBAC and Billing at 0%). Everything below was verified against production during the program; items that are built but blocked on the owner's account/keys are listed under **Honest limits** — nothing there is claimed as live.

---

## Summary overview

```
Landing Page          ████████████████████ 100%  (Completed)
Authentication        ████████████████████ 100%  (Password + SSO code shipped; SSO live use needs OAuth apps — see limits)
Database & Prisma     ████████████████████ 100%  (Completed)
Dashboard UI          ████████████████████ 100%  (Completed; mobile ~390px layout NOT verified — see limits)
Security Engine       ████████████████████ 100%  (Completed)
GitHub/GitLab Integr  ████████████████████ 100%  (PR-bot live success needs his PAT + a real PR — see limits)
LLM Model (Gemini)    ████████████████████ 100%  (Completed, rule-engine fallback)
Classifier Model (ML) ████████████████████ 100%  (v3_real in production)
Team / RBAC           ████████████████████ 100%  (Completed)
Billing / Razorpay    ████████████████░░░░  80%  (Code + fail-closed enforcement live; lifecycle test BLOCKED — see limits)
Compliance Engine     ████████████████████ 100%  (Completed)
SBOM + Threat Intel   ████████████████████ 100%  (Completed)
Custom Rules          ████████████████████ 100%  (Completed)
SSO / OIDC            ████████████████░░░░  80%  (Code + fail-closed proof live; provider sign-ins need OAuth apps — see limits)
On-prem package       ████████████████░░░░  80%  (Authored + statically verified; runtime smoke test NOT run — see limits)
Mobile app (PRD Ph.3) ░░░░░░░░░░░░░░░░░░░░   0%  (OUT of scope by the owner's order — website only)

Overall (website scope)  ~95% — the remainder is the blocked/his-step items below, not missing code (except SAML, see limits).
```

**Production topology:** backend `https://securegaurd.onrender.com` (Render) · classifier `https://secureguard-classifier.onrender.com` (Render) · frontend `https://secureguard-main.vercel.app` (Vercel, project `secureguard-main`) · database: dedicated Supabase Postgres via Prisma pooler · mail: Brevo HTTPS API (Render free tier blocks SMTP ports). No mock data anywhere in the product: every flow above either runs against a real service or fails closed with an honest error.

---

## 1. Completed work

### Frontend & landing page (100%)
- Full landing page (Hero, Scanner Previews, Features, How It Works, Pricing, Testimonials, CTA, Footer), session-aware navbar, dark design system.
- Website polish (Day 8, all 21 items live-proven): custom 404, full favicon set, skeletons + empty states, unified toasts, `prefers-reduced-motion`, OG images, built-in product-analytics events, cookie consent (real stored consent state), security headers, contact form → real Brevo email, per-page title/meta/OG/canonical/Schema.org, sitemap + robots.txt, breadcrumbs, internal links, WebP images, lazy loading, font preload + display swap.
- Legal pages: Privacy Policy + Terms of Service (accurate to shipped behaviour; no certifications claimed).

### Authentication & session system (100%)
- Registration, login, logout; dual-token JWT (15-min access token in memory + 7-day rotating refresh token in an HttpOnly `SameSite=None; Secure` cookie, 60 s grace window for the superseded token, reuse detection kills the session); email verification; forgot/reset password (generic responses, no enumeration).
- Route-by-route auth audit (matrix in `docs/route-auth-matrix.md`); RBAC middleware on every org route; Auditor is read-only everywhere, including the admin pages (server-guarded, not just hidden).
- **SSO/OIDC (Day 10, code complete):** "Continue with Google / GitHub / GitLab" — real authorization-code + PKCE flows, HMAC-signed state, verified-email requirement, account linking by provider identity then email, unusable random password for SSO-created accounts. Env-gated and fail-closed: with no provider configured, `GET /api/auth/oauth/providers` returns `[]`, no button renders, and the authorize endpoint answers 501. Setup + verification steps: `docs/OAUTH_SSO.md`.
- CAPTCHA: Cloudflare Turnstile on register / forgot-password / contact (server-verified; inert fail-open until keys are set — see limits). Rate limiters on all auth/public endpoints (per-instance in-memory stores — a global limit is NOT proven; see limits). Delete-account flow with password + typed `DELETE` confirmation and sole-owner org handoff.
- Error tracking: Sentry frontend + backend, inert without a DSN (see limits).

### Database architecture (100%)
- PostgreSQL via Prisma 7. Models: `User` (incl. OAuth identity columns + refresh grace-window columns), `Organization`, `Subscription`, `StripeWebhookEvent` (legacy, unused since the Razorpay switch), `RazorpayWebhookEvent`, `OrganizationMembership`, `OrganizationInvitation`, `AuditLog`, `Repository`, `Scan`, `Vulnerability`, `ComplianceReport`, `Sbom`, `AlertSetting`, `AlertLog`, `AnalyticsEvent`, `ContactMessage`, `CustomRule`.
- Cascading deletes; PATs encrypted at rest (AES-256-GCM); `mlFeatures` JSON + `userLabel` on vulnerabilities; audit log for every privileged action, with an audit-log viewer for Owners/Admins.

### Security scanning engines (100%)
- **Secrets:** AWS keys, private keys, hardcoded secrets/tokens (with `process.env` exclusion).
- **SAST:** SQL injection, XSS, path traversal, weak JWT verification, remote command execution — AST-extracted ML features for JS/TS.
- **SCA:** vulnerable dependency dictionary + lockfile parsing; SBOM (SPDX 2.3 + CycloneDX 1.6) generated and stored per scan; live NVD threat-intel enrichment (CVE/CVSS, cached with refresh stamps).
- **IaC:** Terraform (TF-001…006), Kubernetes, Dockerfile, CloudFormation (CFN-001…006) rule sets with CWE mappings.
- **API security:** OpenAPI/Swagger ingestion (URL via SSRF guard, or pasted content) → auth/rate-limit/data-exposure/scheme findings in the same pipeline.
- **Custom rules (Day 10):** org-authored YAML rules (`CUSTOM-xxx`), validated at write time, testable against sample code and against a past scan's repository (re-scan of the current tree, stated as such), fired in real scans alongside built-ins. Custom findings carry no ML features, so the classifier can never suppress them. Built-in rule library page included.
- **Continuous learning:** feedback labels → dataset export → retrain job with held-out comparison + rollback gate. Day-6 cycle (223 real rows): baseline `v3_real` 0.9778 acc / 1.0 recall vs retrain 0.9556 / 1.0 → gate HOLD, no deploy. Production model remains `v3_real`.

### GitHub / GitLab integrations (100%*)
- PAT manager (encrypted), remote repository importer, webhook auto-scan on push (signature-verified), CI template.
- **PR bot (Day 7):** real GitHub check-run + summary comment with the user's PAT. *Success path is unit-proven only — a live PR run needs his PAT + a real PR (see limits). No-PAT 400 and bad-PAT GitHub 401 are live-proven.
- **Scan alerts (Day 7):** Slack webhook (allow-listed URLs only) + Brevo email on scan completion / new critical, with a delivery log. *Delivery to his own Slack workspace needs his webhook URL (see limits).

### Dashboard UI (100%)
- Overview stats + health score, repositories, scan history, vulnerability database with filters, full vulnerability detail page (CWE/CVE links, occurrence history, AI fix panel, SHAP explanation, ranker priority), compliance reports + dashboard, SBOM viewer + threat intel, scan alerts settings, product-activity analytics, team/members/invitations/audit, billing & usage, settings (incl. delete account), custom rules.
- Onboarding wizard (5 steps, skippable). First-workspace empty state (Day 10 fix): a fresh account with no workspace now sees "Create your first workspace" instead of perpetual loading skeletons.
- Severity ranker (which finding to fix first) + FP classifier explanations surfaced in the UI.

### Team & organizations (100%)
- Invitations end-to-end (real Brevo mail → accept link → membership with role → revoke/remove/leave), ownership transfer, member role changes, team UI, admin action logging + viewer. Two-account isolation live-proven (Account B cannot see/touch Account A's org, scans, or reports; cross-org access 403/404).

### Billing — Razorpay, INR (80% — blocked, see limits)
- Plans Free / Pro / Enterprise via real Razorpay Plans + Subscriptions; subscription-auth flow; upgrade/downgrade/cancel/invoices UI driven by Razorpay APIs (no hosted portal at Razorpay — management UI is ours); plan limits enforced by real subscription state (fail-closed webhook drives plan changes; no client-side trust); unsigned-webhook rejection live-proven with the new handler.
- **BLOCKED:** the full lifecycle test (subscribe → PRO → limit lifted → cancel → period-end downgrade → webhook trail + invoices with real rows) cannot pass because the Render key/secret pair or plan IDs do not authenticate against the Razorpay API (`create-subscription` → 502 "Billing provider error"; live price fetch returns null). Needs his Razorpay dashboard check. Nothing is faked around it.

### Compliance engine (100%)
- SOC 2, HIPAA, PCI-DSS, GDPR mappings driven by real scan findings; PDF + JSON exports (< 60 s), report history, org-scoped downloads (outsiders get 404); compliance dashboard with per-framework drill-down. Live-proven from real LocalKart + NodeGoat scans.

---

## 2. LLM model integration (Gemini)

| Property | Details |
|---|---|
| **LLM Model Used** | **Google Gemini 1.5 Flash** (`gemini-1.5-flash`) via Google Generative Language API |
| **Fallback Engine** | Context-aware **Rule-Based AI Engine** with 11+ OWASP remediation templates |
| **Code Location** | `backend/utils/aiFixEngine.js` & `backend/routes/ai.js` |

How it works: "Generate AI Fix" on a vulnerability → `/api/ai/fix/:vulnId` → Gemini (when `GEMINI_API_KEY` is set) generates a fixed snippet + CWE mapping + explanation as structured JSON, else the rule-based engine answers. Fixes are cached in `vulnerability.aiFix`; the diff viewer shows original vs proposed; "Apply AI Fix" marks the finding fixed (`aiFixApplied: true`).

## 3. ML false-positive classifier

| Property | Details |
|---|---|
| **Classifier Model** | **XGBoost Binary Classifier** (`model.joblib`), production version **v3_real** |
| **Microservice** | **Python FastAPI** (`backend/services/fp-classifier`, port `:8001`) |
| **Explainability** | **SHAP** top-5 feature contributions (`explainer.py`) |
| **Calibration** | Per-CWE conformal thresholds (`conformal_calibration.py`) |
| **Severity Ranker** | Sibling package (`backend/services/severity-ranker`), same FastAPI process under `/v2` |

How it works: scans extract AST/contextual features → batched `POST /classify/batch` (chunks of 50, `X-SecureGuard-Key` auth) → per-CWE calibrated thresholds decide REAL vs FALSE_POSITIVE → SHAP explanations stored on the finding. Safety: secrets bypass filtering (always REAL); IaC/API findings are never suppressed by the SAST-trained model; classifier outage/timeout fails open (REAL). Retraining is gated (held-out comparison + rollback; Day-6 cycle held — see above).

---

## 4. Honest limits — built but NOT live-proven, or blocked on the owner

| # | Item | State | What the owner must do |
|---|---|---|---|
| 1 | Razorpay lifecycle + invoices with real rows | BLOCKED (Day 3, re-probed 2026-11-02) | Dashboard check: key/secret pair or plan IDs (`plan_TsQUygFt8pPmZN`, `plan_TsQXnhunbsec1h`) do not authenticate against the Razorpay API |
| 2 | SSO provider sign-ins (Google/GitHub/GitLab) | Code live, fail-closed proven; no provider live | Register OAuth apps + set client id/secret on Render (`docs/OAUTH_SSO.md`), then verify one real sign-in per provider |
| 3 | Enterprise SAML | NOT BUILT (deliberately — no fake SAML surface exists) | Needs a customer IdP (or samltest.id proof) + a vetted SAML library; do not promise it until proven |
| 4 | Turnstile real-challenge enforcement | Code live, inert until keys set | Create a Turnstile widget; set `TURNSTILE_SECRET_KEY` (Render) + `VITE_TURNSTILE_SITE_KEY` (Vercel); verify a real signup |
| 5 | Sentry dashboard errors | Code live, inert until DSN set | Create a Sentry project; set DSNs; temporarily enable `SENTRY_TEST_ROUTE`, hit `/_test-error`, confirm in dashboard, remove the var |
| 6 | DB backup trial restore | Script + restore doc exist; NO backup taken, NO restore run | Confirm Supabase automated backups/PITR; run `backend/scripts/backup-db.sh` on a host with `DATABASE_URL` + `pg_dump`; trial-restore into a scratch DB |
| 7 | Global (shared-store) rate limiting | Per-instance limiters live + proven to trip; global limit NOT proven (headers oscillate across Render instances) | Decide on Upstash Redis (or equivalent) + Render env; code change to use a shared store when configured |
| 8 | PR-bot live SUCCESS | Unit-proven only (no-PAT 400 / bad-PAT 401 live-proven) | Provide a GitHub PAT + a real PR in a repo he owns |
| 9 | Slack alerts to his workspace | POST path proven (dummy webhook → Slack 404 `no_team`) | Provide his Slack webhook URL |
| 10 | Mobile layout at ~390px | NOT VERIFIED (3 browser attempts, 2026-11-01/02 — the browser tooling has no viewport control) | Check on a real phone, or a route with device emulation; do not claim a mobile pass before that |
| 11 | On-prem runtime smoke test | Package authored + statically verified; never run (no Docker in the authoring VM) | Run `docs/ON_PREM.md` checklist on a Docker host (~10 min) |
| 12 | ESLint debt | 10 pre-existing `react-hooks/set-state-in-effect` errors in fetch effects (Day-9 code fixed in-run; build is green) | Separate refactor; "eslint clean" is not claimed |
| 13 | Mobile app (PRD Phase 3) | OUT of scope by his order | — |

**Pre-existing observations (not Day-10 scope, recorded for honesty):** the Dashboard seeds a placeholder repository (`secureguard-main`, pointed at the user's GitHub namespace) when an org has no repos — it is not a real connected repo. CORS rejections surface as generic 500s through the error handler (no leak; noisy in Sentry once configured). `npm audit` could not run on the authoring VM (registry 403); dependency updates were applied at `npm outdated` Wanted versions and verified by builds + test suites, not by an audit count.

---

## 5. Program record (10 days, 2026-10-24 → 2026-11-02)

| Day | Scope | Outcome |
|---|---|---|
| 1 | Auth & RBAC foundation | Complete |
| 2 | Team & organizations | Complete (invite mail landed in Gmail Spam — authenticated-domain follow-up is his optional step) |
| 3 | Razorpay billing | **Incomplete — blocked** (see limit #1; code + enforcement live) |
| 4 | Compliance engine | Complete |
| 5 | Advanced IaC + API scanning | Complete |
| 6 | SBOM + threat intel + retrain cycle | Complete (retrain gate HOLD — honest metrics, no deploy) |
| 7 | Product completeness (detail page, onboarding, alerts, PR bot) | Complete (PR-bot success + Slack carries, see limits) |
| 8 | Website polish (21 items) | Complete |
| 9 | Production hardening | Incomplete on one test only (mobile layout — limit #10); zero-workspace skeleton bug found, fixed Day 10 |
| 10 | SSO, custom rules, on-prem, full acceptance | Complete for Day-10 scope; acceptance table in `REPORTS/day-10.md` (goal workspace). Day-3 + mobile items remain open above. |

Daily reports: `~/workspace/goals/secureguard-phase23-10day/REPORTS/day-01.md` … `day-10.md`. State: `hidden_files/STATE.json`. Throwaway test data from the program (test orgs/scans/reports) was left in the production DB where noted in the day reports, except the Day-10 probe accounts/orgs, which were deleted via the real delete-account flow and verified gone (login → 400).
