# SecureGaurd — Threat Model (Day 3, 20-Day Transformation)

**Date:** 2026-11-16 (Day 3 of the 20-day program)
**Modelled commit:** `e8c7d31` — "add day 2 competitor research and differentiation"
**Repo:** `r1shabhsharma05/SecureGaurd` — app root `SecureGaurd-main/`
**Method:** source inspection at the modelled commit (every route file, middleware,
auth flow, scanner, webhook and billing path), grounded in the Day 1 audit
(`docs/MASTER_PROJECT_AUDIT.md`, commit `bf49b47`) and re-verified where the
code changed since. No destructive test was run against production. No secret
values were read or printed anywhere in this document (env var names only).
**Companion document:** `docs/SECURITY_HARDENING_CHECKLIST.md` — the
per-item PASS / FAIL / BLOCKED / NOT APPLICABLE verification of the same
controls. This threat model states what can go wrong and why; the checklist
states what was verified and with what evidence.

## 1. System overview

SecureGaurd is a React 19 SPA (Vercel) talking to an Express 5 API (Render)
backed by Prisma/PostgreSQL (Supabase project `wkvvxqlflhjiqkhwxrsl`,
ap-southeast-1), with a Python XGBoost false-positive classifier and severity
ranker (Render), Razorpay billing, Brevo/SMTP mail, Gemini AI fix generation,
and GitHub/GitLab webhooks plus a PR bot. Users belong to organizations with
roles OWNER / ADMIN / DEVELOPER / AUDITOR; every data access is scoped by
organization in application code. Scans run synchronously inside the HTTP
request: anonymous-HTTPS clone (up to 180 s) + regex/AST scan + classifier
batch call + SBOM + alerts. There is no queue, no worker, and no file-upload
feature anywhere in the product.

## 2. Assets

| Asset | Value | Where it lives |
|---|---|---|
| User credentials (bcrypt hashes, refresh tokens) | Account takeover if leaked | PostgreSQL `User` table; refresh tokens bcrypt-hashed, rotating |
| JWT / refresh signing secrets | Forge any session if leaked | Render env only (`JWT_SECRET`, `JWT_REFRESH_SECRET`); fail-fast if unset |
| Data-encryption key | Decrypts stored GitHub/GitLab PATs | Render env only (`ENCRYPTION_KEY`, 64-hex, required at startup) |
| GitHub/GitLab PATs | Read private repos if leaked | `User` table, AES-256-GCM encrypted at rest |
| Customer source code (cloned repos) | Confidential customer IP | Ephemeral clone dir on the Render instance, deleted after scan |
| Scan findings / SBOMs / compliance reports | Customer security posture — sensitive | PostgreSQL (`Scan`, `Vulnerability`, `Sbom`, `ComplianceReport`) |
| Razorpay keys + webhook secret | Payment fraud if leaked | Render env only; webhook HMAC-verified |
| Webhook secrets (GitHub/GitLab per-repo) | Forge scan triggers if leaked | `Repository` table, encrypted |
| Classifier API key | Abuse the ML service if leaked | Render env only; classifier fail-closed without it |
| Audit logs | Forensic record of privileged actions | PostgreSQL `AuditLog` table |
| Supabase database itself | All of the above at rest | Supabase ap-southeast-1; backups: none ever taken (see T5) |

## 3. Threat actors

| Actor | Capability | Motivation |
|---|---|---|
| Unauthenticated internet attacker | No credentials; can hit every public endpoint | Account takeover, bot signup, spam, DoS |
| Registered low-privilege user (DEVELOPER / AUDITOR, or a member of org A) | Valid session, limited role, one org | Cross-tenant data access (IDOR), privilege escalation, reading another org's findings |
| Malicious repository owner | Controls the repo content that gets cloned and scanned | SSRF, path traversal, symlink escape, zip/resource exhaustion against the scanner |
| Malicious webhook sender | Can POST to the webhook endpoints | Forged scan triggers, replay, quota exhaustion |
| Compromised dependency / supply chain | Code runs in the build or at runtime | Backdoor, data exfiltration |
| Insider / leaked credential holder | Holds a real secret from git history or a doc | Session forgery (old JWT secret), DB access (old dev credential) |
| AI-suggestion consumer | Receives AI-generated fix text | Applying an unreviewed or malicious fix to their own repo (supply-chain via AI) |

Out of scope for this model: physical attacks on Vercel/Render/Supabase
infrastructure, and attacks on the user's own GitHub account (out of
SecureGaurd's control). Both are recorded as accepted external dependencies,
not as findings.

## 4. Trust boundaries

```
[ internet ] ──(1)── [ SPA on Vercel ] ──(2)── [ Express API on Render ]
                                                      │  │  │  │
                                        (3) Prisma ──► [ PostgreSQL / Supabase ]
                                        (4) HTTPS ──► [ classifier (FastAPI) ]
                                        (5) HTTPS ──► [ GitHub / GitLab / NVD / Gemini / Razorpay / Brevo ]
                                                      │
                                        (6) git clone ──► [ customer repo (anonymous HTTPS only) ]
```

| # | Boundary | Crossing rule |
|---|---|---|
| 1 | Internet → SPA | Static assets only; no secrets in the bundle (only `VITE_API_URL`, `VITE_TURNSTILE_SITE_KEY`, `VITE_SENTRY_DSN`, `VITE_ENABLE_SEVERITY_RANK`) |
| 2 | SPA → API | Bearer access token (15 min) + httpOnly `sg_refresh` cookie; `x-organization-id` header; CORS allow-list, no wildcard |
| 3 | API → DB | Prisma parameterized queries only; org-scoped `where` on every tenant query; single `DATABASE_URL` credential |
| 4 | API → classifier | `X-SecureGuard-Key` header; fail-closed unless `CLASSIFIER_ALLOW_UNAUTHENTICATED=1` |
| 5 | API → third parties | Per-service keys from env only; webhook HMAC verification on inbound billing/webhook calls |
| 6 | API → git clone | Anonymous HTTPS only; host allowlist `github.com` / `gitlab.com` (+ `EXTRA_GIT_HOSTS`); credentials in URLs rejected; symlink containment; 180 s clone cap |

The most important boundary fact: **tenant isolation is enforced only in
application code** (Prisma `where: { organizationId }`). There is no
PostgreSQL Row Level Security policy in any migration, so a single missed
`where` clause is a cross-tenant leak. That is why the Day 1 audit's
"verified good" tenant-isolation finding is conditional on code review, and
why RLS is a Day 7 item (T5-adjacent, checklist item DB-3).

## 5. Attack surface map

| Entry point | Auth required | Exposure | Notes |
|---|---|---|---|
| `POST /api/auth/register`, `/login` | No | Internet | Rate-limited 10/15 min; Turnstile-gated only if key set (T3) |
| `POST /api/auth/refresh`, `GET /api/auth/me` | Session / token | Internet | **No rate limit** (T9) |
| `POST /api/auth/forgot-password`, `/reset-password` | No | Internet | Rate-limited 5/hr; hashed single-use tokens |
| `DELETE /api/auth/account` | Yes | Internet | Rate-limited 3/hr; password + typed DELETE |
| `GET /api/auth/oauth/:provider/callback` | No | Internet | Rate-limited; PKCE + HMAC-signed state |
| `POST /api/scans/trigger` | Yes + OWNER/ADMIN/DEVELOPER | Internet | Rate-limited 10/10 min; synchronous clone+scan (T2) |
| `POST /api/integration/github`, `/gitlab` (webhooks) | HMAC / token | Internet | Rate-limited; per-repo secret, timing-safe compare, idempotency |
| `POST /api/billing/webhook` (Razorpay) | HMAC | Internet | Ordering guard + idempotency, with a concurrency race (T10) |
| `POST /api/contact`, `POST /api/analytics/events` | No | Internet | Rate-limited; contact validated + honeypot + Turnstile-if-set |
| All other `/api/*` routes (88 total) | Yes + org role | Internet | `requireOrgContext` + `requireOrgRole`; route-auth matrix stale since 2026-10-24 — full re-verification is Day 5 |
| `GET /health` | No | Internet | Status only, no data |
| `GET /api/_test-error` | No | Internet | Exists **only** when `SENTRY_TEST_ROUTE=enabled`; must stay unset in prod |
| Classifier `POST /classify/batch`, `/v2/rank` | `X-SecureGuard-Key` | Internet | Fail-closed by default |
| Git clone of customer repos | N/A (outbound) | Repo content | Anonymous HTTPS; host allowlist; symlink containment; SSRF-pinned fetch for URL inputs |
| Frontend routes (`/dashboard`, `/vulnerabilities/:id`, …) | Client-side guard only | Internet | Per-page re-implemented guards; no route-level guard; `/onboarding` has no logged-out guard |

## 6. STRIDE analysis

### 6.1 SPA (frontend)

| Threat | Assessment | Controls in place | Residual |
|---|---|---|---|
| Spoofing — fake login page / phishing | Out of scope for the app; no control in-repo | — | Accepted; brand-domain discipline only |
| Tampering — XSS via rendered finding data | React auto-escapes; **zero** `dangerouslySetInnerHTML` in `src/` | React escaping; helmet headers | Low. No CSP header exists, so a future raw-HTML render would have no second layer (checklist SEC-14) |
| Repudiation — user denies an action | Audit logs exist for privileged actions | `createAuditLog` in org/billing/compliance/alerts/ai/auth flows | Low. Coverage not exhaustively audited per action (Day 7 spot-check) |
| Information disclosure — secrets in bundle | Verified: only non-secret `VITE_*` vars | Build-time env only | Low |
| Denial of service — heavy frontend | Main chunk 741.5 kB (231.6 kB gzip); limited code-splitting | 5 lazy tab pages | Low; perf is Day 17 |
| Elevation — client-side role checks bypassed | Frontend role checks are cosmetic; backend re-checks every route | `requireOrgRole` server-side | Low, conditional on the Day 5 route-matrix re-verification |

### 6.2 API (Express)

| Threat | Assessment | Controls in place | Residual |
|---|---|---|---|
| Spoofing — session forgery | JWT signed with env secret; fail-fast if unset | `validateEnv()`; 15-min access tokens | Low. Old `JWT_SECRET` still in git history (T13) — rotation recorded done, history purge pending Rishabh's word |
| Spoofing — refresh-token theft/replay | Rotating refresh tokens, bcrypt-hashed, reuse detection with atomic compare-and-swap, 60 s grace | `routes/auth.js:259-317` | Low. `/refresh` has no rate limit (T9) — guessing is bcrypt-bound per attempt but unlimited attempts are allowed |
| Tampering — IDOR / cross-tenant access | Every `:id` lookup is org-scoped (verified Day 1) | Prisma `where: { organizationId }` throughout | **Medium.** `requireOrgContext` falls back to the caller's first org on a malformed org id instead of 400ing (T4); no DB-level RLS as a second layer |
| Tampering — mass assignment / bad input | Per-route manual validation; no shared schema library | `validateContactInput`, per-route checks | Medium. Validation is ad-hoc; no zod/express-validator; a missed check is a live bug (Day 6 standardisation) |
| Repudiation — privileged action without a trace | `AuditLog` writes on org/billing/compliance/alerts/AI/auth actions | `middleware/rbac.js:106` helper | Low |
| Information disclosure — stack traces / verbose errors | Generic 500s, no stack leak; Sentry error handler last | `server.js` | Low |
| Information disclosure — CORS misconfiguration | Allow-list + Vercel-preview regex scoped to the team's project slug; deny-without-error | `config/cors.js` | Low |
| Denial of service — synchronous scans | **Highest architectural risk.** Clone (180 s) + scan + classifier inside the request; no queue, no per-scan HTTP timeout; 10/10-min trigger limiter is per-IP and trust-proxy dependent | Scan trigger limiter; entitlement check | **High (T2).** An authenticated user can pin the single Node process with a few large-repo scans. Fix is Day 13 (background queue) |
| Denial of service — auth-endpoint abuse | Login/register/reset limited; refresh/me unlimited | `express-rate-limit` on most auth routes | Low (T9) |
| Elevation — AUDITOR performing writes | Write routes require OWNER/ADMIN/DEVELOPER | `requireOrgRole` on every write route spot-checked | Low, pending Day 5 matrix re-verification |

### 6.3 Scanner and repository handling

| Threat | Assessment | Controls in place | Residual |
|---|---|---|---|
| SSRF via repo URL / API-spec URL | Pinned-IP socket fetch, single DNS resolution, redirect re-validation, 2 MB cap | `utils/ssrfGuard.js` | Low. Clone path notes its own TOCTOU residual, bounded by the host allowlist |
| Path traversal / symlink escape from repo content | Symlink containment verified in the 2026-11-08 fix round | Scanner containment | Low |
| Resource exhaustion — zip bombs, huge repos, oversized files | Clone cap 180 s; no per-file size cap found in scan path | Clone timeout only | Medium. No queue/concurrency limit until Day 13; no per-scan resource quota |
| Malicious repo code executed by the scanner | Scanner is regex + Babel AST feature extraction; it does not execute repo code | No `eval`/`exec` of repo content in scan path | Low |
| Private-repo credential leak | Clone is anonymous HTTPS only; PAT never passed to git; credentials in URLs rejected | `utils/repoScanSource.js:17-157` | Low — but private repos cannot be scanned at all (Day 12) |
| Secret disclosure — scanned secrets logged or stored | Secret redaction in logs (2026-11-08 fix) | Redaction utilities | Low. Findings themselves legitimately contain secret patterns — access is org-scoped |

### 6.4 Classifier (Python FastAPI)

| Threat | Assessment | Controls in place | Residual |
|---|---|---|---|
| Unauthenticated abuse | `X-SecureGuard-Key` required; fail-closed by default | Classifier auth | Low. Webhook scan path calls the classifier **without** the key, so FP suppression silently never runs there (T11) — fail-open to REAL, invisible |
| Model tampering | Model files tracked in git; stale duplicate copy exists | Git history | Low. No model-file change is allowed without documented reason + approval (standing rule) |
| Wrong predictions presented as fact | Classifier output is a label + confidence; SEC-* rules skip ML by design | `LIMITATIONS.md` documents fail-open behaviour | Medium. Ranker trained on heuristic labels, not analyst labels; independent evaluation is Day 10. No finding may be auto-dismissed on ML alone (standing rule) |
| Availability — classifier down / slow | 5 s timeout per 50-finding chunk; findings stay REAL on failure | Fail-open to REAL | Low for correctness; scan latency impact is Medium (serial chunk calls) |

### 6.5 Webhooks and billing

| Threat | Assessment | Controls in place | Residual |
|---|---|---|---|
| Forged GitHub/GitLab webhook | HMAC-SHA256 over raw body / GitLab token; per-repo secret first, shared fallback; timing-safe compare; fail-closed | `routes/integration.js` | Low |
| Webhook replay / duplicate delivery | Idempotency via `WebhookDelivery` | Idempotency keys | Low |
| Forged Razorpay webhook | HMAC verify; ordering guard; idempotency | `routes/billingWebhook.js` | Low, except the idempotency check sits outside the transaction — two concurrent duplicates can both pass it; the loser 500s (retried, not double-applied) (T10) |
| Billing orphan — org deleted, subscription lives on | Legacy Stripe columns; org delete 502s if a Stripe sub exists | Known, documented (S9) | Medium. Manual Stripe-dashboard action required; fix is a Day 15 item |
| Email spoofing / spam via contact form | Validated + honeypot + rate-limited; Turnstile only if configured | `routes/public.js`, `utils/publicSite.js` | Low (T3 for the CAPTCHA gap) |

### 6.6 Database (Supabase PostgreSQL)

| Threat | Assessment | Controls in place | Residual |
|---|---|---|---|
| SQL injection | Prisma parameterized queries everywhere; only raw SQL is `pg_advisory_xact_lock` template tags | Prisma | Low |
| Cross-tenant read via missed scope | App-level scoping only; **no Postgres RLS** | Code review + org-scoped queries | **Medium.** One missed `where` is a leak. RLS is a Day 7 item |
| Data loss | **No backup has ever been taken; no trial restore performed** | `docs/BACKUP_AND_RESTORE.md` states this honestly | **High (T5).** A destructive bug or Supabase incident is unrecoverable. Day 7 must take + restore-test a backup |
| Credential exposure | `DATABASE_URL` in Render env only; `.env` ignored and untracked | `.gitignore`, `validateEnv()` | Low. Least-privilege DB credentials unverified (owner dashboard check, Day 4) |
| Audit-trail tampering | `AuditLog` rows are append-only by convention, not by DB constraint | Application code only | Low. DB-level append-only enforcement is a Day 7 consideration |

## 7. Prioritized risk register

Severity follows the security-audit skill: assigned only to confirmed,
source-grounded findings. Items needing live verification are marked
UNVERIFIED, not given a severity.

| ID | Risk | Severity | Evidence | Fix day |
|---|---|---|---|---|
| T1 | Email verification is cosmetic — register returns a token immediately; login never checks `isEmailVerified`; an attacker registering with someone else's email gets a working session | High | `routes/auth.js:98-152`, `:190-228`; no verification UI anywhere | 5 |
| T2 | Synchronous scans are a DoS surface — clone (180 s) + scan + classifier in-request, no queue, no per-scan HTTP timeout, single Node process | High | `routes/scans.js:167-505`, `routes/integration.js:66-313` | 13 |
| T3 | Turnstile fails open when unconfigured — with `TURNSTILE_SECRET_KEY` unset there is no bot protection on signup, password reset or contact | Medium | `utils/turnstile.js`; key presence in prod UNVERIFIED | 4 |
| T4 | `requireOrgContext` falls back to the caller's first org on a malformed org id (`parseInt("12abc")` coerces to 12) instead of 400ing | Medium | `middleware/rbac.js:36-57` | 5 |
| T5 | No database backup ever taken or restore-tested; no Postgres RLS as a second isolation layer | High (backup) / Medium (RLS) | `docs/BACKUP_AND_RESTORE.md`; no `CREATE POLICY` in any migration | 7 |
| T6 | No Content-Security-Policy header on Vercel or from helmet — a future raw-HTML render has no second layer against XSS | Medium | `vercel.json` headers; `server.js:54` helmet without CSP | 6 |
| T7 | Legacy Stripe subscriptions block org deletion (502) and orphan live subscriptions | Medium | `routes/organizations.js:21-38` | 15 |
| T8 | Dependency vulnerability posture UNKNOWN — `npm audit` blocked on this VM; Sep 2026 report's 4 high Prisma advisories unresolved | Medium | Day 1 §7; `npm outdated` root 15 (6 major), backend 10 (2 major) | 4 |
| T9 | No rate limit on `POST /api/auth/refresh` and `GET /api/auth/me` | Low | `routes/auth.js:259`, `:426` — no limiter attached, unlike register/login/reset | 6 |
| T10 | Razorpay webhook idempotency check outside the transaction — concurrent duplicates can both pass; loser 500s (retried, not double-applied) | Low | `routes/billingWebhook.js:141-155` | 6 |
| T11 | Webhook scan path calls the classifier without `X-SecureGuard-Key` — FP suppression silently never runs on webhook-triggered scans | Low | `routes/integration.js:206-213` vs `routes/scans.js:280-294` | 6 |
| T12 | Dev MongoDB credential string printed in a tracked doc | Low | `SECURITY_AUDIT.md:90` — redacted in this run; rotation of the dev credential still owed (owner action) | 3 (redacted) / 4 (rotate) |
| T13 | Real `JWT_SECRET` in pushed git history (`e1e3dc9`, Apr 2026); rotation recorded done; history purge pending Rishabh's word | Low (post-rotation) | Git history; gitleaks CI now blocks future commits | 4 (purge decision) |
| T14 | Fake scan progress — frontend animates 0–100% with random filenames before the real trigger fires; mock UX in a production flow | Low (integrity) | `Dashboard.tsx:453-492` | 14 |
| T15 | `orgFetch` stale-token 401 retry re-fires with the expired token; `completeOnboarding` silently marks onboarding complete locally on server failure | Low | `OrganizationContext.tsx:130-145`; `AuthContext.tsx:100-113` | 5 |
| T16 | No MFA; OAuth providers shipped but none live; SAML explicit 501 while Pricing sells SSO/SAML/SCIM | Info | `routes/auth.js:469`; `docs/OAUTH_SSO.md` | 12 / 15 / 16 |
| T17 | Classifier fail-open + heuristic-trained ranker; NVD enrichment unauthenticated with 6 s throttle and per-process cache | Info | `LIMITATIONS.md` §0, §10; `utils/nvdEnrichment.js` | 9 / 10 |

## 8. Remediation plan (mapped to the 20-day schedule)

| Day | Work that closes these risks |
|---|---|
| 3 (this run) | Threat model + hardening checklist; redact S8/T12 credential string from `SECURITY_AUDIT.md` |
| 4 | Dependency scan via GitHub Actions (T8); Turnstile key presence check (T3); rotate dev MongoDB credential (T12); history-purge decision (T13) |
| 5 | Gate login on email verification + verification/resend UI (T1); fix `requireOrgContext` fallback (T4); fix `orgFetch` + `completeOnboarding` (T15); re-verify the route-auth matrix against the 88-route inventory |
| 6 | Add CSP header (T6); rate-limit `/refresh` + `/me` (T9); move Razorpay idempotency check inside the transaction (T10); pass the classifier key on the webhook path (T11); standardise input validation |
| 7 | Take + restore-test a Supabase backup; implement Postgres RLS (T5); security regression tests; SECURITY_GATE_REPORT.md — **gate: no Phase 4 work until it passes** |
| 11 | Real AI remediation (diff → approval → branch → patch → tests → rescan → PR); never mark fixed on suggestion alone |
| 12 | Authenticated private-repo clone via PAT (least-privilege, redacted, cleaned up) |
| 13 | Background queue/worker for scans with timeouts, retries, cancellation, resource quotas (T2) |
| 14 | Remove fake scan progress; real scan-status polling (T14) |
| 15 | Legacy Stripe orphan handling (T7); RBAC/SSO/billing verification |
| 19 | CI gate (test + lint + build on push to main); classifier service in `render.yaml` |

## 9. Residual risk and assumptions

- After Day 7, the largest residual risks are architectural (T2 until Day 13)
  and procedural (backup/restore discipline, dependency hygiene). Neither is
  closed by this document.
- The model assumes Render/Vercel/Supabase enforce HTTPS and platform-level
  isolation correctly, and that Rishabh's own GitHub account and the
  `TURNSTILE_SECRET_KEY` / OAuth provider credentials are managed by him.
  Those assumptions are recorded, not verified, here.
- The model assumes the Day 1 audit's "verified good" tenant-isolation
  finding holds at this commit. The only code changes between `bf49b47`
  (audited) and `e8c7d31` (modelled) are cursor/logout UI, README copy, and
  the Day 1 + Day 2 docs — no auth, route, or query code changed — so the
  assumption is sound, and Day 5 re-verifies it against the live route
  inventory anyway.
- No threat in this model is marked resolved by documentation alone. Each
  fix day must produce code + test evidence, and the Day 7 gate re-checks
  every applicable item before Phase 4 starts.

## 10. Evidence index

- Day 1 audit: `docs/MASTER_PROJECT_AUDIT.md` (commit `bf49b47`).
- This run's verification greps (2026-11-16 ~01:00–02:00 IST): RBAC roles in
  `middleware/rbac.js` + 8 route files; audit-log helper `createAuditLog`
  (`middleware/rbac.js:106`) with call sites in organizations (9),
  billing, compliance, alerts, ai, auth, customRules, billingWebhook;
  rate limiters in `routes/auth.js` (register/login 10/15 min, reset 5/hr,
  account-delete 3/hr, OAuth callback), `routes/scans.js` (trigger 10/10
  min), `routes/public.js` (contact, analytics), `routes/integration.js`
  (webhook), `routes/customRules.js` (rule test); no limiter on
  `routes/auth.js:259` (`/refresh`) or `:426` (`/me`); CORS allow-list
  `backend/config/cors.js`; helmet without CSP `backend/server.js:54`;
  `vercel.json` headers (no CSP); zero `dangerouslySetInnerHTML` in `src/`;
  no `CREATE POLICY` in `backend/prisma/` migrations; no multer / file
  upload / Supabase storage use anywhere; no `.env` tracked (only
  `.env.example` files); gitleaks workflow
  `.github/workflows/secret-scan.yml`; `sg_refresh` cookie httpOnly +
  secure + SameSite=None (`routes/auth.js:75-81`); offline tests this run:
  `node --test backend/tests/aiFixEngine.test.js
  backend/tests/startup_routes.test.js` → 8 pass, 0 fail;
  `node backend/tests/astExtraction.test.js` → 4 pass, 0 fail.
- Live probes: frontend `https://secureguard-main.vercel.app/` 200;
  backend `https://securegaurd.onrender.com/health` 200;
  classifier `https://secureguard-classifier.onrender.com/health` 200
  (see the Day 3 run log for timings).
- Run log: `~/workspace/goals/securegaurd-20-day-transformation/hidden_files/day03-run-log.md`
