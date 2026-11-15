# SecureGaurd — Security Hardening Checklist (Day 3, 20-Day Transformation)

**Date:** 2026-11-16 (Day 3 of the 20-day program)
**Verified commit:** `e8c7d31` — "add day 2 competitor research and differentiation"
**Fix-all run:** 2026-11-16 ~01:15–02:30 IST — user ordered every FAIL /
PARTIAL / BLOCKED item fixed. Code pushed in 3 batches (heads `670755d`,
`25561d9`, `6dac31e`); live probes re-run after deploy. Statuses below
reflect the post-fix-all state. The RLS migration was deliberately NOT
pushed (Render's pre-deploy `prisma migrate deploy` would auto-apply it
before call-site conversion — see SEC-31).
**Repo:** `r1shabhsharma05/SecureGaurd` — app root `SecureGaurd-main/`
**Sources:** the seven reference screenshots supplied by Rishabh on 2026-11-13
(transcribed in `~/workspace/goals/securegaurd-20-day-transformation/hidden_files/REFERENCE_SCREENSHOTS.md`).
This checklist covers the **security items from screenshots 03, 06 and 07**
(website/SEO items from 01, 02, 05 are Day 16/17; UX items from 04 are
Day 14). Overlapping items across the three screenshots are merged into one
entry each and the source screenshots are named per item.

**WARNING — read before trusting any status here:** the checkmarks (✓/✗)
and "01/19 FIXED" shown in the reels are the creators' ILLUSTRATIVE states,
NOT SecureGaurd's status. Every status below was verified against
SecureGaurd's own source at the verified commit, with the evidence cited per
item. Nothing here copies a reel's checkmark.

**Status key:** PASS = verified working with evidence. FAIL = verified not
working / not present. PARTIAL = partly working, with a named gap.
BLOCKED = cannot be verified from here (external service / owner-only
dashboard / needs a live run). NOT APPLICABLE = the product has no such
feature, so the check does not apply. No blanket PASS anywhere in this
document.

## Summary counts

| Status | Count |
|---|---|
| PASS | 24 |
| PARTIAL | 15 |
| FAIL | 4 |
| BLOCKED | 0 |
| NOT APPLICABLE | 3 |
| **Total merged items** | **46** |

FAIL items (must clear before the Day 7 gate): SEC-03 (secrets in git
history — purge procedure ready, needs the owner's word), SEC-31 (Row Level
Security — migration written, not applied), SEC-32 (database backups —
never taken), SEC-34 (CAPTCHA fail-open — keys unset, re-confirmed live
2026-11-16). Fixed by the fix-all run: SEC-09 (email verification is a
real gate now), SEC-37 (fake scan progress removed), SEC-19 (CSP live on
both hosts). SEC-06 moved FAIL → PARTIAL (mongoose removed; file deletions
outstanding). SEC-13 moved BLOCKED → PARTIAL (measured: 15 findings,
3 HIGH; fixes not applied, CI workflow still to be pushed via browser).

Companion document: `docs/THREAT_MODEL.md` — the threat model behind these
checks, with the prioritized risk register (T1–T17) and the fix-day mapping.
Day 1 baseline: `docs/MASTER_PROJECT_AUDIT.md` (findings S1–S9 referenced
below).

---

## A. Secrets and credential protection

### SEC-01 — Hide API keys / API keys off the frontend
- **Status:** PASS
- **Sources:** screenshots 03, 06
- **Files inspected:** `src/` (all `import.meta.env` uses), `backend/config/env.js`,
  `backend/server.js`, `vercel.json`
- **Implementation evidence:** the frontend bundle contains only four
  non-secret `VITE_*` variables: `VITE_API_URL` (1 use),
  `VITE_ENABLE_SEVERITY_RANK` (1 use), `VITE_SENTRY_DSN` (2 uses),
  `VITE_TURNSTILE_SITE_KEY` (1 use). All real keys (`JWT_SECRET`,
  `JWT_REFRESH_SECRET`, `ENCRYPTION_KEY`, `DATABASE_URL`, `GEMINI_API_KEY`,
  `RAZORPAY_KEY_ID/SECRET`, `CLASSIFIER_API_KEY`, `BREVO_API_KEY`,
  `TURNSTILE_SECRET_KEY`, OAuth client secrets) are read server-side only.
  Backend startup fail-fasts if `JWT_SECRET`, `JWT_REFRESH_SECRET`,
  `ENCRYPTION_KEY` (64-hex) or `DATABASE_URL` is missing
  (`validateEnv()` in `backend/server.js`).
- **Test evidence:** no test asserts on this; verified by grep over `src/`
  this run. Offline test suite 12/12 pass (see §H).
- **Remaining risk:** low. A future `VITE_*` addition could leak a secret;
  no CI check blocks `VITE_` secrets today (Day 19 CI item).
- **Reviewer notes:** none.

### SEC-02 — Check env variables
- **Status:** PASS (with an UNVERIFIED caveat — see remaining risk)
- **Sources:** screenshot 03
- **Files inspected:** `backend/config/env.js`, `backend/server.js`,
  `render.yaml`, `SecureGaurd-main/.env.example`,
  `SecureGaurd-main/backend/.env.example`
- **Implementation evidence:** `validateEnv()` fail-fasts at startup on the
  four required secrets. `render.yaml` declares the production env (names
  only, all `sync: false`): `NODE_ENV=production`, `FRONTEND_URL`,
  `DATABASE_URL`, `JWT_SECRET`, `JWT_REFRESH_SECRET`, `ENCRYPTION_KEY`,
  `WEBHOOK_SECRET`, `GEMINI_API_KEY`, `CLASSIFIER_API_KEY`. Example files
  document the full 32-name backend inventory and 4 frontend names.
- **Test evidence:** `backend/tests/deployment_config.test.js` exists but is
  env-gated — it fails at import without real secrets (expected behaviour,
  not a code failure). Not run this run.
- **Remaining risk:** whether the optional keys (`TURNSTILE_SECRET_KEY`,
  `SENTRY_DSN`, OAuth provider credentials, `GEMINI_API_KEY`,
  `BREVO_API_KEY`/SMTP) are actually set in production Render/Vercel env is
  UNVERIFIED — only Rishabh can check those dashboards. Verification
  procedure for Day 4: owner opens the Render + Vercel dashboards and
  confirms presence (never prints values); record presence/absence per key.
- **Reviewer notes:** none.

### SEC-03 — Secrets in git history
- **Status:** FAIL
- **Sources:** screenshot 03
- **Files inspected:** git history; `.github/workflows/secret-scan.yml`
- **Implementation evidence:** a real `JWT_SECRET` was committed in
  `e1e3dc9` (2026-04-16) and removed in `0204134`. Rotation is recorded as
  done (Day 1 audit §4.2). The preventive control now exists: gitleaks runs
  on PRs and pushes to `main` over full history (`fetch-depth: 0`) and
  blocks any future `.env`/credential commit. No `.env` file is tracked
  today; only `.env.example` files are tracked. `.gitignore` ignores
  `*.env` and `backend/.env`.
- **Test evidence:** Day 1 secret-pattern grep over HEAD found no real
  secret values in the current tree (only test fixtures and UI placeholders).
- **Remaining risk:** the old secret value is still retrievable from pushed
  history by anyone with repo access. Rotation mitigates exploitation, but
  the history itself is still exposed.
- **Reviewer notes:** fix = history purge (needs Rishabh's word) or accept
  the residual risk in writing. Assigned Day 4.
  **Fix-all run (2026-11-16):** purge verdict SAFE subject to 2
  preconditions — (a) forks check at
  `github.com/r1shabhsharma05/SecureGaurd/forks` (browser), (b) owner
  confirms the current Render `JWT_SECRET` differs from the committed
  value. Verified: 241 commits, 2 authors only (236 ×
  rishabhsharma14426@gmail.com, 5 × your-email@gmail.com), 0 open PRs,
  no tags, 7 refs. Exact purge procedure prepared; **no rewrite
  executed** — destructive rewrite needs his word. Caveat: the 2026-11-08
  JWT rotation is assertion-only — no repo record proves the production
  value actually changed.

### SEC-04 — Protect JWT signing secrets / database credentials
- **Status:** PARTIAL
- **Sources:** screenshot 03 (Phase 3A)
- **Files inspected:** `backend/config/env.js`, `backend/server.js`,
  `backend/prisma/schema.prisma`
- **Implementation evidence:** `JWT_SECRET` / `JWT_REFRESH_SECRET` /
  `ENCRYPTION_KEY` are required at startup, never in code, never in the
  frontend bundle. `DATABASE_URL` is env-only. PATs are AES-256-GCM
  encrypted at rest (`backend/utils/cryptoUtils.js:11-51`).
- **Test evidence:** startup fail-fast verified by the env-gated
  `deployment_config.test.js` behaviour (fails without secrets).
- **Remaining risk:** least-privilege DB credentials are UNVERIFIED (Supabase
  dashboard, owner-only). Legacy plaintext PAT passthrough exists for
  pre-encryption values (`cryptoUtils.js:36-42`) — a migration gap, not a
  live leak. The old JWT secret in history is SEC-03.
- **Fix-all run (2026-11-16):** `backend/scripts/migrate-plaintext-pats.js`
  written (dry-run default, 7/7 self-test pass) to re-encrypt legacy
  plaintext PATs. Live run BLOCKED — no DB credentials on this VM; exact
  run procedure + least-privilege DB check procedure documented in the
  run report. Least-privilege DB credentials still UNVERIFIED.
- **Reviewer notes:** Day 4 checks the Supabase credential scope; Day 5+
  migrates legacy plaintext PATs.

### SEC-05 — Check exposed files
- **Status:** PARTIAL (credential string removed this run; rotation still owed)
- **Sources:** screenshot 03
- **Files inspected:** `SECURITY_AUDIT.md`, `.gitignore` (repo root +
  `SecureGaurd-main/`), `git ls-files`
- **Implementation evidence:** no `.env` tracked; `dist/` untracked and
  gitignored; `node_modules` ignored. `SECURITY_AUDIT.md:90` printed a
  dev MongoDB credential string (`glanexus_admin` + password) in plain text
  in a tracked doc — Day 1 finding S8. **Fixed this run:** the password
  value was redacted from `SECURITY_AUDIT.md` in the Day 3 commit; the
  finding text is preserved. Rotation of that dev credential is still owed
  (owner action, Day 4).
- **Test evidence:** `git ls-files | grep -i .env` returns only the three
  `.env.example` files. Post-redaction grep confirms the password string is
  gone from the file.
- **Remaining risk:** low after redaction, until the dev credential itself
  is rotated. The file is a Sep 2026 historical audit doc — its other
  claims are stale (see Day 1 §10) and it should not be treated as current.
- **Reviewer notes:** mark PASS once Day 4 confirms the dev credential
  rotation.
  **Fix-all run (2026-11-16):** the dev MongoDB is DEAD/UNUSED — the only
  references are the redacted doc line and a transitive mongoose dep
  (now removed, SEC-06). Rotation step = delete Atlas user
  `glanexus_admin` (owner-only; no Atlas target identifiable from the
  repo). The credential string itself is covered by the SEC-03 purge.

### SEC-06 — Unused packages (and stale duplicates)
- **Status:** PARTIAL (mongoose removed; stale file deletions outstanding)
- **Sources:** screenshot 03
- **Files inspected:** `backend/package.json`, `package.json`, repo tree
- **Implementation evidence:** `mongoose@^9.11.4` is declared in
  `backend/package.json` and never imported anywhere (Day 1 §6). A stale
  duplicate classifier copy exists at `classifier model/files/` (Oct 16;
  model 489 KB) alongside the live `backend/services/fp-classifier/` (Oct 23
  retrain, 296 KB). The generated Prisma client is committed
  (`backend/generated/prisma/`, ~8.6 MB of wasm + base64 JS).
  `sample_findings.csv` exists in 2 copies (same blob — corrected from the
  Day 3 claim of 3).
- **Test evidence:** none — inventory fact, not a test outcome.
- **Remaining risk:** low. Unused deps widen the supply-chain surface and
  confuse audits; the stale classifier copy risks being mistaken for the
  live model. Model files must NOT be touched without a documented reason,
  impact analysis and approval (standing rule) — the stale copy's removal
  needs that approval.
- **Reviewer notes:** cleanup assigned Day 19 (with the documented reason
  each). Do not delete the stale model copy unapproved.
  **Fix-all run (2026-11-16):** mongoose REMOVED from `backend/package.json`
  + lockfile (0 hits in lockfile; commit `670755d`). The stale classifier
  copy + committed `backend/generated/prisma/` are on the exact deletion
  list for the browser web-UI push (the GitHub App API cannot delete).
  Deleting the stale model copy still needs his approval per the standing
  rule.

---

## B. Authentication

### SEC-07 — Proper authentication (real login / logout, hashing, sessions)
- **Status:** PARTIAL
- **Sources:** screenshots 03, 06
- **Files inspected:** `backend/routes/auth.js`, `src/context/AuthContext.tsx`,
  `src/services/authService.ts`
- **Implementation evidence:** register/login/logout/session-restore wired
  end-to-end. Passwords bcrypt(12). Refresh tokens bcrypt-hashed, rotating,
  with reuse detection and atomic compare-and-swap plus a 60 s grace window
  (`auth.js:259-317`). Reset tokens are `crypto.randomBytes(32)`, SHA-256
  hash stored only, single-use, 1 h expiry; reset clears all sessions.
  Logout invalidates the refresh-token family. `sg_refresh` cookie is
  httpOnly + `secure: true` + `SameSite=None` (`auth.js:75-81`, documented
  as required for cross-site Vercel→Render). OAuth uses auth-code + PKCE
  with HMAC-signed state (`utils/oauth.js:89-115`).
- **Test evidence:** offline suite 12/12 pass. Live auth flows end-to-end
  NOT run against production (needs a throwaway test account — Day 7/18
  procedure, never real user data).
- **Remaining risk:** no MFA anywhere. OAuth providers shipped but none
  live (`docs/OAUTH_SSO.md`).
  **Fix-all run (2026-11-16):** email verification is now a real gate
  (SEC-09 PASS). `orgFetch` stale-token retry now uses the token
  `refreshSession()` returns (was re-sending the expired token);
  `completeOnboarding` throws on failure instead of completing locally
  (commit `670755d`). `/onboarding` is now behind the RequireAuth guard
  (SEC-44, commit `25561d9`).
- **Reviewer notes:** the auth core is unusually careful for a solo project;
  the gaps are verification and MFA, not the token machinery.

### SEC-08 — Hash passwords
- **Status:** PASS
- **Sources:** screenshot 03
- **Files inspected:** `backend/routes/auth.js`
- **Implementation evidence:** bcrypt cost 12 on register and password
  reset paths. No plaintext password storage; no password in logs or
  responses.
- **Test evidence:** code inspection; no dedicated unit test for the hash
  cost (Day 18 test item).
- **Remaining risk:** none known.
- **Reviewer notes:** none.

### SEC-09 — Email verification
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `backend/routes/auth.js`, `src/components/VerifyEmailPage.tsx`,
  `src/App.tsx`, `src/components/NeonAuth.tsx`, `src/components/Dashboard.tsx`
- **Implementation evidence:** verification is a real gate now (commit
  `670755d`): register returns 201 `{ requiresVerification: true }` and NO
  tokens until verified; login returns 403 `email_not_verified` for pending
  accounts; `/refresh` + `/me` are gated too. New `POST
  /api/auth/resend-verification` (5/hr, generic 200). `VerifyEmailPage.tsx`
  + `/verify-email` route + resend UI in NeonAuth and Dashboard Settings.
  Grandfathering: the gate applies only when a pending token exists
  (`emailVerifyToken != null`) — pre-existing accounts pass untouched, no
  migration, no lockout. Mailer: Brevo HTTP API preferred, SMTP fallback;
  register 503s honestly BEFORE creating the account if mail is
  unconfigured (row deleted if the send fails). Password-change endpoint +
  Dashboard card added (SEC-38).
- **Test evidence:** 8 new auth-verification tests pass
  (`backend/tests/authVerification.test.js`); vite build passes. LIVE
  probe 2026-11-16 ~02:20 IST: register
  `sg-fixall-20261116@example.com` → 201 `{ requiresVerification: true }`,
  no tokens; login → 403 `email_not_verified`. Resend route live: 200
  generic message. Deploy precondition: `BREVO_API_KEY`/SMTP must be set
  on Render or signup 503s (mail proven working in prod by the
  forgot-password probe, so risk is low).
- **Remaining risk:** low. The email-click verify step was NOT tested live
  (needs a mailbox to click the link). Leftover: the probe account
  `sg-fixall-20261116@example.com` is an unverified row in prod — it
  cannot self-delete (no token, login blocked); owner deletes via DB.
- **Reviewer notes:** fix Day 5: gate login/registration on verification,
  add verification + resend UI, add password-change UI (also missing).
  — DONE by the fix-all run, 2026-11-16.

### SEC-10 — Password reset
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `backend/routes/auth.js:345-411`,
  `src/services/authService.ts:28-48`
- **Implementation evidence:** hashed single-use token, 1 h expiry, clears
  all sessions on reset. Forgot-password and reset-password rate-limited
  5/hr (`resetLimiter`). Frontend reset flow wired.
- **Test evidence:** code inspection; live flow NOT run (needs a throwaway
  account — Day 7/18).
- **Remaining risk:** low. Turnstile on forgot-password is fail-open if
  unconfigured (SEC-30).
- **Reviewer notes:** none.

### SEC-11 — Real login and logout
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `backend/routes/auth.js:190-228` (login),
  `:318` (logout), `src/context/AuthContext.tsx`
- **Implementation evidence:** real credential check (bcrypt), real session
  creation, real logout (refresh-token revocation), session restore on
  reload via `/refresh`. No demo/hardcoded credentials.
- **Test evidence:** code inspection; live flow NOT run (throwaway account
  procedure, Day 7/18).
- **Remaining risk:** low. `/refresh` and `/me` are now rate-limited
  (SEC-17, fix-all run).
- **Reviewer notes:** none.

### SEC-12 — Delete account button
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `backend/routes/auth.js:632`,
  `backend/utils/accountDeletion.js`
- **Implementation evidence:** `DELETE /api/auth/account` requires the
  password + typed `DELETE`, is rate-limited 3/hr (`accountDeleteLimiter`),
  and cascades org-asset handoff to a remaining OWNER/ADMIN. Frontend
  delete-account flow exists.
- **Test evidence:** code inspection; live deletion NOT tested (destructive
  by nature — test only with a throwaway account, Day 18).
- **Remaining risk:** low. Legacy Stripe subscriptions block org deletion
  (SEC-33), which can strand a deleting user's org.
- **Reviewer notes:** none.

### SEC-13 — Update dependencies / dependency vulnerability scanning
- **Status:** PARTIAL (measured; fixes not applied, CI first run pending)
- **Sources:** screenshots 03, 07
- **Files inspected:** `package.json`, `backend/package.json`
  (dependency lists + outdated counts)
- **Implementation evidence:** `npm audit` is BLOCKED on this VM in both
  packages — the registry rejects the audit endpoint (403
  `policy_denied`, verified 2026-11-14). `npm outdated` works: root 15
  outdated / 6 major (incl. TypeScript 6→7, ESLint 9→10, framer-motion
  12→14); backend 10 outdated / 2 major (dotenv 17→18, Prisma 7→8.0.0-rc).
  The Sep 2026 readiness report's claim of 4 high Prisma advisories is
  stale and must be re-measured, not quoted.
  **Fix-all run (2026-11-16):** OSV scan of both lockfiles — 585 packages,
  **15 findings: 0 critical, 3 HIGH, 10 MODERATE, 2 LOW**, all transitive.
  HIGHs: body-parser 2.3.0, deepmerge-ts 7.1.5, mysql2 3.15.3 (auth-plugin
  downgrade leaking plaintext creds — fix first). Zero Prisma findings —
  the Sep 2026 "4 high Prisma advisories" claim is dead. Files:
  `.github/workflows/dependency-scan.yml` (npm audit, fails on
  high/critical, push + weekly + dispatch), `docs/DEPENDENCY_VULNERABILITIES.md`,
  `SecureGaurd-main/scripts/osv-scan.mjs`; raw JSON kept OUT of the repo
  (`~/workspace/goals/securegaurd-20-day-transformation/hidden_files/osv-scan-results-2026-11-16.json`).
- **Test evidence:** OSV scan output (measured baseline, not a PASS claim).
  The CI gate has NOT had its first run — the workflow file could NOT be
  pushed via the GitHub App API (403 on `git/trees`; the App cannot write
  `.github/workflows/`), so it must go via the browser web-UI push.
- **Remaining risk:** medium — 3 HIGHs unfixed; the scan is measured but
  the remediation is not done. Do not report it as clean.
- **Reviewer notes:** Day 4 runs dependency scanning in GitHub Actions (or
  another registry-allowed runner) and records the vulnerability list with
  evidence. This item stays BLOCKED until then — never PASS.
  — Updated: scan done 2026-11-16; remediation + first CI run still open.

---

## C. Authorization and data isolation

### SEC-14 — Protect admin routes / hide admin pages properly
- **Status:** PASS
- **Sources:** screenshots 03, 07
- **Files inspected:** `backend/middleware/rbac.js`,
  `backend/routes/billing.js`, `compliance.js`, `alerts.js`, `ai.js`,
  `classifier.js`, `customRules.js`, `src/App.tsx`
- **Implementation evidence:** privileged routes enforce
  `requireOrgRole(['OWNER', 'ADMIN'])` or `['OWNER', 'ADMIN',
  'DEVELOPER']` (billing invoices, compliance generate/delete, alert
  settings/test, AI fix generate/apply, classifier status, custom-rule
  writes). There is no standalone admin page in the frontend (13 routes in
  `src/App.tsx`; none admin-only); privileged UI (organisation settings,
  alerts, compliance, custom rules) is role-gated in the UI and
  server-enforced. Frontend role checks are cosmetic; the backend is
  authoritative.
- **Test evidence:** code inspection; live RBAC matrix NOT run (needs two
  test orgs + test users — Day 5/7 procedure).
- **Remaining risk:** low, conditional on the Day 5 route-matrix
  re-verification (the 2026-10-24 matrix is stale, 32 commits since).
- **Reviewer notes:** none.

### SEC-15 — Users access own data / stop IDOR bugs / organization isolation
- **Status:** PARTIAL
- **Sources:** screenshots 03, 07
- **Files inspected:** `backend/middleware/rbac.js:36-57`,
  `backend/routes/scans.js:137-144`, `vulnerabilities.js:42-56`,
  `repos.js:154-164`, `compliance.js`, `sboms.js`, `customRules.js`,
  `ai.js`, `ml.js`
- **Implementation evidence:** every `:id` lookup spot-checked scopes by
  org (Day 1 §4.2 — no unscoped `:id` fetch found). BUT
  `requireOrgContext` silently falls back to the caller's first org on a
  malformed org id (`!isNaN(parseInt(...))` gate; `parseInt("12abc")`
  coerces to 12) instead of 400ing — Day 1 finding S3 (Medium), threat
  T4. Wrong-org data can be returned for a malformed header.
- **Test evidence:** code inspection; live cross-tenant IDOR matrix NOT run
  (Day 5/7 procedure: two test orgs, cross-org reads/writes on every `:id`
  route, expect 404).
  **Fix-all run (2026-11-16):** `requireOrgContext` now strict-validates
  org ids (`/^\d+$/`, else 400, no DB lookup, no fallback to first org) —
  commit `670755d`. New `backend/tests/rbac.test.js` (8 tests); offline
  suite 20/20. Live cross-tenant matrix still BLOCKED: it needs two
  verified accounts + two orgs, and verification needs a mailbox to click
  the link — no mailbox is available from this VM (using the user's own
  email for a probe account was NOT done without his word).
- **Remaining risk:** medium until S3 is fixed (Day 5) and the live matrix
  passes (Day 7 gate). S3 fix is done; the live matrix is the remaining
  step.
- **Reviewer notes:** do not mark PASS until both the S3 fix and the live
  matrix land.

### SEC-16 — Auth on every API route / never trust the frontend
- **Status:** PARTIAL
- **Sources:** screenshot 07
- **Files inspected:** `backend/server.js:74-119` (router mounts),
  `docs/route-auth-matrix.md`, `backend/routes/public.js`
- **Implementation evidence:** 17 routers mounted under `/api/*`; all
  require auth except deliberate public endpoints: `GET /health`, `POST
  /api/analytics/events` (rate-limited), `POST /api/contact`
  (rate-limited, validated, honeypot), OAuth callback (rate-limited),
  and `GET /api/_test-error` (only when `SENTRY_TEST_ROUTE=enabled`).
  Spot-checks pass. BUT `docs/route-auth-matrix.md` (audited 2026-10-24)
  claims every route is exactly one of AUTH+ORG / AUTH /
  PUBLIC-DELIBERATE, and 32 commits have landed since — the backend
  inventory (88 router routes + 2 server-level) was not fully re-checked
  against it.
- **Test evidence:** code inspection; `backend/tests/security_audit_test.js`
  and `phase2_rbac_multitenancy_verify.js` exist but need a live server +
  DB (not run).
  **Fix-all run (2026-11-16):** **92/92 routes checked** (90 router + 2
  server-level), **no holes** — commit `6dac31e`. Matrix rewritten at
  `SecureGaurd-main/docs/route-auth-matrix.md` (stale Oct 24 corrections:
  missing /alerts + /custom-rules routers, Razorpay billing, 13 new
  routes). Live cross-tenant matrix still outstanding — same blocker as
  SEC-15 (needs two verified accounts; no mailbox from this VM).
- **Remaining risk:** medium. One unprotected route added since Oct 24
  would be a live hole. Code-level re-verification is now done; the live
  matrix is the remaining step.
- **Reviewer notes:** full re-verification is Day 5; the Day 7 gate
  requires it to pass.

---

## D. Backend security

### SEC-17 — Rate limiting
- **Status:** PARTIAL
- **Sources:** screenshots 03, 06, 07
- **Files inspected:** `backend/routes/auth.js:26-60,472`,
  `backend/routes/scans.js:157-167`, `backend/routes/public.js:37-45`,
  `backend/routes/integration.js:14`, `backend/routes/customRules.js:22-25`
- **Implementation evidence:** limiters exist and are attached:
  register/login 10 per 15 min; forgot/reset-password 5/hr; account-delete
  3/hr; OAuth callback limited; scan trigger 10 per 10 min; webhook
  limited; contact + analytics limited; custom-rule test limited.
  Standard headers on, legacy headers off. GAPS: `POST /api/auth/refresh`
  (`auth.js:259`) and `GET /api/auth/me` (`auth.js:426`) have NO limiter —
  Day 1 finding S4 (Low). Refresh guessing is bcrypt-bound per attempt,
  but unlimited attempts are allowed; `/me` mints a fresh access token
  per call with no rotation.
- **Test evidence:** code inspection; live rate-limit tests NOT run (would
  need to hammer production — Day 6 procedure against a staging/local
  stack, or carefully rate-limited live probes).
  **Fix-all run (2026-11-16):** `refreshLimiter` 30/15min + `meLimiter`
  60/15min added (commit `670755d`). Live trigger probe 2026-11-16:
  35 rapid `POST /api/auth/refresh` → 35× 401, no 429 — INCONCLUSIVE,
  not a limiter failure: the VM's egress IP rotates per request and the
  limiters key on `req.ip` (same confound as the SafeLife 6.1 probes).
  Live 429 proof needs a stable IP or Render logs.
- **Remaining risk:** low, but the two gaps are real and cheap to close.
  Gaps closed in code; live trigger proof outstanding.
- **Reviewer notes:** fix Day 6.

### SEC-18 — Sanitize user input / sanitize forms
- **Status:** PARTIAL
- **Sources:** screenshots 03, 07
- **Files inspected:** `backend/utils/publicSite.js:52-85`
  (`validateContactInput`), `backend/routes/public.js:87-92`,
  `backend/routes/scans.js:167-175` (repositoryId validation),
  `backend/routes/auth.js` (per-route checks)
- **Implementation evidence:** contact input is validated
  (`validateContactInput` + honeypot) and rejected with 400s; scan trigger
  validates `repositoryId`; auth routes validate inputs per-route. There is
  NO shared validation library (no zod, no express-validator) and NO
  sanitization library (no DOMPurify — correctly not needed, since nothing
  renders raw user HTML; see SEC-21). "Sanitize" hits elsewhere in the
  backend are AI-fix suggestion text and SBOM ref sanitizing, not input
  handling.
- **Test evidence:** code inspection; no validation unit tests found.
  **Fix-all run (2026-11-16):** zod 4.6.7 installed; new
  `backend/utils/validation.js` (`validateBody`, `validateQuery`, `zEmail`,
  `zPassword`, `zIntId`, `zString`, `zPagination`, contact + scan-trigger
  schemas); applied to `public.js` contact + `scans.js` trigger /
  export-feedback (commit `670755d`). Merge-time bug caught + fixed:
  assigning `req.query` throws on Express 5.3.0 (getter-only) — fixed
  with `Object.defineProperty` shadowing + a real-Express-5 regression
  test. Validation tests **11/11 pass** (live check: `/t` → 200,
  `/t?limit=abc` → 400).
- **Remaining risk:** medium. Validation is ad-hoc per route; a missed
  check on a new route is a live bug. Standardise on Day 6. The shared
  library now exists and is wired into the highest-risk routes (contact,
  scan trigger, auth change-password); remaining POST/PATCH routes still
  use per-route checks — apply `validateBody` to them as follow-up.
- **Reviewer notes:** do not confuse the scanner's `sanitizerPatterns.json`
  (AST feature detection) with input sanitization — different thing.

### SEC-19 — Security headers
- **Status:** PASS
- **Sources:** screenshots 03, 07
- **Files inspected:** `backend/server.js:54`, `vercel.json`
- **Implementation evidence:** helmet is mounted (CORP relaxed to
  `cross-origin`). Vercel serves `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy:
  strict-origin-when-cross-origin`, `Permissions-Policy: camera=(),
  microphone=(), geolocation=()`, `Cross-Origin-Opener-Policy:
  same-origin` on all routes, plus immutable 1-year cache on `/assets/*`.
  **Fix-all run (2026-11-16):** CSP added — `vercel.json` (SPA, exact
  sha256 hash for the JSON-LD inline script, no `unsafe-inline`) + helmet
  CSP on the API (`default-src 'none'; frame-ancestors 'none'; base-uri
  'none'`) — commits `670755d` / `25561d9`.
- **Test evidence:** header list read from `vercel.json` this run; live
  header probe NOT run (Day 6/19 procedure: `curl -I` the live site and
  record headers).
  **LIVE probe 2026-11-16 ~02:20 IST (post-deploy):** `curl -I
  https://secureguard-main.vercel.app/` → `Content-Security-Policy:
  default-src 'self'; script-src 'self' https://challenges.cloudflare.com
  'sha256-kMmCx3PdlC2uIS/i/kHI6X5BO2x37lUcyiklQI3zmtM'; … frame-ancestors
  'none'` + `X-Content-Type-Options: nosniff`. Backend `/health` →
  `content-security-policy: default-src 'none';frame-ancestors 'none';
  base-uri 'none'`. Both hosts serve CSP.
- **Remaining risk:** low. CSP is live; keep the sha256 hash in sync if
  the JSON-LD inline script ever changes.
- **Reviewer notes:** fix Day 6 (add CSP), verify live on Day 19.
  — DONE by the fix-all run, 2026-11-16.

### SEC-20 — Block XSS
- **Status:** PASS
- **Sources:** screenshot 03
- **Files inspected:** `src/` (all `.tsx`/`.ts`)
- **Implementation evidence:** **zero** `dangerouslySetInnerHTML` uses in
  the entire frontend. React auto-escapes all interpolated values. No user
  content is rendered as raw HTML. Helmet + `nosniff` headers are set
  (SEC-19).
- **Test evidence:** grep this run (0 hits). No XSS test suite exists
  (Day 18 item).
- **Remaining risk:** low. CSP is now live (SEC-19, fix-all run) — the
  second layer exists.
- **Reviewer notes:** none.

### SEC-21 — Check CORS settings / lock down CORS
- **Status:** PASS
- **Sources:** screenshots 03, 07
- **Files inspected:** `backend/config/cors.js`, `backend/server.js:55`
- **Implementation evidence:** allow-list, no wildcard: localhost dev
  origins + `FRONTEND_URL` / `FRONTEND_URLS` + a Vercel-preview regex
  scoped to this project's team slug
  (`secureguard-main-<suffix>-rish0000-dots-projects.vercel.app`), so it
  cannot match another team's `secureguard-main-*` site. `credentials:
  true`; unlisted origins are denied without an error (the CORS callback
  throws are handled so they don't become 500s). Non-browser requests with
  no `Origin` header pass through (standard; auth still applies).
- **Test evidence:** code inspection; live CORS probe NOT run (Day 6
  procedure: preflight from an unlisted origin, expect no
  `Access-Control-Allow-Origin`).
- **Remaining risk:** low.
- **Reviewer notes:** none.

### SEC-22 — Input validation (backend) — see SEC-18
- **Status:** PARTIAL — merged into SEC-18 (same evidence, same gap).
  Fix-all run: shared zod library exists + 3 routes wired (see SEC-18);
  remaining routes still ad-hoc.
- **Sources:** screenshot 03 ("sanitize forms" overlaps screenshot 06
  "form validation" — the frontend half is SEC-34).
- **Reviewer notes:** kept as a pointer so the screenshot-03 item is not
  lost in the merge.

### SEC-23 — Secure file uploads / check file upload types
- **Status:** NOT APPLICABLE
- **Sources:** screenshot 07
- **Files inspected:** `backend/` + `src/` (grep for multer, upload
  handlers, Supabase storage)
- **Implementation evidence:** there is NO file-upload feature anywhere:
  no multer, no `upload.single/array`, no Supabase storage use. API-spec
  scanning is URL/paste only. Avatars are not a feature (no avatar code
  found).
- **Test evidence:** grep this run (0 hits).
- **Remaining risk:** none — but if file upload is ever added, it must ship
  with type allow-listing, size caps, virus scanning and private storage
  from day one.
- **Reviewer notes:** revisit if Day 12+ adds uploads.

### SEC-24 — Private storage buckets
- **Status:** NOT APPLICABLE
- **Sources:** screenshot 07
- **Files inspected:** same as SEC-23
- **Implementation evidence:** no storage buckets exist (no file storage
  feature). Supabase is used as PostgreSQL only.
- **Test evidence:** grep this run (0 hits for storage/bucket use).
- **Remaining risk:** none.
- **Reviewer notes:** if Supabase Storage is ever adopted, buckets must be
  private with signed URLs and RLS — record that here at the time.

### SEC-25 — HTTPS everywhere / force HTTPS
- **Status:** PASS (platform-enforced; one on-prem caveat)
- **Sources:** screenshots 01-adjacent, 07
- **Files inspected:** `vercel.json`, `render.yaml`, `nginx.conf`
- **Implementation evidence:** Vercel and Render both serve HTTPS by
  default with automatic certificates; the Vercel `/api/*` rewrite points
  at `https://securegaurd.onrender.com/api/:path*`. `trust proxy` is set
  (default 1 hop) so rate limiting sees real client IPs behind the proxy.
  Caveat: the on-prem `nginx.conf` serves plain HTTP — documented as
  on-prem only, and `docs/ON_PREM.md` states the compose setup was
  statically verified only, never smoke-tested.
- **Test evidence:** live probes this run hit `https://` endpoints only
  (frontend 200, backend `/health` 200, classifier `/health` 200).
- **Remaining risk:** low. On-prem TLS is an operator responsibility if
  that path is ever used (Day 19).
- **Reviewer notes:** none.

### SEC-26 — Debug mode off in production
- **Status:** PASS
- **Sources:** screenshots 03, 07
- **Files inspected:** `backend/server.js:89-93`, `backend/utils/sentry.js`,
  `backend/config/env.js:42`, `render.yaml`
- **Implementation evidence:** no debug endpoints exist by default. The
  forced Sentry test error (`GET /api/_test-error`) exists ONLY when
  `SENTRY_TEST_ROUTE=enabled`, and the env doc warns to set it only to
  verify Sentry, then remove it. `render.yaml` sets
  `NODE_ENV=production`. Prisma uses minimal error format in production.
  Generic 500s with no stack leak.
- **Test evidence:** code inspection; production presence of
  `SENTRY_TEST_ROUTE` is UNVERIFIED (owner dashboard check, Day 4 —
  confirm it is unset).
- **Remaining risk:** low, conditional on that Day 4 check.
- **Reviewer notes:** none.

### SEC-27 — Verify webhook signatures
- **Status:** PASS
- **Sources:** screenshot 07
- **Files inspected:** `backend/routes/integration.js`,
  `backend/routes/billingWebhook.js`, `backend/utils/razorpay.js`
- **Implementation evidence:** GitHub HMAC-SHA256 over the raw body,
  GitLab token, per-repo secret first then shared fallback, timing-safe
  compare, fail-closed; idempotency via `WebhookDelivery`. Razorpay HMAC
  verify + ordering guard + idempotency; billing webhook mounted before
  `express.json` so the raw body survives for HMAC. Fail-closed on
  placeholder credentials.
- **Test evidence:** code inspection + Day 1. Live webhook tests NOT run
  (would need a real repo webhook delivery — Day 12/18 procedure).
- **Remaining risk:** low. Known race: Razorpay idempotency check sits
  outside the transaction (SEC-31).
- **Reviewer notes:** none.

### SEC-28 — SSRF prevention
- **Status:** PASS (with a noted residual)
- **Sources:** Phase 3D (plan requirement, covered by screenshots 03/07
  indirectly via "secure database / check exposed files" — recorded here
  because the scanner fetches arbitrary URLs)
- **Files inspected:** `backend/utils/ssrfGuard.js`,
  `backend/utils/repoScanSource.js:17-157`
- **Implementation evidence:** pinned-IP socket fetch, single DNS
  resolution, redirect re-validation, 2 MB cap for URL fetches. Git clone
  is anonymous HTTPS only, host allowlist `github.com`/`gitlab.com` (+
  `EXTRA_GIT_HOSTS`), credentials in URLs rejected, SSH remotes rewritten
  to HTTPS, PAT never passed to git.
- **Test evidence:** code inspection + 2026-11-08 fix round (DNS-rebinding
  pinning). No live SSRF test run (Day 6 procedure, against a staging
  stack — never point a live SSRF probe at internal metadata endpoints
  from production).
- **Remaining risk:** low. The clone path notes its own TOCTOU residual,
  bounded by the host allowlist.
- **Reviewer notes:** none.

### SEC-29 — Secure error responses / no stack traces in production
- **Status:** PASS
- **Sources:** Phase 3D
- **Files inspected:** `backend/server.js` (error handler, Sentry last)
- **Implementation evidence:** generic 500s; Sentry error handler is last
  middleware; no stack traces in responses. Frontend has `ErrorBoundary`
  + toast error states.
- **Test evidence:** code inspection; live probe of a bad route returns
  `Cannot GET /` (404, no stack) — confirmed Day 1.
- **Remaining risk:** low.
- **Reviewer notes:** none.

---

## E. Database security

### SEC-30 — Parameterized queries
- **Status:** PASS
- **Sources:** screenshot 07
- **Files inspected:** `backend/prisma/schema.prisma`,
  `backend/routes/*.js`, `backend/utils/*.js`
- **Implementation evidence:** all data access goes through Prisma
  parameterized queries. The only raw SQL in app code is
  `pg_advisory_xact_lock` in `organizations.js:307,380` and `repos.js:85`
  (parameterized template tags — safe). `$queryRaw` appears only in
  `tests/verify_db_schema.js` (test-only).
- **Test evidence:** code inspection; offline suite 12/12 pass.
- **Remaining risk:** low.
- **Reviewer notes:** none.

### SEC-31 — Row Level Security
- **Status:** FAIL
- **Sources:** screenshots 06, 07
- **Files inspected:** `backend/prisma/` (all 7 migrations + schema)
- **Implementation evidence:** NO `CREATE POLICY` / `ENABLE ROW LEVEL
  SECURITY` statement exists in any migration. Tenant isolation is
  enforced ONLY in application code (Prisma `where: { organizationId }`),
  which Day 1 verified as correctly applied on every spot-checked route —
  but a single missed `where` is a cross-tenant leak, and there is no
  second layer. Supabase project `wkvvxqlflhjiqkhwxrsl` (ap-southeast-1).
- **Test evidence:** grep this run (0 policy hits). No DB-level test exists.
  **Fix-all run (2026-11-16):** RLS migration written —
  `backend/prisma/migrations/20261116_rls_policies/migration.sql` (534
  lines, 16 policies, 13 tables, `FORCE ROW LEVEL SECURITY`, backfill,
  self-check) + `backend/utils/rlsContext.js` (per-transaction session
  vars `app.current_org_id` / `app.current_user_id` via SET LOCAL) + 12/12
  tests. **Validated against real PostgreSQL 17.5 via PGlite: 42/42
  checks pass** (cross-org reads 0 rows, unset-var reads 0 rows,
  AuditLog UPDATE/DELETE raise). **NOT applied — stays FAIL until the
  live matrix passes.**
- **Remaining risk:** medium. This is the defence-in-depth gap behind
  SEC-15 (S3). **Rollout order (non-negotiable):** (1) deploy rlsContext
  + convert call sites (NOT done yet — call-site list in
  `SecureGaurd-main/docs/BACKUP_AND_RESTORE.md` §5.1), (2) verify the app
  DB user is NOT superuser (if `postgres`, create `secureguard_app` role
  + repoint Render `DATABASE_URL` — without this RLS is a no-op even with
  FORCE), (3) backfill check, (4) apply the migration via the browser SQL
  Editor, (5) live cross-tenant matrix. **The migration was deliberately
  NOT pushed to main** — Render's pre-deploy `prisma migrate deploy`
  would auto-apply it on the next deploy, and with no call-site
  conversion every org-scoped query would return zero rows.
- **Reviewer notes:** implement Postgres RLS on Day 7, with the live
  cross-tenant matrix as the verification. The app connects with a single
  `DATABASE_URL` credential — RLS design must account for that (either a
  per-request session variable or a separate restricted role), or it does
  not actually enforce anything.

### SEC-32 — Database backups
- **Status:** FAIL
- **Sources:** screenshot 06
- **Files inspected:** `docs/BACKUP_AND_RESTORE.md`
- **Implementation evidence:** the doc states honestly that NO backup has
  ever been taken and NO trial restore has ever been performed. Supabase
  PITR/backup status is UNVERIFIED (owner dashboard check, Day 4/7).
- **Test evidence:** none — absence of backups is itself the evidence.
  **Fix-all run (2026-11-16):** honestly still FAIL — the Supabase
  Management API returns 403 (the connected token only sees the "Saftey
  App" org, not project `wkvvxqlflhjiqkhwxrsl`); PITR unverified.
  `docs/BACKUP_AND_RESTORE.md` updated with the true status + a
  restore-test procedure (cannot run from here — no `pg_dump`, no
  `DATABASE_URL`).
- **Remaining risk:** high. A destructive bug, a bad migration, or a
  Supabase incident is unrecoverable. This is a Day 7 production blocker.
- **Reviewer notes:** Day 7 must take a backup AND restore-test it into a
  disposable database and record the procedure. Do not mark PASS on a
  backup that was never restored.

### SEC-33 — Secure database (general: least privilege, migrations, retention)
- **Status:** PARTIAL
- **Sources:** screenshot 03
- **Files inspected:** `backend/prisma/schema.prisma` (19 models),
  `backend/prisma/migrations/` (7 migrations), `render.yaml`
- **Implementation evidence:** migrations are versioned and applied via
  `prisma migrate deploy` as a Render pre-deploy command. Sensitive data
  (PATs, webhook secrets, Slack URLs) is encrypted at rest. Audit logging
  exists (`AuditLog` model). GAPS: no RLS (SEC-31), no backups (SEC-32),
  least-privilege DB credentials UNVERIFIED, no data-retention rules
  documented, no DB-level append-only enforcement on audit logs.
  **Fix-all run (2026-11-16):** `docs/DATA_RETENTION.md` created
  (AuditLog 365d, AnalyticsEvent 90d, etc.; no purge job exists yet).
  AuditLog append-only trigger is in the RLS migration (PGlite-verified)
  — not applied yet (SEC-31).
- **Test evidence:** `backend/tests/verify_db_schema.js` exists (needs live
  DB; not run).
- **Remaining risk:** medium — carried by SEC-31/SEC-32.
- **Reviewer notes:** Day 7 covers backups + RLS + retention; Day 19
  covers the migration/CI story.

---

## F. Production security

### SEC-34 — CAPTCHA on public forms
- **Status:** FAIL
- **Sources:** screenshot 07
- **Files inspected:** `backend/utils/turnstile.js`,
  `backend/routes/auth.js:98,333`, `backend/routes/public.js:87`,
  `src/components/TurnstileWidget.tsx`
- **Implementation evidence:** the Turnstile integration is fully built —
  widget in the frontend, server-side verification against Cloudflare's
  `siteverify` API, hard 400 on a missing/invalid token and 503 on a
  Cloudflare outage WHEN the key is set. BUT with `TURNSTILE_SECRET_KEY`
  unset the guard passes requests through and logs one loud warning
  (deliberate tradeoff, documented in `turnstile.js`: fail-closed broke
  signup/forgot-password/contact for every user from 2026-11-08 to
  2026-11-09 because the keys were never set). Whether the key is set in
  production is UNVERIFIED (owner-only dashboards). Day 1 finding S2
  (Medium); threat T3.
- **Test evidence:** code inspection; live signup bot-protection NOT
  verified (cannot verify without attempting a signup — Day 4 owner check).
  **LIVE re-probe 2026-11-16 ~02:20 IST: FAIL confirmed** — Turnstile key
  still unset: signup, forgot-password and contact all succeed with no
  token (the fix-all register probe returned 201 with no Turnstile token).
  No code change (fail-closed would repeat the Nov 8 outage; the warning
  is already loud). Exact owner steps: Cloudflare Turnstile widget (domain
  `secureguard-main.vercel.app`) → `TURNSTILE_SECRET_KEY` on Render
  (`secureguard-api`) + `VITE_TURNSTILE_SITE_KEY` on Vercel
  (`secureguard-main`, Production) → redeploy both → re-probe must 400
  without a token.
- **Remaining risk:** medium — no bot protection on signup, password reset
  or contact until the key is set.
- **Reviewer notes:** fix = Rishabh creates the Turnstile widget in
  Cloudflare and sets `TURNSTILE_SECRET_KEY` on Render +
  `VITE_TURNSTILE_SITE_KEY` on Vercel (his step, Day 4). Do NOT flip the
  guard to fail-closed before the keys exist — that repeats the Nov 8
  outage.

### SEC-35 — Log admin actions
- **Status:** PASS
- **Sources:** screenshot 07
- **Files inspected:** `backend/middleware/rbac.js:106-126`
  (`createAuditLog`), call sites in `organizations.js` (9),
  `billing.js`, `compliance.js`, `alerts.js`, `ai.js`, `auth.js:714-726`,
  `billingWebhook.js:175`, `customRules.js`
- **Implementation evidence:** `createAuditLog(organizationId, actorId,
  action, targetType, targetId, details)` writes to the `AuditLog` table
  and is called on org create/update/delete, member/invite changes,
  billing events, compliance report generate/delete, alert-settings
  changes, AI fix generate/apply/false-positive, account deletion, and
  webhook billing events.
- **Test evidence:** code inspection; no test asserts audit-log coverage.
- **Remaining risk:** low. Coverage was not exhaustively audited per
  privileged action — a Day 7 spot-check should confirm every
  OWNER/ADMIN-only route writes a log row.
- **Reviewer notes:** none.

### SEC-36 — Loading states / empty states / clear error messages
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `src/components/Skeleton.tsx`,
  `src/components/EmptyState.tsx`, `src/components/Toast.tsx`,
  `src/components/ErrorBoundary.tsx`, `src/components/Dashboard.tsx`
- **Implementation evidence:** skeleton loaders, empty states, toast
  notifications and an error boundary all exist and are used across the
  dashboard. Server errors are generic and user-safe (SEC-29).
- **Test evidence:** code inspection (Day 1 §3.1). No frontend tests exist
  (0 test files in `src/` — Day 18).
- **Remaining risk:** low. The fake scan progress (SEC-37) is removed
  (fix-all run).
- **Reviewer notes:** none.

### SEC-37 — Fake scan progress (integrity check, not in the screenshots)
- **Status:** PASS
- **Sources:** Day 1 audit §3.3.1 (not a screenshot item; included so the
  checklist does not certify a flow it knows is mocked)
- **Files inspected:** `src/components/Dashboard.tsx`, `src/components/OnboardingWizard.tsx`
- **Implementation evidence:** the dashboard ran a 2.4 s interval cycling
  random filenames from a hardcoded `SCAN_FILES` list and animated 0→100%
  BEFORE the real scan trigger fired. Cosmetic progress presented as a
  live scan — mock UX in a production flow, against the plan's rule 11.
  **Fix-all run (2026-11-16):** FIXED in `Dashboard.tsx` — the fake
  interval + 0→100% animation are removed; an honest indeterminate
  spinner + real `GET /api/scans/:id` poll (2 s, 2-min cap) replaces them
  (commit `25561d9`). The same fake-progress pattern in
  `OnboardingWizard.tsx` was fixed in the same run (indeterminate bar +
  static "Scan running…" text). Frontend build passes (1.66 s).
- **Test evidence:** code inspection (Day 1 + this run). Grep confirms zero
  remaining references to the fake progress state.
- **Remaining risk:** none known — the flow is honest now.
- **Reviewer notes:** fix Day 14: remove the fake progress, poll real scan
  status (`GET /api/scans/:id`, as the onboarding wizard already does).
  — DONE by the fix-all run, 2026-11-16.

### SEC-38 — Form validation (frontend)
- **Status:** PARTIAL
- **Sources:** screenshot 06
- **Files inspected:** `src/pages/`, `src/components/` (validation
  markers), `backend/utils/publicSite.js` (server side, SEC-18)
- **Implementation evidence:** 35 `required` / `pattern` / `minLength` /
  `maxLength` markers across pages and components; server-side contact
  validation exists. GAPS: no shared validation schema, no
  password-change UI at all (Dashboard Settings promises it in copy,
  `Dashboard.tsx:824`), no email-verification UI (SEC-09).
  **Fix-all run (2026-11-16):** password-change endpoint + Dashboard
  Settings card added; verification + resend UI added (NeonAuth +
  Dashboard Settings + `VerifyEmailPage.tsx`) — commits `670755d` /
  `25561d9`. No shared FRONTEND validation schema yet.
- **Test evidence:** code inspection; no frontend tests (Day 18).
- **Remaining risk:** low. Server-side validation is the real control and
  exists where it matters most (contact, scan trigger, auth).
- **Reviewer notes:** fix the missing UIs on Day 5 (verification,
  password change). — DONE by the fix-all run, 2026-11-16.

### SEC-39 — Mobile layout
- **Status:** PARTIAL
- **Sources:** screenshot 06
- **Files inspected:** `src/` (28 `@media` queries counted Day 1)
- **Implementation evidence:** responsive CSS exists (28 `@media`
  queries). No device verification has ever been done.
  **Fix-all run (2026-11-16):** real viewport check (headless Chromium,
  390×844 and 360×740, `/`, `/login`, `/dashboard` unauth): NO horizontal
  overflow anywhere. Fixes shipped (commit `25561d9`): hamburger button
  (≤768px) opening the sidebar as a fixed overlay drawer — the HIGH
  finding (sidebar was `display:none`, all 10 nav items unreachable on
  phones); scan-history tables wrapped in an `overflow-x` scroller
  (MEDIUM); vuln table wrapper `overflow-x: auto` (LOW). The hamburger
  markup + styles ship in the built bundle (verified in `dist/`).
- **Test evidence:** none — static attributes only. Now: viewport probe
  (above) + frontend build green.
- **Remaining risk:** low. A layout bug on a phone is a UX defect, not a
  security hole. The AUTHENTICATED dashboard was NOT measured (needs a
  login) — that check is still open.
- **Reviewer notes:** real-device check is Day 14/18.

### SEC-40 — Custom 404 page
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `src/components/NotFound.tsx`,
  `src/App.tsx:129` (catch-all route)
- **Implementation evidence:** catch-all `*` route renders `NotFound`.
- **Test evidence:** code inspection; live 404 NOT probed this run (Day 1
  confirmed the backend 404 shape; frontend 404 is a Day 14/18 check).
- **Remaining risk:** none known.
- **Reviewer notes:** none.

### SEC-41 — Analytics installed
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `backend/routes/public.js:53,132`,
  `backend/routes/auth.js` (analytics references)
- **Implementation evidence:** product analytics are wired:
  `POST /api/analytics/events` (rate-limited, public) and `GET
  /api/analytics/summary` (authenticated). Events persist to the
  `AnalyticsEvent` table.
- **Test evidence:** code inspection.
- **Remaining risk:** low. This is first-party product analytics, not a
  third-party tracker — no cookie-consent dependency arises from it.
  Third-party analytics (if ever added) needs a privacy-policy update.
- **Reviewer notes:** none.

### SEC-42 — Error tracking
- **Status:** PARTIAL
- **Sources:** screenshot 06
- **Files inspected:** `src/main.tsx:10-16`, `backend/utils/sentry.js`,
  `backend/server.js`
- **Implementation evidence:** Sentry is wired on both sides and env-gated
  (only initialises when the DSN is set). The backend error handler is the
  Sentry handler, last in the chain.
- **Test evidence:** code inspection. Whether `SENTRY_DSN` is actually set
  in production Render/Vercel env is UNVERIFIED (owner dashboard check,
  Day 4).
- **Remaining risk:** low. Without a DSN, errors are invisible in
  production — an observability gap, not a vulnerability.
- **Reviewer notes:** confirm DSN presence on Day 4; add the Day 19
  monitoring item.

### SEC-43 — Privacy policy page / terms page
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `src/components/LegalPages.tsx`,
  `src/App.tsx:122-123`
- **Implementation evidence:** `/privacy` and `/terms` routes render the
  legal pages. Cookie consent banner exists (`CookieConsent.tsx`).
- **Test evidence:** code inspection (Day 1 §3.1).
- **Remaining risk:** low. Legal content accuracy (does the policy match
  actual data practices — e.g. no third-party tracker is named) is a Day
  16 review, not a code check. Cookie policy / refund policy pages are
  Day 16 items (screenshots 01/05), not this checklist.
- **Reviewer notes:** none.

### SEC-44 — Onboarding flow
- **Status:** PASS
- **Sources:** screenshot 06
- **Files inspected:** `src/components/OnboardingWizard.tsx`,
  `src/App.tsx:124`
- **Implementation evidence:** onboarding wizard is wired (connect repo,
  first scan, invite) and polls real scan status (`GET /api/scans/:id`).
- **Test evidence:** code inspection.
- **Remaining risk:** low. `/onboarding` has no logged-out guard — an
  anonymous user can open it (Day 1 §3.2). Cosmetic; the wizard's API
  calls still require auth.
- **Reviewer notes:** add the guard on Day 5 or Day 14.

---

## G. Application security verification (how this checklist was verified)

### SEC-45 — Full security audit (this program)
- **Status:** PARTIAL (in progress — this is Day 3 of 20)
- **Sources:** screenshot 03
- **Files inspected:** this document + `docs/THREAT_MODEL.md` +
  `docs/MASTER_PROJECT_AUDIT.md`
- **Implementation evidence:** Day 1 audit complete (commit `bf49b47`);
  Day 3 threat model + this checklist complete (commit `e8c7d31`). The
  2026-11-08 fix round (25 fixes) and the Sep 2026 audits are superseded
  as baselines. The Day 7 `SECURITY_GATE_REPORT.md` is the verdict
  document; the gate requires every applicable item here to be PASS with
  evidence, no unresolved critical/high issues, and all exceptions
  documented and approved.
  **Fix-all run (2026-11-16):** all 7 FAIL + 14 PARTIAL + 1 BLOCKED
  worked; code pushed (heads `670755d`, `25561d9`, `6dac31e`); live
  probes re-run. `docs/SECURITY_GATE_REPORT.md` written this run —
  **verdict: GATE NOT PASSED** (SEC-03, SEC-31, SEC-32, SEC-34 still
  FAIL; SEC-13's 3 HIGHs unfixed; live cross-tenant matrix outstanding).
- **Test evidence:** offline suite this run: `node --test
  backend/tests/aiFixEngine.test.js backend/tests/startup_routes.test.js`
  → 8 pass, 0 fail; `node backend/tests/astExtraction.test.js` → 4 pass,
  0 fail. `deployment_config.test.js` env-gated (not run — needs real
  secrets). `compliance.test.js` + 24 verify scripts + 6 Python tests
  need a live server/DB or pytest — not run here (Day 18).
  **Fix-all run tests:** full offline suite **47/47 pass** + astExtraction
  4/4; validation 11/11 (incl. a real-Express-5 regression test); rbac
  8/8; RLS 12/12 + PGlite 42/42; auth-verification 8/8; PAT-migration
  self-test 7/7; frontend vite build green (1.66 s).
- **Remaining risk:** the gate has not run yet. Nothing in this document
  is a gate pass. — Still true: the gate report records NOT PASSED.
- **Reviewer notes:** do not start Phase 4 features until the Day 7 gate
  passes.

### SEC-46 — "Check caption" (screenshot 06, item 20)
- **Status:** NOT APPLICABLE
- **Sources:** screenshot 06
- **Files inspected:** n/a
- **Implementation evidence:** "Check caption" is a reel-creator
  instruction to their own viewers, not a product requirement. There is
  nothing in SecureGaurd to verify against it.
- **Reviewer notes:** recorded so the item is accounted for, not skipped
  silently.

---

## H. Verification method and evidence (this run)

- **Commit verified:** `e8c7d31` (remote HEAD at run start, clone re-synced
  to it; working tree clean except the unrelated sync-record file).
- **Code changes since the Day 1 audit (`bf49b47`):** cursor/logout UI,
  README copy, Day 1 + Day 2 docs only — no auth, route, or query code
  changed, so Day 1's source-grounded findings carry forward and are
  cited, not re-derived.
- **Fresh checks this run (2026-11-16 ~01:00–02:00 IST):** RBAC roles in
  `middleware/rbac.js` + 8 route files; `createAuditLog` helper + call
  sites; rate limiters in auth/scans/public/integration/customRules routes
  and the two gaps (`/refresh` `auth.js:259`, `/me` `auth.js:426`); CORS
  allow-list; helmet without CSP; `vercel.json` headers (no CSP); zero
  `dangerouslySetInnerHTML` in `src/`; no `CREATE POLICY` in any migration;
  no multer / file upload / Supabase storage use; no `.env` tracked (only
  `.env.example`); gitleaks workflow; `sg_refresh` cookie flags; frontend
  `VITE_*` inventory (4 non-secret vars); 13 frontend routes; 35 form
  validation markers; contact validation via `validateContactInput`.
- **Tests run this run:** `node --test backend/tests/aiFixEngine.test.js
  backend/tests/startup_routes.test.js` → **8 pass, 0 fail**;
  `node backend/tests/astExtraction.test.js` → **4 pass, 0 fail**.
  Total offline: **12 pass, 0 fail** (same as Day 1).
- **Live probes this run:** frontend
  `https://secureguard-main.vercel.app/` 200; backend
  `https://securegaurd.onrender.com/health` 200; classifier
  `https://secureguard-classifier.onrender.com/health` 200 (see the Day 3
  run log for timings).
- **Not verified this run (carried as BLOCKED/UNVERIFIED, never assumed):**
  production env-var presence (Turnstile, Sentry, OAuth, Gemini, Brevo —
  owner dashboards, Day 4); live auth flows end-to-end (throwaway account,
  Day 7/18); live cross-tenant IDOR/RBAC matrix (two test orgs, Day 5/7);
  live rate-limit/CORS/CSP header probes (Day 6/19); live webhook
  deliveries (Day 12/18); Supabase backups/PITR + least-privilege DB creds
  (owner dashboard, Day 4/7); dependency vulnerabilities (Day 4, GitHub
  Actions); classifier model quality on independent data (Day 10).
- **Fix made this run:** redacted the dev MongoDB credential string from
  `SECURITY_AUDIT.md:90` (Day 1 finding S8). Rotation of that dev
  credential is still owed — see SEC-05.
- **Run log:**
  `~/workspace/goals/securegaurd-20-day-transformation/hidden_files/day03-run-log.md`

## H.1 Fix-all run (2026-11-16 ~01:15–02:30 IST) — evidence

- **Commits pushed:** `670755d` (backend: auth gate, rbac, validation,
  webhooks, tests, migration script), `25561d9` (frontend: fake-progress
  removal, mobile nav, verify-email page, CSP), `6dac31e` (docs: route
  matrix, backups, retention, dependency scan). Sync record:
  `~/workspace/SecureGaurd.muse-github-snapshot-sync.json`.
- **NOT pushed (deliberate):** RLS migration
  `backend/prisma/migrations/20261116_rls_policies/migration.sql` (Render
  pre-deploy would auto-apply it before call-site conversion — see
  SEC-31); `.github/workflows/dependency-scan.yml` (GitHub App API 403 on
  `git/trees` — the App cannot write `.github/workflows/`; needs the
  browser web-UI push); deletions (stale classifier copy, committed
  `backend/generated/prisma/` — API cannot delete; browser push).
- **Tests:** full offline suite 47/47 + astExtraction 4/4; validation
  11/11; rbac 8/8; RLS 12/12 + PGlite 42/42 (PostgreSQL 17.5); auth
  verification 8/8; PAT-migration self-test 7/7; vite build 1.66 s.
  Merge-time bug caught + fixed: `req.query` assignment throws on
  Express 5.3.0 (getter-only) — `Object.defineProperty` shadowing + a
  real-Express regression test.
- **Live probes (post-deploy, ~02:20 IST):** frontend 200; backend
  `/health` 200 `{"status":"ok"}`; frontend CSP + backend helmet CSP
  verified via `curl -I`; register → 201 `{ requiresVerification: true }`,
  login → 403 `email_not_verified`; resend-verification → 200 generic;
  register with NO Turnstile token → 201 (SEC-34 re-confirmed FAIL);
  35× `POST /api/auth/refresh` → 35× 401, no 429 (INCONCLUSIVE — VM
  egress IP rotates; limiters key on `req.ip`).
- **Mobile viewport (headless Chromium, 390×844 + 360×740):** no horizontal
  overflow on `/`, `/login`, `/dashboard` (unauth). Authenticated
  dashboard NOT measured (needs login).
- **Leftovers in prod:** probe account `sg-fixall-20261116@example.com`
  (unverified, cannot self-delete — owner deletes via DB); ContactMessage
  row id 4 (from the Day 3 probe — no API to delete it).
- **Not verified this run (carried as BLOCKED/UNVERIFIED, never assumed):**
  live cross-tenant matrix (needs 2 verified accounts = 2 mailboxes);
  email-click verify (needs a mailbox); live 429 trigger (needs a stable
  IP or Render logs); authenticated-dashboard mobile check (needs login);
  Supabase backups/PITR + least-privilege DB creds (owner dashboard);
  Turnstile/Sentry/OAuth/Gemini env presence (owner dashboards).

## I. What must happen before the Day 7 gate

1. Day 4: dependency scan via GitHub Actions (SEC-13) — **scan DONE,
   remediation + first CI run open** (workflow file needs browser push);
   Turnstile key presence (SEC-34) — **still FAIL, owner step**;
   dev-credential rotation (SEC-05) — **delete Atlas user
   `glanexus_admin`, owner step**; history-purge decision (SEC-03) —
   **procedure ready, needs his word**; production env presence
   (SEC-02/SEC-26/SEC-42) — still owner dashboards.
2. Day 5: email-verification gating + UI (SEC-09) — **DONE**;
   `requireOrgContext` fallback fix (SEC-15) — **DONE**; route-auth
   matrix re-verification (SEC-16) — **DONE (code-level; live matrix
   open)**; `orgFetch`/`completeOnboarding` fixes (SEC-07) — **DONE**.
3. Day 6: CSP header (SEC-19) — **DONE, live-verified**; rate-limit
   `/refresh` + `/me` (SEC-17) — **DONE in code; live 429 proof open**;
   Razorpay idempotency inside the transaction (threat T10) — **DONE**;
   classifier key on the webhook path (threat T11) — **DONE**;
   standardised input validation (SEC-18) — **DONE (lib + 3 routes;
   remaining routes follow-up)**; live CORS/rate-limit/header probes —
   **header probes DONE; rate-limit probe inconclusive**.
4. Day 7: backup taken + restore-tested (SEC-32) — **still FAIL**;
   Postgres RLS (SEC-31) — **migration written, not applied; call-site
   conversion + app-role check first**; live cross-tenant matrix
   (SEC-15/SEC-16) — **open (needs 2 mailboxes)**; security regression
   tests — **DONE (47/47 + new suites)**; `SECURITY_GATE_REPORT.md` —
   **written this run: GATE NOT PASSED**. No Phase 4 work until it passes.
