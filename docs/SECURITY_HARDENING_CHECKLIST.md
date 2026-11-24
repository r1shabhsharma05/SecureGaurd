# SecureGaurd — Security Hardening Checklist (Day 3, 20-Day Transformation)

**Date:** 2026-11-16 (Day 3 of the 20-day program)
**Verified commit:** `e8c7d31` — "add day 2 competitor research and differentiation"
**Fix-all run:** 2026-11-16 ~01:15–02:30 IST — user ordered every FAIL /
PARTIAL / BLOCKED item fixed. Code pushed in 3 batches (heads `670755d`,
`25561d9`, `6dac31e`); live probes re-run after deploy. Statuses below
reflect the post-fix-all state. The RLS migration was deliberately NOT
pushed (Render's pre-deploy `prisma migrate deploy` would auto-apply it
before call-site conversion — see SEC-31).
**Day 4 update:** 2026-11-17 — no status changes. Day 4 notes added to
SEC-02/03/04/05/13/26/34/42 (gitleaks full-history scan, OSV re-scan,
render.yaml blueprint fix, live probes); detail in
`docs/SECRETS_AND_INFRASTRUCTURE.md`. Verified commit for the Day 4
evidence: `8ebfe75d`.
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
| PASS | 28 |
| PARTIAL | 13 |
| FAIL | 2 |
| BLOCKED | 0 |
| NOT APPLICABLE | 3 |
| **Total merged items** | **46** |

FAIL items (must clear before the Day 7 gate): SEC-03 (secrets in git
history — purge procedure ready, needs the owner's word), SEC-31 (Row Level
Security — app role live with 20 permissive policies since 22 Nov, tenant
policies still not applied). SEC-34 CLOSED 2026-11-24 (Turnstile live — see SEC-34
note). SEC-32 CLOSED 2026-11-24 (first backup + trial restore passed —
see SEC-32 note). Fixed by the fix-all run: SEC-09 (email verification is a
real gate now), SEC-37 (fake scan progress removed), SEC-19 (CSP live on
both hosts). SEC-06 moved FAIL → PARTIAL (mongoose removed; file deletions
outstanding). SEC-13 moved BLOCKED → PARTIAL (measured: 15 findings,
3 HIGH; fixes not applied, CI workflow still to be pushed via browser).
**Gate pass (2026-11-18):** counts UNCHANGED — 24 PASS / 15 PARTIAL /
4 FAIL / 0 BLOCKED / 3 N/A. Within-item progress: SEC-13's 3 HIGHs fixed
(commit `9aa4ce5`, OSV re-scan 3 findings), SEC-31 call-site conversion
done (commits `a72de3d` / `1d7aa1f` / `f13a2ce`), SEC-33 purge script
landed — but no item crossed to PASS: all 4 FAILs still need owner
actions (see `docs/SECURITY_GATE_REPORT.md`).
**Day 6 (2026-11-19):** counts STILL UNCHANGED — no item crossed to
PASS. Within-item progress: SEC-18 coverage 3 → 9/48 routes, SEC-17
limiter-trip proven in-process, SEC-19/SEC-21 live re-verified. The 4
FAILs are owner actions; Rishabh confirmed all 9 done 2026-11-19
~01:00 IST — gate re-verification is Day 7, not this run.
**Day 7 (2026-11-20):** counts STILL UNCHANGED — 24 PASS / 15 PARTIAL /
4 FAIL / 0 BLOCKED / 3 N/A, re-verified item by item at `7d471db`.
Gate verdict: **NOT PASSED** (`docs/SECURITY_GATE_REPORT.md` rewritten
for Day 7; database detail in `docs/DATABASE_SECURITY.md`). Within-item
progress since 18 Nov: OAuth Google + GitHub LIVE (SEC-07 note),
OSV 3 → 2 findings (SEC-13), routes 92 → 97 all classified (SEC-16),
RLS coverage 54 → 63 files (SEC-31), suite 147/149. The 4 FAILs
(SEC-03, SEC-31, SEC-32, SEC-34) were each re-probed and stand —
all four need owner/dashboard actions, not code. Phase 4 stays
blocked until they clear.
**Day 9 (2026-11-22):** counts STILL UNCHANGED — 24 PASS / 15 PARTIAL /
4 FAIL / 0 BLOCKED / 3 N/A at `af650fa`. Gate verdict: **NOT PASSED**
(Day 9 section in `docs/SECURITY_GATE_REPORT.md`). Within-item: OSV
2 → 3 findings (new effect advisory, SEC-13 note below); SEC-31
role-switch pack prepared (`docs/SEC31_ROLE_SWITCH.md`, not applied);
suite 147/149, RLS test 12/12, coverage 63/0. Phase 4 (Days 8–9)
has not started — gate rule. The 4 FAILs still need owner actions.
**Day 10 (2026-11-23):** counts CHANGED — **25 PASS / 14 PARTIAL /
4 FAIL / 0 BLOCKED / 3 N/A** at `93d710d`. SEC-13 crossed to PASS
(3 findings fixed via overrides, OSV 0/589 — see SEC-13 note).
SEC-18 gap shrank (39 `validateBody` sites; 19/51 mutating routes
still inline — stays PARTIAL). Auth events now audit-logged
(`logAuthEvent`, primary-org resolution — gate decision 8 closed in
code). Suite 160/162 (same 2 env failures), frontend build green,
production probes 200. Gate verdict: still **NOT PASSED** — the 4
FAILs (SEC-03, SEC-31, SEC-32, SEC-34) stand; Phase 4 (Day 10
ML/AI) has not started — gate rule. See the Day 10 section in
`docs/SECURITY_GATE_REPORT.md`.
**Day 11 (2026-11-24):** counts CHANGED — **27 PASS / 13 PARTIAL /
3 FAIL / 0 BLOCKED / 3 N/A**. SEC-18 + SEC-22 crossed to PASS (strict
id params, commit `b36b839` — see SEC-18 note; suite 167/169, same 2
env failures) and SEC-34 crossed to PASS (Turnstile live end to end,
commit `1a11ff9` — see SEC-34 note). The Day 11 cron's own code was
wiped by a mistaken `git reset --hard` and re-applied + re-verified
the same day (same commit message, same 11 files); see
`docs/SECURITY_GATE_REPORT.md` Day 11 section. Remaining FAILs:
SEC-03 (history purge), SEC-31 (tenant RLS), SEC-32 (backups — pg_dump
blocked on RLS as the app role, owner path choice pending). Gate
verdict: still **NOT PASSED** — Phase 4 has not started. Count note:
the Day 11 cron log claimed 27/12/4/3 before SEC-34 closed; the
arithmetic from the 24/15/4/3 baseline (SEC-18, SEC-22 out of
PARTIAL; SEC-34 out of FAIL) is 27/13/3/3 — the one-item discrepancy
is for the Day 12 full recount to settle, not for editing counts here.
**Same evening (2026-11-24 ~19:15 IST): SEC-32 also closed** — owner
picked the postgres-password reset path; password reset via dashboard,
first backup `secureguard-20261124-134015.dump.gz` (20 tables) +
trial restore into a local PG 17 scratch DB passed (row counts
matched on all spot-checked tables). Counts now **28 PASS / 13
PARTIAL / 2 FAIL / 0 BLOCKED / 3 N/A**; remaining FAILs SEC-03 +
SEC-31. See the SEC-32 note.

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
  **Day 4 (2026-11-17):** `render.yaml` declared only 10 vars — the 14
  optional integration vars were missing from the blueprint. Fixed:
  `TURNSTILE_SECRET_KEY`, `SENTRY_DSN`, `BREVO_API_KEY`, `EMAIL_FROM`,
  `CONTACT_EMAIL`, `FP_CLASSIFIER_URL`, `GEMINI_WEB2API_URL/KEY`,
  `GOOGLE/GITHUB/GITLAB_CLIENT_ID/SECRET`, `BACKEND_URL` added as
  `sync: false` (names only); 24 vars total. YAML validated; see
  `docs/SECRETS_AND_INFRASTRUCTURE.md` §3.
- **Test evidence:** `backend/tests/deployment_config.test.js` exists but is
  env-gated — it fails at import without real secrets (expected behaviour,
  not a code failure). **Day 4:** run with dummy required vars —
  **3/3 pass**. Backend offline suite 51/52 (the 1 failure is the
  compliance DB test, which needs a live Postgres — environmental).
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
  **Day 4 (2026-11-17):** gitleaks 8.28.0 full-history scan — 182 commits,
  ~93.35 MB, **6 findings, 0 real secrets** (1 false-positive identifier,
  1 doc placeholder `sg-internal-…-change-me` ×3, 2 intentional scanner-test
  fixtures). Raw report kept out of the repo. **Detection gap:** the same
  default rules did NOT flag the known real `JWT_SECRET` + `MONGO_URI` in
  `e1e3dc9` — a green gitleaks run (local or CI) is not proof of a clean
  history. CI secret-scan is green on every push including `8ebfe75d`
  (same blind spot). Full detail: `docs/SECRETS_AND_INFRASTRUCTURE.md` §1.
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
  **Gate pass (2026-11-18):** forks check DONE — GitHub API
  `/repos/r1shabhsharma05/SecureGaurd/forks` returns `[]`, `forks_count:
  0`. Precondition (a) cleared. Still open: (b) owner confirms the
  current Render `JWT_SECRET` differs from the committed value, and his
  word for the rewrite. No purge prep dir exists yet — prepare it from
  the `~/workspace/tmp-work/safelife-purge` pattern before the rewrite;
  do NOT execute a rewrite / force-push without his explicit
  confirmation.
  **Day 7 (2026-11-20):** gitleaks full-history re-run — 210 commits,
  same 6 false-positive findings, 0 real secrets detected; the
  `e1e3dc9` detection gap stands (default rules still miss the known
  leak). History intact (no rewrite has happened). Raw report:
  `hidden_files/gitleaks-full-history-2026-11-20.json`. Stays FAIL.

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
  **Gate pass (2026-11-18):** self-test re-run — **7/7 pass**
  (`node scripts/migrate-plaintext-pats.js --self-test`). Live run still
  BLOCKED (no DB creds, no `ENCRYPTION_KEY` on this VM); the dry-run
  fails at startup on the missing key, as designed.
- **Reviewer notes:** Day 4 checks the Supabase credential scope; Day 5+
  migrates legacy plaintext PATs.
  **Day 4 (2026-11-17):** Supabase scope check NOT done — no Supabase
  dashboard access from this VM. Owner check recorded in
  `docs/SECRETS_AND_INFRASTRUCTURE.md` §2 (project
  `wkvvxqlflhjiqkhwxrsl` → Settings → API).

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
  **Day 4 (2026-11-17):** owner step confirmed as deletion (see
  `docs/SECRETS_AND_INFRASTRUCTURE.md` §2). Day 4 cannot confirm it —
  no Atlas access from this VM. Stays PARTIAL until the owner deletes
  the user (or confirms it is already gone).

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
  **Gate pass (2026-11-18):** re-verified via GitHub API —
  `SecureGaurd-main/backend/generated/prisma/` is STILL in the repo
  (contents: `prisma`), and the stale `classifier model/files/` copy is
  still there. Both deletions still need the browser web-UI push; the
  model copy additionally needs his approval. Unchanged.

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
  **Day 5 (2026-11-18):** re-verified the token lifecycle, RBAC and
  IDOR claims in code (see `docs/AUTH_AND_AUTHORIZATION.md`) — no gaps
  found in the sampled routes. One real bug fixed: auth routes did not
  normalize email addresses, so `Rishabh@Example.com` at register and
  `rishabh@example.com` at login were different accounts;
  `normalizeEmail()` + `findUserByEmail()` (canonical-first,
  case-insensitive fallback) now applied to register, login,
  forgot-password, resend-verification and the OAuth callback, with 4
  new offline tests (31/31 pass incl. existing suites). Stays PARTIAL:
  no MFA, no per-account lockout (IP rate limit only), live flows
  still unrun (mailbox blocker).
  **Gate pass (2026-11-18):** MFA check — `grep -rni totp|mfa|authenticator|2fa`
  over `backend/` returns 0 hits: no MFA/TOTP/2FA code exists anywhere.
  OAuth providers exist in code (Google, GitHub, GitLab in
  `utils/oauth.js`, auth-code + PKCE + HMAC state) but none is live
  (`docs/OAUTH_SSO.md` — file lives under `SecureGaurd-main/docs/`).
  Stays PARTIAL.
  **Day 7 (2026-11-20):** OAuth is now LIVE — Google (new Cloud
  project `securegaurd-515208`, client on Render) + GitHub (OAuth app
  "SecureGuard", vars on Render), both set 19 Nov;
  `GET /api/auth/oauth/providers` re-probed Day 7 → google + github.
  Stays PARTIAL: still no MFA, no per-account lockout (IP rate limit
  only). New adjacent gap recorded Day 7: auth events (login/logout/
  password) are not audit-logged — see SEC-35 note + gate report.
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
- **Status:** PASS (Day 10, 2026-11-23 — 0 OSV findings across 589
  packages; CI scan live; see Day 10 note below)
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
  **Day 4 (2026-11-17):** OSV re-run — 569 unique packages (was 585),
  **same 15 findings, identical advisory IDs** (verified by comparing
  both raw JSON files); `npm outdated` re-verified (root 17/6 major,
  backend 9/2 major — mongoose gone). `docs/DEPENDENCY_VULNERABILITIES.md`
  updated. CI workflow push: `.github/workflows/dependency-scan.yml` goes
  via browser web-UI today (App API 403s on `.github/workflows/`);
  `scripts/osv-scan.mjs` pushed with the docs via the API. First CI run
  pending the push — see `docs/SECRETS_AND_INFRASTRUCTURE.md` §4.
  **Day 4 first run (2026-11-17, run 44005648268): FAILURE, informative.**
  Backend job: audit gate tripped as designed — npm audit 12 vulns
  (7 moderate, 5 high: body-parser, deepmerge-ts, mysql2). Root job:
  audit step passed, but the artifact upload failed on the path
  `SecureGaurd-main/./npm-audit.json` — workflow bug, one-line fix
  (conditional path) pushed via browser web-UI the same morning
  (commit `6324afb`); **second run (44006630822): root job fully green**
  (artifact `npm-audit-root` uploaded), backend job still red on the
  audit gate as designed. Remediation is Day 9. Stays PARTIAL.
  **Gate pass (2026-11-18):** all 3 HIGHs FIXED — body-parser 2.3.0→
  2.4.0, deepmerge-ts 7.1.5→8.0.2 (via @prisma/config 7.10.1), mysql2
  3.15.3→3.24.4 (commit `9aa4ce5`; OSV 15 findings → 3). Re-scan after
  the RLS work: 568 packages, same 3 findings — 1 HIGH picomatch@4.0.7
  (GHSA-fc5q-39xc-vjpf, NO fixed version exists; build-time only via
  vite) + 2 MODERATE majors (minimatch 11.0.1, glob 14.0.2 — Day 9).
  CI workflow `.github/workflows/dependency-scan.yml` verified LIVE via
  GitHub API (present alongside `secret-scan.yml`) — the browser push
  from 17 Nov morning worked; no re-push needed. Stays PARTIAL until the
  owner risk-accepts picomatch in writing (with expiry) or upstream
  ships 4.0.8.
  **Day 7 (2026-11-20):** OSV re-scan — 587 packages (568 on 18 Nov;
  +19 from bullmq/ioredis), **2 findings**: minimatch@10.2.6
  (GHSA-g3hv-75wg-m249 / CVE-2026-118764, glob DoS, fixed in 11.0.1)
  + glob@13.0.6 (GHSA-3g3m-2fjr-6pw4 / CVE-2026-118773, fixed in
  14.0.2). The picomatch HIGH is no longer returned by OSV for
  4.0.7 — the package is unchanged, the advisory state changed; NOT
  claimed as fixed, and the picomatch risk-accept ask is moot. Both
  remaining fixes are major bumps (Day 9). Raw results:
  `hidden_files/osv-scan-results-2026-11-20.json`. Stays PARTIAL.
  **Day 9 (2026-11-22):** OSV re-scan — 587 packages, **3 findings**:
  the same minimatch + glob, plus **new** effect@3.20.0
  (GHSA-7589-6fvf-x4pw / CVE-2026-121707, fixed in 3.22.1, backend
  lockfile). Package unchanged — new advisory published against it;
  NOT claimed fixed. Day 9 dependency remediation did not run: the
  security gate still fails, so Phase 4 stays blocked. Raw results:
  `hidden_files/osv-scan-results-2026-11-22.json`. Stays PARTIAL.
  **Day 10 (2026-11-23):** all 3 findings FIXED via npm `overrides`
  (commit `93d710d`): minimatch → 11.0.9 (fix 11.0.1), glob → 14.0.6
  (fix 14.0.2), effect → 3.22.5 (fix 3.22.1) — verified in both
  lockfiles. OSV re-scan: **589 packages, 0 vulnerable** (raw:
  `hidden_files/osv-scan-results-2026-11-23.json`). Backend suite
  160/162 (same 2 pre-existing env failures), frontend build green,
  production probes 200 after push. Automated scanning is in place
  (CI `dependency-scan.yml` live + `scripts/osv-scan.mjs`). **Status
  → PASS** (no known vulnerabilities at scan time; outdated majors
  remain but are not vulnerabilities). New advisories can appear any
  day — re-scan is part of every gate re-check.

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
  **Day 5 (2026-11-18):** re-verified in code — every `:id` lookup
  sampled (scans, vulnerabilities, repos, sboms, compliance, custom
  rules) scopes by `organizationId`, 404 on cross-org ids; no unscoped
  fetch found. Live matrix still BLOCKED on the same mailbox
  blocker; procedure in `docs/AUTH_AND_AUTHORIZATION.md` §4.
  **Gate pass (2026-11-18):** code-level isolation now enforced by the
  RLS conversion (commits `a72de3d` / `1d7aa1f` / `f13a2ce`) — every
  tenant-table access runs inside an `rlsContext` (PGlite test 12/12:
  cross-org reads 0 rows, unset vars 0 rows); `scripts/check-rls-coverage.js`
  passes (54 files, 0 bare `prisma.<tenant-table>` accesses). Live
  cross-tenant matrix still BLOCKED (mailbox).
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
  **Day 5 (2026-11-18):** router mounts + per-router middleware counts
  re-checked, sensitive routes spot-checked (no holes found); full
  92-route re-count is a Day 7 gate item. Live matrix still BLOCKED.
  **Gate pass (2026-11-18):** full re-count DONE — 90 `router.METHOD`
  definitions (42 GET, 33 POST, 7 PATCH, 7 DELETE, 1 PUT) + 2
  server-level (`GET /health`, `GET /api/_test-error`) = **92, no
  holes**. Live matrix still BLOCKED (mailbox).
  **Day 7 (2026-11-20):** re-count DONE — 95 `router.METHOD`
  definitions (44 GET, 34 POST, 8 PATCH, 8 DELETE, 1 PUT) + 2
  server-level = **97, no new holes**. The 5 routes added since
  18 Nov (api-keys create/list/revoke, scans queue/stats, auth
  PATCH /me) are all behind auth + org context (apiKeys router
  mounts `authMiddleware` + `requireOrgContext`, OWNER/ADMIN on
  writes; queue/stats under the scans router's
  `authenticateRequest`; `/me` PATCH takes `authMiddleware`).
  Live matrix still BLOCKED (mailbox). Stays PARTIAL.
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
  **Gate pass (2026-11-18):** Render API is unreachable from this VM
  (401, no token/service ID on the VM) — no logs, no live 429 proof.
  Stays PARTIAL as a probe limitation, not a limiter failure.
  **Day 6 (2026-11-19):** limiter is mounted and counting — new
  `backend/tests/authValidation.test.js` spends the process's shared
  `authLimiter` budget (10/15 min): 11 rapid logins answer 400, 400,
  then 429 × 9. Live 429 proof still outstanding (same rotating-IP
  confound; the 35-request live probe was NOT repeated — it would return
  the same inconclusive result). Needs a stable IP or Render logs.
- **Remaining risk:** low, but the two gaps are real and cheap to close.
  Gaps closed in code; live trigger proof outstanding.
- **Reviewer notes:** fix Day 6.

### SEC-18 — Sanitize user input / sanitize forms
- **Status:** PASS
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
  **Gate pass (2026-11-18):** measured the full gap — of the 48
  mutating routes, only 3 use the shared `validateBody` (auth
  change-password, scan trigger, public contact; the export-feedback
  GET uses `validateQuery`). **45 mutating routes have NO shared
  validation** and rely on inline checks: ai.js 3, alerts.js 2, auth.js
  10, billing.js 2, billingWebhook.js 1, compliance.js 2, customRules.js
  5, integration.js 3, invitations.js 1, ml.js 1, organizations.js 9,
  public.js 1, repos.js 2, scans.js 1 (api-spec), vulnerabilities.js 2.
  No route is unvalidated; the gap is consistency, not absence. Wiring
  all 45 is Day 8+ refactor work, not a silent gate-pass change.
- **Remaining risk:** medium. Validation is ad-hoc per route; a missed
  check on a new route is a live bug. The auth surface (the
  unauthenticated routes) is now standardised (Day 6, 9/48); the
  remaining 39 authenticated mutating routes still use per-route checks
  — apply `validateBody` to them as follow-up (Day 8+).
  **Day 6 (2026-11-19):** the auth unit is done — 6 routes wired
  (register, login, resend-verification, forgot-password, reset-password,
  delete-account), 11/11 new tests + 49/49 regression set; coverage
  3 → **9 of 48** mutating routes. Deliberately not wired: verify-email
  (query-or-body token), OAuth callback (redirect flow), no-body routes.
  See `docs/BACKEND_SECURITY.md`.
  **Day 10 (2026-11-23, commit `93d710d`):** shared validation wired
  into the remaining route files (alerts, apiKeys, billing, compliance,
  customRules, integration, ml, organizations, public, repos, scans,
  vulnerabilities + `patchMeSchema` on auth). Measured on the pushed
  tree: **39 `validateBody` + 2 `validateQuery` call sites** across 13
  route files; **19 of 51 mutating routes** still rely on inline checks
  (ai.js 3, auth.js 4 incl. verify-email/OAuth flows, organizations.js
  4, billingWebhook 1 signature-verified, invitations 1, + 6 singletons).
  Validation + RBAC + RLS-migration tests 47/47; full backend suite
  160/162 (same 2 env failures). Stays PARTIAL — gap is now consistency
  on 19 routes, not absence; no route is unvalidated.
  **Day 11 (2026-11-24, commit `b36b839` "strict id params, no parseint
  coercion"):** the remaining gap closed — route-by-route audit found
  the real hole was id-param coercion (`parseInt("12abc")` → 12,
  `Number("12.5")` → 12.5), not missing `validateBody` (every
  body-bearing mutating route already runs it; the 19 inline routes are
  bodyless/signature/query-or-body by design). `parseIdParam` added to
  `backend/utils/validation.js` (digits-only safe positive int, else
  null) and wired at **25 sites across 10 files** (16 `parseInt` +
  8 `Number` path params + the `?scanId=` filter), each route keeping
  its existing 400 message; `grep parseInt(req.params|Number(req.params`
  after: no leftovers. New `backend/tests/validationParams.test.js`
  **4/4** (literals pinned); full backend suite **167/169** (same 2 env
  failures); frontend build green; secret-scan of the diff clean.
  Deliberately untouched: body/query id parses (`req.body` memberId,
  `req.body` scanId, `?repositoryId`, pagination `page`/`limit`) —
  out of this item's path-param scope.
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
  **Day 6 (2026-11-19) live re-verify:** frontend 200 — CSP present
  with the same sha256 hash as `vercel.json`, plus nosniff, DENY,
  Referrer-Policy, Permissions-Policy, COOP, HSTS; backend `/health`
  200 — `default-src 'none';frame-ancestors 'none';base-uri 'none'` +
  nosniff. See `docs/BACKEND_SECURITY.md`.
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
  **Day 6 (2026-11-19):** re-grep `dangerouslySetInnerHTML` in `src/` —
  still **0 hits**.
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
  **Day 6 (2026-11-19) live probe:** preflight from unlisted origin
  `https://evil.example.com` → 200 with NO `Access-Control-Allow-Origin`
  (denied, no 500); same preflight from
  `https://secureguard-main.vercel.app` → 204 with the origin +
  `Access-Control-Allow-Credentials: true`. Procedure done, PASS stands.
- **Remaining risk:** low.
- **Reviewer notes:** none.

### SEC-22 — Input validation (backend) — see SEC-18
- **Status:** PASS — merged into SEC-18 (same evidence, same gap).
  Fix-all run: shared zod library exists + 3 routes wired (see SEC-18);
  remaining routes still ad-hoc.
  **Gate pass (2026-11-18):** measured — 45 of 48 mutating routes lack
  the shared validator (see SEC-18). Same verdict, exact count now.
  **Day 6 (2026-11-19):** 6 auth routes wired to the shared library
  (register, login, resend-verification, forgot-password, reset-password,
  delete-account — `backend/tests/authValidation.test.js` 11/11, plus
  49/49 in the regression set). Coverage is now **9 of 48** mutating
  routes. Deliberately NOT wired: verify-email (token from query OR
  body), OAuth callback (browser redirect flow — a 400 would break it),
  refresh/logout/complete-onboarding (no body). 39 routes remain ad-hoc
  — Day 8+ refactor, not a silent change. See
  `docs/BACKEND_SECURITY.md`.
  **Day 11 (2026-11-24):** PASS with SEC-18 — same evidence (strict
  id params, commit `b36b839`, 25 sites, tests 4/4 + suite 167/169).
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
  **Day 6 (2026-11-19):** re-grep upload handlers (multer,
  upload.single/array, express-fileupload, busboy) in `backend/` +
  `src/` — still **0 hits**.
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
  **Day 4 (2026-11-17):** live probe `GET /api/_test-error` → **404** —
  the test route is not enabled in production. Caveat resolved; the
  dashboard confirm is now a belt-and-braces check only.
  **Day 6 (2026-11-19):** re-probed `GET /api/_test-error` → **404**
  again — still not enabled in production.
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
  **Day 6 (2026-11-19):** code unchanged by this run; re-read confirms
  the HMAC/idempotency wiring above. Live test still needs a real
  delivery (Day 12/18).
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
  **Day 6 (2026-11-19):** `ssrfGuard.js` re-read — single resolution per
  hop, every address must be public, pinned-IP dialing with
  `remoteAddress` verified pre-request, redirect re-validation (max 3),
  2 MB cap, 10 s timeout, credentials rejected. No live test run (same
  staging-only rule — production is not the place to probe metadata
  endpoints). See `docs/BACKEND_SECURITY.md`.
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
  **Gate pass (2026-11-18) — rollout step (1) DONE in code:**
  call-site conversion complete — commits `a72de3d` (rbac + org
  migration), `1d7aa1f` (billing, alerts, repos, invitations), `f13a2ce`
  (scans, integration, billingWebhook, organizations, auth, ml, billing,
  sboms, ai, vulnerabilities, compliance, customRules, alerts).
  `backend/scripts/check-rls-coverage.js` passes (54 files, 0 bare
  `prisma.<tenant-table>` accesses); new PGlite migration test
  `backend/tests/rlsMigration.test.js` 12/12 (16 policies / 13 tables,
  cross-org 0 rows, fail-closed, bootstrap INSERT, append-only AuditLog).
  Full offline suite 77 tests, 75 pass (2 known environmental failures).
  Migration file deliberately STILL NOT pushed (Render pre-deploy would
  auto-apply). Steps (2)–(5) outstanding: superuser check + backfill +
  SQL Editor apply + live matrix. **Leftovers (documented, need
  decisions):** the scans export-feedback operator path now 503s under
  RLS (no service-role path — needs a design decision); the public
  analytics summary's Scan/Vulnerability counts need a context when
  called from `routes/public.js`; `routes/public.js` (AnalyticsEvent /
  ContactMessage, no RLS) and `routes/classifier.js` (0 tenant sites)
  verified as needing no change.
  **Day 7 (2026-11-20):** coverage re-verified — 63 files, 0 bare
  accesses (all 19 Nov batches landed inside the wrapper). Migration
  still NOT applied, still untracked in git by design. New gap: the
  `ApiKey` table (19 Nov) postdates the migration's 13 tables and
  needs its own policy added before apply (expect 17 policies, not
  16). Steps (2)–(5) still outstanding. Full rollout procedure:
  `docs/DATABASE_SECURITY.md` §6.1. Stays FAIL.
  **Day 12 (2026-11-25):** Step E dry-run on a scratch PGlite 0.4.3
  (24 Nov backup restored: 20 tables, User 29 / Org 21 / Scan 21 /
  Vulnerability 122, 20 permissive policies). Pre-steps applied
  cleanly (0 policies, RLS on 14 / off on 6); migration applied
  cleanly, self-check passes (17 policies / 14 tables, RLS+FORCE on
  all 14). Two scratch-only findings: (1) migration needs an explicit
  `SET search_path TO public;` first — a session with an empty
  search_path fails at §1 (guard note added to
  `docs/SEC31_STEP_E_APPLY.sql`); (2) behavioural isolation could NOT
  be verified in the scratch env (pglite-server ignores the requested
  role and errors on any RLS-table read as non-superuser, proven on a
  trivial control table) — in-process suite 12/12 still proves the
  policy logic; real-data proof stays with the live apply. Stays FAIL
  until Step E completes; owner decisions still owed.
- **Reviewer notes:** implement Postgres RLS on Day 7, with the live
  cross-tenant matrix as the verification. The app connects with a single
  `DATABASE_URL` credential — RLS design must account for that (either a
  per-request session variable or a separate restricted role), or it does
  not actually enforce anything.

### SEC-32 — Database backups
- **Status:** PASS
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
  **Gate pass (2026-11-18):** re-probed — Supabase Management API
  unauthenticated → 401; with the connected token → 403 (token sees
  only the "Saftey App" org). PITR status STILL UNVERIFIED. Backup
  script `backend/scripts/backup-db.sh` exists; it needs `pg_dump` +
  production `DATABASE_URL` (Render env only). No backup ever taken, no
  trial restore performed. Still FAIL.
- **Remaining risk:** low — a backup now exists and restores. Gaps
  that remain: the archive is UNENCRYPTED (no passphrase set yet);
  no recurring schedule yet (daily suggested until Supabase automated
  backups are confirmed, weekly after); `_prisma_migrations` does not
  exist in prod (schema synced without migration history) so restores
  carry data + policies but no migration state.
- **Reviewer notes:** Day 7 must take a backup AND restore-test it into a
  disposable database and record the procedure. Do not mark PASS on a
  backup that was never restored.
  **Day 11 close-out (2026-11-24 ~19:15 IST):** PASS. Owner picked the
  free `pg_dump` route, then the postgres-password reset path (dashboard
  reset, user-chosen password, 19:08 IST). `pg_dump` 17.12 as the
  `postgres` role (direct connection; the app role cannot dump — RLS
  blocks pg_dump's COPY/cursor, proven). Archive
  `backend/backups/secureguard-20261124-134015.dump.gz` (1.6 MB, 0600,
  manifest lists all 20 public tables + data). Script fixes landed:
  `--schema=public` + `--inserts`, manifest step fixed (pg_restore
  does not read stdin — temp file first). Trial restore into a local
  PG 17.12 scratch DB (PGDG server, run as `nobody`, deleted after):
  with `secureguard_app` created first, pg_restore completed with
  only the benign `schema "public" already exists` error; 20/20
  tables + 20/20 policies restored; row counts matched prod exactly
  (User 29, Organization 21, Scan 21, Vulnerability 122, ApiKey 2,
  Repository 9). Full record: `docs/BACKUP_AND_RESTORE.md` §2–§3.

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
  **Gate pass (2026-11-18):** `backend/scripts/purge-retention.js`
  landed (dry-run default, `--apply` deletes; 4/4 offline tests) —
  covers ONLY the no-RLS tables (AnalyticsEvent 90d, ContactMessage 2y,
  Stripe/Razorpay webhook events + WebhookDelivery 90d). The RLS tables
  (AlertLog 180d, OrganizationInvitation EXPIRED/REVOKED + 30d) and
  AuditLog still need the owner-role SQL in `docs/DATA_RETENTION.md`
  §3. **Open conflict:** the §3 AuditLog DELETE will FAIL once the RLS
  migration is applied — the append-only trigger blocks direct DELETE
  while the org exists, for every role including superuser. Needs a
  decision: amend the trigger with a retention carve-out, or accept
  indefinite AuditLog retention. No scheduled job exists (no in-process
  scheduler in this backend — monthly Render Cron Job); no purge has
  ever run. Stays PARTIAL.
- **Test evidence:** `backend/tests/verify_db_schema.js` exists (needs live
  DB; not run).
- **Remaining risk:** medium — carried by SEC-31/SEC-32.
- **Reviewer notes:** Day 7 covers backups + RLS + retention; Day 19
  covers the migration/CI story.

---

## F. Production security

### SEC-34 — CAPTCHA on public forms
- **Status:** PASS
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
  **Day 4 re-probe 2026-11-17 (no signup attempted):** live frontend
  bundle (`assets/index-Ac2tFl7a.js`) contains no Turnstile site key and
  zero references to `challenges.cloudflare.com`; the token is attached
  only when present. Captcha is off on both ends — FAIL re-confirmed.
  **Gate pass (2026-11-18) — LIVE re-probe:** `POST /api/auth/register`
  (no token) → **201** `{ requiresVerification: true }`;
  forgot-password → 200; contact → **201** (new ContactMessage row id
  5). Live bundle still has 0 Turnstile references. Still FAIL — keys
  unset, guard still fail-open by design.
  **Day 7 (2026-11-20, no signup attempted):** live bundle
  (`assets/index-DAcJsNBs.js`) now contains the Turnstile widget code
  (4 references; CSP allows `challenges.cloudflare.com`) but **no
  site key** is baked in — `VITE_TURNSTILE_SITE_KEY` still unset, so
  the guard still passes requests through. FAIL re-confirmed without
  creating probe rows.
- **Remaining risk:** low — bot protection live on signup,
  forgot-password and contact. The `/login` route has no Turnstile
  guard by design (rate-limited; not part of this item's scope).
- **Reviewer notes:** fix = Rishabh creates the Turnstile widget in
  Cloudflare and sets `TURNSTILE_SECRET_KEY` on Render +
  `VITE_TURNSTILE_SITE_KEY` on Vercel (his step, Day 4). Do NOT flip the
  guard to fail-closed before the keys exist — that repeats the Nov 8
  outage.
  **Day 11 close-out (2026-11-24):** PASS, verified end to end.
  Cloudflare widget "SecureGaurd" (Managed, hostname
  `secureguard-main.vercel.app`); `TURNSTILE_SECRET_KEY` set on Render
  (deploy Live 12:24 IST), `VITE_TURNSTILE_SITE_KEY` set on Vercel
  Production (redeploy ready 12:29 IST); site keys verified MATCH
  character by character. Backend enforcement proven by direct POST:
  `POST /api/auth/register` with no token → **400** ("Security check
  is required"); register without a token is also blocked client-side.
  The live widget initially failed to load ("The security check failed
  to load") — root cause was a wrong script URL in
  `TurnstileWidget.tsx` (`turnstile/api.js` 404s; correct URL is
  `turnstile/v0/api.js`, verified 200), fixed in one line, commit
  `1a11ff9` "update turnstile script url", pushed on his word. Live
  probe after deploy (cloud browser, 13:02 IST): `/signup` renders the
  widget — "Verify you are human" checkbox + Cloudflare logo, no
  error. Note: `/login` accepting a no-token request is by design —
  the guard covers register/forgot-password/contact only.

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
  **Day 7 spot-check (2026-11-20):** `createAuditLog` call sites
  grepped across routes/services — 40+ action types covering org,
  member, repo, scan, billing, API-key, custom-rule, alert,
  compliance, AI-fix and vulnerability changes. Not an exhaustive
  per-route proof (no test asserts coverage). **Gap found:** auth
  events (login, logout, password change/reset) write NO audit row;
  `AuditLog.organizationId` is required, so the fix needs a schema
  decision (nullable org for auth events vs primary-org resolution
  at login) — tracked in the gate report, not silently patched.
  Admin-action scope of this item still passes; the auth-event gap
  is adjacent and recorded, not hidden.
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
  **Gate pass (2026-11-18):** grep over `src/` — zero `zod` imports:
  no shared frontend schema exists; validation is per-form inline
  (`required` / `pattern` / `minLength` / `maxLength`). Stays PARTIAL.
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
  **Gate pass (2026-11-18):** authenticated dashboard still NOT
  measured — measuring it needs a logged-in session on a real phone
  (his device). No change; stays PARTIAL.
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
  **Day 4 (2026-11-17):** live frontend bundle contains **zero** `sentry`
  matches — `VITE_SENTRY_DSN` is unset in production, so frontend error
  tracking is off. Backend DSN presence is still dashboard-only (not
  observable from outside); `SENTRY_TEST_ROUTE` verified absent via the
  404 probe (SEC-26).
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
   **Day 5 run (2026-11-18):** claims re-verified in code, no holes in
   sampled routes; email case-sensitivity bug fixed
   (`normalizeEmail`/`findUserByEmail`, 4 new tests, 31/31 offline
   pass); `docs/AUTH_AND_AUTHORIZATION.md` written. Live cross-tenant
   matrix still BLOCKED (mailbox); SEC-07/15/16 stay PARTIAL.
3. Day 6: CSP header (SEC-19) — **DONE, live re-verified 2026-11-19**;
   rate-limit `/refresh` + `/me` (SEC-17) — **DONE in code; limiter
   trips at 10 in-process (new test), live 429 proof still open**;
   Razorpay idempotency inside the transaction (threat T10) — **DONE**;
   classifier key on the webhook path (threat T11) — **DONE**;
   standardised input validation (SEC-18) — **auth routes wired 2026-11-19
   (9/48 routes; 39 remain, Day 8+)**; live CORS probe — **DONE
   2026-11-19 (unlisted origin denied, allowed origin 204)**; SSRF +
   webhook code re-read — **PASS stands, live tests need staging/real
   delivery**. **Day 6 run (2026-11-19):** 6 auth routes wired to the
   shared zod library, 11/11 new tests + 49/49 regression set,
   `docs/BACKEND_SECURITY.md` written. SEC-17/18/22 stay PARTIAL.
4. Day 7: backup taken + restore-tested (SEC-32) — **still FAIL**;
   Postgres RLS (SEC-31) — **migration written, not applied; call-site
   conversion + app-role check first**; live cross-tenant matrix
   (SEC-15/SEC-16) — **open (needs 2 mailboxes)**; security regression
   tests — **DONE (47/47 + new suites)**; `SECURITY_GATE_REPORT.md` —
   **written this run: GATE NOT PASSED**. No Phase 4 work until it passes.
