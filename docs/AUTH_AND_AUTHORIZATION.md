# SecureGaurd — Authentication & Authorization (Day 5, 2026-11-18)

Day 5 of the 20-day transformation: login, logout, token lifecycle, RBAC,
IDOR and tenant isolation. The Nov 16 fix-all run had already implemented
the headline Day 5 fixes (SEC-09 verification gate, strict
`requireOrgContext`, the 92/92 route-auth matrix). This run re-verified
those claims against the code as it stands at remote HEAD `7356683e`,
fixed the one real auth bug it found (email case-sensitivity), and
records what is still only verified in code — not live.

No status in `SECURITY_HARDENING_CHECKLIST.md` changes on this run:
SEC-07 stays PARTIAL (no MFA; live flows unrun), SEC-15/SEC-16 stay
PARTIAL (live cross-tenant matrix still blocked). Counts stay 24 PASS /
15 PARTIAL / 4 FAIL / 3 N/A.

## 1. What was re-verified (code, HEAD 7356683e)

### Token lifecycle — verified, no gaps found

- Access token 15 min, refresh token 7 days
  (`backend/routes/auth.js:29-30`).
- Refresh is bcrypt-hashed at rest, rotating, with an atomic
  compare-and-swap and a 60 s grace window for the superseded token;
  reuse outside the grace window kills the session server-side
  (`auth.js:376-441`, `/refresh`).
- `POST /logout` nulls the stored refresh token and the in-grace
  superseded token, and clears the `sg_refresh` cookie.
- `GET /me` is a read-only session restore: it mints an access token
  but does NOT rotate the refresh token (concurrent restores in
  multiple tabs used to log each other out).
- `sg_refresh` cookie is httpOnly + `secure: true` + `SameSite=None`
  (required for cross-site Vercel → Render).
- The access token lives only in React state (`AuthContext.tsx:37`);
  the frontend also clears legacy `localStorage` remnants
  (`sg_token`, `sg_user`) on logout. No token in `localStorage`.
- Password change (`POST /change-password`) requires the current
  password and clears all sessions afterwards, same as reset.
  Password reset clears all sessions; reset tokens are
  `crypto.randomBytes(32)`, SHA-256 hash stored only, single-use,
  1 h expiry.
- Login and register return the same generic `Invalid credentials` /
  `User already exists` shapes; resend-verification and
  forgot-password are generic-200 for unknown emails (no enumeration).

### Email verification gate (SEC-09) — verified

- Register returns 201 `{ requiresVerification: true }` and NO tokens
  until verified; login returns 403 `email_not_verified` for pending
  accounts; `/refresh` and `/me` are gated the same way.
- Gate applies only when a pending token exists
  (`emailVerifyToken != null`) — pre-existing accounts are
  grandfathered, no migration, no lockout.
- Register 503s honestly BEFORE creating the account if mail is
  unconfigured, and deletes the row if the send fails (no orphaned
  unverifiable account).

### RBAC — verified, no gaps found

- `requireOrgContext` (`backend/middleware/rbac.js:36-57`): a supplied
  org id must match `/^\d+$/` or it is a 400 — no fallback to the
  caller's first org (the Day 1 S3 finding, fixed in commit
  `670755d`). Non-members get 403. Absent id takes the default-org
  path (auto-migrates a default org for users with none).
- `requireOrgRole` enforces OWNER/ADMIN/DEVELOPER/AUDITOR per route:
  org update/delete, member add/remove/role-change, invitations,
  transfer-ownership, audit-log reads, billing, compliance
  generate/delete, alert settings, AI fix generate/apply, classifier
  status, custom-rule writes, repo delete. Spot-checked in
  `organizations.js` (15 role-gated routes), `vulnerabilities.js`
  (`PATCH /:id/status` requires OWNER/ADMIN/DEVELOPER — AUDITOR is
  read-only), `repos.js`, `sboms.js`.
- Invitation accept (`routes/invitations.js:54-117`) requires auth and
  an email match with the invite, and consumes the invitation
  conditionally (one accept wins).
- GitHub/GitLab PATs are encrypted at rest (`encrypt`/`decrypt` in
  `routes/integration.js`); OAuth is auth-code + PKCE with
  HMAC-signed state, and unconfigured providers 501 instead of
  redirecting nowhere.

### IDOR / tenant isolation (SEC-15) — verified in code, not live

- Every `:id` lookup sampled scopes by org: `scans.js` (`scan` by
  `id + organizationId`), `vulnerabilities.js` (`vuln` via
  `scan.organizationId`), `repos.js`, `sboms.js`, `compliance.js`
  (reports + PDF), `customRules.js` — all `findFirst` with
  `organizationId: req.organizationId`, 404 on cross-org ids.
  No unscoped `:id` fetch found in the sampled routes.
- The route-auth matrix (`docs/route-auth-matrix.md`, rewritten in
  commit `6dac31e`) claims 92/92 routes checked with no holes.
  This run did not re-count all 92; it verified the router mounts in
  `server.js` and the middleware counts per router file, and
  spot-checked the sensitive routes above. A full re-count is a Day 7
  gate item, not a Day 5 claim.

## 2. The Day 5 fix — email case-sensitivity

### The bug

`User.email` is `@unique`, and Postgres `=` on text is exact, but no
auth route normalized the address. Registering as
`Rishabh@Example.com` and logging in as `rishabh@example.com` failed
(`Invalid credentials`), and the two casings could become two
accounts. The invitations route already normalized
(`organizations.js:538`, `trim().toLowerCase()`); the auth routes did
not. The shared validation lib's `zEmail` also normalizes — but the
auth routes do not use it.

### The change (smallest complete fix)

`SecureGaurd-main/backend/routes/auth.js` — `normalizeEmail()` +
`findUserByEmail()` helpers, applied server-side only:

- Register: duplicate check and stored address use the canonical
  (trimmed, lowercase) form; the verification mail goes to it.
- Login, forgot-password, resend-verification: lookup via
  `findUserByEmail`, which tries the canonical form first and falls
  back to a case-insensitive match — so accounts created before this
  change (stored mixed-case) keep working whatever case the user
  types now. Mail goes to the stored address.
- OAuth callback: the provider email is normalized before lookup and
  before creating the linked account, so an OAuth login never strands
  or duplicates a mixed-case address.
- No frontend change, no schema change, no migration. One extra DB
  query only on a lookup miss.

### Tests — 31/31 pass (offline, 2026-11-18 ~01:20 IST)

- New `backend/tests/authEmailNormalization.test.js` (4 tests):
  register stores the trimmed lowercase address and login works in
  any case (full verify-then-login flow); a pre-normalization
  mixed-case account still logs in in any case; forgot-password finds
  the account in any case and mails the stored address; register
  rejects a differently-cased duplicate.
- Existing suites re-run in the same command: `authVerification`
  (8), `rbac` (8), `validation` (11) — all pass.
- `aiFixEngine`, `startup_routes`, `astExtraction`,
  `deployment_config` re-run: all pass (`deployment_config` 3/3
  needs JWT/ENCRYPTION_KEY/DATABASE_URL set — dummy values in this
  run; without them it fails at `server.js` env validation, which is
  pre-existing and unrelated to this change).
- Run: `node --test backend/tests/authEmailNormalization.test.js
  backend/tests/authVerification.test.js backend/tests/rbac.test.js
  backend/tests/validation.test.js` from `SecureGaurd-main/backend`.

## 3. Live state (probed 2026-11-18 ~01:25 IST, before push)

- Frontend `https://secureguard-main.vercel.app/` — 200, 1.30 s.
- Backend `https://securegaurd.onrender.com/health` — 200
  `{"status":"ok"}`, 28.1 s (Render cold start).
- Classifier `https://secureguard-classifier.onrender.com/health` —
  200, v2.2.1, `model_version v3_real, model_loaded true`, 58.2 s
  (cold start).
- This run's code change is backend-only; live behavior of the fix
  (login with a differently-cased email) is NOT probed live — it
  needs a verified account, which needs a mailbox (see §4).

## 4. Still open — not disguised as done

- **Live cross-tenant IDOR matrix (SEC-15/SEC-16): BLOCKED.** Needs
  two verified accounts in two orgs, cross-org reads/writes on every
  `:id` route, expecting 404. Blocked on a mailbox to click the
  verification link — no mailbox is reachable from this VM, and using
  the user's own email for a probe account is not done without his
  word. Procedure is in the checklist §H; the Day 7 gate requires it.
- **Live auth flows end-to-end (SEC-07): NOT RUN.** Register →
  verify (click) → login → refresh → logout → password reset, against
  production. Same mailbox blocker. The leftover probe account
  `sg-fixall-20261116@example.com` is still an unverified row in
  prod — it cannot self-delete (no token, login blocked); owner
  deletes via DB.
- **No MFA anywhere.** No per-account lockout either: login
  brute-force protection is the IP rate limit only (10 attempts /
  15 min, `authLimiter`). A distributed guessing attack is slowed,
  not stopped; a per-account lockout is a Day 18 / follow-up design
  decision (lockouts create their own account-DoS vector — not
  added silently in this run).
- **One refresh token per user:** logging in on a second device
  invalidates the first device's session (login overwrites the
  stored hash). Deliberate, but undocumented until now — a
  multi-device user will see the other device logged out.
- **OAuth providers shipped but none live** (`docs/OAUTH_SSO.md`):
  no provider client id/secret is set in production, so the buttons
  are hidden and the routes 501. SAML is not implemented.

## 5. What Day 5 did not change

- No auth/validation weakened to make tests pass. No secrets added
  or exposed (grep-verified: no credential strings in the changed
  files). No ML model files or training data touched. No routes
  added, removed, or re-scoped; the route-auth matrix is unchanged.
- Two test failures found while fixing were real test bugs, not
  code bugs: the first fallback (exact-address only) could never
  find a stored mixed-case row from a lowercase login, and the
  fallback gate (`normalized !== email`) never fired for an already
  lowercase login. Both were fixed in the code (unconditional
  case-insensitive fallback on miss), not by weakening the tests.
