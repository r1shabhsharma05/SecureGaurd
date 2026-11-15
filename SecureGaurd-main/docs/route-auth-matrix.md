# SecureGaurd API — Route / Auth Matrix

Re-audited 2026-11-16 (Day 3, 20-Day Transformation program; SEC-16).
Verified commit: `6d28ae4` — "add day 3 threat model and security checklist".
CAUTION: other Day-5 units are editing route files in this same clone
concurrently (auth.js gained `resend-verification` + `change-password`
and `refreshLimiter`/`meLimiter`; scans.js/public.js gained shared
validation). This matrix was re-verified against the working tree AFTER
those edits landed, and line numbers below are as read in that final
pass — re-check them if any route file changes again before push.
Previous audit: 2026-10-24. Since then: 64 commits, 20 touching
`backend/routes/`.

Every route is exactly one of:
**AUTH+ORG** (JWT + verified org membership, queries scoped to `req.organizationId`),
**AUTH** (JWT only — no org concept on that route, or own-account data only),
**SVC-or-JWT** (service key OR JWT, see below), or
**PUBLIC-DELIBERATE** (no JWT by design, with the compensating control named).

Roles: `OWNER` · `ADMIN` · `DEVELOPER` · `AUDITOR` (read-only — blocked from every write route by `requireOrgRole`).

Legend — Auth column: `—` = no auth middleware. Org column: `✓` = membership verified + all data access scoped to the org.

## Audit result

- **Routes checked: 92 / 92** — 90 router routes + 2 server-level routes
  (`backend/server.js:74-119` mounts; inventory taken by grepping every
  `router.(get|post|patch|put|delete|use)` in `backend/routes/*.js` and
  reading each handler's middleware chain). The first pass found 88
  router routes; a recount caught 2 more in `auth.js`
  (`resend-verification`, `change-password`) that landed from another
  unit's concurrent edit — both verified and classified below.
- **AUTH+ORG: 63 · AUTH: 7 · SVC-or-JWT: 1 · PUBLIC-DELIBERATE: 21.**
- **Holes found: none.** Every route that touches tenant data requires JWT
  and org membership, or a named compensating control (below). No route
  was found missing auth that should have it, so no route fix was needed.
- **Changes vs the 2026-10-24 matrix** (the matrix was stale, not the code):
  two whole routers were missing — `/api/alerts` (4 routes) and
  `/api/custom-rules` (8 routes); billing moved Stripe
  `create-checkout-session` / `create-portal-session` → Razorpay
  `create-subscription` + `invoices`; `GET /api/classifier/status` is now
  AUTH+ORG OWNER/ADMIN (was JWT-only — stricter, not a hole); new routes
  since Oct 24: `POST /api/scans/api-spec`, `GET /api/scans/stats/summary`,
  `GET /api/vulnerabilities/:id/explanation`,
  `GET /api/sboms/:id/cyclonedx`, `GET /api/sboms/:id/threat-intel`,
  `POST /api/organizations/:organizationId/leave`,
  `POST /api/organizations/:organizationId/transfer-ownership`,
  `GET /api/auth/oauth/providers`, `GET /api/auth/oauth/:provider`,
  `GET /api/auth/oauth/:provider/callback`, `DELETE /api/auth/account`,
  `POST /api/auth/resend-verification`, `POST /api/auth/change-password`,
  `GET /api/analytics/summary`. `POST /api/auth/refresh` and
  `GET /api/auth/me` are now rate-limited in the Day-5 working tree
  (T9 gap closed by another unit — re-confirm at push).

## Deliberately public routes (no JWT — compensating control in place)

| Method + path | Evidence | Compensating control |
|---|---|---|
| `GET /health` | `backend/server.js:85` | Liveness only, returns `{status:'ok'}` — no data |
| `GET /api/_test-error` | `backend/server.js:94` | Exists ONLY when `SENTRY_TEST_ROUTE=enabled`; throws into the Sentry error handler |
| `POST /api/auth/register` | `backend/routes/auth.js:143` | Rate-limited (10/15m); Turnstile; input-validated; bcrypt(12) |
| `GET\|POST /api/auth/verify-email` | `backend/routes/auth.js:233-234` | Single-use token-gated (token is a 64-hex secret, consumed on use) |
| `POST /api/auth/resend-verification` | `backend/routes/auth.js:241` | Rate-limited; rotates the 24 h verification token and re-sends it; anti-enumeration (unknown/already-verified emails get the same generic 200); honest 503 when mail unconfigured |
| `POST /api/auth/login` | `backend/routes/auth.js:277` | Rate-limited (10/15m); bcrypt compare; generic "invalid credentials"; SEC-09 gate: unverified accounts (created after the gate shipped) cannot sign in |
| `POST /api/auth/refresh` | `backend/routes/auth.js:355` | Rate-limited (refreshLimiter — T9 gap closed in the Day-5 working tree); refresh-token session: httpOnly `Secure; SameSite=None` cookie, JWT verified, bcrypt hash match against DB, rotation with 60 s grace window (see below); SEC-09 gate applies |
| `POST /api/auth/logout` | `backend/routes/auth.js:422` | Cookie session invalidation (no data returned) |
| `POST /api/auth/forgot-password` | `backend/routes/auth.js:437` | Rate-limited (5/h); honest 503 when mail unconfigured; always-200 when configured (no email enumeration) |
| `POST /api/auth/reset-password` | `backend/routes/auth.js:491` | Single-use 64-hex token + 1 h expiry; clears password + all sessions |
| `GET /api/auth/me` | `backend/routes/auth.js:566` | Rate-limited (meLimiter — T9 gap closed in the Day-5 working tree). Session restore: validates the refresh cookie against the DB hash (current or in-grace previous). Read-only — does NOT rotate, so concurrent tab restores can't invalidate each other; SEC-09 gate applies (pending-verification → 401 `email_not_verified`) |
| `GET /api/auth/oauth/providers` | `backend/routes/auth.js:633` | Returns only the list of configured provider names — no user data, no secrets |
| `GET /api/auth/oauth/:provider` | `backend/routes/auth.js:638` | OAuth start: 404 unknown provider, 501 if unconfigured; HMAC-signed state + PKCE cookies set, 302 to the provider |
| `GET /api/auth/oauth/:provider/callback` | `backend/routes/auth.js:666` | Rate-limited (30/h); state-cookie match + HMAC state verify + PKCE verifier required; provider errors logged, never shown |
| `GET /api/invitations/:token` | `backend/routes/invitations.js:10` | Token-gated (SHA-256 of a 64-hex secret); reveals only the invite's own org name/role/email; expired/non-pending → 400 |
| `POST /api/integration/webhook/:platform` | `backend/routes/integration.js:66` | HMAC signature over the raw body (`x-hub-signature-256` / `x-gitlab-token`); fails CLOSED when no secret configured; rate-limited (30/5m); bad signature → 401 regardless of repo existence |
| `POST /api/billing/webhook` | `backend/routes/billingWebhook.js:95`, mounted `backend/server.js:74` before `express.json` | Razorpay HMAC-SHA256 (`x-razorpay-signature` over the raw body, `utils/razorpay.js:verifyWebhookSignature`); fails CLOSED when `RAZORPAY_WEBHOOK_SECRET` is missing or a placeholder; idempotent (`StripeWebhookEvent`) |
| `GET /api/classifier/health` | `backend/routes/classifier.js:63` | Liveness only — coarse `{running: boolean}`, no upstream detail re-served |
| `POST /api/analytics/events` | `backend/routes/public.js:54` | Closed event allow-list, flat short-string props only, no IP / no client-supplied identity stored; rate-limited (120/15m) |
| `POST /api/contact` | `backend/routes/public.js:88` | Validated (shared schema) + honeypot + Turnstile; rate-limited (5/h); stored only after the mail provider accepts it |

## Authenticated routes

### /api/auth — `auth.js` (no router-level `use`; per-route middleware)
| Method + path | Auth | Org | Roles | Evidence |
|---|---|---|---|---|
| `POST /complete-onboarding` | JWT | — | any authenticated | `auth.js:738` — sets own `onboardingCompleted` only |
| `POST /change-password` | JWT | — | any authenticated | `auth.js:535` — rate-limited; requires current password (a stolen session alone must not change it); bcrypt(12); clears all sessions + refresh cookie afterwards |
| `DELETE /account` | JWT | — | any authenticated | `auth.js:776` — rate-limited (3/h); requires current password + typed `DELETE`; org-asset handoff per `utils/accountDeletion.js` |

### /api/repos — `router.use(auth, requireOrgContext)` (`repos.js:20-21`)
| Method + path | Roles | Evidence |
|---|---|---|
| `GET /` | all 4 | `repos.js:24` — org-scoped list |
| `POST /` | OWNER, ADMIN, DEVELOPER | `repos.js:47` — entitlement-checked; audit-logged |
| `DELETE /:id` | OWNER, ADMIN | `repos.js:154` — `findFirst({id, organizationId})` — cross-org → 404 |

### /api/scans — `router.use(auth, requireOrgContext)` (`scans.js:113-114`)
| Method + path | Auth | Org | Roles | Evidence |
|---|---|---|---|---|
| `GET /export-feedback` | svc or JWT | ✓ multi-org | all 4 | `scans.js:48` — declared BEFORE the router-level `use`. Service callers present `x-secureguard-key` = `CLASSIFIER_API_KEY`; user callers are scoped to orgs they belong to — never other tenants' labels. Service path disabled when `CLASSIFIER_API_KEY` unset (falls through to JWT). Export capped (default 1000, max 5000 rows) |
| `GET /` | JWT | ✓ | all 4 | `scans.js:117` — org-scoped list |
| `GET /:id` | JWT | ✓ | all 4 | `scans.js:136` — `findFirst({id, organizationId})` — cross-org → 404 |
| `POST /trigger` | JWT | ✓ | OWNER, ADMIN, DEVELOPER | `scans.js:166` — rate-limited (10/10m); entitlement-checked; repo must belong to org |
| `POST /api-spec` | JWT | ✓ | OWNER, ADMIN, DEVELOPER | `scans.js:508` — rate-limited; same entitlement check as trigger |
| `GET /stats/summary` | JWT | ✓ | all 4 | `scans.js:570` — counts caller's org open vulns by severity only |

### /api/vulnerabilities — `router.use(auth, requireOrgContext)` (`vulnerabilities.js:7-8`)
| Method + path | Roles | Evidence |
|---|---|---|
| `GET /` | all 4 | `vulnerabilities.js:11` — `scan.organizationId` scoped; filter-validated |
| `GET /:id` | all 4 | `vulnerabilities.js:42` — `findFirst({id, scan.organizationId})` — cross-org → 404 |
| `GET /:id/explanation` | all 4 | `vulnerabilities.js:118` — same org scoping as `/:id` |
| `PATCH /:id/status` | OWNER, ADMIN, DEVELOPER | `vulnerabilities.js:186` — allowlisted statuses; audit-logged |
| `PATCH /:id/label` | OWNER, ADMIN, DEVELOPER | `vulnerabilities.js:235` — allowlisted labels (`real`/`false_positive`) |

### /api/integration — webhook `:66` is public (above); `router.use(auth)` at `integration.js:325`
| Method + path | Auth | Org | Roles | Evidence |
|---|---|---|---|---|
| `GET /tokens` | JWT | — | any | `integration.js:328` — lists own PAT metadata (never secret values) |
| `POST /tokens` | JWT | — | any | `integration.js:346` — PAT encrypted at rest (AES-256-GCM) |
| `GET /repos` | JWT | — | any | `integration.js:365` — connected-platform repo listing for own account |
| `POST /pr-bot` | JWT | ✓ | OWNER, ADMIN, DEVELOPER | `integration.js:440` — `requireOrgContext`; repo must belong to org |

### /api/ai — `router.use(auth, requireOrgContext)` (`ai.js:8-9`)
| Method + path | Roles | Evidence |
|---|---|---|
| `POST /fix/:vulnId` | OWNER, ADMIN, DEVELOPER | `ai.js:13` — vuln org-scoped; fix cached; audit-logged |
| `PATCH /fix/:vulnId/apply` | OWNER, ADMIN, DEVELOPER | `ai.js:91` — requires generated fix; audit-logged |
| `PATCH /false-positive/:vulnId` | OWNER, ADMIN, DEVELOPER | `ai.js:128` — audit trail via status change |
| `GET /status` | all 4 | `ai.js:154` — config presence only — no key material returned |

### /api/classifier — `classifier.js` (per-route middleware)
| Method + path | Auth | Org | Roles | Evidence |
|---|---|---|---|---|
| `GET /status` | JWT | ✓ | OWNER, ADMIN | `classifier.js:34` — coarse status only; never returns the internal classifier URL or raw model-info. Stricter than the Oct 2026 matrix (was JWT-only) |
| `GET /health` | — | — | — | `classifier.js:63` — public liveness, see above |

### /api/v2/ml — `ml.js`
| Method + path | Auth | Org | Roles | Evidence |
|---|---|---|---|---|
| `POST /rank` | JWT | ✓ | all 4 | `ml.js:59` — read: scores caller's org vulns; 1–100 ids; degraded fallback is static tiering, explicitly marked |

### /api/compliance — `router.use(auth, requireOrgContext)` (`compliance.js:10-11`)
| Method + path | Roles | Evidence |
|---|---|---|
| `POST /generate` | OWNER, ADMIN, DEVELOPER | `compliance.js:42` — repo must belong to org; audit-logged |
| `GET /reports` | all 4 | `compliance.js:151` — org-scoped |
| `GET /reports/:id` | all 4 | `compliance.js:173` — `findFirst({id, organizationId})` — cross-org → 404 |
| `GET /reports/:id/pdf` | all 4 | `compliance.js:204` — same scoping |
| `GET /reports/:id/json` | all 4 | `compliance.js:243` — same scoping |
| `DELETE /reports/:id` | OWNER, ADMIN | `compliance.js:278` — org-scoped |

### /api/organizations — `router.use(auth)` (`organizations.js:51`)
| Method + path | Org | Roles | Evidence |
|---|---|---|---|
| `GET /` | — | any | `organizations.js:64` — lists only own memberships |
| `POST /` | — | any | `organizations.js:96` — creator becomes OWNER; audit-logged |
| `GET /:organizationId` | ✓ | all 4 | `organizations.js:155` — non-member → 403 |
| `PATCH /:organizationId` | ✓ | OWNER, ADMIN | `organizations.js:185` |
| `DELETE /:organizationId` | ✓ | OWNER | `organizations.js:207` — sole-owner org: blocked unless ownership transferred |
| `GET /:organizationId/members` | ✓ | all 4 | `organizations.js:235` — member list incl. roles |
| `PATCH /:organizationId/members/:memberId` | ✓ | OWNER, ADMIN | `organizations.js:265` — Admin cannot touch Owner roles; last Owner cannot be demoted; audit-logged |
| `DELETE /:organizationId/members/:memberId` | ✓ | OWNER, ADMIN | `organizations.js:346` — last-Owner removal blocked; audit-logged |
| `POST /:organizationId/leave` | ✓ | all 4 | `organizations.js:413` — own membership removal; org-asset handoff applies |
| `POST /:organizationId/transfer-ownership` | ✓ | OWNER | `organizations.js:463` |
| `POST /:organizationId/invitations` | ✓ | OWNER, ADMIN | `organizations.js:524` — server-validated role allowlist (Owner may grant OWNER; Admin up to ADMIN; AUDITOR grantable); audit-logged |
| `GET /:organizationId/invitations` | ✓ | OWNER, ADMIN | `organizations.js:660` — pending invites (no raw tokens re-exposed) |
| `DELETE /:organizationId/invitations/:invitationId` | ✓ | OWNER, ADMIN | `organizations.js:685` — revoke; audit-logged |
| `GET /:organizationId/audit-logs` | ✓ | OWNER, ADMIN | `organizations.js:718` — append-only admin action log |

### /api/invitations — `invitations.js`
| Method + path | Auth | Org | Notes |
|---|---|---|---|
| `GET /:token` | — | — | `invitations.js:10` — public token-gated, see above |
| `POST /:token/accept` | JWT | — | `invitations.js:55` — SHA-256 token match, expiry + single-use enforced; creates membership with the invited role — the role comes from the stored invitation, never the client |

### /api/billing — `router.use(auth)` (`billing.js:15`)
| Method + path | Org | Roles | Evidence |
|---|---|---|---|
| `GET /usage` | ✓ | all 4 | `billing.js:22` — subscription + usage vs limits |
| `POST /create-subscription` | ✓ | OWNER | `billing.js:41` — Razorpay subscription; org id in metadata; plan activates only via the webhook, never here; fails closed on missing/placeholder plan id |
| `GET /invoices` | ✓ | OWNER, ADMIN | `billing.js:100` — Razorpay invoices for the org's subscription |
| `POST /cancel-subscription` | ✓ | OWNER | `billing.js:126` — cancel-at-period-end; webhook confirms |

Note: the Oct 2026 matrix listed Stripe `create-checkout-session` /
`create-portal-session` here — both are gone; billing is Razorpay now.

### /api/sboms — `router.use(auth, requireOrgContext)` (`sboms.js:7-8`)
| Method + path | Roles | Evidence |
|---|---|---|
| `GET /` | all 4 | `sboms.js:27` — org-scoped |
| `GET /:id` | all 4 | `sboms.js:47` — `findFirst({id, organizationId})` — cross-org → 404 |
| `GET /:id/download` | all 4 | `sboms.js:81` — same scoping |
| `GET /:id/cyclonedx` | all 4 | `sboms.js:116` — same scoping |
| `GET /:id/threat-intel` | all 4 | `sboms.js:152` — same scoping |
| `GET /repository/:repositoryId` | all 4 | `sboms.js:199` — repo org-scoped |

### /api/alerts — `router.use(auth, requireOrgContext)` (`alerts.js:11-12`)
| Method + path | Roles | Evidence |
|---|---|---|
| `GET /settings` | all 4 | `alerts.js:40` — org-scoped; webhook URL never returned (masked flag only) |
| `PUT /settings` | OWNER, ADMIN | `alerts.js:52` |
| `POST /test` | OWNER, ADMIN | `alerts.js:95` |
| `GET /logs` | all 4 | `alerts.js:137` — org-scoped |

### /api/custom-rules — `router.use(auth, requireOrgContext)` (`customRules.js:15-16`); `WRITE_ROLES = ['OWNER','ADMIN','DEVELOPER']` (`customRules.js:19`)
| Method + path | Roles | Evidence |
|---|---|---|
| `GET /library` | all 4 | `customRules.js:75` — org-scoped library |
| `GET /` | all 4 | `customRules.js:114` — org-scoped |
| `GET /:id` | all 4 | `customRules.js:128` — org-scoped |
| `POST /` | OWNER, ADMIN, DEVELOPER | `customRules.js:175` |
| `PATCH /:id` | OWNER, ADMIN, DEVELOPER | `customRules.js:205` |
| `DELETE /:id` | OWNER, ADMIN, DEVELOPER | `customRules.js:241` |
| `POST /:id/test` | OWNER, ADMIN, DEVELOPER | `customRules.js:259` — rate-limited |
| `POST /:id/test-scan` | OWNER, ADMIN, DEVELOPER | `customRules.js:289` |

### /api (public-site router) — `public.js`, mounted `backend/server.js:115`
| Method + path | Auth | Org | Notes |
|---|---|---|---|
| `POST /analytics/events` | — | — | `public.js:54` — public, see above |
| `POST /contact` | — | — | `public.js:88` — public, see above |
| `GET /analytics/summary` | JWT | — | `public.js:133` — aggregate counts only (no per-user rows, no emails, no IPs); range must be 7d/30d/90d or 400. No org scope is correct here: the summary is global product analytics, not tenant data |

## Refresh-token rotation grace window (the /refresh race fix)

Two concurrent `POST /api/auth/refresh` calls presenting the same token used to
race: both passed the bcrypt check, both rotated, the loser's new token was
instantly invalid → spurious logout.

Fix (2026-10-24): the rotation keeps the superseded token hash in
`User.previousRefreshToken` with a 60 s `User.refreshGraceExpiresAt` window.
A refresh presenting the superseded token inside the window is honored once
more and rotated again. The compare-and-swap is atomic
(`updateMany({ where: { id, refreshToken: <verified hash> } })`) — the loser of
the race re-reads and falls into the grace path instead of corrupting state.
Presenting an unknown or out-of-grace token invalidates the session
(reuse detection). `GET /api/auth/me` accepts the in-grace previous token
read-only; `/logout` and password reset clear both tokens.

## Known non-holes / judgment calls (recorded so they are not re-flagged)

- `GET /api/analytics/summary` is AUTH without org: it returns global
  aggregate counts only, no tenant rows — verified `public.js:133` +
  `utils/analyticsSummary.js`.
- `GET /api/integration/tokens|repos` and `POST /api/integration/tokens`
  are AUTH without org: they operate on the caller's own connected
  account, which has no org concept.
- `GET|POST /api/organizations/` are AUTH without org: listing/creating
  one's own orgs cannot be org-scoped (the org is what is being listed).
- `GET /api/auth/oauth/providers` is public: it returns configured
  provider names only.
- `GET /api/scans/export-feedback` is the only SVC-or-JWT route; the
  service-key path is operator-level by design and the JWT path is scoped
  to the caller's own orgs (`scans.js:48-114`).
- Rate-limit gaps on `POST /api/auth/refresh` and `GET /api/auth/me`
  (SEC-17 / T9) are closed in the Day-5 working tree
  (`refreshLimiter`/`meLimiter`, `auth.js:61-79`) by another unit's
  uncommitted work — re-confirm they survive to push; they are
  authenticated-session endpoints, not missing-auth holes.
- Live cross-tenant verification (two test orgs, cross-org reads/writes
  on every `:id` route, expect 404) is a coordinator step after push —
  not done here; this matrix is the static code-side verification only.
