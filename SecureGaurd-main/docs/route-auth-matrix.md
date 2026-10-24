# SecureGaurd API — Route / Auth Matrix

Audited 2026-10-24 (Day 1, Phase 2+3 program). Every route is exactly one of:
**AUTH+ORG** (JWT + verified org membership, queries scoped to `req.organizationId`),
**AUTH** (JWT only), or **PUBLIC-DELIBERATE** (no JWT by design, with the compensating control named).

Roles: `OWNER` · `ADMIN` · `DEVELOPER` · `AUDITOR` (read-only — blocked from every write route by `requireOrgRole`).

Legend — Auth column: `—` = no auth middleware. Org column: `✓` = membership verified + all data access scoped to the org; `svc` = service-key path (see notes).

## Deliberately public routes (no JWT — compensating control in place)

| Method + path | Compensating control |
|---|---|
| `GET /health` | Liveness only, returns `{status:'ok'}` — no data |
| `POST /api/auth/register` | Rate-limited (10/15m); input-validated; bcrypt(12) |
| `GET\|POST /api/auth/verify-email` | Single-use token-gated (token is a 64-hex secret, consumed on use) |
| `POST /api/auth/login` | Rate-limited (10/15m); bcrypt compare; generic "invalid credentials" |
| `POST /api/auth/refresh` | Refresh-token session: httpOnly `Secure; SameSite=None` cookie, JWT verified, bcrypt hash match against DB, rotation with 60 s grace window (see below) |
| `POST /api/auth/logout` | Cookie session invalidation |
| `POST /api/auth/forgot-password` | Rate-limited (5/h); honest 503 when mail unconfigured; always-200 when configured (no email enumeration) |
| `POST /api/auth/reset-password` | Single-use 64-hex token + 1 h expiry; clears password + all sessions |
| `GET /api/auth/me` | Session restore: validates the refresh cookie against the DB hash (current or in-grace previous). Read-only — does NOT rotate, so concurrent tab restores can't invalidate each other |
| `GET /api/invitations/:token` | Token-gated (64-hex secret); reveals only the invite's own org name/role/email |
| `POST /api/integration/webhook/:platform` | HMAC signature over the raw body (`x-hub-signature-256` / `x-gitlab-token`); fails CLOSED when `WEBHOOK_SECRET` unset; rate-limited (30/5m) |
| `POST /api/billing/webhook` | Stripe signature via `stripe.webhooks.constructEvent`; fails CLOSED when `STRIPE_WEBHOOK_SECRET` missing/placeholder; idempotent (`StripeWebhookEvent`) |
| `GET /api/classifier/health` | Liveness only — no data |

## Authenticated routes

### /api/auth
| Method + path | Org | Roles | Notes |
|---|---|---|---|
| `POST /complete-onboarding` | — | any authenticated | Sets own `onboardingCompleted` only |

### /api/repos — `router.use(auth, requireOrgContext)`
| Method + path | Roles | Notes |
|---|---|---|
| `GET /` | all 4 | org-scoped list |
| `POST /` | OWNER, ADMIN, DEVELOPER | entitlement-checked; audit-logged |
| `DELETE /:id` | OWNER, ADMIN | `findFirst({id, organizationId})` — cross-org → 404 |

### /api/scans
| Method + path | Auth | Org | Roles | Notes |
|---|---|---|---|---|
| `GET /export-feedback` | svc or JWT | ✓ multi-org | all 4 | Service callers present `x-secureguard-key` = `CLASSIFIER_API_KEY`; user callers are scoped to orgs they belong to — never other tenants' labels |
| `GET /` | JWT | ✓ | all 4 | org-scoped list |
| `GET /:id` | JWT | ✓ | all 4 | `findFirst({id, organizationId})` — cross-org → 404 |
| `POST /trigger` | JWT | ✓ | OWNER, ADMIN, DEVELOPER | rate-limited (10/10m); entitlement-checked; repo must belong to org |

### /api/vulnerabilities — `router.use(auth, requireOrgContext)`
| Method + path | Roles | Notes |
|---|---|---|
| `GET /` | all 4 | `scan.organizationId` scoped; filter-validated |
| `GET /:id` | all 4 | `findFirst({id, scan.organizationId})` — cross-org → 404 |
| `PATCH /:id/status` | OWNER, ADMIN, DEVELOPER | allowlisted statuses; audit-logged |
| `PATCH /:id/label` | OWNER, ADMIN, DEVELOPER | allowlisted labels (`real`/`false_positive`) |

### /api/integration
| Method + path | Auth | Org | Roles | Notes |
|---|---|---|---|---|
| `GET /tokens` | JWT | — | any | lists own PAT metadata (never secret values) |
| `POST /tokens` | JWT | — | any | PAT encrypted at rest (AES-256-GCM) |
| `GET /repos` | JWT | — | any | connected-platform repo listing for own account |
| `POST /pr-bot` | JWT | ✓ | OWNER, ADMIN, DEVELOPER | repo must belong to org |

### /api/ai — `router.use(auth, requireOrgContext)`
| Method + path | Roles | Notes |
|---|---|---|
| `POST /fix/:vulnId` | OWNER, ADMIN, DEVELOPER | vuln org-scoped; fix cached; audit-logged |
| `PATCH /fix/:vulnId/apply` | OWNER, ADMIN, DEVELOPER | requires generated fix; audit-logged |
| `PATCH /false-positive/:vulnId` | OWNER, ADMIN, DEVELOPER | audit trail via status change |
| `GET /status` | all 4 | config presence only — no key material returned |

### /api/classifier
| Method + path | Auth | Notes |
|---|---|---|
| `GET /status` | JWT | service reachability |

### /api/v2/ml
| Method + path | Auth | Org | Roles | Notes |
|---|---|---|---|---|
| `POST /rank` | JWT | ✓ | all 4 | read: scores caller's org vulns; 1–100 ids; degraded fallback is static tiering, explicitly marked |

### /api/compliance — `router.use(auth, requireOrgContext)`
| Method + path | Roles | Notes |
|---|---|---|
| `POST /generate` | OWNER, ADMIN, DEVELOPER | repo must belong to org; audit-logged |
| `GET /reports` | all 4 | org-scoped |
| `GET /reports/:id` | all 4 | `findFirst({id, organizationId})` — cross-org → 404 |
| `GET /reports/:id/pdf` | all 4 | same scoping |
| `GET /reports/:id/json` | all 4 | same scoping |
| `DELETE /reports/:id` | OWNER, ADMIN | org-scoped |

### /api/organizations — `router.use(auth)`
| Method + path | Org | Roles | Notes |
|---|---|---|---|
| `GET /` | — | any | lists only own memberships |
| `POST /` | — | any | creator becomes OWNER; audit-logged |
| `GET /:organizationId` | ✓ | all 4 | non-member → 403 |
| `PATCH /:organizationId` | ✓ | OWNER, ADMIN | |
| `DELETE /:organizationId` | ✓ | OWNER | sole-owner org: blocked unless ownership transferred |
| `GET /:organizationId/members` | ✓ | all 4 | member list incl. roles |
| `PATCH /:organizationId/members/:memberId` | ✓ | OWNER, ADMIN | Admin cannot touch Owner roles; last Owner cannot be demoted; audit-logged |
| `DELETE /:organizationId/members/:memberId` | ✓ | OWNER, ADMIN | last-Owner removal blocked; audit-logged |
| `POST /:organizationId/invitations` | ✓ | OWNER, ADMIN | server-validated role allowlist (Owner may grant OWNER; Admin up to ADMIN; AUDITOR grantable); audit-logged |
| `GET /:organizationId/invitations` | ✓ | OWNER, ADMIN | pending invites (no raw tokens re-exposed) |
| `DELETE /:organizationId/invitations/:invitationId` | ✓ | OWNER, ADMIN | revoke; audit-logged |
| `GET /:organizationId/audit-logs` | ✓ | OWNER, ADMIN | append-only admin action log |

### /api/invitations
| Method + path | Auth | Notes |
|---|---|---|
| `POST /:token/accept` | JWT | SHA-256 token match, expiry + single-use enforced; creates membership with the invited role — the role comes from the stored invitation, never the client |

### /api/billing — `router.use(auth)`
| Method + path | Org | Roles | Notes |
|---|---|---|---|
| `GET /usage` | ✓ | all 4 | subscription + usage vs limits |
| `POST /create-checkout-session` | ✓ | OWNER | Stripe checkout; org id in metadata |
| `POST /create-portal-session` | ✓ | OWNER | Stripe customer portal |
| `POST /cancel-subscription` | ✓ | OWNER | cancel-at-period-end; webhook confirms |

### /api/sboms — `router.use(auth, requireOrgContext)`
| Method + path | Roles | Notes |
|---|---|---|
| `GET /` | all 4 | org-scoped |
| `GET /:id` | all 4 | `findFirst({id, organizationId})` — cross-org → 404 |
| `GET /:id/download` | all 4 | same scoping |
| `GET /repository/:repositoryId` | all 4 | repo org-scoped |

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
