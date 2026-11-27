# SecureGaurd — Enterprise Completion Audit (Day 15)

**Date:** 2026-11-28 (Day 15 of the 20-day program)
**Base:** remote HEAD `f1778435` ("day 14 dashboard ux audit, gate re-check")
**Scope:** plan Day 15 — enterprise completion: RBAC, SSO, billing,
invitations, audit logs, compliance, notifications. Read-only audit;
no code was changed in this scope (see §1).

## 1. Gate re-check first — still NOT PASSED

**Counts unchanged: 29 PASS / 12 PARTIAL / 2 FAIL / 0 BLOCKED / 3 N/A.**
No item crossed to PASS, none regressed. The 2 FAILs stand, both
owner-gated:

- **SEC-03** — secrets in git history (`e1e3dc9`). Needs his Atlas MFA
  code / `glanexus_admin` deletion + the history-rewrite word.
- **SEC-31** — no tenant RLS policies (20 permissive `app_full_access`
  policies; 0 tenant-scoped). Needs his Step E decisions (backup-first,
  extra tables, export-feedback 503 design).

No owner decisions recorded since Day 14 (checked 28 Nov; today's
memory log carries only the Day 14 delivery note). Remote HEAD is
unchanged since Day 14 (`f1778435`, verified via the GitHub MCP
`list_commits`). **Phase 4 (Day 15 enterprise features) therefore did
not start; this document is a verification audit of the enterprise
surface as it already exists, not a build.**

Fresh live probes this run (read-only, no probe accounts created):

| Probe | Result |
|---|---|
| Frontend `https://secureguard-main.vercel.app/` | 200 |
| Backend `/health` | 200 `{"status":"ok","db":"up"}` |
| Classifier `/health` | 200, `model_loaded: true`, v2.2.1 / `v3_real` |
| `GET /api/auth/oauth/providers` | google + github listed (GitLab absent — see §3) |
| `GET /api/billing/usage` (no auth) | 401 |
| `GET /api/organizations/1/audit-logs` (no auth) | 401 |
| `GET /api/invitations/doesnotexist123` (no auth) | **500** — see finding F1 (§5) |
| `POST /api/billing/webhook` `{}` (no signature) | 400 (signature check fails closed) |

**Run limitation (stated plainly, same as Days 13–14):** no local
test, build, OSV or Gitleaks run happened this turn — the local clone
content failed the execution-risk check at run start, so no git/npm
command ran inside `~/workspace/SecureGaurd`. Test counts cited below
are Day 12's fresh evidence (25 Nov: backend suite 167/169, OSV 589
packages / 0 vulnerable, RLS coverage 63 files / 0 bare, Gitleaks 6
findings identical to 20 Nov), labelled as such — NOT re-measured
today. The unauthenticated GitHub REST API is rate-limited from this
VM (0/60 remaining), so the Day 13/14 "docs-only" claim is evidenced
from those runs' own manifests and run logs (each lists exactly 3
docs files), not from a fresh API diff of `f1778435`/`9d9593f`.

## 2. Verdict by area

| # | Area | Verdict | Headline |
|---|---|---|---|
| E1 | RBAC | **PRESENT** | 4 roles, org context + role gates on every route, AUDITOR read-only |
| E2 | SSO / OIDC | **PRESENT, gaps** | Google + GitHub live; GitLab code-only; SAML absent (honest 501); no MFA |
| E3 | Billing + usage limits | **PRESENT, gaps** | Razorpay test-mode verified; limits enforced at every sink; Stripe NOT implemented; live billing blocked on owner KYC |
| E4 | Invitations | **PRESENT, 1 live defect** | Email-bound, single-use, expiring invites; inspect endpoint 500s on invalid token (F1) |
| E5 | Audit logs | **PRESENT, gaps** | Auth + privileged actions logged, org-scoped UI; retention undecided (SEC-33) |
| E6 | Compliance | **PRESENT, honesty note** | 4 frameworks from real findings, PDF/JSON export; self-assessed score, not certification |
| E7 | Notifications | **PRESENT, partial** | Slack + email with real test + delivery ledger; no in-app notification centre |

## 3. E1 — RBAC (PRESENT)

`backend/middleware/rbac.js` (218 lines), `backend/routes/organizations.js`
(855 lines), `backend/prisma/schema.prisma` (`OrganizationMembership`,
`role` OWNER | ADMIN | DEVELOPER | AUDITOR).

- **Roles:** OWNER / ADMIN / DEVELOPER / AUDITOR. AUDITOR is read-only
  by construction: write routes require OWNER/ADMIN/DEVELOPER, e.g.
  compliance generate `requireOrgRole(['OWNER','ADMIN','DEVELOPER'])`,
  billing invoices OWNER/ADMIN, org delete OWNER only.
- **Org context:** `requireOrgContext` resolves the org from the
  `x-organization-id` header / query / body / route param, verifies a
  membership row for the caller, 403s on non-membership, 400s on a
  malformed id (strict digits-only check — Day 11 fix). API keys pin
  their own org and die with the creator's membership. Memberships are
  cached 60 s; mutations clear the cache, so revocation is immediate.
- **Member management:** list / change-role / remove / leave /
  transfer-ownership endpoints, all OWNER/ADMIN-gated (role change and
  remove at `organizations.js:302` / `:403`). Role grants are
  server-validated: an Admin cannot invite an Owner (see §5).
- **Tests:** `backend/tests/rbac.test.js`,
  `phase2_rbac_multitenancy_verify.js` (Day 12 suite 167/169 overall,
  same 2 pre-existing env failures).
- **Caveat (not a new gap):** tenant isolation still rests on this
  application layer, not the database — the 20 live RLS policies are
  permissive (`SEC-31` FAIL). If this middleware is bypassed, nothing
  below it enforces tenancy. That is exactly what Step E closes.

## 4. E2 — SSO / OIDC (PRESENT, gaps)

`backend/routes/auth.js:675+` (SSO/OIDC), `backend/utils/oauth.js`,
`docs/OAUTH_SSO.md`. Schema: `oauthGoogleId` / `oauthGithubId` /
`oauthGitlabId` (unique, set only by a verified callback).

- **Live (verified today):** `GET /api/auth/oauth/providers` returns
  google + github. Real authorization-code + PKCE (S256) flows,
  HMAC-signed `state` in a short-lived HttpOnly cookie, rate-limited
  callback (30/hour), account linking by verified provider email with
  a link-conflict guard, new accounts created with an unusable random
  password hash. OAuth logins are audit-logged (`logAuthEvent`,
  `method: oauth:<provider>`).
- **GitLab:** implemented in code, no OAuth app registered — the
  provider is omitted from `/providers` and its start endpoint
  answers 501. Honest unavailable, not faked.
- **SAML: NOT implemented.** The code says so in a comment and
  `docs/OAUTH_SSO.md`; the config surface deliberately 501s rather
  than pretending a SAML login exists. Enterprise SSO via SAML is
  therefore unavailable — a real gap for enterprise buyers, stated
  plainly, not a hidden one.
- **MFA: absent.** No `mfa`/`totp`/`authenticator` match anywhere in
  `backend/` or `src/` (excluding tests). SEC-07 stays PARTIAL; the
  remaining gap is MFA + per-account lockout design.
- **No SCIM** (no directory-sync code or schema). Not claimed anywhere.

## 5. E3 — Billing + usage limits (PRESENT, gaps)

`backend/routes/billing.js` (174 lines), `backend/routes/billingWebhook.js`
(346 lines), `backend/services/billingService.js`,
`backend/config/plans.js`, `backend/utils/razorpay.js`,
`backend/prisma/schema.prisma` (`Subscription`, `StripeWebhookEvent`,
`RazorpayWebhookEvent`).

- **Provider is Razorpay only, in practice.** Test mode verified live
  19 Nov (hosted checkout reached, test subscription created, no
  payment taken). Create-subscription returns Razorpay's hosted URL
  and changes NO local plan until the `subscription.activated`
  webhook lands; cancel is OWNER-only and fails closed (a Razorpay
  rejection leaves the local flag untouched). Webhook: HMAC signature
  verification, idempotency via `RazorpayWebhookEvent`, event-ordering
  guard (`lastWebhookEventAt`), unknown plan IDs resolve to null, never
  silently FREE. Unauthenticated webhook POST `{}` → 400 today.
- **Live billing is BLOCKED on the owner** (Razorpay business type +
  KYC). Prices are never invented: `priceMonthly` is null for paid
  plans until fetched live from Razorpay.
- **Usage limits are enforced, not just displayed.** `PLANS`:
  FREE 3 repos / 10 scans / 3 members; PRO 25 / 200 / 15; ENTERPRISE
  effectively unlimited. Enforcement points (all verified in code):
  `checkCanAddRepository` (`routes/repos.js`), `checkCanInviteMember`
  + pending-invite counting (`routes/organizations.js:620`, invite
  counts members + pending so pre-issued invites cannot overshoot),
  `checkCanTriggerScan` (imported in `routes/scans.js`), and a second
  member-limit check inside the invite-accept transaction
  (`routes/invitations.js:170`). `GET /api/billing/usage` returns real
  counts + remaining for the caller's org (401 unauthenticated, today).
- **Stripe: NOT implemented.** The schema carries `stripeCustomerId` /
  `stripeSubscriptionId` and `StripeWebhookEvent`, but there is no
  Stripe SDK, no Stripe webhook route, and no Stripe cancel helper.
  `cancelOrgProviderSubscription` (`organizations.js:42`) fails closed:
  an org with a live Stripe subscription CANNOT be deleted (502 with a
  manual-cancel message) so billing cannot continue silently after the
  Subscription row cascade-deletes. Stripe must not be listed as a
  working billing path.
- **Invoices:** `GET /api/billing/invoices` reads real Razorpay
  invoices (OWNER/ADMIN); empty list when no Razorpay subscription.
  The frontend settings modal has billing / invoices tabs wired to
  these endpoints (`src/components/OrganizationSettingsModal.tsx`).

## 6. E4 — Invitations (PRESENT, 1 live defect)

`backend/routes/invitations.js` (252 lines), `backend/routes/organizations.js:620–836`,
`OrganizationInvitation` model (token hash only, never the raw token).

- **Sound design, verified in code.** Invite creation is
  OWNER/ADMIN-only with server-side role validation (Owners may grant
  any role incl. AUDITOR; Admins at most ADMIN; a client-supplied role
  is never trusted). The invite email is sent for real via Brevo
  (`utils/mailer`); a mail failure is reported, not swallowed. Tokens
  are sha256-hashed at rest, expire, and are consumed by a conditional
  single-claim update (`updateMany … status: PENDING`), so a concurrent
  double-accept aborts instead of creating a second membership.
  Accept is email-bound: the token alone is not sufficient — the
  accepting account's email must match `invitedEmail`. Revocation
  (delete) and listing endpoints exist, OWNER/ADMIN-gated. Frontend
  has members / invitations tabs + an accept-invite page.
- **F1 — NEW LIVE FINDING: invitation inspect 500s on an invalid
  token.** `GET /api/invitations/doesnotexist123` (no auth) returned
  **500 `{"message":"Server error inspecting invitation"}`** — probed
  twice this run (01:0x IST, two different bogus tokens, same 500).
  Expected: 404 "Invalid or non-existent invitation". The handler
  resolves the tenant first via the SECURITY DEFINER function
  `resolveOrgIdForInvitationAny`; the 500 means that resolution (or
  the RLS context around it) throws for an unknown hash instead of
  returning null. Impact: low–medium — any bad, expired-link or
  mistyped invite URL shows a server error instead of a clean
  "invalid invitation" message, and the accept flow's error path is
  unproven for invalid tokens. Valid-token accept is NOT probed
  (no real invite token available to this run). Root cause is
  unverified (needs a backend log read); the symptom is verified
  live. Not a gate-count change — no checklist item maps to this
  endpoint's error shape — but it is recorded here and in the Day 15
  gate-report section as a post-gate fix (small, targeted: make the
  resolver return null on unknown hash / catch and 404).

## 7. E5 — Audit logs (PRESENT, gaps)

`backend/middleware/rbac.js` (`createAuditLog`, `logAuthEvent`),
`backend/routes/organizations.js:836` (`GET /:organizationId/audit-logs`),
`AuditLog` model.

- **What is logged:** privileged actions via `createAuditLog`
  (org create, member invite/accept/role-change/remove, billing
  checkout/cancel, compliance generate/delete, alert-settings update,
  limit rejections) and auth events via `logAuthEvent` (login, logout,
  password change/reset — Day 10 fix, resolved to the user's primary
  org, never throws into the auth handler). Writes run inside the RLS
  org context; a missing actor refuses the write with a loud log
  instead of failing the request.
- **Reading:** OWNER/ADMIN-only, org-scoped, last 100 rows with actor
  name/email. Unauthenticated probe today → 401. Frontend audit tab
  exists in the organization settings modal.
- **Gaps (already on the gate as SEC-33, PARTIAL):** retention rules +
  purge script exist (`backend/scripts/purge-retention.js`) but no
  scheduled job runs it and no purge has ever run; the AuditLog
  append-only trigger vs 365-day retention conflict is still
  undecided. AuditLog rows keep a null actor after account deletion
  (by design — the audit trail survives the user).

## 8. E6 — Compliance (PRESENT, honesty note)

`backend/routes/compliance.js` (341 lines),
`backend/services/complianceEngine.js`, `ComplianceReport` model.

- **Real generation from real findings.** `POST /api/compliance/generate`
  (OWNER/ADMIN/DEVELOPER; AUDITOR read-only) scopes findings to the
  org's repository and the requested date range (first-scan date OR
  re-detection in an in-range scan via `detectedInScanIds`), then
  `evaluateCompliance` computes passed/partial/failed controls and a
  score from control outcomes plus severity deductions (Critical −15,
  High −8, Medium −4, Low −1). Frameworks: SOC2, HIPAA, PCI-DSS, GDPR.
  Reports list/get/export as PDF (`utils/pdfGenerator`) and JSON;
  delete is OWNER/ADMIN and audit-logged. Generation and deletion are
  audit-logged; reports are org-scoped (404 otherwise).
- **Honesty note:** the score is a self-assessed mapping of the org's
  own scan findings to framework controls — it is NOT an auditor
  certification, and no doc or UI text seen in this audit claims it
  is. Keep it that way in any marketing copy.

## 9. E7 — Notifications (PRESENT, partial)

`backend/routes/alerts.js` (155 lines), `AlertSetting` / `AlertLog`
models, `backend/utils/scanAlerts.js`, `backend/utils/mailer.js`
(Brevo).

- **Two channels, both real.** Slack: webhook URL must match
  `https://hooks.slack.com/services/*`, stored AES-256-GCM encrypted,
  never returned (only a masked form), enable-without-URL is a 400.
  Email: via Brevo to the org's members / the caller's own address
  for tests. Settings are per-org, OWNER/ADMIN-only, audit-logged.
  `POST /api/alerts/test` sends a REAL test message and returns the
  provider's actual outcome (a missing webhook / unconfigured mail
  transport is reported as failure, never success). Every attempt is
  written to `AlertLog` (channel, event, masked target, delivered /
  failed / skipped, provider id, error); `GET /api/alerts/logs`
  returns the last 50, org-scoped. Frontend `AlertsSettings.tsx`
  wires these endpoints.
- **Partial:** there is no in-app notification centre (no
  Notification model in the schema, no notification UI beyond the
  alerts settings). Alert delivery on scan completion / new critical
  is opt-in per org (`AlertSetting`, no row = silent). No retry
  behaviour is claimed here — none was verified in this audit.

## 10. Post-gate build order (Day 15 scope)

Nothing below is built — gate-blocked. Order if/when the gate passes:

1. **F1** — invite-inspect 404 on unknown token (small, targeted;
   verify with the same two bogus-token probes + a real invite
   accept end-to-end).
2. **MFA** (SEC-07) — TOTP for password accounts; then per-account
   lockout design.
3. **SAML SSO** — only if an enterprise buyer needs it; until then
   keep the honest 501 + doc.
4. **Stripe decision** — either implement (SDK + webhook + cancel) or
   remove the Stripe columns from the schema/docs so the surface
   stops implying a second provider.
5. **Retention job** (SEC-33) — schedule `purge-retention.js`, resolve
   the AuditLog append-only vs 365-day conflict.
6. **In-app notifications** — only if users ask; Slack + email cover
   the current surface.

## 11. Evidence and limitations

- Code inspected at the Day 14 base (`f1778435`); the local tree's
  code files match it (Days 13/14 were docs-only pushes per their
  manifests and run logs — see §1).
- Live evidence this run: frontend 200, backend `/health` ok,
  classifier `model_loaded: true` v2.2.1/`v3_real`, OAuth providers
  google+github, billing/audit-log 401s, webhook 400, invite-inspect
  500 (twice). No probe accounts were created; no authenticated
  dashboard, invite-accept, billing checkout, Slack/email delivery,
  or compliance-generation flow was exercised live (no credentials,
  no tokens) — those are code-verified only, stated as such.
- Test counts are Day 12's (25 Nov), labelled in §1 — not re-measured
  this run for the reason stated there.
