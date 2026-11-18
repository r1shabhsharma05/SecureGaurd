# BACKEND SECURITY — Day 6 (2026-11-19)

Day 6 of the 20-day transformation: backend security — input validation,
SSRF, XSS, CORS, security headers, rate limiting, upload security and
webhook verification. One code unit end-to-end (shared validation wired
into the auth routes) plus live re-verification of the controls the
fix-all run put in place on 2026-11-16.

## What changed in code

### Shared validation extended to auth.js (SEC-18 / SEC-22)

Before Day 6, 3 of the 48 mutating routes used the shared zod library
(`validateBody`): change-password, scan trigger, public contact. The
other 45 relied on inline per-route checks — same boundary, but a missed
check on a new route was a live bug.

Day 6 wires 6 more routes, all in `backend/routes/auth.js` — the
highest-risk surface, since it is unauthenticated:

| Route | Schema | Replaces |
|---|---|---|
| `POST /api/auth/register` | `registerSchema` | presence check + password length check |
| `POST /api/auth/login` | `loginSchema` | presence check |
| `POST /api/auth/resend-verification` | `emailOnlySchema` | presence check |
| `POST /api/auth/forgot-password` | `emailOnlySchema` | presence check |
| `POST /api/auth/reset-password` | `resetPasswordSchema` | presence + length checks |
| `DELETE /api/auth/account` | `deleteAccountSchema` | password + `confirmation === 'DELETE'` check |

Schemas live in `backend/utils/validation.js` next to the existing ones.
Each mirrors the inline check it replaces — same 400, same boundary —
so no accepted input changes, only where the rejection happens (at the
trust boundary, before any DB or mail call). The removed guards are
deleted, not duplicated.

Deliberate non-changes, with reasons:

- **Login password is a non-empty string, NOT `zPassword`.** The old code
  only required presence; a length floor would answer a short password
  with a shape error instead of "Invalid credentials". A test pins this.
- **`POST /api/auth/verify-email` is not wired.** Its token comes from
  the query string OR the body; the handler's presence check already
  covers both. A test pins the 400.
- **OAuth callback (`GET /api/auth/oauth/:provider/callback`) is not
  wired.** It is a browser redirect flow: a missing code/state must
  redirect to `/login?oauth_error=invalid_state`, not answer 400 JSON.
- **`/refresh`, `/logout`, `/complete-onboarding` take no body** — there
  is nothing to validate.
- **Anti-enumeration behaviour is untouched.** Forgot-password still
  answers the generic 200 for unknown emails; resend-verification still
  answers the generic 200 for unknown/already-verified accounts. Tests
  pin both.

Coverage after Day 6: **9 of 48 mutating routes** use the shared
validator (7 auth + contact + scan trigger). 39 remain ad-hoc — the
Day 8+ refactor the gate pass already scoped; wiring them all in one
night would be a 39-route diff with no per-route review, which is how
regressions ship.

### Files changed

- `SecureGaurd-main/backend/utils/validation.js` — 5 new schemas + exports.
- `SecureGaurd-main/backend/routes/auth.js` — 6 routes wired, 6 inline
  guards removed.
- `SecureGaurd-main/backend/tests/authValidation.test.js` — new, 11 tests.

## Tests (offline, 2026-11-19 ~01:20 IST)

New file `backend/tests/authValidation.test.js`: **11/11 pass, 0 fail.**

- Register rejects a missing field, short password, malformed email,
  over-long (129-char) password; accepts valid input (201, stored
  trimmed lowercase).
- Login rejects a missing password and a malformed email; a short but
  present password still answers "Invalid credentials" (the
  behaviour-preservation test for the non-`zPassword` decision).
- Resend-verification and forgot-password reject missing/malformed
  emails; forgot-password still answers the generic 200 for an unknown
  email.
- Reset-password rejects a missing token and a short new password.
- Delete-account rejects a wrong confirmation and a missing password
  (400 from the schema, before the destructive handler runs; requests
  carry a signed Bearer token because `authMiddleware` precedes the
  validator in that chain).
- Verify-email POST still rejects a missing token.
- **Rate limiter is mounted, not decorative:** the file's last test
  spends the process's shared `authLimiter` budget (10/15 min) — the
  first two of 11 rapid logins answer 400, the rest 429.

Regression set, same command:
`authValidation` 11 + `authVerification` 8 + `authEmailNormalization` 4
+ `validation` 11 + `rbac` 8 + `scanQueueCache` 4 + `startup_routes` 4
= **49/49 pass, 0 fail.** ESLint on the three touched files: 0 errors
(backend is eslint-ignored by repo config — pre-existing).

## Live verification (2026-11-19 ~01:05 IST)

All probes are read-only header/status checks against production; no
hammering, no real accounts, no destructive requests.

### Security headers — SEC-19, re-verified PASS

`curl -I https://secureguard-main.vercel.app/` → 200 with:

- `Content-Security-Policy: default-src 'self'; script-src 'self'
  https://challenges.cloudflare.com
  'sha256-kMmCx3PdlC2uIS/i/kHI6X5BO2x37lUcyiklQI3zmtM'; … frame-ancestors
  'none'` — the sha256 hash matches `vercel.json`; no `unsafe-inline`.
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: strict-origin-when-cross-origin`,
  `Permissions-Policy: camera=(), microphone=(), geolocation=()`,
  `Cross-Origin-Opener-Policy: same-origin`,
  `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.

`curl -I https://securegaurd.onrender.com/health` → 200 with
`content-security-policy: default-src 'none';frame-ancestors 'none';
base-uri 'none'` + `x-content-type-options: nosniff`. Both hosts serve
the CSP the fix-all run added.

### CORS — SEC-21, live probe PASS

Preflight `OPTIONS /api/auth/me` from unlisted origin
`https://evil.example.com` → 200 with **no**
`Access-Control-Allow-Origin` header (denied, and no 500 — the denial
no longer masquerades as a server crash). Same preflight from
`https://secureguard-main.vercel.app` → 204 with
`Access-Control-Allow-Origin: https://secureguard-main.vercel.app` +
`Access-Control-Allow-Credentials: true`.

### XSS / uploads — SEC-20 / SEC-23, re-verified

- `dangerouslySetInnerHTML` in `src/`: **0 hits** (unchanged).
- Upload handlers (`multer`, `upload.single/array`, `express-fileupload`,
  `busboy`) in `backend/` + `src/`: **0 hits** — still no upload
  feature, SEC-23 stays NOT APPLICABLE.
- `eval(` / `new Function(` in `backend/` (excl. tests): **0 hits**.

### Debug route — SEC-26, re-verified

`GET /api/_test-error` → **404**. The Sentry test route is still not
enabled in production.

### Health — all three hosts up

- Frontend `https://secureguard-main.vercel.app/` → 200.
- Backend `https://securegaurd.onrender.com/health` → 200.
- Classifier `https://secureguard-classifier.onrender.com/health` →
  200, `model_loaded: true`, `model_version: v3_real`.

## Re-verified by code read (no live test — see why)

### SSRF — SEC-28, still PASS

`backend/utils/ssrfGuard.js` re-read: single DNS resolution per hop,
every resolved address must be public (one private A record blocks the
host), pinned-IP dialing with `remoteAddress` checked against the
validated set before any request bytes, redirect re-validation (max 3
hops), 2 MB body cap, 10 s timeout, credentials in URLs rejected,
`http(s)` only. `isPrivateIp` covers IPv4 (incl. CGNAT 100.64/10,
link-local, multicast/reserved), IPv6 loopback/link-local/unique-local
and IPv4-mapped addresses. No live SSRF test was run: pointing a
production probe at internal metadata endpoints is a destructive test
against the live service. The Day 6 procedure in the checklist stands —
run it against a staging stack, never production.

### Webhooks — SEC-27, still PASS

`backend/routes/integration.js` (GitHub HMAC-SHA256 over the raw body,
GitLab token, per-repo secret first, timing-safe compare, fail-closed)
and `backend/routes/billingWebhook.js` (Razorpay HMAC + idempotency,
mounted before `express.json` so the raw body survives) unchanged by
Day 6. No live webhook test — that needs a real repo webhook delivery
(Day 12/18 procedure).

### Rate limiting — SEC-17, still PARTIAL (probe limitation, not a code gap)

The limiters are mounted and counting — the new test file proves the
shared `authLimiter` trips at 10 in-process. A **live** 429 proof is
still outstanding: the fix-all run's 35 rapid `POST /api/auth/refresh`
answered 35× 401 with no 429, which is inconclusive, not a failure —
the VM's egress IP rotates per request and the limiters key on `req.ip`.
A live 429 needs a stable egress IP or Render request logs; the Render
API is unreachable from this VM (401, no token/service ID on the VM).
Day 6 did not repeat the 35-request probe: it would return the same
inconclusive result and burn production requests for no new evidence.

## What is still open (not disguised as done)

1. **39 of 48 mutating routes still use ad-hoc validation** (SEC-18
   stays PARTIAL). The shared library exists and covers the
   highest-risk routes; the rest is Day 8+ refactor work.
2. **Live 429 proof** (SEC-17) — needs a stable IP or Render logs.
3. **Live SSRF test** (SEC-28) — staging stack only, never production.
4. **Live webhook test** (SEC-27) — needs a real delivery (Day 12/18).
5. **Gate items** (SEC-03 history purge, SEC-31, SEC-32, SEC-34) are
   owner actions. Rishabh confirmed all 9 owner actions done on
   2026-11-19 ~01:00 IST ("kr li check shi h sab"); gate
   re-verification is Day 7 (2026-11-20), not this run — this doc does
   not claim the gate passed.

## Next

Day 7 (2026-11-20) — database security + the security gate:
re-verify the gate items against the now-completed owner actions,
re-run the route-auth matrix, and write `docs/SECURITY_GATE_REPORT.md`.
