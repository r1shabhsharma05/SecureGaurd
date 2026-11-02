# SSO / OIDC sign-in — setup and status

**Status (Day 10, 2026-11-02): code shipped and unit-proven; no provider is
live yet.** The backend answers `GET /api/auth/oauth/providers` with an empty
list until OAuth apps are registered, the frontend shows no SSO buttons until
then, and `GET /api/auth/oauth/:provider` answers 501. Nothing about SSO is
faked: the full authorization-code + PKCE flow is implemented in
`backend/utils/oauth.js` + `backend/routes/auth.js` and unit-tested with
stubbed provider calls (`backend/tests/phase2_day10_oauth_verify.js`).

## HIS STEPS — register the OAuth apps

For each provider wanted, create an OAuth app in that provider's console and
set the two environment variables on the Render backend service (never in the
frontend — the secrets must never reach a browser bundle):

| Provider | Console | Env vars | Redirect URI to register |
|---|---|---|---|
| Google | Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web) | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | `https://securegaurd.onrender.com/api/auth/oauth/google/callback` |
| GitHub | GitHub Settings → Developer settings → OAuth Apps | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | `https://securegaurd.onrender.com/api/auth/oauth/github/callback` |
| GitLab | GitLab → Preferences → Applications (or group settings) | `GITLAB_CLIENT_ID`, `GITLAB_CLIENT_SECRET` | `https://securegaurd.onrender.com/api/auth/oauth/gitlab/callback` |

If the backend ever runs under a different public origin, set `BACKEND_URL`
to that origin (it overrides the request host when building redirect URIs);
otherwise the request host is used (Render sets `X-Forwarded-Proto`, and the
app trusts one proxy hop).

After setting the variables and redeploying, verify for real:

1. `GET /api/auth/oauth/providers` lists the provider.
2. The login/signup pages show "Continue with \<Provider\>".
3. A real sign-in with that provider lands on `/oauth/callback` → dashboard,
   and the account appears (new email = new account; existing email = linked).
4. A second sign-in with the same provider account reuses the linked account
   (no duplicate account is created).

## How it works

- Authorization-code flow with PKCE (S256) for all three providers; `state`
  is HMAC-signed with `JWT_SECRET` and kept in a short-lived HttpOnly cookie.
- The provider callback exchanges the code server-side, fetches the profile,
  and requires a **verified** email (Google `email_verified`; GitHub primary
  verified address from `/user/emails`; GitLab `confirmed_at`).
- Linking: provider identity first (`oauthGoogleId` / `oauthGithubId` /
  `oauthGitlabId`), then matching verified email. If the email belongs to an
  account already linked to a *different* provider identity, sign-in fails
  with `account_link_conflict` instead of silently taking over the account.
- New accounts get an unusable random password hash — password login can
  never guess it. Forgot-password still works for SSO-created accounts.
- Session handling is identical to password login: the same refresh-cookie
  rotation, the same access token. The callback page carries **no token in
  the URL**; it restores the session via `POST /api/auth/refresh`.

## SAML — not implemented (stated, not hidden)

Enterprise SAML was in the Day-10 plan with a test-IdP proof. It is **not**
built: adding SAML safely needs a vetted SAML library plus a real IdP
exchange (metadata, signed assertions), and a half-built SAML login would be
worse than none. There is deliberately no SAML button, route, or "configured"
signal anywhere in the product. When a customer IdP exists, the work is: pick
a maintained SAML library, add a metadata-driven config path, prove it
against that customer's IdP (or samltest.id), and only then surface a button.
Until then, OIDC (Google/GitHub/GitLab) is the real SSO surface.
