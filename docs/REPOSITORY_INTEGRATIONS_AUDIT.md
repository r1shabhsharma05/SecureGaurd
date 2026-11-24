# SecureGaurd — Repository Integrations Audit (Day 12, 2026-11-25)

Base: commit `c8aa61c` ("strict id params, backup fix and gate docs update",
remote HEAD verified 25 Nov 01:00 IST — Day 11 push landed). Live probes
same morning: frontend 200, backend `/health` `{"status":"ok","db":"up"}`,
classifier `model_loaded: true` v2.2.1 / `v3_real`.

**Verdict: AUDIT ONLY — no integration code changed.** The Day 7 security
gate is still NOT PASSED (29 PASS / 12 PARTIAL / 2 FAIL / 0 BLOCKED /
3 N/A — recount settled Day 12, see `docs/SECURITY_GATE_REPORT.md`),
so Phase 4 implementation stays blocked. This document records what the
Day 12 scope (GitHub/GitLab authentication, private cloning, webhooks,
repository synchronization) actually does today, with file evidence, and
names the one headline gap honestly instead of claiming it works.

## Status table

| Item | Status | Evidence |
|---|---|---|
| GitHub OAuth login | LIVE | `GET /api/auth/oauth/providers` returns google + github (25 Nov live probe); code `backend/utils/oauth.js` (PKCE S256, HMAC-signed state) |
| GitLab OAuth login | CODE ONLY, NOT CONFIGURED | Provider exists in `oauth.js`; live providers endpoint lists only google + github — no GitLab app registered, no env keys on Render. Creating the app is the owner's step (`oauth.js` header) |
| GitHub / GitLab PAT storage | IMPLEMENTED | `POST /api/integration/tokens` encrypts with AES-256-GCM (`backend/utils/cryptoUtils.js`, dedicated `ENCRYPTION_KEY`, fail-closed, no JWT-secret derivation). Residual: legacy-plaintext passthrough in `decrypt()` for pre-encryption PATs |
| Repo listing via provider API | IMPLEMENTED | `GET /api/integration/repos` (github: `api.github.com/user/repos`, gitlab: `gitlab.com/api/v4/projects?owned=true`), token decrypted server-side, never logged |
| Private-repository cloning | **NOT IMPLEMENTED** | See below — the scanner clones anonymously; non-public URLs are rejected at connect time |
| Repo connect validation | IMPLEMENTED (public-only) | `POST /api/repos`: anonymous `git ls-remote` reachability probe; non-public URL → 400 "Connect a public repository URL" (`backend/routes/repos.js`) |
| GitHub webhook (push → scan) | IMPLEMENTED, code-verified | `POST /api/integration/webhook/github` (`backend/routes/integration.js`): HMAC-SHA256 over raw body, per-repo secret + shared `WEBHOOK_SECRET` fallback, fail-closed, timing-safe compare, 30 req / 5 min rate limit, delivery idempotency (`WebhookDelivery` unique), quota-checked, temp-dir cleanup in all paths |
| GitLab webhook | IMPLEMENTED, code-verified | Same endpoint, `X-Gitlab-Token` timing-safe compare; delivery id falls back to `(repositoryId, commitSha)` (GitLab sends no delivery id) |
| Webhook tests | **NONE** | No `*.test.js` covers webhook signature verification (only `purgeRetention.test.js` touches the `WebhookDelivery` table). Live verification not done — needs a registered repo + provider webhook config (owner step) |
| Repository synchronization | **NOT IMPLEMENTED** | No scheduled sync, no default-branch refresh, no metadata refresh job (`server.js` has no scheduler; no cron). Only metadata write is `riskLevel` on scan completion |
| PR bot (check run + comment) | IMPLEMENTED | `POST /api/integration/pr-bot`: real GitHub check run + PR comment from the commit's own scan verdict only; no PAT → honest 400; GitHub rejection surfaced as 502, never a fabricated success; GitHub-only (GitLab → 400) |
| Webhook secret handling | IMPLEMENTED | Per-repo 256-bit secret minted at creation (`generateWebhookSecret`), returned once in the 201 response, never in list/detail responses; pre-secret repos fall back to shared `WEBHOOK_SECRET` (rotation still owed) |

## Headline gap: private cloning does not exist

`backend/utils/repoScanSource.js` (`resolveScanTarget`) clones with
anonymous HTTPS only, and `validateCloneUrl` **rejects any URL carrying
credentials**. The encrypted PATs are used for API listing and the PR bot
only — grep over `routes/ utils/ services/` finds no `x-access-token`,
`extraheader`, `credential.helper`, `GIT_ASKPASS`, or any other
authenticated-clone path. Consequences, all verified in code:

- A private repo cannot be connected: `POST /api/repos` rejects it at
  the reachability probe.
- Webhook-triggered scans of a private repo would fail at clone with an
  honest 502 (`resolveScanTarget` throws; a failed Scan row is written).
- Plan acceptance criterion "Private repository scans work" is **unmet**,
  and Phase 4 §4 ("authenticated clone/fetch, least-privilege scopes,
  token redaction, secure cleanup") is **not done**.

This is NOT fixed in this run: building authenticated cloning is a Phase 4
feature and the gate is closed. Implementation sketch for when the gate
passes (not built, not tested):

1. Clone with the decrypted PAT via `GIT_ASKPASS` (a short-lived helper
   script fed the token on stdin/stdout only) or `git -c
   credential.helper=` — never embed the token in the clone URL, never
   log the URL or the helper's output.
2. Scope: PAT needs `repo` (GitHub) / `read_repository` (GitLab) only;
   document the least-privilege scope in the connect UI.
3. Keep the existing guards: host allowlist, no-redirect clone
   (`http.followRedirects=false`), public-address DNS check, `--depth 1`,
   180 s timeout — and add the missing clone size/disk cap (today there
   is none: oversized-repo / resource-exhaustion protection is Day 13
   scope, not present).
4. Tests: stub-PAT clone of a private fixture repo, token-absence in
   logs/URLs, webhook scan of a private repo end to end.

## Verification procedures (for the owner / the live matrix)

- **Webhook live:** register a repo, copy its one-time webhook secret
  from the 201 response, configure the provider webhook with it, push a
  commit — expect a completed Scan with the pushed `commitSha` and a
  `WEBHOOK_SCAN_COMPLETED` audit row; re-deliver the same delivery id —
  expect 200 `duplicate: true` with no second Scan.
- **Private clone (after the fix):** connect a private repo with a PAT,
  run a scan — expect findings from the private tree and no token in any
  log line, URL, or error message.
- **GitLab OAuth (after app registration):** set `GITLAB_CLIENT_ID` /
  `GITLAB_CLIENT_SECRET` on Render, restart — expect `gitlab` in
  `GET /api/auth/oauth/providers` and a working login round-trip.

## Related Day 12 work

- Gate recount settled: checklist file counts **29 PASS / 12 PARTIAL /
  2 FAIL / 0 BLOCKED / 3 N/A** (46 items); the gate report's 28/13 was a
  one-item arithmetic slip (SEC-13, crossed Day 10, missed in the report).
- SEC-31 Step E dry-run (scratch PGlite, restored 24 Nov backup):
  pre-steps + migration apply cleanly, self-check passes (17 policies /
  14 tables, RLS+FORCE on all 14, disabled on the 6). Two scratch-only
  findings recorded in the gate report: (1) migration needs an explicit
  `SET search_path TO public;` first — a session with an empty
  search_path fails at §1 (guard note added to
  `docs/SEC31_STEP_E_APPLY.sql`); (2) behavioural isolation could NOT
  be verified in the scratch env — pglite-server 0.4.3 ignores the
  requested role (always superuser, bypasses RLS) and raises
  "query would be affected by row-level security policy" on any
  RLS-table read as a non-superuser, proven on a trivial control table.
  The in-process suite (`rlsMigration.test.js`, 12/12) already proves the
  policy logic on stub data; real-data behavioural proof stays with the
  live apply (Supabase SQL Editor step 4d smoke). Full log:
  goal `hidden_files/day12-dryrun.log`.
- SEC-32 archive re-verified: `pg_restore --list` (pg 17.12 client)
  reads the 24 Nov archive, TOC identical to the stored manifest
  (255 entries, 20 tables). Note: pg_restore 16 rejects this
  17.12-written archive — use the 17 client (`~/workspace/pg-client-17`).
