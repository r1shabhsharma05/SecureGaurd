# Secrets and Infrastructure Security — Day 4 (2026-11-17)

20-day transformation, Day 4: credential rotation, Git history review,
environment security, dependency scanning, secure configuration.
Head at time of writing: `8ebfe75d` (+ the Day 4 change below, unpushed).
Companion: `docs/SECURITY_HARDENING_CHECKLIST.md` (SEC-02/03/05/13/26/34/42),
`docs/DEPENDENCY_VULNERABILITIES.md`, `docs/THREAT_MODEL.md` (T2, T5, T7).

Status: **work done, gate still not passed.** Three items stay FAIL/BLOCKED
and need the owner: history purge (SEC-03), dev MongoDB rotation (SEC-05),
Turnstile keys (SEC-34). Nothing here is disguised as PASS.

## 1. Git history review — Gitleaks, full history

- Tool: gitleaks 8.28.0, local binary `~/workspace/tools/gitleaks/gitleaks`
  (home-folder install; no system install).
- Command: `gitleaks git --log-opts "--all" --report-format json
  --report-path <hidden_files>/gitleaks-full-history-2026-11-17.json`
- Result: **182 commits scanned, ~93.35 MB, 6 findings, 0 real secrets.**
- Raw report (out of the repo):
  `~/workspace/goals/securegaurd-20-day-transformation/hidden_files/gitleaks-full-history-2026-11-17.json`

| # | Rule | Commit | File:line | Verdict |
|---|---|---|---|---|
| 1 | generic-api-key | 534d5ef | `backend/tests/aiFixEngine.test.js:17` | False positive — the match is the identifier `savedWeb2ApiKey`, not a value |
| 2–4 | curl-auth-header | 7fe3bf9 | `backend/services/fp-classifier/ONCALL.md:78,117,152` | Placeholder — literal `sg-internal-fp-classifier-key-change-me` in a doc example (3 occurrences) |
| 5 | generic-api-key | 7fe3bf9 | `backend/tests/fixtures/secrets_variants.js:2` | Intentional fixture — fake AWS-like key written to trigger the app's own secret scanner (comment: "triggers SEC-001") |
| 6 | generic-api-key | 7fe3bf9 | `backend/tests/generateFixtures.js:121` | Same fixture value, embedded in the generator |

### Detection gap (important)

Gitleaks default rules did **not** flag the one known real leak:
commit `e1e3dc9` (2026-04-16) committed `backend/.env` with a real
`JWT_SECRET` (38 chars, rotated 2026-11-08) and a `MONGO_URI` (37 chars,
carrying the dev MongoDB credential — see §2). Lesson: a passing
gitleaks run is **not** proof of a clean history. The CI secret-scan
workflow (gitleaks-action, full history, `fetch-depth: 0`) is green on
every push including `8ebfe75d` — same blind spot applies to it. Do not
treat either green run as "no secrets ever leaked". The history purge
(SEC-03) is the only real fix for `e1e3dc9`.

### Current tree

- No `.env` file is tracked (`git ls-files` grep for `.env` / `.pem` /
  `.key` / credentials: no hits; only the three `.env.example` files).
- Secret-pattern grep over the current tree (config, server, turnstile,
  sentry): no hardcoded secret values — only `process.env` reads,
  placeholders and comments.

## 2. Credential inventory and rotation

| Credential | Status | Evidence / next step |
|---|---|---|
| JWT_SECRET (current) | Rotated 2026-11-08 | Day 1 audit §4.2. Old value survives only in history (`e1e3dc9`) — see SEC-03 |
| JWT_REFRESH_SECRET | Set, independent of JWT_SECRET | `backend/config/env.js` — no derived fallback |
| ENCRYPTION_KEY (PAT AES-256-GCM) | Set (64-hex required) | `validateEnv()` enforces presence; format enforced where the key is used |
| Dev MongoDB credential (`glanexus_admin`) | **Rotation/deletion still owed — owner action** | Printed in `SECURITY_AUDIT.md:90` (redacted Day 3, value never re-printed here) and committed in `e1e3dc9` `backend/.env` as `MONGO_URI`. Fix-all run (2026-11-16) found the dev MongoDB DEAD/UNUSED — the only references are the redacted doc line and the (now removed) transitive mongoose dep — so the owner step is to **delete the Atlas user `glanexus_admin`** (no Atlas target identifiable from the repo). Procedure below |
| Legacy plaintext PATs | Migration script ready, live run BLOCKED | `backend/scripts/migrate-plaintext-pats.js` (dry-run default, 7/7 self-test pass). Live run needs DB credentials — none on this VM. Procedure in the fix-all run report; Day 5+ executes with the owner |
| Supabase service credentials | Scope check owed | Day 3 note: Day 4 checks the Supabase credential scope — **not done**: no Supabase dashboard access from this VM. Owner check: Supabase dashboard → project `wkvvxqlflhjiqkhwxrsl` → Settings → API → confirm only the `anon`/`service_role` keys in use, and that the service key is not in any frontend bundle or doc |

### Dev MongoDB credential — owner step (delete, not rotate)

The fix-all run established this dev MongoDB is dead/unused, so there is
nothing to re-point — delete the user:

1. Atlas (or the Mongo host) → Database Access → user `glanexus_admin`
   → delete the user. No Atlas target is identifiable from the repo, so
   this needs the owner's Atlas access.
2. If anything still uses it (nothing in the repo does), rotate instead:
   change the password, store the new one in the Secure Vault only, and
   verify the old password no longer authenticates (one `mongosh`
   attempt with the old password must fail).
3. The value is also in git history (`e1e3dc9`) — deletion, not file
   edits, is what neutralises it; the purge (SEC-03) removes the copy.

### History purge procedure (SEC-03 — needs the owner's word)

Do not run without his explicit go-ahead: it rewrites public history.

1. `git filter-repo --path backend/.env --invert-paths` (or
   `--replace-text` with the exact secret patterns) on a fresh clone.
2. `git push --force-with-lease origin main` — every collaborator
   re-clones; Vercel/Render redeploy from the new head automatically.
3. Re-verify: `gitleaks git --log-opts "--all"` must show 0 findings
   for `e1e3dc9`, and `git log --all -- backend/.env` must be empty.
4. The JWT secret is already rotated, so the purge is hygiene +
   Mongo-credential removal, not an active-leak emergency — but the
   Mongo user must be deleted first (above), or the purge alone
   leaves a live credential in pre-purge clones.

## 3. Environment security

- `backend/config/env.js` — `validateEnv()` fail-fasts at startup on
  the four required secrets (`JWT_SECRET`, `JWT_REFRESH_SECRET`,
  `ENCRYPTION_KEY`, `DATABASE_URL`). No hardcoded defaults anywhere.
- `.env.example` files (root, backend) contain placeholders only
  (`<redacted>` / empty values). No real values.
- `render.yaml` **fixed today**: the blueprint declared only 10 vars;
  the 14 optional integration vars (`TURNSTILE_SECRET_KEY`,
  `SENTRY_DSN`, `BREVO_API_KEY`, `EMAIL_FROM`, `CONTACT_EMAIL`,
  `FP_CLASSIFIER_URL`, `GEMINI_WEB2API_URL`, `GEMINI_WEB2API_KEY`,
  `GOOGLE_CLIENT_ID/SECRET`, `GITHUB_CLIENT_ID/SECRET`,
  `GITLAB_CLIENT_ID/SECRET`, `BACKEND_URL`) were missing, so a
  blueprint re-sync would not have documented them. All added as
  `sync: false` (names only, values stay in the Render dashboard).
  YAML validated; backend `deployment_config` tests 3/3 pass.
- `vercel.json` — CSP (incl. `challenges.cloudflare.com` allow-list),
  `X-Frame-Options: DENY`, `nosniff`, strict referrer policy; API
  rewrites proxy to Render. No secrets in it.
- Frontend env: `VITE_TURNSTILE_SITE_KEY` and `VITE_SENTRY_DSN` are
  the only public-by-design vars; both are **unset** in production
  (bundle evidence, §5).

### Production env presence — what this VM can and cannot verify

Verifiable from outside (done today, §5): `SENTRY_TEST_ROUTE` is off
(`GET /api/_test-error` → 404); Turnstile is off on both ends (no site
key in the live bundle, token sent only when present); frontend Sentry
is off (no Sentry code in the live bundle). **Not verifiable from this
VM** (owner dashboard check — Render → secureguard-api → Environment,
Vercel → project → Settings → Environment Variables): presence of
`TURNSTILE_SECRET_KEY`, `SENTRY_DSN` (backend), `BREVO_API_KEY`,
`EMAIL_FROM`, `GEMINI_API_KEY`, `CLASSIFIER_API_KEY`, OAuth client
secrets. The backend is up and signing JWTs, so the four required
secrets are necessarily set.

## 4. Dependency scanning

- `npm audit` is **still BLOCKED** on this VM (registry 403
  `policy_denied` on the audit endpoint, verified 2026-11-14).
- OSV re-run today (`SecureGaurd-main/scripts/osv-scan.mjs`,
  2026-11-17 ~01:02 IST): **569 unique packages, 15 findings —
  0 critical, 3 HIGH, 10 MODERATE, 2 LOW — identical advisory set to
  2026-11-16** (IDs compared across both raw JSON files). HIGHs:
  body-parser 2.3.0, deepmerge-ts 7.1.5, mysql2 3.15.3 (auth-plugin
  downgrade leaking plaintext creds — fix first, Day 9). Zero Prisma
  findings. Full list: `docs/DEPENDENCY_VULNERABILITIES.md`.
- `npm outdated` re-verified today: root 17 outdated / 6 major
  (unchanged), backend 9 outdated / 2 major (was 10 — mongoose
  removed). Prisma 7.10.0 → 8.0.0-rc.34 (release candidate — do not
  chase it for this item).
- CI: `.github/workflows/dependency-scan.yml` (npm audit, fails on
  high/critical, push + weekly + dispatch) was written by the fix-all
  run but **could not be pushed via the GitHub App API** (403 on
  `git/trees` — the App cannot write `.github/workflows/`). It was
  pushed 2026-11-17 via the browser web-UI (commit `5dc349f`,
  file blob matches the local copy byte-for-byte).
- **First CI run (2026-11-17 ~02:18 IST, run 44005648268, 41 s):
  conclusion FAILURE — and the failure is informative, not a broken
  pipeline.** Backend job: the audit gate tripped as designed — npm
  audit reports 12 vulnerabilities (7 moderate, 5 high), including
  high-severity body-parser, deepmerge-ts (via prisma) and mysql2;
  artifact `npm-audit-backend` (2.4 KB) uploaded. (npm audit counts
  differ from the OSV count above — different advisory data; the
  overlapping HIGHs are the same packages.) Root job: the audit step
  PASSED (no high/critical in the root package), but the upload-artifact
  step failed on the path `SecureGaurd-main/./npm-audit.json`
  (upload-artifact rejects `.` path segments) — a workflow bug, not a
  vulnerability. Fix (one-line conditional path, commit `6324afb`)
  applied via the browser web-UI the same morning.
- **Second CI run (2026-11-17 ~02:57 IST, run 44006630822, 51 s):
  root job fully green** (audit passed, artifact `npm-audit-root`
  799 B uploaded — the path error is gone); **backend job still red
  on the audit gate as designed** (real highs; artifact
  `npm-audit-backend` 2.4 KB uploaded). Overall conclusion failure
  only because of the backend gate. Evidence: browser-verified
  Actions UI; the public API re-check was rate-limited (403), so run
  detail rests on the UI report. Remediation of the 3 HIGHs is Day 9.

## 5. Live probes (2026-11-17 ~01:0x IST)

| Probe | Result |
|---|---|
| `https://secureguard-main.vercel.app/` | 200, ~1.0 s |
| `https://securegaurd.onrender.com/health` | 200 `{"status":"ok"}` |
| `https://secureguard-classifier.onrender.com/health` | 200, `version 2.2.1`, `model_version v3_real`, `model_loaded true`, `severity_ranker_ready true` |
| `GET /api/_test-error` | 404 — `SENTRY_TEST_ROUTE` not enabled in production (SEC-26 caveat resolved) |
| Live frontend bundle (`assets/index-Ac2tFl7a.js`, 746 KB) | `turnstile` appears 3× (token attached only when present: `...o?{turnstileToken:o}:{}`); **0** references to `challenges.cloudflare.com`, **no** Turnstile site key (`0x4AAAA…`) — widget renders nothing, captcha off (SEC-34 re-confirmed live) |
| Same bundle | **0** `sentry` matches — `VITE_SENTRY_DSN` unset in production; frontend error tracking off (SEC-42) |

## 6. Owner actions (exact)

1. **History purge (SEC-03)** — say the word; procedure in §2. Until
   then the old JWT secret + dev Mongo credential remain in history
   (JWT already rotated, so no active leak from it).
2. **Delete the dev MongoDB user `glanexus_admin` (SEC-05)** — procedure in §2. The DB is dead/unused per the fix-all run; deletion is the step, rotation only if something still uses it.
3. **Turnstile keys (SEC-34)** — create a Cloudflare Turnstile
   site + secret key, set `TURNSTILE_SECRET_KEY` on Render and
   `VITE_TURNSTILE_SITE_KEY` on Vercel, redeploy both. Until then
   signup / forgot-password / contact stay fail-open by design.
4. **Production env presence (SEC-02/42)** — confirm in the Render +
   Vercel dashboards that `SENTRY_DSN` (backend), `BREVO_API_KEY`,
   `GEMINI_API_KEY`, `CLASSIFIER_API_KEY` and the OAuth secrets are
   set, and that `SENTRY_TEST_ROUTE` is absent (verified absent via
   the 404 probe today, but confirm it is not set to any value).

## 7. Test evidence

- Backend offline suite: **51/52 pass**. The one failure,
  `tests/compliance.test.js` ("ComplianceReport Table Exists"),
  needs a live Postgres — it runs `prisma.user.findFirst` against the
  dummy `DATABASE_URL` used on this VM, so it cannot pass here. It is
  environmental, pre-existing, and unrelated to today's change (no
  test reads `render.yaml`; the only file changed is `render.yaml`).
- `tests/deployment_config.test.js`: **3/3 pass**.
- `render.yaml`: YAML parses, 24 env vars declared (was 10).
- Gitleaks 8.28.0 full-history scan: 182 commits, 6 findings, all
  non-secrets (§1). CI secret-scan workflow green on all pushes
  including `8ebfe75d` (GitHub Actions runs list, 2026-11-17).
