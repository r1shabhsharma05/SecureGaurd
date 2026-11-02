# SecureGuard on-prem install (Docker Compose)

**Verification status — read first.** This package was statically verified
only (Compose YAML parses; every `COPY` path in the Dockerfiles exists in
this repo; the classifier's sibling-package layout was checked against
`service.py`). The authoring VM has no Docker, so **no container was ever
started here**. The smoke test below is the first-run checklist for a Docker
host. Do not describe this package as runtime-verified until that checklist
passes on a real host.

## What runs

| Service | Image / build | Port |
|---|---|---|
| `db` | `postgres:16-alpine` (data in the `pgdata` volume) | internal only |
| `classifier` | Python 3.12 + FastAPI FP classifier + severity ranker | internal only (8001) |
| `backend` | Node 22 + Express API; Prisma migrations run at start | internal only (5000) |
| `frontend` | Vite build served by Nginx; `/api/*` proxied to backend | `${FRONTEND_PORT:-80}` on the host |

Only the frontend port is published. The database, classifier, and backend
are reachable only inside the Compose network — publish them only while
debugging, and never publish Postgres to the internet.

## Prerequisites

- Docker Engine + Docker Compose v2 (any recent Docker Desktop / Linux install).
- ~4 GB free RAM (the classifier loads scikit-learn/xgboost/SHAP models),
  ~2 GB free disk for images + the Postgres volume.
- No other service on the chosen frontend port.

## Install

```bash
cd SecureGaurd-main
cp .env.onprem.example .env
# Fill in .env: POSTGRES_PASSWORD, JWT_SECRET, JWT_REFRESH_SECRET,
# ENCRYPTION_KEY, WEBHOOK_SECRET, CLASSIFIER_API_KEY.
# Generate each secret with: openssl rand -hex 32
# (ENCRYPTION_KEY format: see backend/.env.example / utils/cryptoUtils.js —
# it must be a valid key for AES-256-GCM, not an arbitrary string.)
docker compose up -d --build
docker compose ps        # all four services healthy
docker compose logs -f backend   # watch the migration + "Server running on port 5000"
```

Open `http://localhost` (or `http://<host>:<FRONTEND_PORT>`).

## First-run smoke test (do this before calling it "installed")

1. **Health:** the backend health route is not exposed through Nginx, so
   check it inside the container:
   `docker compose exec backend node -e
   "fetch('http://localhost:5000/health').then(r=>console.log(r.status))"`
   must print `200`. The frontend healthcheck in Compose proves Nginx serves `/`.
2. **Register** a user in the browser → **Create workspace** on the Dashboard
   (the first-workspace empty state) → **Connect a public GitHub repo** (no PAT
   needed for public clones) → **Run a scan** → findings appear. The scan
   proves backend + classifier + DB end to end (the classifier is consulted
   for SAST findings; a classifier outage degrades to "all findings real",
   it never fails a scan silently).
3. **Custom rule:** Dashboard → Custom Rules → create the example rule →
   Test sample code → 1 match; Test against the scan's repository → matches
   from the real engine.
4. **Compliance:** generate one report from the scan (PDF download works).
5. **Stop/start:** `docker compose down && docker compose up -d` — data
   survives in the `pgdata` volume; the backend re-applies migrations
   idempotently on start.

If any step fails, capture `docker compose logs backend classifier` — the
backend logs the exact failure (migration error, classifier unreachable,
missing env) instead of a generic page.

## Configuration differences from the hosted deployment

- **Mail (Brevo):** unset `BREVO_API_KEY` = verification/reset emails are
  skipped or answer 503 honestly (same behaviour as hosted when unconfigured).
  Set it + `EMAIL_FROM` to enable real mail.
- **Billing (Razorpay):** not wired for on-prem use; the billing tab answers
  with the same fail-closed "Billing provider error" until Razorpay keys +
  plan IDs are configured. Do not present on-prem billing as working.
- **SSO/OIDC:** set the provider client id/secret + `BACKEND_URL` to the
  public backend origin, and register the redirect URIs from
  `docs/OAUTH_SSO.md` (replace the Render host with your host).
- **Turnstile/Sentry:** inert until their keys are set (same as hosted).
- **Scans of private repos:** need a GitHub/GitLab PAT saved in Settings,
  exactly as on hosted. Public repos clone anonymously.
- **HTTPS:** this package serves plain HTTP on localhost. For any
  network-exposed install, terminate TLS in front of Nginx (reverse proxy /
  load balancer) and set `FRONTEND_URL` + `BACKEND_URL` to the `https://`
  origin — the backend trusts one proxy hop for `X-Forwarded-Proto`.

## Backups and restore

```bash
# Snapshot (host needs pg_dump, or run it inside a throwaway container):
docker compose exec db pg_dump -U secureguard secureguard | gzip > secureguard-$(date +%F).sql.gz
# Restore into a FRESH database (never over a live one without a snapshot):
docker compose down -v   # destroys pgdata — only on a scratch host
docker compose up -d db
zcat secureguard-YYYY-MM-DD.sql.gz | docker compose exec -T db psql -U secureguard secureguard
docker compose up -d
```

For the full backup/restore procedure (including the scripted `pg_dump`
snapshot used on hosted), see `docs/BACKUP_AND_RESTORE.md`.

## Upgrading

```bash
git pull
docker compose up -d --build
```

Migrations run automatically at backend start. If the backend container
keeps restarting after an upgrade, read its logs first — a failed migration
is the usual cause, and the previous image is still available via
`docker compose up -d --build` after reverting the pull.

## Removing

```bash
docker compose down -v   # also deletes the pgdata volume (all scan data)
```
