# Dependency Vulnerabilities — SEC-13

Scan date: **2026-11-18 ~02:30 IST** (gate-pass run).
Previous scans: 2026-11-17 ~01:02 IST (15 findings, 0 critical, 3 high);
2026-11-16 ~01:26 IST (15 findings, same set).
Status: **remediation done for the gate blockers** — 3 findings remain,
0 critical, **1 high** (picomatch — no fixed version exists; see below),
2 moderate (major-bump fixes, Day 9). The 3 HIGHs from 17 Nov are all
fixed by the upgrades in this run; 9 further findings (fast-uri ×5,
ip-address ×3, qs ×1) are also fixed. Full detail of the 17 Nov baseline
is kept below the 18 Nov section — do not hand-edit the tables; re-run
the scan instead.

## Method

`npm audit` is BLOCKED on this VM in both packages — the registry rejects
the audit endpoint (403 `policy_denied`, verified 2026-11-14, re-confirmed
as the reason this scan uses another source). The scan below was run
instead with the OSV API, which is reachable from the VM:

- Script: `SecureGaurd-main/scripts/osv-scan.mjs`
  (`node scripts/osv-scan.mjs --out <results.json>`; Node ≥ 18, no
  dependencies, no auth). It reads both lockfiles, extracts every unique
  `package@version`, POSTs them to `https://api.osv.dev/v1/querybatch`,
  then enriches each hit with a full `GET /v1/vulns/{id}` — the
  querybatch response carries only id + modified, so severity, summary
  and fixed versions come from the per-vulnerability lookup.
- Raw results JSON (568 packages, 3 findings with full OSV records):
  `~/workspace/goals/securegaurd-20-day-transformation/hidden_files/osv-scan-results-2026-11-18.json`
  (kept out of the repo; `osv-scan-results.json` is gitignored). Previous
  runs: `.../osv-scan-results-2026-11-17.json` (569 packages, 15 findings),
  `.../osv-scan-results-2026-11-16.json` (585 packages, 15 findings).
- Scope: **direct + transitive** dependencies, as pinned in the lockfiles.
  OSV matching is version-based (the vulnerable version is present in the
  tree); it is NOT a reachability/exploitability analysis for this app.
  A finding means "this version is installed", not "this app is
  exploitable through it".

## Totals (2026-11-18 re-scan, after remediation)

| | Count |
|---|---|
| Unique `package@version` pairs scanned | 568 (569 on 2026-11-17, 585 on 2026-11-16) |
| Lockfiles | `SecureGaurd-main/package-lock.json` (250 entries), `SecureGaurd-main/backend/package-lock.json` (353 entries) |
| Vulnerable packages | 3 (all transitive — none is a direct dependency) |
| Total findings | 3 |
| Critical | 0 |
| High | 1 |
| Moderate | 2 |
| Low | 0 |

Severity labels are the **GitHub severity** published on each advisory
as carried by OSV (`database_specific.severity`); the CVSS vector for
each finding is quoted verbatim from OSV. No numeric CVSS scores are
stated anywhere in this document because OSV returns vectors, not
computed base scores, and no score was calculated here.

The September 2026 readiness report's claim of "4 high Prisma
advisories" is stale: **no Prisma package appears in this scan's
findings** (Prisma 7.10.1 / @prisma/client 7.10.1 are installed and
return no OSV hits). Do not quote the old claim.

## What the 2026-11-18 remediation changed

Upgrades applied in `SecureGaurd-main/backend/` (commit pending — gate-pass
run, 2026-11-18):

| Package | Before → after | How | Finding(s) cleared |
|---|---|---|---|
| prisma / @prisma/client | 7.10.0 / 7.8.0 → **7.10.1** | `npm install prisma@7.10.1 @prisma/client@7.10.1` (patch bump, `^7.8.0` range) | deepmerge-ts HIGH + mysql2 HIGH + mysql2 MOD (prisma 7.10.1 bundles @prisma/config 7.10.1 → deepmerge-ts 8.0.2, and mysql2 3.24.4) |
| body-parser | 2.3.0 → **2.4.0** | added as direct dep `^2.4.0` (express 5.3.0 allows `^2.0.1`) | body-parser HIGH |
| fast-uri | 3.1.7 → **3.1.9** | `npm update fast-uri` (via ajv ← @prisma/dev) | fast-uri ×5 (2 LOW, 3 MOD) |
| ip-address | 10.7.0 → **10.7.6** | `npm update ip-address` (via express-rate-limit) | ip-address ×3 MOD |
| qs | 6.16.0 → 6.16.1 | pulled in by the prisma 7.10.1 tree refresh | qs MOD |

Notes: `npm install` on this VM needs `--no-audit` (the registry audit
endpoint 403s — known VM policy, not a failure) and `--ignore-scripts`
(the `@prisma/engines` postinstall binary download resets mid-flight
with ECONNRESET; retried, then ran separately — the client runtime does
not need it, `prismaClient` loads OK). Verification: full offline suite
**52/54 pass** (same 2 environmental failures as before the upgrade:
compliance DB test needs live Postgres, deployment_config needs real
secrets — neither is a regression); OSV re-scan **15 → 3 findings**.

## Remaining findings (2026-11-18)

| # | Advisory | CVE | Package @ installed | Severity | Fixed in |
|---|---|---|---|---|---|
| 1 | GHSA-fc5q-39xc-vjpf | CVE-2026-112366 | picomatch@4.0.7 | HIGH | **none listed** (latest release is 4.0.7) |
| 2 | GHSA-g3hv-75wg-m249 | CVE-2026-118764 | minimatch@10.2.6 | MODERATE | 11.0.1 (major) |
| 3 | GHSA-3g3m-2fjr-6pw4 | CVE-2026-118773 | glob@13.0.6 | MODERATE | 14.0.2 (major) |

- **picomatch@4.0.7 — HIGH** — "picomatch vulnerable to ReDoS through
  single-branch repeated extglobs" — `CVSS_V3:
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, `CVSS_V4:
  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`.
  Published 2026-10-19; OSV `last_affected: 4.0.7`, no fixed version.
  Reachability: picomatch is a transitive dep of **vite** (root dev
  tooling) — build-time only. No user-controlled glob reaches it at
  runtime; the backend does not depend on it. No patch exists upstream;
  containment = none needed beyond that (not production-reachable).
  **Owner decision needed:** risk-accept in writing with an expiry, or
  wait for upstream 4.0.8. Do NOT claim this HIGH is fixed.
- **minimatch@10.2.6 — MODERATE** — globparts-amplification DoS, fixed
  in **11.0.1** (major). Parent: `@typescript-eslint/typescript-estree`
  (root) and `glob@13.0.6` (backend, via @sentry/bundler-plugins).
  Major bump needs the parent upgrades — Day 9 work.
- **glob@13.0.6 — MODERATE** — "Glob: AbortSignal cancellation bypass
  allows post-timeout filesystem traversal", fixed in **14.0.2**
  (major). Parent: `@sentry/bundler-plugins`. Day 9 work.

## Findings (2026-11-17 baseline — superseded by the 18 Nov scan above)

| # | Advisory | CVE | Package @ installed | Severity | Fixed in |
|---|---|---|---|---|---|
| 1 | GHSA-27r3-jxmh-p828 | CVE-2026-111181 | body-parser@2.3.0 | HIGH | 2.4.0 (also 1.20.9 on the v1 line) |
| 2 | GHSA-ggr8-5vv4-36mx | CVE-2026-40345 | deepmerge-ts@7.1.5 | HIGH | 8.0.0 |
| 3 | GHSA-3f6p-5ww8-9rcr | — (no CVE alias in OSV record) | mysql2@3.15.3 | HIGH | 3.22.0 |
| 4 | GHSA-333x-w4r6-6crp | CVE-2026-110725 | fast-uri@3.1.7 | LOW | 3.1.9 |
| 5 | GHSA-hrr3-gc8f-f4qj | CVE-2026-86472 | fast-uri@3.1.7 | MODERATE | 3.1.8 |
| 6 | GHSA-w74x-v6f9-j3xg | CVE-2026-110306 | fast-uri@3.1.7 | MODERATE | 3.1.9 |
| 7 | GHSA-wjr9-j795-jxcr | CVE-2026-110180 | fast-uri@3.1.7 | MODERATE | 3.1.9 |
| 8 | GHSA-xhq7-xmqj-769h | CVE-2026-110095 | fast-uri@3.1.7 | LOW | 3.1.9 |
| 9 | GHSA-3g3m-2fjr-6pw4 | CVE-2026-118773 | glob@13.0.6 | MODERATE | 14.0.2 |
| 10 | GHSA-h3mg-xc3c-68pw | CVE-2026-101911 | ip-address@10.7.0 | MODERATE | 10.7.1 |
| 11 | GHSA-j6r3-76f7-8jcv | CVE-2026-101912 | ip-address@10.7.0 | MODERATE | 10.7.1 |
| 12 | GHSA-rxp7-6hxx-x8q5 | CVE-2026-111997 | ip-address@10.7.0 | MODERATE | 10.7.4 |
| 13 | GHSA-g3hv-75wg-m249 | CVE-2026-118764 | minimatch@10.2.6 | MODERATE | 11.0.1 |
| 14 | GHSA-rgwj-5xj2-c3m3 | — (no CVE alias in OSV record) | mysql2@3.15.3 | MODERATE | 3.23.1 |
| 15 | GHSA-6pq8-jhm2-2vcw | CVE-2026-110816 | qs@6.16.0 | MODERATE | 6.16.1 |

All findings are in `backend/package-lock.json` except minimatch, which
is in **both** lockfiles. Summaries (verbatim from OSV) and CVSS vectors:

- **body-parser@2.3.0 — HIGH** — "body-parser vulnerable to Denial of
  Service via trailing bytes after a compressed request body" —
  `CVSS_V3: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.
- **deepmerge-ts@7.1.5 — HIGH** — "DeepmergeTS has stack exhaustion when
  merging recursive object graphs" —
  `CVSS_V4: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`.
- **mysql2@3.15.3 — HIGH** — "MySQL2: Auth Plugin Downgrade to
  mysql_clear_password Leaks Plaintext Credentials" —
  `CVSS_V4: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`.
  Most security-relevant finding: a downgrade that can expose plaintext
  DB credentials. Reachability in this app not assessed — mysql2 is
  transitive, not a direct dependency.
- **mysql2@3.15.3 — MODERATE** — "MySQL2: Unbounded zlib inflate in
  compressed MySQL protocol handler allows decompression-bomb DoS" —
  `CVSS_V3: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`.
- **fast-uri@3.1.7 — 5 findings (2 LOW, 3 MODERATE)** — scheme
  injection via unescaped first-segment colon; inconsistent host case
  normalisation via percent-encoded octets; URI scheme spoofing via
  percent-encoded scheme decoding; host confusion via unchecked WHATWG
  host canonicalisation; improper path equivalence in relative reference
  normalisation. All fixed by upgrading to **3.1.9** (GHSA-hrr3 fixed
  from 3.1.8).
- **glob@13.0.6 — MODERATE** — "Glob: AbortSignal cancellation bypass
  allows post-timeout filesystem traversal" —
  `CVSS_V4: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`.
- **ip-address@10.7.0 — 3 MODERATE** — unbounded parse diagnostic
  (DoS); `isInSubnet()`/`isHostInSubnet()` cross-family comparison
  admitting out-of-range addresses past an allowlist check; quadratic
  zone-identifier matching (DoS). All fixed by upgrading to **10.7.4**
  (first two fixed from 10.7.1).
- **minimatch@10.2.6 — MODERATE** — "minimatch has potential denial of
  service via globparts amplification" —
  `CVSS_V4: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`.
- **qs@6.16.0 — MODERATE** — "`qs.stringify` with arrayFormat 'comma'
  throws an uncaught TypeError on array elements carrying a non-callable
  own toString (DoS)" — CVSS v3 and v4 vectors both published by OSV;
  fixed in **6.16.1**.

## Fix guidance (2026-11-18 state)

Fixed in this run: body-parser, deepmerge-ts, mysql2, fast-uri,
ip-address, qs (see the remediation table above). Still open:

| Package | Upgrade to (clears all its findings) | Notes |
|---|---|---|
| picomatch | **no fixed version exists** (4.0.7 latest) | Owner risk-accept with expiry, or wait for upstream. Build-time vite dep only. |
| glob | 14.0.2 | Major bump; parent @sentry/bundler-plugins. Day 9. |
| minimatch | 11.0.1 | Major bump; present in both trees. Day 9. |

After any upgrade, re-run `node SecureGaurd-main/scripts/osv-scan.mjs`
and confirm the finding count drops; do not hand-edit the tables above.

## Continuous scanning (CI)

`.github/workflows/dependency-scan.yml` runs `npm audit
--audit-level=high` for root and backend on push to `main`, weekly
(Mondays 06:00 UTC), and on `workflow_dispatch`. The job **fails on any
high or critical finding** and uploads the full `npm audit --json`
report as an artifact (30-day retention). Workflow results are read via
the GitHub Actions UI — no API read tool for runs is available from
this VM. First run has not happened yet at the time of writing; the
next scan after the fixes above should be the first green run.

## Outdated packages (context, re-verified 2026-11-17)

`npm outdated` works from the VM (only `npm audit` is blocked).

- **Root** (`SecureGaurd-main/`): **17 outdated / 6 major.**
  Majors: `@eslint/js` 9.39.5→10.0.1, `@types/node` 25.9.9→26.6.6,
  `concurrently` 9.2.5→10.0.7, `eslint` 9.39.5→10.15.0,
  `framer-motion` 12.43.0→14.14.0, `typescript` 6.0.3→7.0.2. (Was 15
  outdated / 6 major on 2026-11-14; two more minor bumps appeared.)
- **Backend** (`SecureGaurd-main/backend/`): **9 outdated / 2 major**
  (was 10 on 2026-11-16 — `mongoose` removed by the fix-all run).
  Majors: `dotenv` 17.4.2→18.0.10,
  `prisma` 7.10.1→8.0.0-rc.34. (`@prisma/client` /
  `@prisma/adapter-pg` 7.8.0→7.10.1 was a minor — done in the 18 Nov
  gate-pass run.)

Outdated ≠ vulnerable: only the 3 findings above are known
vulnerabilities. The major bumps (notably TypeScript 7, ESLint 10,
Prisma 8-rc) are upgrade work, not security fixes, and Prisma 8 is a
release candidate — do not chase it for this item.

## Limitations

- OSV is a version database, not a runtime check: no finding here is
  proven exploitable in SecureGaurd, and absence of a finding is not
  proof of safety (zero-days / unreported issues are invisible to it).
- `npm audit` results from the CI workflow may differ slightly from
  OSV (different advisory sources); the CI run is the gate, this scan
  is the measured baseline.
- Scan covers the two npm lockfiles only. No other ecosystems are
  present in this repo's dependency tree.
