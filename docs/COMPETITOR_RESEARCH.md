# SecureGaurd — Competitor Research (Day 2, 20-Day Transformation)

**Research date:** 2026-11-15 (Day 2 of the 20-day program)
**SecureGaurd baseline:** `docs/MASTER_PROJECT_AUDIT.md` (Day 1, audited commit `bf49b47`,
2026-11-14). The SecureGaurd column below is grounded in that audit, not in README
marketing copy.
**Competitors:** Snyk, Semgrep, GitHub Advanced Security, SonarQube / SonarQube Cloud,
Mend.io, Socket, Bearer, Aikido Security — the eight named in the plan.
**Method:** official documentation, product pages, pricing pages and changelogs,
accessed 2026-11-15, corroborated by independent sources where noted. Vendor
marketing claims (false-positive rates, accuracy percentages, "3x more vulns") are
reported as **vendor claims**, not independently measured facts. Prices are public
list prices as read on 2026-11-15 unless flagged otherwise; re-verify before
quoting — several vendors' pricing pages render behind JavaScript and the figures
below were corroborated by independent reads of the same pages (see §7 caveats).
**Status key:** ● yes / full · ◐ partial · ○ no · ? unknown / not verified.

## 1. Capability matrix

| Capability | SecureGaurd | Snyk | Semgrep | GitHub Adv. Sec. | SonarQube | Mend.io | Socket | Bearer | Aikido |
|---|---|---|---|---|---|---|---|---|---|
| SAST | ◐ | ● | ● | ● | ● | ● | ◐ | ● | ● |
| DAST | ○ | ● | ○ | ○ | ○ | ◐ | ○ | ○ | ● |
| SCA | ◐ | ● | ● | ● | ◐ | ● | ● | ○ | ● |
| Secret detection | ◐ | ● | ● | ● | ● | ● | ◐ | ● | ● |
| Dependency vuln detection | ◐ | ● | ● | ● | ◐ | ● | ● | ○ | ● |
| SBOM | ● | ◐ | ● | ● | ◐ | ● | ◐ | ○ | ● |
| License compliance | ◐ | ● | ● | ◐ | ◐ | ● | ● | ○ | ● |
| Container security | ○ | ● | ◐ | ○ | ◐ | ● | ◐ | ○ | ● |
| IaC security | ◐ | ● | ◐ | ◐ | ● | ◐ | ○ | ○ | ● |
| API security | ◐ | ● | ○ | ○ | ◐ | ◐ | ○ | ◐ | ● |
| AI remediation | ◐ | ● | ● | ● | ● | ● | ◐ | ◐ | ● |
| False-positive reduction | ◐ | ● | ● | ◐ | ● | ● | ● | ◐ | ● |
| Vulnerability prioritization | ◐ | ● | ● | ◐ | ● | ● | ● | ● | ● |
| GitHub/GitLab integrations | ◐ | ● | ● | ◐ | ● | ● | ◐ | ● | ● |
| PR automation | ◐ | ● | ● | ● | ● | ● | ● | ◐ | ● |
| Developer experience | ◐ | ● | ● | ● | ● | ● | ● | ◐ | ● |
| Enterprise RBAC | ◐ | ● | ● | ● | ● | ● | ◐ | ? | ◐ |
| Compliance reporting | ◐ | ● | ◐ | ◐ | ● | ● | ◐ | ◐ | ● |
| Deployment | SaaS + on-prem (untested) | SaaS only | SaaS + local CLI | Cloud + Server | Cloud + Server + free Community | SaaS / hybrid / on-prem | SaaS + CLI | Local CLI + cloud dash. | SaaS + local scanners |
| Paid entry point | Pro $29/seat/mo | Team $25/dev/mo | $30/contrib/mo per module | $49/active committer/mo (both SKUs) | Cloud Team $34/mo per 100k LOC | up to $1,000/dev/yr | Team $25/seat/mo (5-seat floor) | not publicly listed | Basic $350/mo flat |

### What the symbols mean for SecureGaurd (audit-grounded)

- **SAST ◐** — 5 regex rules + Babel AST features; intra-procedural taint only, no
  semantic / source-to-sink analysis.
- **DAST ○** — nothing. No running-app testing anywhere in code or docs.
- **SCA ◐** — SBOM extractor (npm/Python/Java/Go/Rust/PHP/Ruby) + live NVD
  enrichment; unauthenticated NVD, 6 s throttle, in-memory cache; unknown version
  treated as zero.
- **Secret detection ◐** — 3 regex rules, working; no entropy analysis, no secret
  validators, no liveness check.
- **Dependency vuln detection ◐** — via NVD enrichment on the SBOM; no advisory
  database of its own, no reachability analysis.
- **SBOM ●** — SPDX 2.3 + CycloneDX 1.6, genuinely working; this is one of
  SecureGaurd's strongest shipped capabilities.
- **License compliance ◐** — license field captured per package in the SBOM (else
  `NOASSERTION`); no license policy / allow-deny enforcement.
- **Container security ○** — none; Docker files are deployment-only.
- **IaC security ◐** — 2 IaC regex rules + scanner; no misconfiguration engine.
- **API security ◐** — API-spec scanner, URL/paste only, no file upload.
- **AI remediation ◐** — generate works (rule templates + Gemini 1.5-flash); apply
  only flips `aiFixApplied=true` + status `fixed` and never writes to the repo;
  no branch / PR creation.
- **False-positive reduction ◐** — XGBoost classifier v3_real live, fail-open;
  SEC-* rules skip ML by design; severity ranker heuristic-trained, behind a
  flag that defaults off.
- **Vulnerability prioritization ◐** — ranker behind flag, degrades to static
  CWE-tier ordering; no exploitability / reachability / KEV evidence.
- **GitHub/GitLab integrations ◐** — webhooks (HMAC, fail-closed) + PR bot
  (real check-runs + PR comments) work; private-repo clone is impossible
  (anonymous HTTPS only).
- **PR automation ◐** — PR bot comments + check-runs; no auto-fix PR creation.
- **Developer experience ◐** — no IDE plugin, no CLI; only a GitHub Actions YAML
  template; dashboard is tab-state, no deep links.
- **Enterprise RBAC ◐** — orgs / members / roles / invites / audit logs work;
  SSO/OIDC code shipped but no provider live; SAML is an explicit 501; no MFA,
  no SCIM.
- **Compliance reporting ◐** — SOC 2 / HIPAA / PCI-DSS / GDPR reports generated
  with deterministic scoring and an explicit not-a-certification disclaimer.
- **Deployment ◐** — SaaS live (Vercel + Render + Supabase); on-prem Docker
  Compose statically verified only, never smoke-tested, needs a manual `.env`.
- **Pricing** — Starter $0, Pro $29/seat/month, Enterprise Custom (Razorpay
  billing live; Stripe dead). Note: Starter advertises "5 private repositories"
  although private-repo scanning does not work — an overclaim to fix, not a
  capability.

## 2. Competitor profiles

### 2.1 Snyk — snyk.io — the developer-first incumbent

Developer-first AppSec built around the IDE / PR / CLI loop: DeepCode AI SAST
(Snyk Code), Open Source SCA over a proprietary vulnerability database (vendor
claim: 3x more vulns than the next public DB), Container, IaC (400+ rules),
Secrets (GA Aug 2026), and API & Web DAST. One-click AI fix PRs across code,
dependencies, containers, IaC, secrets and APIs. Prioritization by a Risk Score
from 12+ factors including reachability, exploit maturity, EPSS/CVSS. 2026
direction is AI/agent security (Evo AI-SPM, Agentic AppSec, Snyk Studio/MCP).

- **Pricing:** Free $0 (5 projects, monthly test limits); Team from $25 per
  contributing developer/month (hard cap: 10 developers, 100 projects); Enterprise
  contact sales — prepaid credits, 1 credit = $1, metered per contributor /
  image / target per day, unused credits expire.
- **Limitations:** SaaS-only (no on-prem platform); key depth Enterprise-gated
  (`snyk sbom`, SBOM support, SSO/RBAC, custom policies); Team's 10-developer
  cap is a pricing cliff; credit metering is hard to forecast; still noisy in
  independent reviews; ~19–20 languages; no binary analysis / IAST.
- **Sources:** snyk.io/plans · snyk.io/product/snyk-code/ ·
  snyk.io/product/snyk-open-source/ · snyk.io/product/dast-api-web/ ·
  snyk.io/platform/compliance/ · updates.snyk.io

### 2.2 Semgrep — semgrep.dev — open-core, rule-driven SAST

Open-core SAST on fast pattern-based YAML rules that look like the code itself —
no build required, runs locally by default, custom rules in minutes. Semgrep Code
(35+ languages, 20,000+ Pro rules, cross-file taint in the platform), Supply
Chain SCA with dataflow reachability (reachable / conditionally reachable /
unreachable) + EPSS, Secrets with validators that confirm whether a secret is
active. AI autotriage + Autofix draft PRs. Newest direction: agent-native
security — Semgrep Guardian and an MCP server scanning code as AI coding agents
write it (announced 12 Nov 2026).

- **Pricing:** Free $0 (up to 10 contributors / 10 private repos); Teams Code
  $30 + Supply Chain $30 + Secrets $15 per contributor/month (full suite
  $75/contributor/month); Enterprise custom. Community Edition CLI (LGPL-2.1)
  free but single-file/single-function only — Semgrep's own README says it
  "will miss many true positives".
- **Limitations:** no DAST, no container-image scanning, no dedicated API
  security; best capabilities paywalled; modular pricing stacks to $75/dev/mo;
  AI use metered via credits; SCA reachability covers fewer languages (12–14)
  than SAST; no full on-prem platform.
- **Sources:** docs.semgrep.dev/introduction · semgrep.dev/pricing/ ·
  docs.semgrep.dev/semgrep-supply-chain/license-compliance ·
  docs.semgrep.dev/semgrep-code/triage-remediation/autofix · trust.semgrep.dev ·
  docs.semgrep.dev/release-notes/2026-11-02

### 2.3 GitHub Advanced Security — github.com/enterprise/advanced-security

The deepest native GitHub integration: CodeQL semantic SAST, Dependabot alerts
and security updates, secret scanning + push protection, dependency review,
SBOM (SPDX export). Since 1 Apr 2025 sold as two products — GitHub Code
Security + GitHub Secret Protection. Oct 2026 AI layer: AI Scan (GA 15 Oct 2026,
covers CodeQL-blind languages incl. PHP / Terraform / Dockerfiles, PR-only and
advisory-only) and agentic autofix (GA 15 Oct 2026, explores code, reruns CodeQL,
opens a draft PR, up to 25 alerts, default-branch only).

- **Pricing:** Secret Protection $19 + Code Security $30 per active committer
  per month ($49 combined); billed per unique active committer (pushed to an
  enabled repo in trailing 90 days), on top of the Team (~$4/user/mo) or
  Enterprise (~$21/user/mo) base plan. Free for public repos. AI Scan and
  agentic autofix consume metered AI credits. (Prices corroborated by
  independent sources citing GitHub's pricing page; not visible in the text
  fetch of the official product page on 2026-11-15 — re-verify before quoting.)
- **Limitations:** GitHub-locked (no GitLab/Bitbucket; Azure DevOps add-on
  only); no native DAST, container-image scanning, API security or runtime
  protection; per-committer pricing scales linearly; AI coverage gated
  (PR-only, advisory-only, skips fork/Dependabot PRs).
- **Sources:** docs.github.com — About GitHub Advanced Security ·
  GitHub security features · GHAS billing concepts ·
  github.com/enterprise/advanced-security ·
  github.blog/changelog/2026-10-15 (agentic autofix GA)

### 2.4 SonarQube / SonarQube Cloud — sonarsource.com

Deterministic, rule-based SAST + code-quality governance (quality gates,
technical-debt tracking) in one developer-first workflow, trusted by 7M+
developers per the vendor. Taint analysis, secrets (400+ patterns), IaC
scanning, AI CodeFix / Remediation Agent / Hunter Agent. SCA, SBOM, licence
compliance, Advanced SAST and container scanning are gated behind the Advanced
Security add-on (Cloud Team/Enterprise; Server Enterprise+). Genuine
self-hosted / air-gapped option plus a free Community Build.

- **Pricing:** Cloud Free $0 (private projects up to 50k LOC); Cloud Team from
  $34/month (up to 100k LOC, LOC-based, largest branch counts); Cloud
  Enterprise custom/annual; Server Community Build $0; Server Developer /
  Enterprise / Data Center not publicly listed (per-instance, per-year by LOC).
- **Limitations:** no DAST or runtime testing; SCA/SBOM/licence/container are
  add-on-gated — core/free is code quality + SAST/secrets/IaC only; LOC-based
  pricing scales steeply; container scanning is open beta, Cloud-only, limited
  base images; free Community Build has no branch or PR analysis.
- **Sources:** sonarsource.com/products/sonarqube/cloud/ ·
  sonarsource.com/plans-and-pricing/ · Advanced Security announcement ·
  container-scanning open beta · SOC 2 Type II announcement

### 2.5 Mend.io — mend.io — reachability + automated remediation at scale

Formerly WhiteSource (rebranded May 2022). Mend SCA (200+ languages/frameworks,
reachability via call-graph proof, CVSS 4.0 + EPSS, malicious-package detection),
Mend SAST (30+ languages, cross-file taint, Agentic Triage with explanation),
Mend Container (image + Kubernetes cluster scanning), Mend Renovate (dependency
update PRs with Merge Confidence from 1.7B installs), SBOM (SPDX 2.2/2.3,
CycloneDX 1.4–1.6, VEX, third-party import). DAST and API Security are
partnered add-ons via Invicti, not native. Forrester Strong Performer in SCA
(Q4 2024) and SAST (Q3 2025).

- **Pricing:** Mend AppSec up to $1,000 per contributing developer per year;
  Mend AI Premium up to $300/dev/yr (add-on); Mend Renovate Enterprise up to
  $250/dev/yr. No free tier for the platform (free only: Renovate Community
  Cloud, Mend Bolt). Figures are Mend.io's own published "up to" ceilings from
  its comparison pages — no standalone official /pricing page was found.
- **Limitations:** no free tier; per-developer pricing gets expensive at scale;
  DAST/API Security require a separate active Invicti account; AI security is
  a separate paid licence; Agentic Triage is SAST-only and advisory (never
  auto-dismisses); reviewers flag confusing navigation between separate
  SAST/SCA portals and complex on-prem/policy setup.
- **Sources:** mend.io/mend-platform/ · mend.io/sast/ · mend.io/sca/ ·
  mend.io/sbom/ · docs.mend.io/platform/latest/mend-dast ·
  mend.io/mend-vs-sonarqube/

### 2.6 Socket — socket.dev — behavioural supply-chain defence

Core strength is dependencies only: analyses what package code actually does
(network, filesystem, shell, env access, obfuscation, install scripts,
typosquatting) to catch malicious / zero-day packages before any CVE exists,
and blocks them at install time via Socket Firewall. Reachability triage
(vendor claim: ~60% CVE-noise cut precomputed, up to 90% full function-level),
human-reviewed AI-validated Certified Patches applied with one CLI command,
2,000+ licence types with pre-merge enforcement, SBOM generation/import
(not on the Free tier).

- **Pricing:** Free $0 (1 seat, 1,000 scans/mo); Team $25 per developer
  seat/month from 5 seats ($125/mo floor); Business $50/seat/mo from 20 seats
  ($1,000/mo floor); Enterprise custom. Seat = anyone who committed to a
  scanned repo in the past 90 days. (Annual-vs-monthly toggle ambiguity:
  independent reads report $20/$40 billed annually vs $25/$50 monthly —
  re-verify on the live pricing page before quoting.)
- **Limitations:** not a full AppSec platform — no DAST, IaC or API security;
  SAST/secrets/container exist only via Socket Basics, an Enterprise add-on
  that orchestrates third-party open-source tools; first-party code coverage
  is limited; per-seat minimums trap small teams; full reachability, SAST,
  secrets, GitLab/Bitbucket/Azure DevOps, SCIM and audit log need Enterprise.
- **Sources:** socket.dev/features/sca · socket.dev/blog/socket-basics ·
  socket.dev/features/patches · socket.dev/blog/introducing-socket-firewall ·
  socket.dev/changelog · socket.dev/blog/announcing-soc-2-type-i-compliance

### 2.7 Bearer — bearer.com — privacy-first, open-source SAST

Open-source CLI (free, no signup) doing SAST + secrets only. Distinct pitch:
traces sensitive-data flows (PII/PHI, 120+ data types) through code and
prioritises findings by data-exposure risk, producing GDPR-oriented privacy /
data-flow reports (PIA / DPIA / RoPA) that most SAST tools do not. GitHub
Action, SARIF code scanning, GitLab CI, diff-only PR scanning, reviewdog PR
comments. Acquired by Cycode; commercial Bearer Pro is sold via Cycode.

- **Pricing:** not publicly listed. Open-source CLI free; Bearer Pro pricing
  via Cycode sales (must be confirmed — packaging opaque after acquisition).
- **Limitations:** narrow scope — no SCA, SBOM, licence, container, IaC or
  DAST; language depth uneven (7 languages; cross-file analysis Pro-only,
  Java/Python/C#/Go only); secrets patterns are not configurable (docs state
  this explicitly); no IDE plugin; no auto-fix PR in the open-source CLI;
  enterprise RBAC unknown (no RBAC/SSO documented for Bearer itself).
- **Sources:** bearer.com · docs.bearer.com · docs.bearer.com/explanations/scanners/ ·
  github.com/Bearer/bearer · docs.bearer.com/guides/github-action/

### 2.8 Aikido Security — aikido.dev — all-in-one code-to-cloud

Bundles 12+ scanners in one platform — SAST, SCA, DAST (ZAP & Nuclei-based
surface monitoring), API security (authenticated DAST + fuzzing, Zen runtime
protection), IaC, secrets (incl. liveness detection), containers (incl. zero-CVE
base images), CSPM, malware, SBOM (CycloneDX 1.6 / SPDX-2.3 / CSV + VEX),
AI pentesting, plus an open-weight security model (Altar-1, Sep 2026) for
on-prem/air-gapped use. AI AutoFix / Agentic Dependency AutoFix open fix PRs.
Flat-rate (not per-seat) pricing; SOC 2 Type II + ISO 27001:2022; FedRAMP
Moderate (Class C, via Knox Systems, Oct 2026).

- **Pricing:** Developer $0 forever (2 users, 10 repos, 10 AI AutoFixes/mo);
  Basic $350/mo ($3,780/yr); Pro $700/mo ($7,560/yr); Advanced $1,050/mo
  ($11,340/yr); Enterprise custom. (The official pricing page's JS table did
  not render in text extraction; $350/$700/$1,050 corroborated by three
  independent Oct 2026 reads of that page. Older sources showed $300/$600 —
  prices have moved. Re-verify before quoting. AI pentesting separately priced,
  from ~$500/test.)
- **Limitations:** steep free-to-paid jump (2 users / 10 repos → $350/mo);
  on-prem scanning, malware detection and attack-surface monitoring start at
  Pro; SIEM / FIPS images / registry broker need Advanced/Enterprise; AI
  features consume monthly AI credits; no fully self-hosted platform (only
  scanners run locally; dashboard is SaaS; local scanners are single-branch,
  no AutoFix in the UI); enterprise depth thinner than incumbents (reviewers
  note limited RBAC scaling and reporting).
- **Sources:** aikido.dev · aikido.dev/pricing ·
  aikido.dev/use-cases/cybersecurity · help.aikido.dev/changelog ·
  help.aikido.dev — SBOM generation docs · aikido.dev/trust-center

## 3. Features everyone already provides (table stakes)

These are present in some form at 6+ of the 8 competitors. Shipping them is
parity, not differentiation — but missing them is a disqualifier.

1. **SAST in the PR** — every competitor except Socket (partial) has first-party
   SAST with PR comments / check-runs. SecureGaurd has the weakest SAST of the
   set (regex + AST features, intra-procedural taint only, no cross-file or
   source-to-sink analysis).
2. **SCA / dependency vulnerability detection** — 7 of 8 (all except Bearer).
   SecureGaurd's NVD-based enrichment is the thinnest implementation here.
3. **Secret detection** — all 8 in some form. SecureGaurd's 3 regex rules are
   the narrowest; every competitor has validators, entropy analysis or liveness
   checks that SecureGaurd lacks.
4. **SBOM generation** — 7 of 8 (all except Bearer). SecureGaurd is genuinely
   at parity here (SPDX 2.3 + CycloneDX 1.6) — one of its few full marks.
5. **License visibility** — 7 of 8. SecureGaurd records licence fields but has
   no policy enforcement; that is the gap, not the data.
6. **PR automation** — fix PRs or PR comments at 7 of 8. SecureGaurd comments
   via its PR bot but creates no fix PRs — and its "apply fix" never touches
   the repo, which is the single largest functional gap in the product.
7. **GitHub integration** — all 8. GitLab support at 6 of 8 (GHAS is
   GitHub-only; Socket gates GitLab behind Enterprise). SecureGaurd supports
   both hosts for webhooks/import but cannot scan private repos on either.
8. **AI-assisted remediation or triage** — all 8 claim it in 2026. The claim is
   cheap; the differentiator is whether the fix is verified (see §6).
9. **Reachability / EPSS-based prioritization** — Snyk, Semgrep, Mend, Socket,
   Aikido, SonarQube (Advanced Security). SecureGaurd has a heuristic ranker
   behind a disabled-by-default flag — effectively absent for users.
10. **Compliance reporting / evidence** — 7 of 8 map findings to SOC 2 / PCI /
    HIPAA / ISO frameworks. SecureGaurd generates the reports but with
    deterministic scoring that is not tied to verified control evidence.

## 4. Features SecureGaurd lacks (ranked by launch impact)

| # | Missing / weak capability | Who has it | Plan day |
|---|---|---|---|
| 1 | **Verified AI remediation** — generate diff → human approval → branch → patch → tests → rescan → PR. Today "apply" only flips a status flag. | Snyk, GHAS (agentic autofix reruns CodeQL), Aikido, Mend, Semgrep (Autofix) | 11 |
| 2 | **Private-repository scanning** — authenticated clone via PAT. Today anonymous HTTPS only; the headline GitHub/GitLab integration works for public repos only. | All 8 (standard) | 12 |
| 3 | **Background scanning** — queue/worker, retries, cancellation, resource limits. Today scans run synchronously in the HTTP request (clone up to 180 s), a DoS surface. | All 8 (standard) | 13 |
| 4 | **Reachability-based prioritization** — reachable vs unreachable, EPSS, KEV. Today a heuristic ranker, flag-off, no exploitability evidence. | Snyk, Semgrep, Mend, Socket, Aikido, SonarQube | 10 / 14 |
| 5 | **DAST / runtime testing** — any dynamic testing of a running app or API. | Snyk, Aikido (Mend via Invicti) | Not in the 20-day plan — explicit non-goal, see §6.4 |
| 6 | **Container-image scanning** | Snyk, Mend, Aikido, SonarQube (beta) | Not in the 20-day plan — explicit non-goal |
| 7 | **Explainable FP triage** — why a finding is a false positive, confidence, analyst feedback loop, model versioning. Classifier exists; none of the explanation/feedback surface exists. | Nobody does this well in-product (see §6.1) — genuine opening | 10 |
| 8 | **Continuous monitoring** — new-CVE watch, reopened-vulnerability and regression detection. Webhooks exist; the monitoring loop does not. | Snyk, Mend, Aikido | 13 |
| 9 | **Email verification enforcement + MFA** — verification is cosmetic (S1, Day 1 audit); no MFA anywhere. | All 8 have enforced verification; MFA standard at Snyk/SonarQube/Mend/Aikido | 5 |
| 10 | **IDE plugin / CLI** — no in-editor or local scanning path. | Snyk, Semgrep, SonarQube, Mend, Socket, Aikido | Not in the 20-day plan — post-launch |
| 11 | **Malware / malicious-package detection** (behavioural, pre-CVE) | Socket (core), Mend, Aikido | Not in the 20-day plan — explicit non-goal |
| 12 | **Enforced license policy** (allow/deny, PR blocking) | Snyk, Semgrep, Mend, Socket, Aikido | 9 |

## 5. Where SecureGaurd can realistically compete

Honest assessment, not aspiration. SecureGaurd is a solo-built product with
one author and 227 commits; it cannot out-feature Snyk or Aikido in 20 days.
It can compete in four places:

1. **Explainable AI triage (strongest).** Every competitor claims FP reduction,
   but the claims are vendor percentages (Snyk 0.08%, Aikido "99% fewer",
   Semgrep "98% fewer") with no in-product explanation of *why* a finding is a
   false positive, no confidence shown to the analyst, no feedback loop, no
   model versioning surfaced, and no holdout evaluation published. SecureGaurd
   already ships a real XGBoost classifier with SHAP test coverage in the repo
   and a severity ranker — the raw material for an explainable triage surface
   exists and no competitor productizes it. This is the Day 10 bet.
2. **Verified remediation (strongest, once built).** Competitors open fix PRs,
   but only GHAS's agentic autofix reruns the scanner before opening the PR.
   Nobody makes "verified fixed by rescan" a first-class, auditable finding
   state with the full evidence trail (diff → approval → tests → rescan →
   closed). SecureGaurd's compliance/reporting engine and audit-log
   infrastructure are the right substrate — if Day 11 builds the loop honestly.
3. **Price and simplicity for small teams.** The market prices small teams out:
   GHAS $49/active committer/mo on top of a base plan; Snyk Team caps at 10
   developers then forces Enterprise; Aikido jumps from $0 to $350/mo; Mend
   up to $1,000/dev/yr; Socket's Team floor is $125/mo. SecureGaurd Pro at
   $29/seat/mo with SBOM + compliance reports included undercuts every
   incumbent's comparable tier — provided the product actually works end to
   end (private repos, background scans, verified fixes). Price is only a
   wedge if the gaps in §4 rows 1–3 close.
4. **Honest, evidence-first posture.** The audit found SecureGaurd's landing
   page overclaims (Stripe, SAML/SCIM, Jira, "50M+ CVEs", "milliseconds").
   Every competitor overclaims too — but in the opposite direction: they hide
   capability behind Enterprise gates and metered credits. A product that
   shows its evidence (deterministic compliance scoring already does this),
   labels unavailable integrations as unavailable, and never presents a mock
   as live is a real, defensible position for developers burned by
   black-box scores. This only works if the fake scan progress and the
   overclaim copy are fixed (Days 14, 16).

## 6. Underserved developer problems (gaps the incumbents leave open)

1. **Small teams and solo developers are priced out of real AppSec.** Every
   incumbent's usable tier starts at $25–$49 per developer/month or a
   $350–$1,000/month floor, with the genuinely useful features (SBOM export,
   SSO, reachability, auto-fix) gated to Enterprise. A $29/seat product with
   no metering maze and no Enterprise gate on SBOM/compliance is an open lane.
2. **Nobody explains their AI.** FP-reduction and auto-fix are sold as
   percentages. Developers cannot see why a finding was dismissed, what the
   model saw, or what would change its mind — and no competitor lets an
   analyst's correction retrain the model in the open. Explainability +
   feedback is the underserved workflow.
3. **"Fixed" is unverified everywhere.** A fix PR merged does not mean the
   vulnerability is gone; only one competitor reruns the scanner before
   opening the PR, and none tracks fix-verification as an auditable state.
   Rescan-proven remediation is an open lane.
4. **Multi-tool sprawl and metering confusion.** Snyk's expiring credits,
   Semgrep's $30+$30+$15 stacking, Mend's three separate licences, GHAS's
   per-committer + AI-credit metering — developers cannot predict cost. One
   price, one platform, no metering maze is a simplification worth selling.
5. **On-prem / air-gapped for small orgs.** Only SonarQube Server (free
   Community Build, but no PR analysis), Mend hybrid and Aikido local scanners
   serve this; all are enterprise-priced or limited. SecureGaurd's Docker
   Compose package exists but was never smoke-tested — a cheap lane to open
   on Day 19 if it is actually verified.
6. **Privacy-first / data-flow SAST is a one-vendor niche.** Only Bearer
   prioritises by sensitive-data flow and produces GDPR data-flow reports.
   SecureGaurd does not do this; it is a noted gap, not a 20-day build.
7. **Supply-chain malware (pre-CVE) is a one-vendor strength.** Only Socket
   leads on behavioural malicious-package detection. SecureGaurd does not do
   this; noted as a gap, not a 20-day build.

## 7. Expensive or complicated workflows to simplify

- **Per-seat / per-committer / credit metering** — Snyk credits that expire,
  Semgrep's three-module stacking, GHAS per-committer + AI credits, Mend's
  per-developer ceilings. Simplify: one flat per-seat price, everything in
  the tier actually included, no credits.
- **Enterprise gating of basics** — SBOM export (Snyk), SSO/RBAC (Snyk,
  Socket), reachability (Socket), on-prem scanning (Aikido). Simplify: SBOM,
  compliance reports and SSO-adjacent features in the standard paid tier.
- **Fix-PR review burden** — competitors open PRs; developers still must
  verify each one by hand. Simplify: attach the rescan result and the test
  outcome to the PR so approval is evidence-based, not trust-based.
- **Triage toil** — every competitor's FP-reduction is a black box; analysts
  re-triage the same classes of finding repeatedly. Simplify: show the
  reason + confidence, accept analyst feedback, and let feedback change
  future classifications visibly.
- **Multi-portal sprawl** — Mend's separate SAST/SCA portals, Snyk's
  separate API & Web login, GHAS's two SKUs. Simplify: one dashboard, one
  finding model, one posture view (Plan Phase 2A).

## 8. Research notes, limits and caveats

- **Research date:** 2026-11-15. Competitor pricing and feature gates change
  frequently (Aikido's prices moved between Aug and Oct 2026; Semgrep
  announced Guardian 12 Nov 2026; GHAS split into two SKUs 1 Apr 2025).
  Re-verify prices on the vendors' live pricing pages before quoting them
  to a customer.
- **Pricing verification gaps:** GHAS $19/$30/$49 and Aikido $350/$700/$1,050
  were corroborated by multiple independent reads of the vendors' own pages
  but not visible in the direct text fetch on 2026-11-15; Socket's
  annual-vs-monthly toggle ($20/$40 vs $25/$50) is unresolved; Mend's figures
  are "up to" ceilings from its comparison pages, not a standalone pricing
  page; Semgrep Guardian $10/seat is corroborated-only, not on the official
  pricing page; SonarQube Server tiers are not publicly listed and no
  third-party figure is quoted here as a list price.
- **Vendor claims are not evidence:** Snyk's 0.08% FP rate and "3x more
  vulns", Aikido's "99% fewer false positives", Semgrep's "98% fewer",
  Mend's "38% better precision / 48% better recall" and "46% more accurate"
  AI fixes, SonarQube's "high precision" — all vendor claims, none
  independently measured in this research. SecureGaurd must not answer them
  with its own unmeasured claim; Day 10 evaluation is the honest response.
- **Bearer enterprise RBAC is unknown** — no RBAC/SSO documented for Bearer
  itself; any enterprise RBAC would be via the Cycode platform and was not
  verified.
- **Compliance entries distinguish vendor-held certifications from frameworks
  the product helps customers evidence** (notably GHAS, Aikido, Snyk HIPAA/PCI
  and Semgrep's SOC 2 scope). Do not repeat a vendor's framework list as if
  it were the vendor's own certification.
- **SecureGaurd column scope:** Day 1 audit at commit `bf49b47` (2026-11-14).
  Anything shipped after that commit is outside this document's SecureGaurd
  column until re-verified.
- **What was not researched:** G2/peer-review sentiment beyond corroboration,
  each vendor's API in depth, and DAST/container runtime internals — out of
  scope for a Day 2 matrix; the matrix marks those as the vendors document
  them.
