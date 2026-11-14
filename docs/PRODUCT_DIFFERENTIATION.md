# SecureGaurd — Product Differentiation (Day 2, 20-Day Transformation)

**Date:** 2026-11-15 (Day 2 of the 20-day program)
**Basis:** `docs/COMPETITOR_RESEARCH.md` (8 competitors, researched 2026-11-15)
and `docs/MASTER_PROJECT_AUDIT.md` (Day 1, audited commit `bf49b47`).
**Purpose:** validate the five differentiators proposed in the plan (Phase 2A–E)
against what competitors actually ship, decide which are real openings, which
are parity work, and which are non-goals — so Days 8–15 build the right things.

## Verdict in one paragraph

SecureGaurd cannot win by adding more features than Snyk or Aikido in 18 days,
and it should not try. It has two genuine openings no competitor productizes —
**explainable AI triage** and **verified remediation** — plus one honest
commercial wedge — **a flat, affordable price for small teams with no metering
maze and no Enterprise gate on SBOM and compliance**. Everything else in the
plan's Phase 2 is parity work that must still be done (private repos, background
scans, reachability, continuous monitoring), because missing it disqualifies the
product regardless of how good the differentiators are. DAST, container
scanning, malware detection and CSPM are explicit non-goals for this program:
three of eight competitors do them well, SecureGaurd does none of them, and
chasing them would consume the program without closing the gaps that actually
lose deals.

## 1. The three bets

### Bet 1 — Explainable AI security triage (LEAD — the strongest differentiator)

**The opening.** Every competitor claims false-positive reduction, but every
claim is a vendor percentage with no inspectable reasoning: Snyk 0.08% FP rate,
Aikido "99% fewer false positives", Semgrep "98% fewer", Mend "38% better
precision / 48% better recall", SonarQube "high precision". None of them shows
the analyst *why* a finding was classified a false positive, what the model
saw, how confident it is, or what would change its mind. None of them wires
analyst feedback back into the model in the open, versions the model where the
analyst can see it, or publishes a holdout evaluation. The workflow — "the AI
dismissed this, and I can see why, and I can disagree" — is underserved
everywhere.

**What SecureGaurd already has.** A real XGBoost false-positive classifier
(v3_real, live per the Day 1 probe), a severity ranker, SHAP test coverage in
the repo (`backend/services/fp-classifier/` tests), and findings that already
carry `mlFeatures` JSON. No competitor in the set starts from a shipped,
self-hosted classifier the team controls — Snyk, Semgrep and Aikido all rent
theirs from a vendor black box.

**What Day 10 must prove.** For every ML-classified finding: the predicted
class, the model confidence, the top contributing features in plain language
(SHAP), the model version, and a clear separation between model prediction
and verified fact. Analyst feedback (confirm / overturn) recorded per finding
and fed into retraining with a stated minimum-feedback threshold. Precision /
recall / F1 / false-negative rate measured on an independent, time-based and
repository-level holdout — never on training data — with data-leakage checks.
No automatic dismissal of anything: a model prediction may deprioritise, it
may never close a finding on its own. Any accuracy number without this
evaluation is not published.

**Failure mode to avoid.** Shipping an "AI confidence" badge with no
explanation behind it. That is exactly the competitors' black box with a
different label, and it is worth less than no badge at all.

### Bet 2 — Verified remediation (LEAD — once Day 11 builds the loop)

**The opening.** All eight competitors open fix PRs or suggest fixes. Only
one — GitHub's agentic autofix — reruns the scanner before opening the PR.
None of them makes "verified fixed by rescan" a first-class, auditable finding
state with the full evidence trail attached: diff, human approval, branch,
patch, test outcome, rescan result, closure. Today a merged fix PR is taken on
trust; a reopened vulnerability is discovered by accident. SecureGaurd's
compliance engine, audit-log infrastructure and deterministic scoring are the
right substrate for an evidence trail competitors do not offer.

**What SecureGaurd already has.** AI fix generation (rule templates + Gemini),
finding status transitions, audit logs, SBOM and compliance reporting. What it
does not have — and what the Day 1 audit calls the single largest functional
gap — is the loop itself: "apply" today only flips `aiFixApplied=true` and the
status to `fixed` and never writes to the repository.

**What Day 11 must prove.** Generate diff → human approval (never automatic)
→ branch creation → patch application → automated test execution → rescan →
PR creation → finding closed only when the rescan confirms the vulnerability
is gone. A fix that fails tests or survives the rescan stays open with the
evidence attached. No finding is ever marked fixed because a suggestion was
generated.

**Failure mode to avoid.** Shipping a prettier version of today's status flip
— a generated patch shown in the UI with a "Fixed" badge and no rescan. That
would repeat the exact dishonesty the Day 1 audit flagged (fake scan progress,
cosmetic email verification) in the product's most safety-critical flow.

### Bet 3 — Honest, flat pricing for small teams (LEAD — commercial wedge)

**The opening.** The market prices small teams out of real AppSec: GitHub
Advanced Security $49/active committer/month on top of a base plan; Snyk Team
caps at 10 developers and then forces Enterprise; Aikido jumps from $0 to
$350/month; Mend up to $1,000/developer/year; Socket's Team floor is $125/month;
Semgrep's full suite stacks to $75/contributor/month. The genuinely useful
features — SBOM export, SSO/RBAC, reachability, auto-fix — are gated to
Enterprise tiers at Snyk, Socket and Aikido. Developers cannot predict cost:
Snyk's expiring credits, Semgrep's module stacking, GHAS per-committer plus
AI-credit metering, Mend's three licences.

**SecureGaurd's position.** Pro at $29/seat/month with SBOM and compliance
reports included undercuts every incumbent's comparable tier — *provided the
product actually works end to end*. Price is only a wedge if the §4 gaps in
the research doc close (private repos, background scans, verified fixes).
Until they do, the honest price for a product that cannot scan private repos
is the free tier, not Pro.

**Pricing principle for the program.** One flat per-seat price. Everything in
the tier actually included — no credits, no per-scan metering, no Enterprise
gate on SBOM, compliance reports or the classifier. If a capability is not
ready, it is labelled unavailable, not sold. Enterprise (custom) may add SSO /
SAML / SCIM, dedicated deployment and SLA — but only when those exist (today
SAML is an explicit 501 and the Pricing page sells it anyway; that copy must
be fixed on Day 16, not after launch).

## 2. Validation of the plan's five proposed differentiators

| # | Differentiator (plan Phase 2) | Verdict | Evidence |
|---|---|---|---|
| A | Unified Security Intelligence — one verified posture view (code, secrets, deps, API, IaC, SBOM, compliance, risk) | **Build to parity, lead on honesty** | Snyk, Aikido and Mend already unify this in one platform; SonarQube unifies code quality + security. SecureGaurd has most of the pieces but they are not unified — the dashboard is tab-state with no risk model and no deep links. The lead is not "unified" (everyone claims it) but *verified*: a posture number that shows its evidence instead of an arbitrary score. Day 14. |
| B | Explainable AI Security Triage | **LEAD** | See Bet 1. No competitor productizes explanations, confidence, feedback or model versioning. Raw material already shipped. Day 10. |
| C | Developer-First Remediation | **Build to parity, lead on verification** | Fix PRs are table stakes (Snyk, GHAS, Aikido, Mend, Semgrep all do them). The lead is the verified loop (Bet 2), not the fix suggestion. Day 11. |
| D | Continuous Security Monitoring | **Build to parity** | Webhooks exist; the monitoring loop (new-CVE watch, reopened-vulnerability and regression detection) does not. Snyk, Mend and Aikido do this well. Requires background scans first (Day 13) — monitoring on top of synchronous scans is not credible. Day 13. |
| E | Risk-Based Prioritization | **Build to parity, lead on transparency** | Everyone prioritises by CVSS/EPSS/reachability now. SecureGaurd's ranker is heuristic-trained and flag-off — effectively absent. The lead is showing the *why* (evidence trail per ranking: severity + exploitability + reachability + exposure) rather than a black-box score. Day 10 / 14. |

## 3. Parity requirements (must-have — missing them disqualifies the product)

These are not differentiators. They are the price of entry, and the program
must close them even though no customer will ever praise them.

1. **Private-repository scanning** (Day 12) — authenticated clone via PAT,
   least-privilege scopes, redacted tokens, secure cleanup. The headline
   integration works for public repos only today.
2. **Background scanning** (Day 13) — queue, workers, retries, timeouts,
   cancellation, resource limits. Synchronous in-request scans are the
   product's biggest availability risk (Day 1 finding S6).
3. **Reachability-aware prioritization** (Days 10/14) — reachable vs
   unreachable, EPSS, KEV. The heuristic ranker must be replaced or
   honestly labelled as heuristic.
4. **Enforced email verification + MFA** (Day 5) — verification is cosmetic
   today (Day 1 finding S1); no MFA exists. Every competitor enforces
   verification.
5. **License policy enforcement** (Day 9) — allow/deny rules with PR blocking;
   the SBOM already carries licence data, the policy layer is missing.
6. **Real scan progress** (Day 14) — remove the fake progress bar (Day 1
   §3.3.1); show real scan status polling. A mock presented as live in the
   core workflow undermines every honesty claim in this document.
7. **Landing-page copy that matches wiring** (Days 16–17) — Stripe, SAML/SCIM,
   Jira, CI plugins, "50M+ CVEs", "milliseconds", "5 private repositories"
   on the free tier. Fix the copy or ship the feature; do not sell what does
   not exist.

## 4. Explicit non-goals for the 20-day program

Decided here so Days 8–15 do not drift into them. Each is a real capability
that competitors have and SecureGaurd lacks — and each is out of scope because
building it honestly in the remaining program time would displace the parity
work in §3 or the bets in §1.

- **DAST / runtime testing** (Snyk, Aikido; Mend via Invicti). No engine, no
  harness, no authenticated-scan infrastructure. Mark as unavailable; do not
  imply it.
- **Container-image scanning** (Snyk, Mend, Aikido; SonarQube beta). No
  scanner, no registry integration. Mark as unavailable.
- **Malware / malicious-package detection** (Socket's core strength; Mend,
  Aikido). Behavioural package analysis is a separate product. Mark as
  unavailable.
- **CSPM / cloud posture** (Aikido, Snyk IaC drift). Out of scope.
- **IDE plugin / CLI** (Snyk, Semgrep, SonarQube, Mend, Socket, Aikido). A
  real wedge for developer experience, but a second program, not this one.
  Post-launch candidate; the GitHub Actions template and PR bot are the
  in-workflow surface for now.
- **Privacy-first data-flow SAST** (Bearer's niche). Noted, not built.

If a customer asks for any of these, the honest answer is "not available in
SecureGaurd; here is what we do instead" — never a roadmap promise without a
date and an owner.

## 5. Positioning statement (for Days 16–17 copy)

> SecureGaurd is the evidence-first AppSec platform for small teams: every
> finding shows its evidence, every AI decision shows its reasoning, and every
> fix is proven by rescan before it is called fixed. One flat price, no
> metering maze, no Enterprise gate on SBOM or compliance.

Three claims, each falsifiable, each tied to a program deliverable: evidence
(Days 8–9, 14), reasoning (Day 10), proof (Day 11). If any of the three is
not true on Day 20, the copy changes — the claim does not stay.

## 6. Validation criteria (what would prove each bet on Day 20)

| Bet | Prove it by | Fails if |
|---|---|---|
| Explainable triage | 50+ findings triaged on a real repo with explanation + confidence + model version shown; holdout precision/recall/F1/FNR published in `docs/`; analyst feedback changes a later classification, demonstrated | Explanations are generic text; metrics measured on training data; feedback goes nowhere |
| Verified remediation | 5+ findings fixed end-to-end on a real repo: diff → approval → branch → patch → tests → rescan → PR → closed-by-rescan, each step evidenced in the audit log | Any finding marked fixed without a passing rescan; any auto-applied patch without human approval |
| Flat honest pricing | Pro tier works end to end on a private repo (scan → findings → fix → SBOM → compliance report) at the listed $29/seat with no metered extra; unavailable features labelled unavailable on the Pricing page | Private-repo scan fails; SBOM/compliance gated; copy still sells SAML/Stripe/Jira |

## 7. Risks

- **The bets depend on the parity work.** Verified remediation needs private
  repos (Day 12) and background scans (Day 13); explainable triage needs the
  classifier evaluation (Day 10). If Days 12–13 slip, Bet 2 slips with them.
  The security gate (Day 7) must not be traded for feature velocity.
- **The classifier may not survive honest evaluation.** The ranker is trained
  on heuristic labels and the classifier on synthetic data (Day 1 audit,
  `LIMITATIONS.md`). If Day 10 holdout metrics are poor, the honest outcome
  is to publish the poor metrics and label the classifier experimental — not
  to tune the evaluation until it passes.
- **Price wedge without parity is a trap.** Selling Pro at $29/seat while
  private-repo scanning is broken would repeat the landing-page overclaim
  pattern. The wedge activates only when §3 rows 1–2 close.
- **Competitor movement.** Semgrep Guardian was announced 12 Nov 2026, GHAS
  agentic autofix went GA 15 Oct 2026, Aikido repriced between Aug and Oct
  2026. The matrix is a 2026-11-15 snapshot; re-check before any launch
  claim that names a competitor.
