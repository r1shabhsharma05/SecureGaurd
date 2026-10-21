# Severity-Priority Ranker

Scores every SAST finding **0–100** answering *"which open finding do I fix
first?"* — the complement to the FP classifier's *"is this finding real?"*.
Lives in `backend/services/severity-ranker/`, served by the classifier
FastAPI service under the versioned **`/v2/rank`** path (same process, same
`X-SecureGuard-Key` auth), proxied to the frontend via **`POST
/api/v2/ml/rank`**, and surfaced in the Dashboard as a feature-flagged **AI
Priority** sort toggle (`VITE_ENABLE_SEVERITY_RANK`).

## Purpose

Static severity strings (`critical/high/medium/low`) don't tell a developer
where to start: ten `high` findings on one scan are unordered. The ranker
fuses three signals into one triage order:

1. **CWE base tier** — vulnerability-class severity (`severity_schema.py`).
2. **Exposure context** — does untrusted input reach the sink? Is the
   endpoint unauthenticated? (Strongest "exploitable now" signals.)
3. **FP probability** — the classifier's P(REAL), so likely-noise findings
   don't top the queue.

## Inputs / outputs

**Input** — the same 18 raw features as `POST /classify` (`rule_id`, `cwe_id`
+ 16 signals). The Node route reads them from the stored `mlFeatures` JSON,
so no re-extraction is needed.

**Output** (`POST /v2/rank`, `POST /v2/rank/batch`):

```json
{
  "priority_score": 87.5,
  "band": "critical",
  "severity_score": 95.0,
  "severity_band": "critical",
  "p_real": 0.97,
  "fp_prediction": "REAL",
  "fallback": false
}
```

The blended score is `0.6 × severity_score + 0.4 × p_real × 100`, mapped to
bands: ≥80 critical, ≥60 high, ≥40 medium, else low. Severity dominates
because `scans.js` already auto-ignores likely-FPs — what reaches the ranker
skews REAL, so severity should drive the order among them. Components are
returned alongside the blend so the UI (or an auditor) can see *why* a
finding ranks where it does.

## The v0 heuristic-label caveat (read this first)

> **No analyst-labeled severity data exists yet.** v0 targets are derived from
> the transparent formula in `severity_schema.heuristic_priority_label` (CWE
> base tier ± exposure/context modifiers), recorded as
> `"label_source": "heuristic_v0"` in `severity_metadata.json`.

The trained `XGBRegressor` learns a smooth approximation of that formula —
held-out: MAE 0.28, R² 0.9987, Spearman ρ 0.9976, i.e. it faithfully tracks
the audited formula with learned feature interactions. **Why a model instead
of the raw formula?** The formula over 18 interacting features is exactly
what a shallow tree ensemble expresses well; the model gives calibrated
0–100 scores plus feature importances, and — most importantly — fixes the
serving contract (schema, endpoint, metadata, safety expectations) *now*, so
when analyst-labeled data arrives only the weights change. The formula
itself stays in `severity_schema.py`, unit-tested, as the auditable source
of truth.

**Upgrade path:** label a few hundred findings with analyst severity →
point `train_severity.py` at the labeled CSV → version the weights
(`v1_analyst`) → the 0–100 contract is unchanged for all callers.

## Training

```bash
cd backend/services/severity-ranker
python train_severity.py [--data ../fp-classifier/sample_findings.csv]
```

- Encodes `rule_id`/`cwe_id` with the FP classifier's **fitted** encoders
  (reused, never refit — identical category mappings at train and serve).
- Trains `XGBRegressor` (200 trees, depth 5) on the shared `FEATURE_COLS`.
- Evaluates on a held-out 20%: MAE, RMSE, R², **Spearman rank correlation**
  (the metric that matters for a prioritizer — order, not exact score).
- Writes `severity_model.joblib` + `severity_metadata.json`.

Weights are a **local build artifact** (not committed — the push transport is
text-only). Until `train_severity.py` runs, `/v2/rank` answers **503** with
the exact remediation command, and `POST /api/v2/ml/rank` degrades to
static CWE-tier ordering marked `degraded: true`.

## Failure modes

| Situation | Behavior |
|---|---|
| Weights missing | Python 503 `RANKER_NOT_TRAINED` → Node `degraded: true` tier fallback |
| Single item errors in a batch | That item falls back to the heuristic formula, marked `fallback: true`; the batch still returns 200 |
| Finding without stored `mlFeatures` | Omitted from `ranked`; Dashboard keeps it in default order |
| Classifier unreachable | Node tier fallback (85/85/80/75/70/60), explicitly marked — never a silent wrong order |
| Malformed finding | 422 from the shared `Finding` schema before any scoring |

## Limits

- v0 ranks *relative* priority, not absolute risk — a 95 is "fix first",
  not "95% chance of breach".
- The heuristic bakes in judgments (e.g. unauthenticated +10, test files
  −15) that real analyst labels may overturn — that's the documented v1.
- CWE tiers cover the 6 classes the scanner emits; unseen CWEs score the
  default tier (65), never a silent 0.
- The 0.6/0.4 blend weights are a reasoned default, not a tuned optimum.
- Like the classifier, this is a triage aid: it never suppresses findings,
  only orders them.
