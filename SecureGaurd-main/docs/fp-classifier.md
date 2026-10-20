# FP Classifier — Architecture, Features & Metrics

The false-positive suppression classifier: an XGBoost microservice that labels
SAST findings **REAL** vs **FALSE_POSITIVE** so developers only triage findings
worth their time. It never deletes a finding — a FALSE_POSITIVE label moves it
to `ignored` status; on any classifier failure the finding stays `open` (fail-safe).

> **Legacy note:** `classifier model/` at the repo root is the original prototype
> (smaller model, standalone scripts). The production service is
> `backend/services/fp-classifier/` — documented here.

## Architecture

```
Developer clicks "Ignore" / "Confirm"          (labels → retraining data)
        │
[Express backend] ── scan → extractASTFeatures() ── enrich (DB counts, git churn)
        │  POST /classify/batch (chunks of 50, 5s timeout, X-SecureGuard-Key)
        ▼
[FastAPI :8001] ── pydantic validation ── predict_finding()
        │  per-CWE conformal threshold (fallback 0.4)
        ▼
[XGBoost model.joblib] → REAL / FALSE_POSITIVE + confidence + explanations
        │
        └── retrain.py (weekly/feedback-threshold) → models_archive/ + model_metadata.json
```

**Serving contract** (`service.py`): `GET /health` (no auth; reports service +
model versions), `POST /classify`, `POST /classify/batch` (≤200 findings),
`GET /model-info`, `GET /metrics` (auth via `X-SecureGuard-Key`). Input ranges
are validated before prediction — violations return 422 and the Node caller
treats any non-2xx as fail-safe REAL.

## Model

- **Algorithm:** XGBoost binary classifier (`XGBClassifier`, `random_state=42`).
- **Training:** `train.py` runs `GridSearchCV` (5-fold, `scoring="recall"` —
  recall is optimized deliberately: missing a REAL vuln is worse than a false
  alarm) over `n_estimators × max_depth × learning_rate × min_child_weight ×
  subsample`.
- **Calibration:** per-CWE conformal thresholds in `thresholds.json`
  (`conformal_calibration.py`); unseen CWEs fall back to the default, and a
  missing file falls back to a fixed 0.4 threshold. Never blocks serving.
- **Explainability:** rule-based `explain_prediction()` always runs; SHAP
  (`explainer.py`) is opt-in via `?include_explanation=true`.
- **Versioning:** service version is the `SERVICE_VERSION` constant in
  `service.py` (contract changes); model version is `model_metadata.json`
  (training runs), both reported by `/health`. Retrained models are archived
  under `models_archive/model_<timestamp>.joblib`; the 2%-drop safety gate in
  `retrain.py` aborts deployment if accuracy/recall regress.

## Features (18)

| # | Feature | Source | Meaning |
|---|---------|--------|---------|
| 1 | `is_string_concat` | astExtractor.js | String building on a sensitive sink |
| 2 | `is_parameterized_query` | astExtractor.js | Placeholders (`?`/`$1`) instead of interpolation |
| 3 | `has_sanitizer_nearby` | astExtractor.js | Sanitize/escape/validate call in scope |
| 4 | `in_test_file` | astExtractor.js | Path looks like a test/spec file |
| 5 | `is_in_vendor_or_generated_dir` | astExtractor.js | `node_modules`/`vendor`/`dist` |
| 6 | `taint_source_distance` | astExtractor.js | AST hops from untrusted input to sink (default 5) |
| 7 | `function_complexity` | astExtractor.js | Branch/loop/logical-op count in enclosing scope |
| 8 | `code_snippet_length` | astExtractor.js | Target line length (chars) |
| 9 | `variable_name_entropy` | astExtractor.js | Shannon entropy: secret-looking literals (SEC-*) or avg identifier entropy |
| 10 | `is_user_input_direct` | astExtractor.js | `req.body/query/params/headers` flows to sink |
| 11 | `has_type_validation` | astExtractor.js | joi/zod/yup or parse/validate/safeParse in scope |
| 12 | `is_third_party_lib_call` | astExtractor.js | Callee imported from a dependency |
| 13 | `same_finding_seen_before_count` | scans.js (DB) | Prior vulns with same rule+file in this repo |
| 14 | `developer_dismissed_similar_before` | scans.js (DB) | Prior `ignored` vulns with same rule in this repo |
| 15 | `file_change_frequency` | scans.js (git) | Commit count touching the file, capped at 50 (training range 0–50); 0 when git unavailable |
| 16 | `is_authenticated_endpoint` | astExtractor.js | `requireAuth`/`isAuthenticated` in scope |
| 17 | `rule_id` | scans.js (RULE_MAP) | SAST-001…SEC-003 → classifier category (label-encoded) |
| 18 | `cwe_id` | scans.js (CWE_MAP) | CWE-89, CWE-79, … (label-encoded; unseen → -1) |

The column order in `FEATURE_COLS` (`feature_schema.py`) is positional — the
model consumes it by position, so it must never be reordered. `RAW_FEATURES`
there mirrors the `Finding` request schema; `test_feature_schema.py` pins both.

## Metrics

Measured 2026-10-20 with `evaluate.py` on the bundled `sample_findings.csv`
(8,000 labeled findings):

| Metric | Value |
|---|---|
| Accuracy | 0.9800 |
| REAL — precision / recall / F1 | 0.9698 / 0.9675 / 0.9686 |
| FALSE_POSITIVE — precision / recall / F1 | 0.9848 / 0.9859 / 0.9853 |
| Missed REAL vulnerabilities (false negatives) | 83 / 2,553 |
| False alarm rate | 0.0141 |

**Honesty note:** this is *in-sample* (the model trained on this data), so 0.98
is optimistic. Treat it as a smoke test that the pipeline is healthy, not as
the production number. The unbiased estimate comes from `retrain.py`'s held-out
split (its safety gate compares new vs old model on the same 20% split).
Re-run any time: `python3 evaluate.py [--data …] [--output report.json]`.

## Retraining

```bash
cd backend/services/fp-classifier
python3 collect_training_data.py   # DB feedback (Ignore/Confirm clicks) + synthetic base
python3 retrain.py [--force] [--threshold 500]
```

Feedback labels come from `GET /api/scans/export-feedback` (userLabel +
mlFeatures per vulnerability). Deployment is atomic (archive → copy → metadata)
and aborts if the new model drops accuracy/recall >2% vs the active model.

## Running the scripts

`train.py` / `generate_sample_data.py` / `evaluate.py` take `--data`, `--out`,
`--out-dir`, `--n` flags and default to files next to the script — no hardcoded
machine paths. `service.py` needs `pip install -r requirements.txt`, then
`uvicorn service:app --host 127.0.0.1 --port 8001`.
