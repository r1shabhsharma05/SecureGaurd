# SecureGuard FP Suppression Classifier

A production-hardened XGBoost microservice that classifies SAST findings as **REAL** vulnerabilities or **FALSE_POSITIVE** noise, reducing alert fatigue while preserving security-critical issues.

---

## Architecture Overview

```
[Frontend Dashboard]
       │  Developer clicks "Ignore" / "Confirm" / "Apply Fix"
       ▼
[Express Backend (Node.js)]
       │  Trigger Scan → Extract AST Features → Batch POST (50/chunk)
       │  Store mlFeatures + userLabel in PostgreSQL
       ▼
[FastAPI Classifier (Python :8001)]
       │  Loads model.joblib → Returns REAL / FALSE_POSITIVE
       ▼
[XGBoost Model]
       └── Periodically retrained via retrain.py + collect_training_data.py
```

---

## Quick Start

```bash
cd backend/services/fp-classifier

# Install Python dependencies
pip install -r requirements.txt

# Start the service (development)
uvicorn service:app --host 0.0.0.0 --port 8001 --reload

# Start the service (production — multi-worker)
uvicorn service:app --host 0.0.0.0 --port 8001 --workers 4
```

> **Windows Note:** Gunicorn is POSIX-only and does not run on Windows.
> Use `uvicorn --workers N` for production multi-process deployment on Windows.

---

## Environment Variables

| Variable | Location | Description |
|---|---|---|
| `FP_CLASSIFIER_URL` | `backend/.env` | URL the Node.js backend uses to reach this service (default: `http://localhost:8001`) |
| `CLASSIFIER_API_KEY` | `backend/.env` | Shared secret key for Node→Python auth. Sent as `X-SecureGuard-Key` header. **Change before production.** |

---

## API Endpoints

### `GET /health`
Returns `{"status": "ok"}`. Used by Node.js health checks. No auth required.

### `POST /classify`
Classify a single finding. Requires `X-SecureGuard-Key` header.

### `POST /classify/batch`
Classify multiple findings in one call. Node.js sends chunks of 50 max.

**Request body:**
```json
{
  "findings": [
    {
      "rule_id": "sqli-concat",
      "cwe_id": "CWE-89",
      "is_string_concat": 1,
      "is_parameterized_query": 0,
      "has_sanitizer_nearby": 0,
      "in_test_file": 0,
      "is_in_vendor_or_generated_dir": 0,
      "taint_source_distance": 2,
      "function_complexity": 14,
      "code_snippet_length": 90,
      "variable_name_entropy": 2.0,
      "is_user_input_direct": 1,
      "has_type_validation": 0,
      "is_third_party_lib_call": 0,
      "same_finding_seen_before_count": 1,
      "developer_dismissed_similar_before": 0,
      "file_change_frequency": 0,
      "is_authenticated_endpoint": 0
    }
  ]
}
```

### `POST /v2/rank`
Priority score (0–100 + band) for one finding — "which open finding do I fix
first?". Blends the FP classifier's P(REAL) with the severity-priority ranker
(`0.6 × severity_score + 0.4 × P(REAL) × 100`; severity dominates because
`scans.js` already auto-ignores likely-FPs). Requires `X-SecureGuard-Key`.
Answers **503** until the ranker is trained (`python train_severity.py` in
`../severity-ranker/`).

### `POST /v2/rank/batch`
Priority scores for up to 200 findings. Per-item fail-safe: a failing item
falls back to the transparent heuristic formula, marked `"fallback": true`,
instead of failing the batch. Requires `X-SecureGuard-Key`.

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

The ranker lives in the sibling package `backend/services/severity-ranker/`
and is served by this same FastAPI process (one deploy, one auth model).
`/health` reports `severity_ranker_ready` / `severity_ranker_version`.
Full design, label caveat, and training docs: `docs/severity-ranker.md`.

### `GET /metrics`
Returns usage statistics derived from `predictions.log`. Requires `X-SecureGuard-Key` header.

```json
{
  "total_predictions": 1240,
  "real_count": 890,
  "false_positive_count": 350,
  "real_percentage": 71.77,
  "false_positive_percentage": 28.23,
  "average_confidence": 0.8421
}
```

---

## Security: Internal-Only Access

The classifier service must **never** be exposed to the public internet. It is intended to be called exclusively by the Node.js backend on the same host/network.

**Protections in place:**
1. **API Key header (`X-SecureGuard-Key`)** — All prediction endpoints reject requests without this header matching `CLASSIFIER_API_KEY` in `.env`.
2. **Bind to localhost only** for dev: `uvicorn service:app --host 127.0.0.1 --port 8001`
3. **Firewall rule (recommended for production):** Allow port `8001` only from the Node.js server's internal IP.

---

## Rule ID Mapping

The Node.js backend maps internal SAST rule IDs to classifier-compatible category names before sending features:

| Internal Rule ID | Classifier `rule_id` |
|---|---|
| `SAST-001` | `sqli-concat` |
| `SAST-002` | `xss-unescaped` |
| `SAST-003` | `path-traversal` |
| `SAST-004` | `hardcoded-secret` |
| `SAST-005` | `insecure-deserialize` |
| `SEC-001/002/003` | **Bypassed** — always REAL |

> **New rule type added?** If a rule ID is not in `RULE_MAP` in `scans.js`, the raw rule ID is passed as-is. The classifier will use `-1` for unknown encodings and the finding defaults to **REAL** (fail-safe). Log a warning and add the mapping + training data.

---

## Model Versioning

Models are versioned by timestamp and archived under `models_archive/`:

```
models_archive/
  model_20260710_183000.joblib
  rule_encoder_20260710_183000.joblib
  cwe_encoder_20260710_183000.joblib
```

Active model files (`model.joblib`, `rule_encoder.joblib`, `cwe_encoder.joblib`) are always the latest approved version.

Metadata is stored in `model_metadata.json`:
```json
{
  "version": "v_20260710_183000",
  "training_date": "2026-07-10T18:30:00",
  "dataset_size": 5500,
  "new_feedback_size": 500,
  "metrics": { "accuracy": 0.921, "recall": 0.914, "precision": 0.889, "f1_score": 0.901 },
  "status": "active"
}
```

---

## Retraining Workflow

```bash
# Step 1: Collect labeled feedback from database and combine with synthetic base
python collect_training_data.py

# Step 2: Retrain the model (checks 500-example threshold by default)
python retrain.py

# Force retrain even if threshold not met (for testing)
python retrain.py --force

# Custom threshold
python retrain.py --threshold 200
```

**Safety Gate:** `retrain.py` automatically compares the new model against the current active model on the same validation split. If accuracy or recall drops by more than 2%, deployment is **aborted** and the previous model is kept.

---

## Performance

- **Batch size:** 50 findings per HTTP request (chunked by Node.js backend)
- **Request timeout:** 5 seconds per chunk (Node.js `AbortController`)
- **Fail-safe:** On timeout or service error, all findings default to `REAL`
- **Baseline accuracy (synthetic data):** ~90% / Recall: ~84%
- **Target accuracy (real data):** >92% after 500+ real feedback labels
