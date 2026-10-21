# SecureGuard — Known Limitations & Design Constraints

This document consolidates all known design constraints, tradeoffs, and future improvement paths for the AST-based feature extraction pipeline and the ML false-positive suppression model.

---

## 0. Hardcoded Secrets (SEC-*) Are NOT Filtered by the ML Model

> [!IMPORTANT]
> This is **intentional by design**, not a bug.

**Why:** The synthetic training data uses a label rule where the hardcoded-secret risk score is computed as `(variable_name_entropy - 3)`. For realistic secret strings, this yields a raw score of approximately **-0.57 to +0.08** — well within the Gaussian noise added during training (`N(0, 1.2)`). The result is that ~50% of real secrets were labeled REAL and ~50% FALSE_POSITIVE during training **purely by noise**, giving the model no reliable signal to classify secrets.

**Current Behavior:** `SEC-001`, `SEC-002`, and `SEC-003` findings **skip ML classification entirely** in `securityScanner.js`. They are always kept as REAL findings (fail-safe / fail-open).

> [!IMPORTANT]
> **Intentional Trade-off:** By completely disabling false-positive suppression for the secrets category, any matches (including development placeholders, test credentials, or local mock constants) will be flagged as **REAL** alerts. This is a deliberate, security-first choice to guarantee zero false-negatives (missed secrets) in production.

**Fix Path:** To enable ML classification of secrets in the future:
1. Generate training data with a stronger secret-specific signal (e.g., add an `is_high_entropy_value` binary feature that is `1` when the literal value entropy > 3.5).
2. Retrain the model on that enriched dataset.
3. Re-enable `mlFeatures` extraction for `SEC-*` rules once precision > 90% is confirmed on a held-out set.

---

## 1. Intra-Procedural Taint Tracing Scoping

- **Limitation:** `astExtractor.js` traces variable assignment flows (taint distance) strictly within the enclosing function/scope (intra-procedural).
- **Impact:** If user input is passed as an argument across multiple functions (e.g., route handler calls `processUser(req.query.id)` which internally calls `db.query`), the tracer inside `processUser` will not trace the parameter back to `req.query` in the route handler.
- **Fallback Behavior:** The parser handles this gracefully by setting `taint_source_distance` to a safe baseline default of `5` and `is_user_input_direct` to `0`, ensuring the finding is still preserved and evaluated rather than suppressed silently.

---

## 2. Configurable Sanitizer Naming Patterns

- **Limitation:** `has_sanitizer_nearby` identifies sanitizer calls based on substring matching of function names (e.g. `escape`, `sanitize`, `validate`).
- **Impact:** Custom sanitizer wrappers with generic or non-standard names (e.g., `cleanInput()`, `stripTags()`) will be missed, resulting in `has_sanitizer_nearby: 0`.
- **Mitigation:** Custom sanitizer names can be appended to the configurable JSON array inside `sanitizerPatterns.json` to extend the detector's capability dynamically without editing parser code.

---

## 3. Hardcoded File Change Frequency (Git Churn)

- **Limitation:** The feature `file_change_frequency` is currently fixed to `0` at runtime.
- **Impact:** In environments where the codebase runtime does not have local `.git` directory metadata (e.g., containerized builds, clean workspace downloads), git history is unreachable.
- **Mitigation:** When Git metadata integration is established, a shell execution of `git log --oneline -- <filePath> | wc -l` can be added to dynamically compute file edit frequency.

---

## 4. Synthetic Training Dataset Dependency

- **Limitation:** The XGBoost model was trained on synthetic SAST data to bootstrap the initial classifier accuracy (~90%).
- **Impact:** True-positive and False-positive characteristics of actual user codebases may have different statistical distributions than the synthetic generator.
- **Mitigation:**
  - `mlFeatures` are now stored in the `Vulnerability` table at scan time.
  - Developer "Confirm/Ignore/Apply Fix" actions write a `userLabel` (`real` or `false_positive`) to the database.
  - Run `collect_training_data.py` to pull labeled feedback + mix with synthetic base.
  - Run `retrain.py` (requires 500+ new feedback examples; override with `--force`) to retrain the model safely.

---

## 5. Model Deployment Rollback Policy

- **Policy:** `retrain.py` compares new model metrics against the currently deployed model on the same validation split.
- **Rollback trigger:** If new model accuracy OR recall drops by more than **2 percentage points**, deployment is automatically aborted and the old model files are preserved.
- **Archive:** All trained model versions are stored in `models_archive/` with timestamps.
- **Manual rollback:** Copy any older `model_<timestamp>.joblib` from `models_archive/` to `model.joblib` and restart the service.

---

## 6. Classifier Timeout & Batch Behavior

- **Batch size:** Node.js backend splits findings into chunks of max **50** before sending to the classifier.
- **Request timeout:** Each chunk has a **5-second** `AbortController` timeout.
- **Fail-open default:** On timeout, service error, or unknown rule ID, the finding defaults to **REAL** (kept as real vulnerability). No finding is silently dropped.

---

## 7. Unknown Rule ID Handling

- **Behavior:** If a new SAST rule ID is added to `securityScanner.js` but not yet added to `RULE_MAP` in `scans.js`, the raw rule ID string is passed to the classifier. The classifier will assign it the encoded value `-1` (unknown class), and the model will likely predict **REAL** (fail-safe). 
- **Action required:** Add the rule ID to `RULE_MAP` in `backend/routes/scans.js` and generate + add training samples for that rule type to `sample_findings.csv`, then retrain.

---

## 8. Classifier Service Availability

- **If the classifier service is down:** The backend will log a `[ML Service Error]` warning. All SAST findings for that scan will be preserved as **REAL** (fail-open). The scan will still complete and save to the database. No data is lost.
- **Health check:** `GET http://localhost:8001/health` returns `{"status": "ok"}` when service is running.

---

## 9. Windows Platform (Gunicorn Not Supported)

- **Limitation:** Gunicorn is POSIX-only and does not run on Windows.
- **Mitigation:** Use `uvicorn service:app --workers 4` for multi-process production deployment on Windows. This provides equivalent concurrency via multiple worker processes.

---

## 10. Severity Ranker v0 Uses Heuristic-Derived Labels

- **Limitation:** The severity-priority ranker (`backend/services/severity-ranker/`) v0 was trained on targets derived from the transparent formula in `severity_schema.heuristic_priority_label` (CWE base tier ± exposure/context modifiers) — **not** on analyst-labeled severity data, which does not exist yet. This is recorded as `"label_source": "heuristic_v0"` in `severity_metadata.json`.
- **Impact:** The ranker faithfully approximates the audited formula (held-out MAE 0.28, Spearman ρ 0.9976), but the formula itself bakes in judgments (e.g. unauthenticated +10, test files −15, the 0.6/0.4 severity-vs-P(REAL) blend) that real analyst labels may overturn. Priority scores are *relative triage order*, not absolute risk.
- **Mitigation:** Label a few hundred findings with analyst severity, point `train_severity.py` at the labeled CSV, and version the weights (`v1_analyst`). The 0–100 serving contract is unchanged, so no caller needs modification. See `docs/severity-ranker.md` ("Upgrade path").

---

## 11. Ranker Availability & Degraded Ordering

- **Limitation:** Ranker weights (`severity_model.joblib`) are a local build artifact and are **not** committed to the repo. Until `python train_severity.py` runs next to the service, `POST /v2/rank` answers **503** with the remediation command.
- **Impact:** With no weights, the Dashboard AI Priority toggle cannot engage and `POST /api/v2/ml/rank` returns `degraded: true` with static CWE-tier ordering (85/85/80/75/70/60). Triage still works — it just loses the exposure-context and P(REAL) blending.
- **Fallback behavior:** If the classifier service is unreachable mid-request, the Node route degrades to the same tier ordering, explicitly marked `degraded: true` — never a silent wrong order. Findings without stored `mlFeatures` are omitted from ranking and keep default order.
