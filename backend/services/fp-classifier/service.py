"""
service.py — Production-grade FastAPI microservice for FP Classifier
Features:
  - API Key authentication
  - Batch + single classify endpoints
  - Prediction logging
  - /metrics endpoint (usage stats)
  - /model-info endpoint (version, training date, metrics)
  - CORS enabled
  - Startup health check
"""

import os
import sys
import json
import datetime
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator
from predict import predict_finding


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
METADATA_JSON = os.path.join(BASE_DIR, "model_metadata.json")

# ─── Severity ranker (sibling package) ────────────────────────────────────────
# Scores "which finding to fix first" (0-100 priority). Same FastAPI process
# under a versioned /v2 path — one deploy, one auth model. Weights load lazily
# inside SeverityRanker, so this service boots even before the first training
# run; /v2/rank then answers 503 with the exact remediation command.
SEVERITY_RANKER_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "severity-ranker"))
SEVERITY_METADATA_JSON = os.path.join(SEVERITY_RANKER_DIR, "severity_metadata.json")
if SEVERITY_RANKER_DIR not in sys.path:
    sys.path.insert(0, SEVERITY_RANKER_DIR)
try:
    from ranker import SeverityRanker, RankerNotTrained
    from severity_schema import heuristic_priority_label, priority_band
    _severity_ranker = SeverityRanker()
    _RANKER_IMPORT_OK = True
except Exception as e:
    _severity_ranker = None
    _RANKER_IMPORT_OK = False
    print(f"[service] severity-ranker unavailable (service still boots): {e}")
LOG_PATH = os.path.join(BASE_DIR, "predictions.log")

# ─── Version ─────────────────────────────────────────────────────────────────
# Bump on service behavior/contract changes. The *model* version (which
# training run produced the weights) is separate and comes from
# model_metadata.json written by retrain.py.
SERVICE_VERSION = "2.2.1"

def get_model_version() -> str:
    """Active model version from training metadata; 'v1_synthetic' before the first retrain."""
    try:
        with open(METADATA_JSON, "r", encoding="utf-8") as f:
            return json.load(f).get("version", "v1_synthetic")
    except (OSError, ValueError):
        return "v1_synthetic"


def get_ranker_version() -> str:
    """Severity-ranker weights version; 'not_trained' until train_severity.py runs."""
    try:
        with open(SEVERITY_METADATA_JSON, "r", encoding="utf-8") as f:
            return json.load(f).get("version", "v0_heuristic")
    except (OSError, ValueError):
        if _severity_ranker is not None and _severity_ranker.is_ready:
            return "v0_heuristic"
        return "not_trained"

# ─── Load API Key from env or .env file ───────────────────────────────────────
CLASSIFIER_API_KEY = os.environ.get("CLASSIFIER_API_KEY")
if not CLASSIFIER_API_KEY:
    env_path = os.path.abspath(os.path.join(BASE_DIR, "..", "..", ".env"))
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    parts = line.split("=", 1)
                    if parts[0].strip() == "CLASSIFIER_API_KEY":
                        CLASSIFIER_API_KEY = parts[1].strip().strip("'").strip('"')
                        break

# ─── Lifespan (startup/shutdown events) ───────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("[SECUREGUARD] FP Classifier Service -- STARTING UP")
    print(f"   Model path : {os.path.join(BASE_DIR, 'model.joblib')}")
    print(f"   API Key    : {'SET (OK)' if CLASSIFIER_API_KEY else 'NOT SET - open access'}")
    # Check model metadata
    if os.path.exists(METADATA_JSON):
        with open(METADATA_JSON, "r", encoding="utf-8") as f:
            meta = json.load(f)
        print(f"   Model Ver  : {meta.get('version', 'unknown')}")
        print(f"   Trained on : {meta.get('dataset_size', '?')} samples")
        metrics = meta.get("metrics", {})
        print(f"   Accuracy   : {metrics.get('accuracy', '?')}")
        print(f"   Recall     : {metrics.get('recall', '?')}")
    else:
        print("   Model Info : No metadata.json found (first run?)")
    print("=" * 60)
    yield
    print("[SECUREGUARD] FP Classifier Service -- SHUTTING DOWN")

# ─── App Setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecureGuard FP Suppression Classifier",
    version=SERVICE_VERSION,
    description="ML-powered False Positive suppression for SAST findings",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Auth Helper ───────────────────────────────────────────────────────────────
def check_auth(request: Request):
    if CLASSIFIER_API_KEY:
        key = request.headers.get("x-secureguard-key")
        if not key or key != CLASSIFIER_API_KEY:
            raise HTTPException(status_code=401, detail="Unauthorized — missing or invalid X-SecureGuard-Key header")

# ─── Logging Helper ────────────────────────────────────────────────────────────
def log_prediction(finding_dict: dict, result_dict: dict):
    try:
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "rule_id": finding_dict.get("rule_id"),
            "cwe_id": finding_dict.get("cwe_id"),
            "prediction": result_dict.get("prediction"),
            "confidence": result_dict.get("confidence"),
            "is_string_concat": finding_dict.get("is_string_concat"),
            "is_parameterized_query": finding_dict.get("is_parameterized_query"),
            "has_sanitizer_nearby": finding_dict.get("has_sanitizer_nearby"),
            "in_test_file": finding_dict.get("in_test_file"),
            "is_user_input_direct": finding_dict.get("is_user_input_direct"),
        }
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[Log Error] {e}")

# ─── Pydantic Models ───────────────────────────────────────────────────────────
# Range validation keeps out-of-distribution / malformed inputs from reaching
# the model (e.g. a negative taint distance or a 2 in a 0/1 flag would
# silently skew the prediction). On the single-finding endpoints a violation
# returns 422 before predict_finding runs; the Node.js caller treats non-2xx
# as fail-safe REAL. Batch endpoints validate per finding instead (see
# BatchRequest), so one bad finding can never fail the whole batch.
#
# Missing numeric features default to the same baselines astExtractor.js
# uses for code it cannot analyze (all flags 0, taint distance 5, complexity
# 1). That is what lets non-SAST findings through: IaC/API scanners
# (iacDockerScanner.js, iacK8sScanner.js, iacTerraformScanner.js,
# apiSpecScanner.js) emit mlFeatures shaped
# {framework, category, resourceType, resourceName, ruleId, cweId, isIaC}
# with none of the 16 SAST signals — they map ruleId/cweId onto the schema
# and take the defaults for the rest, then classify like any other finding.
class Finding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(validation_alias=AliasChoices("rule_id", "ruleId"), min_length=1, max_length=128)
    cwe_id: str = Field(validation_alias=AliasChoices("cwe_id", "cweId"), min_length=1, max_length=64)
    is_string_concat: int = Field(default=0, ge=0, le=1)
    is_parameterized_query: int = Field(default=0, ge=0, le=1)
    has_sanitizer_nearby: int = Field(default=0, ge=0, le=1)
    in_test_file: int = Field(default=0, ge=0, le=1)
    is_in_vendor_or_generated_dir: int = Field(default=0, ge=0, le=1)
    taint_source_distance: int = Field(default=5, ge=0, le=10000)
    function_complexity: int = Field(default=1, ge=0, le=100000)
    code_snippet_length: int = Field(default=0, ge=0, le=1000000)
    variable_name_entropy: float = Field(default=0.0, ge=0.0, le=20.0)
    is_user_input_direct: int = Field(default=0, ge=0, le=1)
    has_type_validation: int = Field(default=0, ge=0, le=1)
    is_third_party_lib_call: int = Field(default=0, ge=0, le=1)
    same_finding_seen_before_count: int = Field(default=0, ge=0, le=1000000)
    # Callers send an unbounded COUNT of past dismissals (a prisma count in
    # scans.js / integration.js), but the model was trained on a 0/1 flag —
    # accept any non-negative count and coerce to the flag.
    developer_dismissed_similar_before: int = Field(default=0, ge=0)
    file_change_frequency: int = Field(default=0, ge=0, le=1000000)
    is_authenticated_endpoint: int = Field(default=0, ge=0, le=1)

    @field_validator("developer_dismissed_similar_before", mode="after")
    @classmethod
    def _dismissed_count_to_flag(cls, v: int) -> int:
        return 1 if v > 0 else 0

class BatchRequest(BaseModel):
    # Node.js sends chunks of 50; cap at 200 to bound CPU/memory per request
    # while leaving headroom for larger legitimate batches.
    # Raw dicts, NOT list[Finding]: FastAPI validates the whole list before
    # the handler runs, so a single unusual finding (e.g. an IaC shape, or a
    # finding with no rule id at all) would 422 the entire batch and the
    # classifier would silently no-op for that scan. Handlers validate each
    # item with _validate_finding and give failures their own fallback entry.
    # (list[Any], not list[dict]: even a non-object item must reach the
    # handler so it can be isolated instead of failing the whole list.)
    findings: list[Any] = Field(min_length=1, max_length=200)


def _validate_finding(raw: Any) -> Finding:
    """Validate one raw batch item; raises on anything unusable so the
    caller can isolate the failure to that single finding."""
    if not isinstance(raw, dict):
        raise ValueError(f"finding must be a JSON object, got {type(raw).__name__}")
    return Finding.model_validate(raw)

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Health check — no auth required. Reports service + model versions."""
    return {
        "status": "ok",
        "service": "SecureGuard FP Classifier",
        "version": SERVICE_VERSION,
        "model_version": get_model_version(),
        "model_loaded": os.path.exists(os.path.join(BASE_DIR, "model.joblib")),
        "severity_ranker_ready": bool(_severity_ranker is not None and _severity_ranker.is_ready),
        "severity_ranker_version": get_ranker_version(),
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.get("/model-info")
def model_info(request: Request):
    """Return current model metadata — version, training date, dataset size, metrics"""
    check_auth(request)
    if not os.path.exists(METADATA_JSON):
        return {
            "version": "v1_synthetic",
            "training_date": "unknown",
            "dataset_size": 8000,
            "new_feedback_size": 0,
            "metrics": {"accuracy": 0.905, "recall": 0.836, "precision": 0.863, "f1_score": 0.849},
            "status": "active",
            "note": "Running on initial synthetic model — no metadata.json found"
        }
    with open(METADATA_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

@app.post("/classify")
def classify(finding: Finding, request: Request, include_explanation: bool = False):
    """Classify a single SAST finding"""
    check_auth(request)
    try:
        result = predict_finding(finding.model_dump(), include_explanation=include_explanation)
        log_prediction(finding.model_dump(), result)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/classify/batch")
def classify_batch(batch_req: BatchRequest, request: Request, include_explanation: bool = False):
    """Classify a batch of findings — recommended for bulk scans.
    Per-finding isolation: an item that fails validation or prediction gets
    the fail-open REAL fallback entry; the rest of the batch still classifies."""
    check_auth(request)
    results = []
    for raw in batch_req.findings:
        try:
            finding_dict = _validate_finding(raw).model_dump()
            result = predict_finding(finding_dict, include_explanation=include_explanation)
            log_prediction(finding_dict, result)
            results.append(result)
        except Exception as e:
            # Fail-open: on error assume REAL so we never miss a real vuln
            results.append({
                "prediction": "REAL",
                "confidence": 1.0,
                "threshold_used": 0.4,
                "error": str(e)
            })
    return {"results": results, "total": len(results)}

# ─── v2: severity-priority ranking ────────────────────────────────────────────
# Blends the FP classifier's P(REAL) with the severity model's 0-100 score.
# scans.js already auto-ignores likely-FPs, so what reaches here skews REAL —
# severity therefore dominates the blend (0.6 / 0.4). Rationale and the
# heuristic-label caveat are documented in docs/severity-ranker.md.
_RANK_SEVERITY_W = 0.6
_RANK_REALPROB_W = 0.4


def _real_probability(fp_result: dict) -> float:
    # predict_finding's "confidence" is P(REAL); unfold it when labeled FP.
    conf = float(fp_result.get("confidence", 1.0))
    return conf if fp_result.get("prediction") == "REAL" else 1.0 - conf


def _rank_one(finding_dict: dict) -> dict:
    fp = predict_finding(finding_dict)
    sev = _severity_ranker.predict_priority(finding_dict)
    p_real = _real_probability(fp)
    priority = round(_RANK_SEVERITY_W * sev["priority_score"] + _RANK_REALPROB_W * p_real * 100, 1)
    return {
        "priority_score": priority,
        "band": priority_band(priority),
        "severity_score": sev["priority_score"],
        "severity_band": sev["band"],
        "p_real": round(p_real, 3),
        "fp_prediction": fp["prediction"],
        "fallback": False,
    }


def _ranker_ready_or_503():
    if not _RANKER_IMPORT_OK or _severity_ranker is None or not _severity_ranker.is_ready:
        raise HTTPException(
            status_code=503,
            detail="Severity ranker not trained — run: python train_severity.py in backend/services/severity-ranker/",
        )


@app.post("/v2/rank")
def rank_single(finding: Finding, request: Request):
    """Priority score (0-100 + band) for one finding. Auth required."""
    check_auth(request)
    _ranker_ready_or_503()
    try:
        return _rank_one(finding.model_dump())
    except RankerNotTrained as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _rank_fallback(raw: dict) -> dict:
    """Heuristic fallback entry for one rank item that could not be scored."""
    score = heuristic_priority_label(raw)
    return {
        "priority_score": round(score, 1),
        "band": priority_band(score),
        "severity_score": round(score, 1),
        "severity_band": priority_band(score),
        "p_real": None,
        "fp_prediction": None,
        "fallback": True,
    }


@app.post("/v2/rank/batch")
def rank_batch(batch_req: BatchRequest, request: Request):
    """Priority scores for a batch. Per-item fail-safe: an item that fails
    validation or scoring falls back to the transparent heuristic formula
    (marked fallback:true) instead of failing the whole batch."""
    check_auth(request)
    _ranker_ready_or_503()
    results = []
    for raw in batch_req.findings:
        try:
            finding_dict = _validate_finding(raw).model_dump()
        except Exception:
            # Unidentifiable item (no rule/CWE id, not an object, …): still
            # gets its own fallback entry, scored from whatever arrived.
            results.append(_rank_fallback(raw if isinstance(raw, dict) else {}))
            continue
        try:
            results.append(_rank_one(finding_dict))
        except RankerNotTrained as e:
            raise HTTPException(status_code=503, detail=str(e))
        except Exception:
            results.append(_rank_fallback(finding_dict))
    return {"results": results, "total": len(results)}

@app.get("/metrics")
def get_metrics(request: Request):
    """Usage stats from prediction log"""
    check_auth(request)
    total = 0
    real_count = 0
    fp_count = 0
    total_conf = 0.0
    rule_breakdown = {}

    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        total += 1
                        pred = entry.get("prediction")
                        conf = float(entry.get("confidence", 0.0))
                        rule = entry.get("rule_id", "unknown")

                        if pred == "REAL":
                            real_count += 1
                        elif pred == "FALSE_POSITIVE":
                            fp_count += 1

                        total_conf += conf

                        # Rule breakdown
                        if rule not in rule_breakdown:
                            rule_breakdown[rule] = {"real": 0, "fp": 0}
                        if pred == "REAL":
                            rule_breakdown[rule]["real"] += 1
                        elif pred == "FALSE_POSITIVE":
                            rule_breakdown[rule]["fp"] += 1
                    except Exception:
                        pass

    return {
        "total_predictions": total,
        "real_count": real_count,
        "false_positive_count": fp_count,
        "real_percentage": round((real_count / total * 100) if total > 0 else 0.0, 2),
        "false_positive_percentage": round((fp_count / total * 100) if total > 0 else 0.0, 2),
        "average_confidence": round((total_conf / total) if total > 0 else 0.0, 4),
        "rule_breakdown": rule_breakdown,
        "log_entries_total": total,
    }
