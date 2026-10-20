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
import json
import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from predict import predict_finding

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
METADATA_JSON = os.path.join(BASE_DIR, "model_metadata.json")
LOG_PATH = os.path.join(BASE_DIR, "predictions.log")

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
    version="2.0.0",
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
# silently skew the prediction). Violations return 422 before predict_finding
# runs; the Node.js caller treats non-2xx as fail-safe REAL.
class Finding(BaseModel):
    rule_id: str = Field(min_length=1, max_length=128)
    cwe_id: str = Field(min_length=1, max_length=64)
    is_string_concat: int = Field(ge=0, le=1)
    is_parameterized_query: int = Field(ge=0, le=1)
    has_sanitizer_nearby: int = Field(ge=0, le=1)
    in_test_file: int = Field(ge=0, le=1)
    is_in_vendor_or_generated_dir: int = Field(ge=0, le=1)
    taint_source_distance: int = Field(ge=0, le=10000)
    function_complexity: int = Field(ge=0, le=100000)
    code_snippet_length: int = Field(ge=0, le=1000000)
    variable_name_entropy: float = Field(ge=0.0, le=20.0)
    is_user_input_direct: int = Field(ge=0, le=1)
    has_type_validation: int = Field(ge=0, le=1)
    is_third_party_lib_call: int = Field(ge=0, le=1)
    same_finding_seen_before_count: int = Field(ge=0, le=1000000)
    developer_dismissed_similar_before: int = Field(ge=0, le=1)
    file_change_frequency: int = Field(ge=0, le=1000000)
    is_authenticated_endpoint: int = Field(ge=0, le=1)

class BatchRequest(BaseModel):
    # Node.js sends chunks of 50; cap at 200 to bound CPU/memory per request
    # while leaving headroom for larger legitimate batches.
    findings: list[Finding] = Field(min_length=1, max_length=200)

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Basic health check — no auth required"""
    return {
        "status": "ok",
        "service": "SecureGuard FP Classifier",
        "version": "2.0.0",
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
    """Classify a batch of SAST findings — recommended for bulk scans"""
    check_auth(request)
    results = []
    for finding in batch_req.findings:
        try:
            result = predict_finding(finding.model_dump(), include_explanation=include_explanation)
            log_prediction(finding.model_dump(), result)
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
