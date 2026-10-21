"""
ranker.py — Serve-time severity-priority scoring.

SeverityRanker loads severity_model.joblib (trained by train_severity.py)
and scores one finding dict (the 18 raw features) to a 0-100 priority plus
a display band. It reuses the FP classifier's shared feature pipeline —
FEATURE_COLS, safe_encode, and the FITTED label encoders — so training and
serving can never disagree on column order or category mapping. The encoders
are reused, not refit: refitting on a subset of data would silently remap
rule/CWE ids and corrupt every score.

Lazy weight loading: importing this module never touches disk, so the
FastAPI service boots even before the first training run. predict_priority
raises RankerNotTrained (with the exact remediation command) when weights
are absent; the /v2/rank endpoint converts that to HTTP 503.
"""

import os
import sys

import joblib
import pandas as pd

# Sibling import: the fp-classifier service dir holds the shared feature
# pipeline (feature_schema.py) and the fitted encoders. Script-style
# sys.path insertion matches how service.py already imports predict.py.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FP_CLASSIFIER_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "fp-classifier"))
if FP_CLASSIFIER_DIR not in sys.path:
    sys.path.insert(0, FP_CLASSIFIER_DIR)

from feature_schema import FEATURE_COLS, safe_encode  # noqa: E402
from severity_schema import priority_band  # noqa: E402

DEFAULT_WEIGHTS_PATH = os.path.join(BASE_DIR, "severity_model.joblib")
RULE_ENCODER_PATH = os.path.join(FP_CLASSIFIER_DIR, "rule_encoder.joblib")
CWE_ENCODER_PATH = os.path.join(FP_CLASSIFIER_DIR, "cwe_encoder.joblib")


class RankerNotTrained(RuntimeError):
    """Raised when severity weights are absent. Not a bug — run the trainer."""


class SeverityRanker:
    def __init__(self, weights_path: str = DEFAULT_WEIGHTS_PATH):
        self.weights_path = weights_path
        self._model = None
        self._rule_encoder = None
        self._cwe_encoder = None

    def _ensure_loaded(self):
        if self._model is not None:
            return
        if not os.path.exists(self.weights_path):
            raise RankerNotTrained(
                f"Severity weights not found at {self.weights_path}. "
                "Train them with: python train_severity.py "
                "(runs in backend/services/severity-ranker/)"
            )
        self._model = joblib.load(self.weights_path)
        # Reuse the FP classifier's fitted encoders — never refit here.
        self._rule_encoder = joblib.load(RULE_ENCODER_PATH)
        self._cwe_encoder = joblib.load(CWE_ENCODER_PATH)

    @property
    def is_ready(self) -> bool:
        """True when weights exist on disk (cheap check, no model load)."""
        return os.path.exists(self.weights_path)

    def predict_priority(self, finding: dict) -> dict:
        """
        Score one finding. `finding` holds the 18 raw features
        (rule_id, cwe_id + 16 signals), same shape as POST /classify.
        Returns {"priority_score": 0-100 float, "band": critical|high|medium|low}.
        """
        self._ensure_loaded()

        row = finding.copy()
        row["rule_id_enc"] = safe_encode(self._rule_encoder, row["rule_id"])
        row["cwe_id_enc"] = safe_encode(self._cwe_encoder, row["cwe_id"])

        X = pd.DataFrame([row])[FEATURE_COLS]
        raw = float(self._model.predict(X)[0])
        score = round(max(0.0, min(100.0, raw)), 1)

        return {"priority_score": score, "band": priority_band(score)}
