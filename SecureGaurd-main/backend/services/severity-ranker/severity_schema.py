"""
severity_schema.py — Label spec + serving contract for the severity-priority ranker.

The ranker answers "which open finding do I fix first?" — a different question
from the FP classifier's "is this finding real?". Every finding scores 0-100;
higher means fix sooner.

v0 LABELS ARE HEURISTIC-DERIVED. No analyst-labeled severity data exists yet,
so train_severity.py derives each row's target from the transparent formula
below (CWE base tier + exposure/context modifiers). The trained XGBRegressor
learns a smooth approximation of that formula: scoring becomes one model call
with learned feature interactions (e.g. user_input_direct x unsanitized x
short taint distance), and — most importantly — the serving contract (input
schema, /v2/rank endpoint, metadata format) is fixed now, so when
analyst-labeled data arrives only the weights change.

Why a trained model instead of the raw formula? The formula on 18 features
with interactions is exactly what a shallow tree ensemble expresses well;
the model gives calibrated 0-100 scores, feature importances for review,
and a versioned artifact (severity_metadata.json) that the retrain loop
can gate on. The formula itself stays in this file, unit-tested, as the
auditable source of truth the model approximates.

Stdlib-only on purpose: unit tests import this without pandas/xgboost.
"""

# Base priority per CWE, grounded in standard severity guidance for these
# vulnerability classes. Injection / network-reach classes outrank XSS
# (which needs user interaction); hardcoded secrets are always kept REAL by
# the scan pipeline but rank lower among themselves because blast radius
# depends on exposure context the scanner cannot see.
CWE_BASE_SCORE = {
    "CWE-89": 85,    # SQL injection — direct data-layer compromise
    "CWE-918": 85,   # SSRF — internal network reach from the app server
    "CWE-502": 80,   # Insecure deserialization — historically RCE-prone
    "CWE-22": 75,    # Path traversal — arbitrary file read/write
    "CWE-79": 70,    # Reflected/stored XSS — session theft, needs interaction
    "CWE-798": 60,   # Hardcoded credentials — real, but impact varies by exposure
}

# Unseen CWE ids: middle of the road, never a silent 0.
DEFAULT_BASE_SCORE = 65

# Bands shown in the Dashboard toggle. Thresholds mirror the base tiers so a
# bare CWE score lands in its intuitive band before modifiers apply.
CRITICAL_MIN = 80
HIGH_MIN = 60
MEDIUM_MIN = 40


def heuristic_priority_label(finding: dict) -> float:
    """
    Transparent v0 label formula. `finding` holds the same 18 raw features
    the FP classifier consumes (rule_id, cwe_id + 16 signals).

    Exposure raises priority: direct user input reaching the sink and
    unauthenticated endpoints are the two strongest "exploitable now"
    signals. Context lowers it: test/vendor code is not production attack
    surface, and a nearby sanitizer meaningfully reduces exploitability.
    Result is clamped to [0, 100].
    """
    score = CWE_BASE_SCORE.get(finding.get("cwe_id"), DEFAULT_BASE_SCORE)

    if finding.get("is_user_input_direct") == 1:
        score += 10  # untrusted input reaches the sink directly
    if finding.get("is_authenticated_endpoint") == 0:
        score += 10  # unauthenticated exposure: worst case for the same bug
    if finding.get("is_string_concat") == 1:
        score += 5   # direct string building on a sensitive sink

    if finding.get("in_test_file") == 1:
        score -= 15  # not production attack surface
    if finding.get("is_in_vendor_or_generated_dir") == 1:
        score -= 10  # third-party / generated code: patch upstream, not here
    if finding.get("has_sanitizer_nearby") == 1:
        score -= 8   # sanitizer present: exploitability reduced, not eliminated

    return float(max(0, min(100, score)))


def priority_band(score: float) -> str:
    """Map a 0-100 priority score to a display band."""
    if score >= CRITICAL_MIN:
        return "critical"
    if score >= HIGH_MIN:
        return "high"
    if score >= MEDIUM_MIN:
        return "medium"
    return "low"
