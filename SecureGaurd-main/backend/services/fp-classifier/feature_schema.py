"""
feature_schema.py — Single source of truth for the FP classifier's feature schema.

The 18-column model feature list used to exist as three hand-synced copies
(train.py, retrain.py, predict.py) held together by a "must match exactly"
comment. Any drift between them silently corrupts training vs. serving
(wrong column order = wrong predictions, no error raised). Import from here.

Stdlib-only on purpose: unit tests can import this without pandas/xgboost.
"""

# Model input columns, in the exact order the XGBoost model was trained on.
# rule_id / cwe_id are label-encoded to rule_id_enc / cwe_id_enc before scoring.
FEATURE_COLS = [
    "rule_id_enc", "cwe_id_enc", "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "taint_source_distance", "function_complexity", "code_snippet_length",
    "variable_name_entropy", "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "same_finding_seen_before_count",
    "developer_dismissed_similar_before", "file_change_frequency",
    "is_authenticated_endpoint",
]

# Raw feature names as produced by the Node.js backend (astExtractor.js plus
# the scans.js enrichment step) and accepted by POST /classify. Must stay in
# sync with the `Finding` pydantic model in service.py.
RAW_FEATURES = [
    "rule_id", "cwe_id",
    "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "taint_source_distance", "function_complexity", "code_snippet_length",
    "variable_name_entropy", "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "same_finding_seen_before_count",
    "developer_dismissed_similar_before", "file_change_frequency",
    "is_authenticated_endpoint",
]

# Features that are strict 0/1 flags (validated as such by the service).
BINARY_FEATURES = frozenset([
    "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "developer_dismissed_similar_before",
    "is_authenticated_endpoint",
])


def safe_encode(encoder, value):
    """
    Encode a single categorical value with a fitted sklearn LabelEncoder.
    Returns -1 for unseen categories instead of raising, so new rule/CWE ids
    degrade to the fail-safe path instead of crashing prediction.
    """
    try:
        return encoder.transform([value])[0]
    except ValueError:
        return -1


def safe_encode_series(encoder, values):
    """Vector version of safe_encode for pandas Series / lists."""
    return [safe_encode(encoder, v) for v in values]
