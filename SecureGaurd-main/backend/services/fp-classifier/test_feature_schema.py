"""
test_feature_schema.py — Unit tests for the FP classifier's shared feature schema.

Stdlib-only on purpose: run with `python3 -m unittest test_feature_schema`
(or `python3 test_feature_schema.py`) without installing pandas/xgboost.

These tests pin the training/serving contract:
- FEATURE_COLS order must never change silently (the model is positional).
- RAW_FEATURES must stay in sync with the `Finding` schema in service.py.
- safe_encode must degrade to -1 on unseen categories, never raise.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feature_schema import (
    FEATURE_COLS,
    RAW_FEATURES,
    BINARY_FEATURES,
    safe_encode,
    safe_encode_series,
)

# The 18 raw inputs the classifier service accepts (mirrors the `Finding`
# pydantic model in service.py). If service.py gains/loses a field, update
# both files together — this test fails otherwise, which is the point.
EXPECTED_RAW_FEATURES = [
    "rule_id", "cwe_id",
    "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "taint_source_distance", "function_complexity", "code_snippet_length",
    "variable_name_entropy", "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "same_finding_seen_before_count",
    "developer_dismissed_similar_before", "file_change_frequency",
    "is_authenticated_endpoint",
]


class FakeEncoder:
    """Minimal LabelEncoder stand-in: only .transform() is used by safe_encode."""

    def __init__(self, classes):
        self._map = {c: i for i, c in enumerate(classes)}

    def transform(self, values):
        out = []
        for v in values:
            if v not in self._map:
                raise ValueError(f"unseen label: {v}")
            out.append(self._map[v])
        return out


class TestFeatureCols(unittest.TestCase):
    def test_column_count_and_uniqueness(self):
        self.assertEqual(len(FEATURE_COLS), 18)
        self.assertEqual(len(set(FEATURE_COLS)), 18, "duplicate model columns")

    def test_encoded_ids_come_first(self):
        # The model was trained with encoded ids in positions 0-1; reordering
        # would silently feed the wrong feature into the wrong split.
        self.assertEqual(FEATURE_COLS[0], "rule_id_enc")
        self.assertEqual(FEATURE_COLS[1], "cwe_id_enc")

    def test_every_raw_feature_has_a_model_column(self):
        mapping = {"rule_id": "rule_id_enc", "cwe_id": "cwe_id_enc"}
        for raw in RAW_FEATURES:
            self.assertIn(mapping.get(raw, raw), FEATURE_COLS, raw)

    def test_binary_features_are_subset_of_raw(self):
        self.assertTrue(BINARY_FEATURES <= set(RAW_FEATURES))
        self.assertEqual(len(BINARY_FEATURES), 10)


class TestRawFeaturesContract(unittest.TestCase):
    def test_matches_finding_schema(self):
        # If this fails, service.py's Finding model and feature_schema.py
        # disagree — fix them together, never just the test.
        self.assertEqual(RAW_FEATURES, EXPECTED_RAW_FEATURES)


class TestSafeEncode(unittest.TestCase):
    def setUp(self):
        self.enc = FakeEncoder(["sqli-concat", "xss-unescaped"])

    def test_known_value(self):
        self.assertEqual(safe_encode(self.enc, "sqli-concat"), 0)
        self.assertEqual(safe_encode(self.enc, "xss-unescaped"), 1)

    def test_unknown_value_falls_back_to_minus_one(self):
        self.assertEqual(safe_encode(self.enc, "brand-new-rule"), -1)

    def test_series_version(self):
        self.assertEqual(
            safe_encode_series(self.enc, ["sqli-concat", "nope", "xss-unescaped"]),
            [0, -1, 1],
        )

    def test_empty_series(self):
        self.assertEqual(safe_encode_series(self.enc, []), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
