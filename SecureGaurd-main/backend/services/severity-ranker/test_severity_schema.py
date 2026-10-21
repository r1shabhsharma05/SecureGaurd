"""
test_severity_schema.py — Unit tests for the severity ranker's label spec.

Stdlib-only on purpose (mirrors test_feature_schema.py): these run without
pandas/xgboost, so they stay green in CI without the heavy ML stack. They
pin the auditable contract the trained model approximates:
  - the CWE tier table covers every CWE the pipeline can emit,
  - the heuristic label formula's exposure/context modifiers,
  - band boundaries,
  - score clamping.

Run: python3 -m unittest test_severity_schema
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from severity_schema import (
    CWE_BASE_SCORE,
    DEFAULT_BASE_SCORE,
    heuristic_priority_label,
    priority_band,
)

# Every CWE the scanner + training data can emit (sample_findings.csv).
KNOWN_CWES = ["CWE-89", "CWE-918", "CWE-502", "CWE-22", "CWE-79", "CWE-798"]


def base_finding(**overrides):
    f = {
        "cwe_id": "CWE-89",
        "is_user_input_direct": 0,
        "is_authenticated_endpoint": 1,
        "is_string_concat": 0,
        "in_test_file": 0,
        "is_in_vendor_or_generated_dir": 0,
        "has_sanitizer_nearby": 0,
    }
    f.update(overrides)
    return f


class TestTierTable(unittest.TestCase):
    def test_covers_all_known_cwes(self):
        for cwe in KNOWN_CWES:
            self.assertIn(cwe, CWE_BASE_SCORE, f"tier missing for {cwe}")

    def test_tier_ordering_matches_threat_model(self):
        # Injection / network-reach classes outrank XSS; secrets rank lowest
        # among themselves (blast radius depends on unseen exposure context).
        self.assertGreaterEqual(CWE_BASE_SCORE["CWE-89"], CWE_BASE_SCORE["CWE-79"])
        self.assertGreaterEqual(CWE_BASE_SCORE["CWE-918"], CWE_BASE_SCORE["CWE-79"])
        self.assertGreaterEqual(CWE_BASE_SCORE["CWE-79"], CWE_BASE_SCORE["CWE-798"])

    def test_all_tiers_within_bounds(self):
        for cwe, score in CWE_BASE_SCORE.items():
            self.assertGreaterEqual(score, 0, cwe)
            self.assertLessEqual(score, 100, cwe)


class TestLabelFormula(unittest.TestCase):
    def test_bare_cwe_scores_its_tier(self):
        self.assertEqual(
            heuristic_priority_label(base_finding()), CWE_BASE_SCORE["CWE-89"]
        )

    def test_exposure_signals_raise_priority(self):
        # CWE-798 (base 60) leaves headroom so clamping doesn't mask the delta.
        plain = heuristic_priority_label(base_finding(cwe_id="CWE-798"))
        exposed = heuristic_priority_label(
            base_finding(cwe_id="CWE-798", is_user_input_direct=1, is_authenticated_endpoint=0)
        )
        self.assertEqual(exposed, plain + 20)

    def test_context_signals_lower_priority(self):
        plain = heuristic_priority_label(base_finding())
        mitigated = heuristic_priority_label(
            base_finding(in_test_file=1, has_sanitizer_nearby=1)
        )
        self.assertEqual(mitigated, plain - 23)

    def test_worst_case_clamps_at_100(self):
        f = base_finding(
            is_user_input_direct=1,
            is_authenticated_endpoint=0,
            is_string_concat=1,
        )
        self.assertEqual(heuristic_priority_label(f), 100.0)

    def test_floor_never_negative(self):
        f = base_finding(
            cwe_id="CWE-798",
            in_test_file=1,
            is_in_vendor_or_generated_dir=1,
            has_sanitizer_nearby=1,
            is_authenticated_endpoint=1,
        )
        score = heuristic_priority_label(f)
        self.assertGreaterEqual(score, 0)
        self.assertEqual(score, 60 - 15 - 10 - 8)

    def test_unknown_cwe_degrades_to_default_never_silent_zero(self):
        score = heuristic_priority_label(base_finding(cwe_id="CWE-9999"))
        self.assertEqual(score, DEFAULT_BASE_SCORE)
        self.assertGreater(score, 0)

    def test_missing_keys_do_not_crash(self):
        # Partial dicts (e.g. new extractor fields not yet added) degrade
        # gracefully instead of raising KeyError.
        self.assertEqual(heuristic_priority_label({"cwe_id": "CWE-89"}), 85)


class TestBands(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(priority_band(100), "critical")
        self.assertEqual(priority_band(80), "critical")
        self.assertEqual(priority_band(79.9), "high")
        self.assertEqual(priority_band(60), "high")
        self.assertEqual(priority_band(59.9), "medium")
        self.assertEqual(priority_band(40), "medium")
        self.assertEqual(priority_band(39.9), "low")
        self.assertEqual(priority_band(0), "low")

    def test_bare_tiers_land_in_intuitive_bands(self):
        self.assertEqual(priority_band(CWE_BASE_SCORE["CWE-89"]), "critical")
        self.assertEqual(priority_band(CWE_BASE_SCORE["CWE-79"]), "high")
        self.assertEqual(priority_band(CWE_BASE_SCORE["CWE-798"]), "high")


if __name__ == "__main__":
    unittest.main()
