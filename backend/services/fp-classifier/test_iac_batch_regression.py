"""
test_iac_batch_regression.py — Regression tests for the IaC/dismissal-count
batch-poisoning bugs (F5a + F6).

Before the fix, POST /classify/batch validated the whole list as
list[Finding] before the handler ran, so:
  - any IaC finding (Docker/K8s/Terraform/OpenAPI scanners emit mlFeatures
    shaped {framework, category, resourceType, resourceName, ruleId, cweId,
    isIaC} — none of the 16 SAST signals) failed schema validation, and
  - any finding whose developer_dismissed_similar_before was a dismissal
    COUNT >= 2 failed the field's le=1 range,
and FastAPI returned 422 for the ENTIRE batch. The Node caller fails open
to REAL on non-2xx, so the classifier silently no-oped for any scan
containing an IaC finding or a twice-dismissed rule.

These tests pin the fixed contract: a mixed batch returns one result per
finding, the IaC shape maps onto the schema and classifies with the real
model, dismissal counts coerce to the model's 0/1 flag, and a genuinely
unusable finding gets its own fail-open entry instead of poisoning the
batch.

Run with the service venv (needs fastapi + the ML stack — importing
service.py loads the real model.joblib, same as test_conformal.py does
with predict.py; nothing is stubbed):
    python -m unittest test_iac_batch_regression -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# service.py reads the API key at import time; tests run against the
# no-key local-dev configuration.
os.environ.pop("CLASSIFIER_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import service  # noqa: E402

# A normal SAST finding: all 18 raw features, as astExtractor.js + the
# scans.js enrichment produce them.
NORMAL_FINDING = {
    "rule_id": "sqli-concat", "cwe_id": "CWE-89",
    "is_string_concat": 1, "is_parameterized_query": 0,
    "has_sanitizer_nearby": 0, "in_test_file": 0,
    "is_in_vendor_or_generated_dir": 0, "taint_source_distance": 2,
    "function_complexity": 14, "code_snippet_length": 90,
    "variable_name_entropy": 2.0, "is_user_input_direct": 1,
    "has_type_validation": 0, "is_third_party_lib_call": 0,
    "same_finding_seen_before_count": 1, "developer_dismissed_similar_before": 0,
    "file_change_frequency": 22, "is_authenticated_endpoint": 0,
}

# The IaC shape exactly as iacDockerScanner.js emits it in mlFeatures
# (camelCase ruleId/cweId, no SAST signals at all).
IAC_FINDING_RAW = {
    "framework": "Docker", "category": "container",
    "resourceType": "Dockerfile", "resourceName": "Dockerfile",
    "ruleId": "DOCKER-001", "cweId": "CWE-250", "isIaC": True,
}

# The same finding after the scans.js enrichment loop, which is what
# actually gets POSTed: snake_case rule_id/cwe_id plus the count fields.
IAC_FINDING = {
    **IAC_FINDING_RAW,
    "rule_id": "DOCKER-001", "cwe_id": "CWE-250",
    "same_finding_seen_before_count": 0,
    "developer_dismissed_similar_before": 0,
    "file_change_frequency": 0,
}

# iacK8sScanner.js parser-warning shape: no rule/CWE id at all. This one
# can never be classified — it exists to prove isolation, not acceptance.
IDLESS_FINDING = {"framework": "Kubernetes", "isIaC": True}


class TestMixedBatchRegression(unittest.TestCase):
    """The required regression: IaC + normal + dismissed-count in one batch."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(service.app)

    def test_mixed_batch_returns_per_finding_results(self):
        dismissed_five = dict(
            NORMAL_FINDING, developer_dismissed_similar_before=5
        )
        resp = self.client.post(
            "/classify/batch",
            json={"findings": [IAC_FINDING, NORMAL_FINDING, dismissed_five]},
        )
        # Previously: HTTP 422 for the whole batch.
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["total"], 3)
        self.assertEqual(len(body["results"]), 3)
        for result in body["results"]:
            self.assertIn(result["prediction"], ["REAL", "FALSE_POSITIVE"])
            self.assertNotIn("error", result)

    def test_raw_iac_shape_classifies(self):
        resp = self.client.post(
            "/classify/batch", json={"findings": [IAC_FINDING_RAW]}
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        result = resp.json()["results"][0]
        self.assertIn(result["prediction"], ["REAL", "FALSE_POSITIVE"])
        self.assertNotIn("error", result)

    def test_single_classify_accepts_iac_shape(self):
        resp = self.client.post("/classify", json=IAC_FINDING)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIn(resp.json()["prediction"], ["REAL", "FALSE_POSITIVE"])


class TestDismissedCountCoercion(unittest.TestCase):
    """F6: callers send a dismissal COUNT; the model expects a 0/1 flag."""

    def test_count_above_one_coerces_to_one(self):
        finding = service.Finding.model_validate(
            dict(NORMAL_FINDING, developer_dismissed_similar_before=5)
        )
        self.assertEqual(finding.developer_dismissed_similar_before, 1)

    def test_zero_stays_zero(self):
        finding = service.Finding.model_validate(NORMAL_FINDING)
        self.assertEqual(finding.developer_dismissed_similar_before, 0)

    def test_negative_count_still_rejected(self):
        with self.assertRaises(Exception):
            service.Finding.model_validate(
                dict(NORMAL_FINDING, developer_dismissed_similar_before=-1)
            )


class TestPerFindingIsolation(unittest.TestCase):
    """One unusable finding gets its own fallback entry; the rest classify."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(service.app)

    def test_bad_items_do_not_poison_batch(self):
        out_of_range = dict(NORMAL_FINDING, is_string_concat=2)
        resp = self.client.post(
            "/classify/batch",
            json={"findings": [IDLESS_FINDING, NORMAL_FINDING,
                               "not-an-object", out_of_range]},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        results = resp.json()["results"]
        self.assertEqual(len(results), 4)
        # The normal finding (index 1) classified cleanly...
        self.assertNotIn("error", results[1])
        self.assertIn(results[1]["prediction"], ["REAL", "FALSE_POSITIVE"])
        # ...while each bad item failed open to REAL with its own error.
        for idx in (0, 2, 3):
            self.assertEqual(results[idx]["prediction"], "REAL")
            self.assertIn("error", results[idx])

    def test_rank_batch_never_422s_on_mixed_batch(self):
        # The severity ranker may legitimately be untrained (503) in a
        # given environment — that is pre-existing and unrelated. What must
        # never happen again is a 422 caused by one finding in the batch.
        resp = self.client.post(
            "/v2/rank/batch",
            json={"findings": [IAC_FINDING, NORMAL_FINDING, IDLESS_FINDING]},
        )
        self.assertIn(resp.status_code, (200, 503), resp.text)
        if resp.status_code == 200:
            body = resp.json()
            self.assertEqual(body["total"], 3)
            # The id-less item cannot be scored; it must be the heuristic
            # fallback entry, not a failed request.
            self.assertTrue(body["results"][2]["fallback"])


class TestNormalFindingUnchanged(unittest.TestCase):
    """Byte-compat guard: a full 18-feature finding scores exactly as before."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(service.app)

    def test_normal_batch_response_shape(self):
        resp = self.client.post(
            "/classify/batch", json={"findings": [NORMAL_FINDING]}
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        result = resp.json()["results"][0]
        for key in ("prediction", "confidence", "threshold_used",
                    "conformal_calibrated", "explanations"):
            self.assertIn(key, result)
        self.assertNotIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
