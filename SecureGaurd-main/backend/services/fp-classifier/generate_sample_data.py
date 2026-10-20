"""
generate_sample_data.py

Ye script DEMO/SYNTHETIC data banata hai jo SAST tool ke findings jaisa dikhta hai.
Real project me ye step aap in tariko se karoge:
  1. Semgrep (ya apna SAST engine) ko sample repos pe chalao -> raw findings milenge
  2. Har finding ko manually ya developer-feedback (ignore/confirm clicks) se label karo
  3. Us labeled CSV ko yahi format me convert karo

Abhi hum sirf PIPELINE dikhane ke liye synthetic data bana rahe hain.
"""

import pandas as pd
import numpy as np
import random
import argparse
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def parse_args():
    parser = argparse.ArgumentParser(description="Generate synthetic SAST findings for classifier training")
    parser.add_argument("--out", default=os.path.join(BASE_DIR, "sample_findings.csv"),
                        help="Where to write the generated CSV (default: sample_findings.csv next to this script)")
    parser.add_argument("--n", type=int, default=8000, help="Number of synthetic rows to generate")
    return parser.parse_args()

ARGS = parse_args()
N_SAMPLES = ARGS.n

random.seed(42)
np.random.seed(42)

rows = []
rule_ids = ["sqli-concat", "xss-unescaped", "hardcoded-secret", "path-traversal", "ssrf-request", "insecure-deserialize"]
cwe_ids = ["CWE-89", "CWE-79", "CWE-798", "CWE-22", "CWE-918", "CWE-502"]

for _ in range(N_SAMPLES):
    rule_idx = random.randint(0, len(rule_ids) - 1)
    rule_id = rule_ids[rule_idx]
    cwe_id = cwe_ids[rule_idx]

    is_string_concat = random.choice([0, 1])
    is_parameterized = random.choice([0, 1]) if is_string_concat == 0 else 0
    has_sanitizer_nearby = random.choice([0, 1])
    in_test_file = random.choices([0, 1], weights=[0.85, 0.15])[0]
    taint_source_distance = random.randint(1, 20)  # kitni lines door se untrusted input aaya
    function_complexity = random.randint(1, 30)     # cyclomatic complexity
    code_snippet_length = random.randint(20, 400)
    variable_name_entropy = round(random.uniform(1.5, 4.5), 2)  # high entropy = secret jaisa lagta hai
    is_in_vendor_or_generated_dir = random.choices([0, 1], weights=[0.9, 0.1])[0]

    # ---- NAYE FEATURES (accuracy improve karne ke liye) ----
    is_user_input_direct = random.choice([0, 1])            # variable seedha request/input se aaya
    has_type_validation = random.choice([0, 1])              # type/schema check hua hai ya nahi
    is_third_party_lib_call = random.choices([0, 1], weights=[0.75, 0.25])[0]
    same_finding_seen_before_count = random.randint(0, 10)   # historically kitni baar ye pattern flag hua
    developer_dismissed_similar_before = random.choices([0, 1], weights=[0.7, 0.3])[0]
    file_change_frequency = random.randint(0, 50)            # kitni baar file recently edit hui (churn)
    is_authenticated_endpoint = random.choice([0, 1])        # auth ke peeche wala endpoint hai ya public

    # ---- REALISTIC LABEL LOGIC (ye asli data me developer feedback se aayega) ----
    real_risk_score = 0
    real_risk_score += 3 if is_string_concat else 0
    real_risk_score -= 3 if is_parameterized else 0
    real_risk_score -= 2 if has_sanitizer_nearby else 0
    real_risk_score -= 4 if in_test_file else 0
    real_risk_score -= 3 if is_in_vendor_or_generated_dir else 0
    real_risk_score += 1 if taint_source_distance < 5 else -1
    real_risk_score += 1 if function_complexity > 15 else 0
    real_risk_score += (variable_name_entropy - 3) if rule_id == "hardcoded-secret" else 0

    real_risk_score += 2 if is_user_input_direct else -1
    real_risk_score -= 2.5 if has_type_validation else 0
    real_risk_score -= 1 if is_third_party_lib_call else 0
    real_risk_score -= 0.3 * same_finding_seen_before_count if developer_dismissed_similar_before else 0
    real_risk_score += 1 if is_authenticated_endpoint == 0 else -0.5  # public endpoint zyada risky
    real_risk_score += 0.5 if file_change_frequency > 20 else 0

    # thoda random noise add karo taaki bilkul perfect-separable na ho (real world jaisa)
    real_risk_score += np.random.normal(0, 1.2)

    label = 1 if real_risk_score > 0 else 0  # 1 = REAL vulnerability, 0 = FALSE POSITIVE

    rows.append({
        "rule_id": rule_id,
        "cwe_id": cwe_id,
        "is_string_concat": is_string_concat,
        "is_parameterized_query": is_parameterized,
        "has_sanitizer_nearby": has_sanitizer_nearby,
        "in_test_file": in_test_file,
        "is_in_vendor_or_generated_dir": is_in_vendor_or_generated_dir,
        "taint_source_distance": taint_source_distance,
        "function_complexity": function_complexity,
        "code_snippet_length": code_snippet_length,
        "variable_name_entropy": variable_name_entropy,
        "is_user_input_direct": is_user_input_direct,
        "has_type_validation": has_type_validation,
        "is_third_party_lib_call": is_third_party_lib_call,
        "same_finding_seen_before_count": same_finding_seen_before_count,
        "developer_dismissed_similar_before": developer_dismissed_similar_before,
        "file_change_frequency": file_change_frequency,
        "is_authenticated_endpoint": is_authenticated_endpoint,
        "label": label,
    })

df = pd.DataFrame(rows)
df.to_csv(ARGS.out, index=False)
print(f"Generated {len(df)} rows -> {ARGS.out}")
print(df["label"].value_counts(normalize=True))
print(df.head())
