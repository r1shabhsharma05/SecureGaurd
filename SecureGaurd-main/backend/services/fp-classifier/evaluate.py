"""
evaluate.py — Evaluate the trained FP classifier on a labeled findings CSV.

Produces accuracy, precision, recall, F1 (per class + macro), the confusion
matrix, and the false-negative count (missed REAL vulnerabilities — the
metric that matters most for a security tool). Prints a human-readable
report and optionally writes a machine-readable JSON report.

Run: python3 evaluate.py [--data sample_findings.csv] [--output evaluation_report.json]
"""

import argparse
import json
import os
import sys

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    precision_recall_fscore_support,
)

from feature_schema import FEATURE_COLS, safe_encode_series

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate the FP classifier on labeled data")
    parser.add_argument("--data", default=os.path.join(BASE_DIR, "sample_findings.csv"),
                        help="Labeled findings CSV with a 'label' column (1=REAL, 0=FALSE_POSITIVE)")
    parser.add_argument("--model", default=os.path.join(BASE_DIR, "model.joblib"),
                        help="Trained model file")
    parser.add_argument("--output", default=None,
                        help="Write JSON report to this path (default: print only)")
    return parser.parse_args()


def main():
    args = parse_args()

    model = joblib.load(args.model)
    rule_encoder = joblib.load(os.path.join(BASE_DIR, "rule_encoder.joblib"))
    cwe_encoder = joblib.load(os.path.join(BASE_DIR, "cwe_encoder.joblib"))

    df = pd.read_csv(args.data)
    if "label" not in df.columns:
        print(f"[ERROR] {args.data} has no 'label' column", file=sys.stderr)
        sys.exit(1)

    df["rule_id_enc"] = safe_encode_series(rule_encoder, df["rule_id"].astype(str))
    df["cwe_id_enc"] = safe_encode_series(cwe_encoder, df["cwe_id"].astype(str))

    X = df[FEATURE_COLS]
    y_true = df["label"].astype(int)
    y_pred = model.predict(X)

    acc = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    # rows = actual [FP, REAL], cols = predicted [FP, REAL]
    tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])

    report = {
        "data": os.path.basename(args.data),
        "n_samples": int(len(df)),
        "accuracy": round(float(acc), 4),
        "per_class": {
            "FALSE_POSITIVE": {
                "precision": round(float(precision[0]), 4),
                "recall": round(float(recall[0]), 4),
                "f1": round(float(f1[0]), 4),
            },
            "REAL": {
                "precision": round(float(precision[1]), 4),
                "recall": round(float(recall[1]), 4),
                "f1": round(float(f1[1]), 4),
            },
        },
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "missed_real_vulns": fn,
        "false_alarm_rate": round(fp / (fp + tn) if (fp + tn) else 0.0, 4),
    }

    print("===== FP CLASSIFIER EVALUATION =====")
    print(f"Data: {report['data']} ({report['n_samples']} labeled findings)")
    print(f"Accuracy:  {report['accuracy']:.4f}")
    print(f"REAL      → precision {report['per_class']['REAL']['precision']:.4f} | "
          f"recall {report['per_class']['REAL']['recall']:.4f} | "
          f"f1 {report['per_class']['REAL']['f1']:.4f}")
    print(f"FALSE_POS  → precision {report['per_class']['FALSE_POSITIVE']['precision']:.4f} | "
          f"recall {report['per_class']['FALSE_POSITIVE']['recall']:.4f} | "
          f"f1 {report['per_class']['FALSE_POSITIVE']['f1']:.4f}")
    print()
    print("Confusion matrix (rows=actual, cols=predicted):")
    print("              Pred:FP   Pred:REAL")
    print(f"Actual:FP     {tn:<10}{fp}")
    print(f"Actual:REAL   {fn:<10}{tp}")
    print()
    print(f"Missed REAL vulnerabilities (false negatives): {fn}")
    print(f"False alarm rate: {report['false_alarm_rate']:.4f}")
    print()
    print(classification_report(y_true, y_pred, target_names=["FALSE_POSITIVE", "REAL"]))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"JSON report written to {args.output}")


if __name__ == "__main__":
    main()
