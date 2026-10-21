"""
train_severity.py — Train the severity-priority ranker (v0).

Labels are heuristic-derived via severity_schema.heuristic_priority_label
(see that module for the formula, its rationale, and why a trained model
instead of the raw formula). No analyst-labeled severity data exists yet;
when it does, point --label-column at it and only the weights change.

Pipeline:
  1. Load a findings CSV (same shape as the FP classifier's training data).
  2. Derive the 0-100 priority target per row from the transparent formula.
  3. Encode rule_id/cwe_id with the FP classifier's FITTED encoders
     (reused, not refit — serving must see identical category mappings).
  4. Train an XGBRegressor on the shared FEATURE_COLS.
  5. Evaluate on a held-out split: MAE, RMSE, R^2, and Spearman rank
     correlation (the metric that matters for a prioritizer — order, not
     exact score).
  6. Write severity_model.joblib + severity_metadata.json (honest
     label_source recorded; never claim analyst labels).

Run: python3 train_severity.py [--data sample_findings.csv] [--out-dir .]
"""

import argparse
import datetime
import json
import os
import sys

import joblib
import pandas as pd
from scipy.stats import spearmanr
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import train_test_split
from xgboost import XGBRegressor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FP_CLASSIFIER_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "fp-classifier"))
if FP_CLASSIFIER_DIR not in sys.path:
    sys.path.insert(0, FP_CLASSIFIER_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from feature_schema import FEATURE_COLS, safe_encode_series  # noqa: E402
from severity_schema import heuristic_priority_label  # noqa: E402

RULE_ENCODER_PATH = os.path.join(FP_CLASSIFIER_DIR, "rule_encoder.joblib")
CWE_ENCODER_PATH = os.path.join(FP_CLASSIFIER_DIR, "cwe_encoder.joblib")


def parse_args():
    p = argparse.ArgumentParser(description="Train the severity-priority ranker (v0, heuristic labels)")
    p.add_argument("--data", default=os.path.join(FP_CLASSIFIER_DIR, "sample_findings.csv"),
                   help="Findings CSV with the 18 raw features (default: fp-classifier sample_findings.csv)")
    p.add_argument("--out-dir", default=BASE_DIR,
                   help="Directory for severity_model.joblib + severity_metadata.json")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    df = pd.read_csv(args.data)
    print(f"Loaded {len(df)} findings from {args.data}")

    # 1. Heuristic labels — the transparent formula, applied per row.
    df["priority"] = df.apply(
        lambda r: heuristic_priority_label(r.to_dict()), axis=1
    )
    print(f"Label range: [{df['priority'].min():.1f}, {df['priority'].max():.1f}] "
          f"mean={df['priority'].mean():.1f}")

    # 2. Shared encoders — fitted by the FP classifier, reused as-is.
    rule_encoder = joblib.load(RULE_ENCODER_PATH)
    cwe_encoder = joblib.load(CWE_ENCODER_PATH)
    df["rule_id_enc"] = safe_encode_series(rule_encoder, df["rule_id"])
    df["cwe_id_enc"] = safe_encode_series(cwe_encoder, df["cwe_id"])
    unseen = int((df[["rule_id_enc", "cwe_id_enc"]] == -1).any(axis=1).sum())
    print(f"Rows with unseen rule/CWE ids (encoded -1, fail-safe path): {unseen}")

    X = df[FEATURE_COLS]
    y = df["priority"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    print(f"Train: {len(X_train)} | Test: {len(X_test)}")

    # 3. Train — shallow regressor; the target is a smooth formula, so a
    # small model suffices and stays fast at serve time.
    model = XGBRegressor(
        n_estimators=200, max_depth=5, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, random_state=42, n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # 4. Evaluate on the untouched split.
    pred = model.predict(X_test)
    mae = mean_absolute_error(y_test, pred)
    rmse = mean_squared_error(y_test, pred) ** 0.5
    r2 = r2_score(y_test, pred)
    rho, _ = spearmanr(y_test, pred)
    print("\n===== HELD-OUT EVALUATION =====")
    print(f"MAE: {mae:.2f} | RMSE: {rmse:.2f} | R^2: {r2:.4f} | Spearman rho: {rho:.4f}")

    importances = pd.Series(model.feature_importances_, index=FEATURE_COLS)
    print("\nTop 5 features by importance:")
    print(importances.sort_values(ascending=False).head(5).to_string())

    # 5. Save weights + honest metadata.
    joblib.dump(model, os.path.join(args.out_dir, "severity_model.joblib"))
    metadata = {
        "version": "v0_heuristic",
        "training_date": datetime.datetime.now().isoformat(),
        "dataset_size": len(df),
        "dataset_source": os.path.basename(args.data),
        "label_source": "heuristic_v0 (severity_schema.heuristic_priority_label) — NOT analyst-labeled",
        "model_type": "XGBRegressor",
        "params": model.get_params(),
        "metrics": {
            "mae": round(float(mae), 3),
            "rmse": round(float(rmse), 3),
            "r2": round(float(r2), 4),
            "spearman_rho": round(float(rho), 4),
        },
        "feature_schema": "FEATURE_COLS (18 cols, shared with fp-classifier)",
        "encoders": "reused fp-classifier rule_encoder.joblib / cwe_encoder.joblib (not refit)",
        "status": "active",
    }
    with open(os.path.join(args.out_dir, "severity_metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"\nSaved weights + metadata to {args.out_dir}")


if __name__ == "__main__":
    main()
