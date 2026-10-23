"""
real_data_retrain.py — Day-8 real-data retrain with Rishabh's feedback loop.

Pipeline (all on REAL data only — never padded with synthetic rows):
  1. Load datasets/day8/real_findings.csv, validate against feature_schema.
  2. Stratified 3-way split: train / dev / test (fixed seed).
  3. BASELINE: the serving v1_synthetic model (model.joblib + its encoders)
     evaluated on the untouched TEST split — the score to beat.
  4. Train v2 on the train split (XGBoost, scale_pos_weight from the real
     label distribution — same philosophy as retrain.py).
  5. FEEDBACK LOOP: run v2 on the DEV split; export every misclassified
     finding to feedback_errors.csv (features, true/predicted label,
     confidence, source repo/file/line); retrain a second pass with those
     hard examples folded back into training at higher sample weight.
  6. Report metrics on the untouched TEST split BEFORE and AFTER the
     feedback pass.
  7. SAFETY GATE: deploy only if v2-after-feedback beats v1 on the test
     set (higher accuracy AND no worse REAL recall — recall is the
     security-critical metric). Otherwise keep v1_synthetic serving and
     say so plainly. The TEST split is never trained on, at any pass.

On deploy: model.joblib / rule_encoder.joblib / cwe_encoder.joblib are
replaced (final weights fit on train+dev with the feedback weights —
test data never seen), model_metadata.json is written as v2_real, and the
previous serving files are archived under models_archive/.

Usage: python3 real_data_retrain.py [--data real_findings.csv] [--feedback-weight 5]
"""

import argparse
import csv
import datetime
import json
import os
import shutil
import sys

import joblib
import pandas as pd
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from feature_schema import FEATURE_COLS, RAW_FEATURES, safe_encode_series

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DAY8_DIR = os.path.join(BASE_DIR, "datasets", "day8")
ARCHIVE_DIR = os.path.join(BASE_DIR, "models_archive")
METADATA_JSON = os.path.join(BASE_DIR, "model_metadata.json")
FEEDBACK_CSV = os.path.join(DAY8_DIR, "feedback_errors.csv")
EVAL_JSON = os.path.join(DAY8_DIR, "evaluation_report.json")

RANDOM_STATE = 42
TEST_SIZE = 0.20
DEV_SIZE = 0.20  # of the whole set; train gets the remaining 60%


def parse_args():
    ap = argparse.ArgumentParser(description="Day-8 real-data retrain with feedback loop")
    ap.add_argument("--data", default=os.path.join(DAY8_DIR, "real_findings.csv"))
    ap.add_argument("--feedback-weight", type=float, default=5.0,
                    help="sample_weight multiplier for dev misclassifications in the 2nd pass")
    ap.add_argument("--dry-run", action="store_true",
                    help="train + evaluate + report, but never replace the serving model")
    return ap.parse_args()


def metrics_dict(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])
    return {
        "n": int(len(y_true)),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_real": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall_real": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_real": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "missed_real": fn,
    }


def encode_new(df):
    rule_enc, cwe_enc = LabelEncoder(), LabelEncoder()
    df = df.copy()
    df["rule_id_enc"] = rule_enc.fit_transform(df["rule_id"].astype(str))
    df["cwe_id_enc"] = cwe_enc.fit_transform(df["cwe_id"].astype(str))
    return df, rule_enc, cwe_enc


def train_xgb(X, y, sample_weight=None):
    n_real, n_fp = int((y == 1).sum()), int((y == 0).sum())
    spw = (n_fp / n_real) if n_real else 1.0
    print(f"  train: {len(y)} rows ({n_real} REAL / {n_fp} FP), scale_pos_weight={spw:.3f}")
    m = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1,
                      min_child_weight=1, subsample=0.8,
                      scale_pos_weight=spw, eval_metric="logloss",
                      random_state=RANDOM_STATE)
    m.fit(X, y, sample_weight=sample_weight)
    return m


def evaluate_v1_on_test(test_df):
    """Serving v1_synthetic baseline on the real TEST split (honest score to beat)."""
    model = joblib.load(os.path.join(BASE_DIR, "model.joblib"))
    rule_enc = joblib.load(os.path.join(BASE_DIR, "rule_encoder.joblib"))
    cwe_enc = joblib.load(os.path.join(BASE_DIR, "cwe_encoder.joblib"))
    t = test_df.copy()
    t["rule_id_enc"] = safe_encode_series(rule_enc, t["rule_id"].astype(str))
    t["cwe_id_enc"] = safe_encode_series(cwe_enc, t["cwe_id"].astype(str))
    return metrics_dict(t["label"].astype(int), model.predict(t[FEATURE_COLS]))


def main():
    args = parse_args()
    df = pd.read_csv(args.data)
    missing = [c for c in RAW_FEATURES + ["label"] if c not in df.columns]
    if missing:
        sys.exit(f"[ERROR] dataset missing columns: {missing}")
    assert df["label"].isin([0, 1]).all(), "labels must be 0/1"
    assert len(df) >= 30, f"only {len(df)} rows — too few for a 3-way split, aborting"
    print(f"loaded {len(df)} real labeled findings "
          f"({int((df['label']==1).sum())} REAL / {int((df['label']==0).sum())} FP)")

    train_df, temp_df = train_test_split(df, test_size=TEST_SIZE + DEV_SIZE,
                                        random_state=RANDOM_STATE, stratify=df["label"])
    dev_ratio = DEV_SIZE / (TEST_SIZE + DEV_SIZE)
    dev_df, test_df = train_test_split(temp_df, test_size=1 - dev_ratio,
                                       random_state=RANDOM_STATE, stratify=temp_df["label"])
    print(f"split: train={len(train_df)} dev={len(dev_df)} test={len(test_df)} (stratified)")

    # ── baseline ──
    print("\n[1/5] v1_synthetic baseline on TEST ...")
    v1 = evaluate_v1_on_test(test_df)
    print(f"  v1: acc={v1['accuracy']} recall_real={v1['recall_real']} "
          f"prec_real={v1['precision_real']} missed={v1['missed_real']}")

    # ── v2 first pass ──
    print("\n[2/5] training v2 (first pass, train split only) ...")
    tr, rule_enc, cwe_enc = encode_new(train_df)
    v2a = train_xgb(tr[FEATURE_COLS], tr["label"].astype(int))
    te = test_df.copy()
    te["rule_id_enc"] = safe_encode_series(rule_enc, te["rule_id"].astype(str))
    te["cwe_id_enc"] = safe_encode_series(cwe_enc, te["cwe_id"].astype(str))
    v2a_test = metrics_dict(te["label"].astype(int), v2a.predict(te[FEATURE_COLS]))
    print(f"  v2-first-pass on TEST: acc={v2a_test['accuracy']} recall_real={v2a_test['recall_real']}")

    # ── feedback loop on DEV ──
    print("\n[3/5] feedback loop: v2 on DEV -> feedback_errors.csv ...")
    de = dev_df.copy()
    de["rule_id_enc"] = safe_encode_series(rule_enc, de["rule_id"].astype(str))
    de["cwe_id_enc"] = safe_encode_series(cwe_enc, de["cwe_id"].astype(str))
    dev_pred = v2a.predict(de[FEATURE_COLS])
    dev_proba = v2a.predict_proba(de[FEATURE_COLS])[:, 1]
    de["pred"], de["proba"] = dev_pred, dev_proba
    errs = de[de["pred"] != de["label"].astype(int)].copy()
    print(f"  dev errors: {len(errs)} / {len(de)}")
    fb_cols = RAW_FEATURES + ["label"]
    with open(FEEDBACK_CSV, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fb_cols + ["predicted_label", "confidence",
                                                     "source_repo", "source_commit", "cve_ghsa"])
        w.writeheader()
        for _, r in errs.iterrows():
            w.writerow({**{c: r[c] for c in fb_cols},
                        "predicted_label": int(r["pred"]),
                        "confidence": round(float(r["proba"]), 4),
                        "source_repo": r.get("source_repo", ""),
                        "source_commit": r.get("source_commit", ""),
                        "cve_ghsa": r.get("cve_ghsa", "")})
    print(f"  wrote {FEEDBACK_CSV}")

    # ── second pass: train + weighted dev errors ──
    print(f"\n[4/5] training v2 (second pass, +{len(errs)} dev errors x{args.feedback_weight} weight) ...")
    err_enc = errs.copy()
    X2 = pd.concat([tr[FEATURE_COLS], err_enc[FEATURE_COLS]], ignore_index=True)
    y2 = pd.concat([tr["label"].astype(int), err_enc["label"].astype(int)], ignore_index=True)
    w2 = [1.0] * len(tr) + [args.feedback_weight] * len(errs)
    v2b = train_xgb(X2, y2, sample_weight=w2)
    v2b_test = metrics_dict(te["label"].astype(int), v2b.predict(te[FEATURE_COLS]))
    print(f"  v2-second-pass on TEST: acc={v2b_test['accuracy']} recall_real={v2b_test['recall_real']}")

    # ── safety gate ──
    print("\n[5/5] safety gate ...")
    wins = (v2b_test["accuracy"] > v1["accuracy"]
            and v2b_test["recall_real"] >= v1["recall_real"])
    print(f"  v2 wins iff acc {v2b_test['accuracy']} > {v1['accuracy']} "
          f"AND recall {v2b_test['recall_real']} >= {v1['recall_real']} -> {'DEPLOY' if wins else 'HOLD'}")

    report = {
        "date": datetime.date.today().isoformat(),
        "dataset": os.path.basename(args.data),
        "n_rows": len(df),
        "split": {"train": len(train_df), "dev": len(dev_df), "test": len(test_df)},
        "dev_errors": int(len(errs)),
        "feedback_weight": args.feedback_weight,
        "baseline_v1_synthetic_on_real_test": v1,
        "v2_first_pass_on_test": v2a_test,
        "v2_second_pass_on_test": v2b_test,
        "gate": {"wins": bool(wins), "deployed": False},
    }

    if wins and not args.dry_run:
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        for f in ("model.joblib", "rule_encoder.joblib", "cwe_encoder.joblib"):
            shutil.copy2(os.path.join(BASE_DIR, f), os.path.join(ARCHIVE_DIR, f"{f}.{ts}.v1_synthetic"))
        # final weights: train + dev (feedback-weighted); TEST never seen
        dev_w = de.copy()
        Xf = pd.concat([tr[FEATURE_COLS], dev_w[FEATURE_COLS]], ignore_index=True)
        yf = pd.concat([tr["label"].astype(int), dev_w["label"].astype(int)], ignore_index=True)
        wf = [1.0] * len(tr) + [args.feedback_weight if p else 1.0
              for p in (dev_w["pred"] != dev_w["label"].astype(int))]
        final_model = train_xgb(Xf, yf, sample_weight=wf)
        joblib.dump(final_model, os.path.join(BASE_DIR, "model.joblib"))
        joblib.dump(rule_enc, os.path.join(BASE_DIR, "rule_encoder.joblib"))
        joblib.dump(cwe_enc, os.path.join(BASE_DIR, "cwe_encoder.joblib"))
        metadata = {
            "version": "v2_real",
            "training_date": datetime.datetime.now().isoformat(),
            "dataset": os.path.basename(args.data),
            "dataset_size": len(df),
            "sources": sorted(df["source_repo"].unique().tolist()) if "source_repo" in df else [],
            "feedback": {"dev_errors": int(len(errs)), "weight": args.feedback_weight},
            "metrics_test": v2b_test,
            "baseline_v1_synthetic_test": v1,
            "status": "active",
        }
        with open(METADATA_JSON, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2)
        report["gate"]["deployed"] = True
        print("  deployed v2_real (model.joblib + encoders + model_metadata.json); v1 archived")
    else:
        print("  HOLD: v1_synthetic keeps serving. " +
              ("dry-run" if args.dry_run else "Gate did not pass — dataset + pipeline shipped, model not deployed."))

    with open(EVAL_JSON, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nevaluation report -> {EVAL_JSON}")


if __name__ == "__main__":
    main()
