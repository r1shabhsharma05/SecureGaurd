"""
retrain.py — Retrain the model with data versioning, validation safety gates, and rollback mechanisms.
"""

import os
import sys
import argparse
import datetime
import shutil
import json
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from xgboost import XGBClassifier

from feature_schema import FEATURE_COLS, safe_encode_series

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_FINDINGS_CSV = os.path.join(BASE_DIR, "sample_findings.csv")
SYNTHETIC_FINDINGS_CSV = os.path.join(BASE_DIR, "synthetic_findings.csv")
METADATA_JSON = os.path.join(BASE_DIR, "model_metadata.json")
ARCHIVE_DIR = os.path.join(BASE_DIR, "models_archive")

os.makedirs(ARCHIVE_DIR, exist_ok=True)

def parse_args():
    parser = argparse.ArgumentParser(description="SecureGuard FP Classifier Retraining Pipeline")
    parser.add_argument("--force", action="store_true", help="Force retraining even if threshold is not met")
    parser.add_argument("--threshold", type=int, default=500, help="Minimum new feedback items required to retrain")
    return parser.parse_args()

def main():
    args = parse_args()
    
    # 1. Check feedback volume threshold
    if not os.path.exists(SAMPLE_FINDINGS_CSV):
        print(f"[ERROR] sample_findings.csv not found at {SAMPLE_FINDINGS_CSV}")
        sys.exit(1)
        
    df = pd.read_csv(SAMPLE_FINDINGS_CSV)
    total_count = len(df)
    
    # If synthetic findings file exists, calculate new feedback entries count
    synthetic_count = 0
    if os.path.exists(SYNTHETIC_FINDINGS_CSV):
        syn_df = pd.read_csv(SYNTHETIC_FINDINGS_CSV)
        synthetic_count = len(syn_df)
        
    new_feedback_count = max(0, total_count - synthetic_count)
    print(f"Total findings: {total_count} | Base synthetic: {synthetic_count} | New feedback: {new_feedback_count}")
    
    if new_feedback_count < args.threshold and not args.force:
        print(f"[Retrain Skipped] Only {new_feedback_count} new feedback findings available. Threshold is {args.threshold}.")
        print("Use --force to override this check.")
        sys.exit(0)
        
    print("Starting retraining pipeline...")
    
    # 2. Encode categorical features
    rule_encoder = LabelEncoder()
    cwe_encoder = LabelEncoder()
    
    df["rule_id_enc"] = rule_encoder.fit_transform(df["rule_id"].astype(str))
    df["cwe_id_enc"] = cwe_encoder.fit_transform(df["cwe_id"].astype(str))

    X = df[FEATURE_COLS]
    y = df["label"]

    # Class imbalance: the data skews toward FALSE_POSITIVE, which biases the
    # model against predicting REAL — the worse error for a security tool.
    # scale_pos_weight rebalances the loss toward the minority (REAL) class.
    # Computed from the actual label distribution, not hardcoded.
    n_real = int((y == 1).sum())
    n_fp = int((y == 0).sum())
    scale_pos_weight = (n_fp / n_real) if n_real else 1.0
    print(f"Class balance: {n_real} REAL / {n_fp} FP -> scale_pos_weight={scale_pos_weight:.3f}")
    
    # 3. Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 4. Train new model
    new_model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        min_child_weight=1,
        subsample=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        random_state=42
    )
    new_model.fit(X_train, y_train)
    
    # Evaluate new model
    y_pred_new = new_model.predict(X_test)
    new_acc = accuracy_score(y_test, y_pred_new)
    new_rec = recall_score(y_test, y_pred_new)
    new_prec = precision_score(y_test, y_pred_new)
    new_f1 = f1_score(y_test, y_pred_new)
    
    print("\n===== NEW MODEL EVALUATION =====")
    print(f"Accuracy:  {new_acc:.3f}")
    print(f"Recall:    {new_rec:.3f}")
    print(f"Precision: {new_prec:.3f}")
    print(f"F1-score:  {new_f1:.3f}")
    
    # 5. Evaluate current active model for comparison (if exists)
    old_model_path = os.path.join(BASE_DIR, "model.joblib")
    old_model_available = False
    old_acc, old_rec = 0.0, 0.0
    
    if os.path.exists(old_model_path):
        try:
            old_model = joblib.load(old_model_path)
            old_rule_enc = joblib.load(os.path.join(BASE_DIR, "rule_encoder.joblib"))
            old_cwe_enc = joblib.load(os.path.join(BASE_DIR, "cwe_encoder.joblib"))
            
            X_test_old = X_test.copy()
            # Map test data back to original index to get string names, then transform with old encoder
            orig_rule_ids = df.loc[X_test.index, "rule_id"].astype(str)
            orig_cwe_ids = df.loc[X_test.index, "cwe_id"].astype(str)
            
            X_test_old["rule_id_enc"] = safe_encode_series(old_rule_enc, orig_rule_ids)
            X_test_old["cwe_id_enc"] = safe_encode_series(old_cwe_enc, orig_cwe_ids)
            
            y_pred_old = old_model.predict(X_test_old)
            old_acc = accuracy_score(y_test, y_pred_old)
            old_rec = recall_score(y_test, y_pred_old)
            old_model_available = True
            
            print("\n===== OLD MODEL COMPARISON =====")
            print(f"Old Accuracy: {old_acc:.3f} | New Accuracy: {new_acc:.3f}")
            print(f"Old Recall:   {old_rec:.3f} | New Recall:   {new_rec:.3f}")
        except Exception as e:
            print(f"\n[Warning] Failed to evaluate old model: {e}")
            
    # 6. Safety Rollback Gate
    # Allow minor fluctuations, but if accuracy/recall drops by more than 2%, abort.
    if old_model_available:
        if new_acc < (old_acc - 0.02) or new_rec < (old_rec - 0.02):
            print("\n🚨 [ROLLBACK TRIGGERED] Model safety gate failed!")
            print(f"New model drops performance below acceptable limits compared to current model.")
            print("Deployment aborted. Keeping previous model files.")
            sys.exit(2)
            
    # 7. Deployment: Save new model and archive
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save temporary versions
    temp_model = os.path.join(ARCHIVE_DIR, f"model_{timestamp}.joblib")
    temp_rule_enc = os.path.join(ARCHIVE_DIR, f"rule_encoder_{timestamp}.joblib")
    temp_cwe_enc = os.path.join(ARCHIVE_DIR, f"cwe_encoder_{timestamp}.joblib")
    
    joblib.dump(new_model, temp_model)
    joblib.dump(rule_encoder, temp_rule_enc)
    joblib.dump(cwe_encoder, temp_cwe_enc)
    
    # Copy to active files
    shutil.copy2(temp_model, os.path.join(BASE_DIR, "model.joblib"))
    shutil.copy2(temp_rule_enc, os.path.join(BASE_DIR, "rule_encoder.joblib"))
    shutil.copy2(temp_cwe_enc, os.path.join(BASE_DIR, "cwe_encoder.joblib"))
    
    # 8. Write metadata
    metadata = {
        "version": f"v_{timestamp}",
        "training_date": datetime.datetime.now().isoformat(),
        "dataset_size": total_count,
        "new_feedback_size": new_feedback_count,
        "metrics": {
            "accuracy": round(float(new_acc), 4),
            "recall": round(float(new_rec), 4),
            "precision": round(float(new_prec), 4),
            "f1_score": round(float(new_f1), 4)
        },
        "status": "active"
    }
    
    with open(METADATA_JSON, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        
    print(f"\n[Success] Model successfully retrained, verified, and deployed as v_{timestamp}!")

if __name__ == "__main__":
    main()
