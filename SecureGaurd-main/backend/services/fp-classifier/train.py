"""
train.py — False Positive Suppression Classifier

Ye script poora training pipeline dikhata hai:
1. Data load
2. Feature preprocessing (categorical encoding)
3. Train/test split
4. Model training (XGBoost)
5. Evaluation (accuracy, precision, recall, F1, confusion matrix)
6. Model save

Run: python3 train.py
"""

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from sklearn.model_selection import GridSearchCV
from xgboost import XGBClassifier
import argparse
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def parse_args():
    parser = argparse.ArgumentParser(description="SecureGuard FP Classifier training pipeline")
    parser.add_argument("--data", default=os.path.join(BASE_DIR, "sample_findings.csv"),
                        help="Path to the labeled findings CSV (default: sample_findings.csv next to this script)")
    parser.add_argument("--out-dir", default=BASE_DIR,
                        help="Directory to write model.joblib and the encoders (default: script directory)")
    return parser.parse_args()

ARGS = parse_args()
os.makedirs(ARGS.out_dir, exist_ok=True)

# ---------- 1. Load data ----------
df = pd.read_csv(ARGS.data)
print(f"Loaded {len(df)} labeled findings from {ARGS.data}\n")

# ---------- 2. Encode categorical features ----------
# Model numbers samajhta hai, text nahi -> rule_id/cwe_id ko numbers me convert karo
rule_encoder = LabelEncoder()
cwe_encoder = LabelEncoder()
df["rule_id_enc"] = rule_encoder.fit_transform(df["rule_id"])
df["cwe_id_enc"] = cwe_encoder.fit_transform(df["cwe_id"])

feature_cols = [
    "rule_id_enc", "cwe_id_enc", "is_string_concat", "is_parameterized_query",
    "has_sanitizer_nearby", "in_test_file", "is_in_vendor_or_generated_dir",
    "taint_source_distance", "function_complexity", "code_snippet_length",
    "variable_name_entropy", "is_user_input_direct", "has_type_validation",
    "is_third_party_lib_call", "same_finding_seen_before_count",
    "developer_dismissed_similar_before", "file_change_frequency",
    "is_authenticated_endpoint",
]

X = df[feature_cols]
y = df["label"]

# ---------- 3. Train/test split ----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train size: {len(X_train)} | Test size: {len(X_test)}\n")

# ---------- 4. Hyperparameter tuning + Train ----------
# GridSearch alag-alag combinations try karke best settings dhoondta hai
# (cross-validation ke saath, taaki overfit na ho)
param_grid = {
    "n_estimators": [150, 300],
    "max_depth": [4, 6, 8],
    "learning_rate": [0.05, 0.1],
    "min_child_weight": [1, 3],
    "subsample": [0.8, 1.0],
}

base_model = XGBClassifier(eval_metric="logloss", random_state=42)

print("Hyperparameter tuning chal raha hai (thoda time lagega)...\n")
grid_search = GridSearchCV(
    base_model, param_grid, scoring="recall",  # recall optimize karo (security priority)
    cv=5, n_jobs=-1, verbose=0,
)
grid_search.fit(X_train, y_train)

model = grid_search.best_estimator_
print(f"Best params found: {grid_search.best_params_}\n")

# ---------- 5. Evaluate ----------
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]  # probability of being REAL vulnerability

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("===== EVALUATION RESULTS =====")
print(f"Accuracy:  {acc:.3f}")
print(f"Precision: {prec:.3f}  (jab model 'REAL' bole, kitni baar sach me real hai)")
print(f"Recall:    {rec:.3f}  (kitni real vulnerabilities model ne pakdi, security ke liye SABSE IMPORTANT)")
print(f"F1-score:  {f1:.3f}")
print()
print("Confusion Matrix (rows=actual, cols=predicted):")
print("              Pred:FP   Pred:REAL")
cm = confusion_matrix(y_test, y_pred)
print(f"Actual:FP     {cm[0][0]:<10}{cm[0][1]}")
print(f"Actual:REAL   {cm[1][0]:<10}{cm[1][1]}")
print()
print(classification_report(y_test, y_pred, target_names=["FALSE_POSITIVE", "REAL"]))

# ---------- 6. Feature importance (model ne kya important samjha) ----------
importances = pd.Series(model.feature_importances_, index=feature_cols).sort_values(ascending=False)
print("===== FEATURE IMPORTANCE (model ne kis feature ko sabse zyada weight diya) =====")
print(importances)

# ---------- 7. Save model + encoders ----------
joblib.dump(model, os.path.join(ARGS.out_dir, "model.joblib"))
joblib.dump(rule_encoder, os.path.join(ARGS.out_dir, "rule_encoder.joblib"))
joblib.dump(cwe_encoder, os.path.join(ARGS.out_dir, "cwe_encoder.joblib"))
print(f"\nModel saved to {os.path.join(ARGS.out_dir, 'model.joblib')}")
