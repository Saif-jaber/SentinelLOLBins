import os
import json
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import joblib

# Repository paths.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
MODEL_DIR = os.path.join(BASE, "results", "models")

# Load the processed matrices for each split.
def load(name):
    return pd.read_parquet(os.path.join(PROC, f"xgb_{name}.parquet"))

train = load("train")
val = load("val")
test = load("test")
holdout = load("holdout")

# Separate features from labels.
X_train = train.drop(columns=["label"])
y_train = train["label"]

X_val = val.drop(columns=["label"])
y_val = val["label"]

X_test = test.drop(columns=["label"])
y_test = test["label"]

X_holdout = holdout.drop(columns=["label"])
y_holdout = holdout["label"]

for n, X, y in [("train", X_train, y_train), ("val", X_val, y_val),
                ("test", X_test, y_test), ("holdout", X_holdout, y_holdout)]:
    print(n, X.shape, "| positives:", int(y.sum()), "of", len(y))

# XGBoost baseline with the parameters fixed before evaluation.
model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1,
)

model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
print("model trained")

# Shared metric helper.
def metrics(name, y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    fpr = fp / (fp + tn)
    print(f"{name}: precision={prec:.3f} recall={rec:.3f} f1={f1:.3f} fpr={fpr:.3f}")
    print(f"  confusion: tn={tn} fp={fp} fn={fn} tp={tp}")

proba_val = model.predict_proba(X_val)[:, 1]
pred_val = (proba_val >= 0.5).astype(int)
metrics("val @0.5", y_val, pred_val)

# Check a few thresholds on validation only.
print("\nthreshold sweep (val):")
for t in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
    pred = (proba_val >= t).astype(int)
    print(f"t={t:.1f} precision={precision_score(y_val, pred):.3f} "
          f"recall={recall_score(y_val, pred):.3f} f1={f1_score(y_val, pred):.3f}")

THRESHOLD = 0.5  # Fallback when the saved threshold is unavailable.
thr_path = os.path.join(BASE, "results", "chosen_threshold.json")
if os.path.exists(thr_path):
    THRESHOLD = json.load(open(thr_path))["threshold"]  # Selected on validation, never on test.
print(f"\nusing validation-selected threshold: {THRESHOLD}")

# Final test evaluation, run once.
proba_test = model.predict_proba(X_test)[:, 1]
pred_test = (proba_test >= THRESHOLD).astype(int)
metrics(f"test @{THRESHOLD}", y_test, pred_test)

# E4 withheld techniques: malicious only, so report recall.
proba_hold = model.predict_proba(X_holdout)[:, 1]
pred_hold = (proba_hold >= THRESHOLD).astype(int)
print(f"holdout (E4): recall={recall_score(y_holdout, pred_hold):.3f} "
      f"caught={int(pred_hold.sum())} of {len(pred_hold)}")

# Feature importance for the report.
imp = pd.Series(model.feature_importances_, index=model.feature_names_in_)
print("\ntop 15 features:")
print(imp.sort_values(ascending=False).head(15))

# Save the trained model.
joblib.dump(model, os.path.join(MODEL_DIR, "xgb_baseline.joblib"))
print("\nmodel saved")