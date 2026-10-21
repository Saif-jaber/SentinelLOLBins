import os
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import joblib

#path stuff
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
MODEL_DIR = os.path.join(BASE, "results", "models")

# for loading the data files for xgboost variables
def load(name):
    return pd.read_parquet(os.path.join(PROC, f"xgb_{name}.parquet"))

train = load("train")
val = load("val")
test = load("test")
holdout = load("holdout")

# configuring the training and labels
X_train = train.drop(columns=["label"])
y_train = train["label"]

X_val = val.drop(columns=["label"])
y_val = val["label"]

X_test = test.drop(columns=["label"])
y_test = test["label"]

X_holdout = holdout.drop(columns=["label"])
y_holdout = holdout["label"]

for n, X, y in [("train", X_train, y_train), ("val", X_val, y_val), # just for confirming everything loads correctly
                ("test", X_test, y_test), ("holdout", X_holdout, y_holdout)]:
    print(n, X.shape, "| positives:", int(y.sum()), "of", len(y))

# training of model xgboost (runs on decision trees)
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

model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False) # learning step
print("model trained")

# the metrics for the evaluation of the xgboost model 
def metrics(name, y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    fpr = fp / (fp + tn)
    print(f"{name}: precision={prec:.3f} recall={rec:.3f} f1={f1:.3f} fpr={fpr:.3f}")
    print(f"  confusion: tn={tn} fp={fp} fn={fn} tp={tp}")

proba_val = model.predict_proba(X_val)[:, 1] # check the probabilities of each class
pred_val = (proba_val >= 0.5).astype(int) # uding the probabilities makes the decision of a threshold of a 0.5
metrics("val @0.5", y_val, pred_val)

# trying diffrent thresholds on val only
print("\nthreshold sweep (val):")
for t in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
    pred = (proba_val >= t).astype(int)
    print(f"t={t:.1f} precision={precision_score(y_val, pred):.3f} "
          f"recall={recall_score(y_val, pred):.3f} f1={f1_score(y_val, pred):.3f}")

THRESHOLD = 0.5  # picked from the val table not from test

# final test check, only run once
proba_test = model.predict_proba(X_test)[:, 1]
pred_test = (proba_test >= THRESHOLD).astype(int)
metrics(f"test @{THRESHOLD}", y_test, pred_test)

# E4 unseen techniques, all malicious so we check recall
proba_hold = model.predict_proba(X_holdout)[:, 1]
pred_hold = (proba_hold >= THRESHOLD).astype(int)
print(f"holdout (E4): recall={recall_score(y_holdout, pred_hold):.3f} "
      f"caught={int(pred_hold.sum())} of {len(pred_hold)}")

# what features the model depends on most
imp = pd.Series(model.feature_importances_, index=model.feature_names_in_)
print("\ntop 15 features:")
print(imp.sort_values(ascending=False).head(15))

# saving the model
joblib.dump(model, os.path.join(MODEL_DIR, "xgb_baseline.joblib"))
print("\nmodel saved")