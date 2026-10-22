import os
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

#path stuff
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
RESULT_DIR = os.path.join(BASE, "results")

# same loader as the training script
def load(name):
    return pd.read_parquet(os.path.join(PROC, f"xgb_{name}.parquet"))

train = load("train")
val = load("val")
test = load("test")
holdout = load("holdout")

y_train = train["label"]
y_val = val["label"]
y_test = test["label"]
y_holdout = holdout["label"]

all_cols = [c for c in train.columns if c != "label"]

# feature groups from the encoded column names
name_cols = [c for c in all_cols if c.startswith("cat__process_name_")]
parent_cols = [c for c in all_cols if c.startswith("cat__parent_process_")]
cmd_cols = [c for c in all_cols if c.startswith("num__cmd_") or c.startswith("num__flag_")]

# the 4 versions we compare
variants = {
    "name only": name_cols,
    "name + parent + cmd": name_cols + parent_cols + cmd_cols,
    "full context": all_cols,
    "full without process name": [c for c in all_cols if c not in name_cols],
}

print("features per variant:")
for k, v in variants.items():
    print(f"  {k}: {len(v)}")

rows = []
for title, cols in variants.items():
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
    model.fit(train[cols], y_train, eval_set=[(val[cols], y_val)], verbose=False)

    proba = model.predict_proba(test[cols])[:, 1]
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()

    proba_h = model.predict_proba(holdout[cols])[:, 1]
    pred_h = (proba_h >= 0.5).astype(int)

    row = {
        "variant": title,
        "n_features": len(cols),
        "precision": round(precision_score(y_test, pred), 3),
        "recall": round(recall_score(y_test, pred), 3),
        "f1": round(f1_score(y_test, pred), 3),
        "fpr": round(fp / (fp + tn), 4),
        "holdout_recall": round(recall_score(y_holdout, pred_h), 3),
    }
    rows.append(row)
    print(f"done: {title}")

# results table for the report
results = pd.DataFrame(rows)
print("\nE3 ablation (test set + E4 holdout):")
print(results.to_string(index=False))

os.makedirs(RESULT_DIR, exist_ok=True)
results.to_csv(os.path.join(RESULT_DIR, "e3_ablation.csv"), index=False)
print("\nsaved results/e3_ablation.csv")
