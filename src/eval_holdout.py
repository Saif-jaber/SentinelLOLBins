import os
import json
import pandas as pd
import joblib
from sklearn.metrics import recall_score, confusion_matrix

#path stuff
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
SPLITS = os.path.join(BASE, "data", "splits")
MODEL_DIR = os.path.join(BASE, "results", "models")
RESULT_DIR = os.path.join(BASE, "results")

# same leakage drop list as preprocess.py so the columns line up
DROP = [
    "label",
    "mitre_technique", "command_source", "rule_category",
    "record_id", "dedup_key", "dataset_origin",
    "command_line", "cmd_normalized", "model_text",
]

def load_ids(name):
    with open(os.path.join(SPLITS, f"{name}.json")) as f:
        return set(json.load(f)["record_ids"])

df = pd.read_parquet(os.path.join(PROC, "sample_100k.parquet"))
features = [c for c in df.columns if c not in DROP]

pre = joblib.load(os.path.join(MODEL_DIR, "preprocessor.joblib"))
model = joblib.load(os.path.join(MODEL_DIR, "xgb_baseline.joblib"))

# use the validation-selected threshold when available
thr_path = os.path.join(RESULT_DIR, "chosen_threshold.json")
THRESHOLD = json.load(open(thr_path))["threshold"] if os.path.exists(thr_path) else 0.5

# E4 withheld techniques (malicious only)
holdout = df[df["record_id"].isin(load_ids("holdout"))]
# benign comparator from test only, never trained on
test_benign = df[df["record_id"].isin(load_ids("test")) & (df["label"] == 0)]

p_hold = model.predict_proba(pre.transform(holdout[features]))[:, 1]
pred_hold = (p_hold >= THRESHOLD).astype(int)

p_ben = model.predict_proba(pre.transform(test_benign[features]))[:, 1]
pred_ben = (p_ben >= THRESHOLD).astype(int)

tn, fp, fn, tp = confusion_matrix(test_benign["label"], pred_ben).ravel()
fpr = fp / (fp + tn)

row = {
    "n_holdout_malicious": int(len(holdout)),
    "holdout_recall": round(recall_score(holdout["label"], pred_hold), 3),
    "holdout_caught": int(pred_hold.sum()),
    "n_benign": int(len(test_benign)),
    "benign_fp": int(fp),
    "benign_fpr": round(fpr, 4),
    "threshold": THRESHOLD,
}
print(row)

os.makedirs(RESULT_DIR, exist_ok=True)
pd.DataFrame([row]).to_csv(os.path.join(RESULT_DIR, "e4_holdout.csv"), index=False)
print("saved results/e4_holdout.csv")
