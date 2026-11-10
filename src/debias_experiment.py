import os
import re
import json
import math
import numpy as np
import pandas as pd
import joblib
from collections import Counter
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from xgboost import XGBClassifier

# Repository paths.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
SPLITS = os.path.join(BASE, "data", "splits")
SPLITS_OUT = os.path.join(BASE, "data", "splits_debiased")
RESULT_DIR = os.path.join(BASE, "results")
MODEL_DIR = os.path.join(BASE, "results", "models")
os.makedirs(SPLITS_OUT, exist_ok=True)

# 1. Remove generator markers and repair the fields they affected.
MARKER = re.compile(r"-?[A-Za-z0-9_:-]*wlgt[A-Za-z0-9_:-]*", re.I)

def clean_text(s):
    s = MARKER.sub("", str(s))
    return re.sub(r"\s+", " ", s).strip()

def entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

df = pd.read_parquet(os.path.join(PROC, "sample_100k.parquet"))
orig_benign_groups = df[df.label == 0]["cmd_normalized"].nunique()
orig_mal_groups = df[df.label == 1]["cmd_normalized"].nunique()

df["command_line"] = df["command_line"].map(clean_text)
df["cmd_normalized"] = df["cmd_normalized"].map(clean_text)
df["model_text"] = ("proc=" + df["process_name"].astype(str)
                    + " | parent=" + df["parent_process"].astype(str)
                    + " | cmd=" + df["command_line"].astype(str))

# only the five features the marker directly changed are recomputed
df["cmd_len"] = df["command_line"].str.len()
df["cmd_token_count"] = df["command_line"].str.split().str.len()
df["cmd_entropy"] = df["command_line"].map(entropy)
df["cmd_avg_token_len"] = df["cmd_len"] / df["cmd_token_count"].replace(0, np.nan)
df["cmd_avg_token_len"] = df["cmd_avg_token_len"].fillna(0.0)
df["cmd_dash_count"] = df["command_line"].str.count("-")

# drop the few templates that occur in both classes (cross-class leakage)
ben_groups = set(df[df.label == 0]["cmd_normalized"])
mal_groups = set(df[df.label == 1]["cmd_normalized"])
shared = ben_groups & mal_groups
df = df[~df["cmd_normalized"].isin(shared)].reset_index(drop=True)

clean_benign_groups = df[df.label == 0]["cmd_normalized"].nunique()
clean_mal_groups = df[df.label == 1]["cmd_normalized"].nunique()
print("benign groups:", orig_benign_groups, "->", clean_benign_groups)
print("malicious groups:", orig_mal_groups, "->", clean_mal_groups)
print("rows dropped for cross-class templates:", int(len(shared)))

df.to_parquet(os.path.join(PROC, "sample_100k_debiased.parquet"), index=False)

# 2. Build group-aware splits from the cleaned template key.
manifest = json.load(open(os.path.join(SPLITS, "manifest.json")))
holdout_techs = manifest["holdout_techniques"]

holdout = df[df["mitre_technique"].isin(holdout_techs)]
rest = df[~df["mitre_technique"].isin(holdout_techs)]

def split_groups(frame, seed=42):
    groups = frame["cmd_normalized"].drop_duplicates().sample(frac=1, random_state=seed)
    n = len(groups)
    return (groups[:int(0.70 * n)], groups[int(0.70 * n):int(0.85 * n)], groups[int(0.85 * n):])

ben = rest[rest.label == 0]
mal = rest[rest.label == 1]
btr, bva, bte = split_groups(ben)
mtr, mva, mte = split_groups(mal)

train = pd.concat([ben[ben.cmd_normalized.isin(btr)], mal[mal.cmd_normalized.isin(mtr)]], ignore_index=True)
val = pd.concat([ben[ben.cmd_normalized.isin(bva)], mal[mal.cmd_normalized.isin(mva)]], ignore_index=True)
test = pd.concat([ben[ben.cmd_normalized.isin(bte)], mal[mal.cmd_normalized.isin(mte)]], ignore_index=True)

seen = set(train.cmd_normalized) | set(val.cmd_normalized) | set(test.cmd_normalized)
holdout_before = len(holdout)
holdout = holdout[~holdout["cmd_normalized"].isin(seen)]

print("split sizes: train", len(train), "val", len(val), "test", len(test), "holdout", len(holdout))
print("holdout overlap dropped:", holdout_before - len(holdout))

def dump(name, d):
    payload = {
        "n_rows": int(len(d)),
        "n_templates": int(d["cmd_normalized"].nunique()),
        "benign": int((d["label"] == 0).sum()),
        "malicious": int((d["label"] == 1).sum()),
        "record_ids": d["record_id"].tolist(),
    }
    json.dump(payload, open(os.path.join(SPLITS_OUT, f"{name}.json"), "w"))
    print(f"{name:8} rows={len(d):6} benign={(d['label']==0).sum():6} mal={(d['label']==1).sum():6}")

for name, d in [("train", train), ("val", val), ("test", test), ("holdout", holdout)]:
    dump(name, d)

json.dump({
    "source": "sample_100k_debiased.parquet",
    "seed": 42,
    "group_key": "cmd_normalized (WLGT markers removed)",
    "ratios": [0.70, 0.15, 0.15],
    "holdout_techniques": holdout_techs,
    "shared_templates_dropped": sorted(map(str, shared)),
    "benign_groups_before_after": [orig_benign_groups, clean_benign_groups],
    "malicious_groups_before_after": [orig_mal_groups, clean_mal_groups],
    "holdout_template_overlap_dropped": int(holdout_before - len(holdout)),
}, open(os.path.join(SPLITS_OUT, "manifest.json"), "w"), indent=2)

# 3. Use the same features and preprocessing as the main XGBoost run.
DROP = [
    "label",
    "mitre_technique", "command_source", "rule_category",
    "record_id", "dedup_key", "dataset_origin",
    "command_line", "cmd_normalized", "model_text",
]
features = [c for c in df.columns if c not in DROP]
CATS = ["process_name", "parent_process"]
NUMS = [c for c in features if c not in CATS]

pre = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False, min_frequency=50), CATS),
    ("num", "passthrough", NUMS),
])
Xtr = pre.fit_transform(train[features])
Xva = pre.transform(val[features])
Xte = pre.transform(test[features])
Xho = pre.transform(holdout[features])

model = XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8, eval_metric="logloss",
    random_state=42, n_jobs=-1,
)
model.fit(Xtr, train["label"], eval_set=[(Xva, val["label"])], verbose=False)

# persist for fusion / score_event reuse
os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(pre, os.path.join(MODEL_DIR, "debiased_preprocessor.joblib"))
joblib.dump(model, os.path.join(MODEL_DIR, "debiased_xgb.joblib"))

def choose_threshold(proba, y):
    best_t, best_f1 = 0.5, -1.0
    for t in [round(x * 0.05, 2) for x in range(1, 20)]:
        f1 = f1_score(y, (proba >= t).astype(int), zero_division=0)
        if f1 > best_f1:
            best_t, best_f1 = t, f1
    return best_t

def summarize(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }

p_va = model.predict_proba(Xva)[:, 1]
THR = choose_threshold(p_va, val["label"])
p_te = model.predict_proba(Xte)[:, 1]
pred_te = (p_te >= THR).astype(int)
te = summarize(test["label"], pred_te)
p_ho = model.predict_proba(Xho)[:, 1]
ho_rec = recall_score(holdout["label"], (p_ho >= THR).astype(int), zero_division=0)
ben_mask = test["label"].values == 0
ben_fpr = float(pred_te[ben_mask].mean())

row = {
    "model": "XGBoost (debiased dataset)",
    "threshold": THR,
    "precision": round(te["precision"], 3),
    "recall": round(te["recall"], 3),
    "f1": round(te["f1"], 3),
    "fpr": round(te["fpr"], 4),
    "holdout_recall": round(ho_rec, 3),
    "holdout_benign_fpr": round(ben_fpr, 4),
}
pd.DataFrame([row]).to_csv(os.path.join(RESULT_DIR, "debias_xgb.csv"), index=False)

# grouped bootstrap CI on the debiased test set
gids = test["cmd_normalized"].values
groups = {}
for i, g in enumerate(gids):
    groups.setdefault(g, []).append(i)
keys = np.array(list(groups.keys()))
idx_arrays = {g: np.asarray(v) for g, v in groups.items()}
rng = np.random.default_rng(42)
boot = []
for _ in range(1000):
    samp = rng.choice(keys, size=len(keys), replace=True)
    idx = np.concatenate([idx_arrays[g] for g in samp])
    s = summarize(test["label"].values[idx], pred_te[idx])
    boot.append((s["precision"], s["recall"], s["f1"], s["fpr"]))
boot = np.array(boot)

point = [te["precision"], te["recall"], te["f1"], te["fpr"]]
ci = pd.DataFrame([{
    "metric": m,
    "point": round(point[i], 3),
    "ci_low": round(float(np.percentile(boot[:, i], 2.5)), 3),
    "ci_high": round(float(np.percentile(boot[:, i], 97.5)), 3),
    "n_boot": 1000,
    "unit": "command template (grouped, debiased)",
} for i, m in enumerate(["precision", "recall", "f1", "fpr"])])
ci.to_csv(os.path.join(RESULT_DIR, "debias_ci.csv"), index=False)

print(row)
print(ci.to_string(index=False))

# comparison against the original (marker-contaminated) run
orig = pd.read_csv(os.path.join(RESULT_DIR, "threshold_test.csv")).iloc[0]
comp = pd.DataFrame([
    {"dataset": "original", "threshold": orig["threshold"], "precision": orig["precision"],
     "recall": orig["recall"], "f1": orig["f1"], "fpr": orig["fpr"]},
    {"dataset": "debiased", "threshold": row["threshold"], "precision": row["precision"],
     "recall": row["recall"], "f1": row["f1"], "fpr": row["fpr"]},
])
comp.to_csv(os.path.join(RESULT_DIR, "debias_comparison.csv"), index=False)
print("\noriginal vs debiased:")
print(comp.to_string(index=False))
print("\nsaved debiased dataset, splits, and results/debias_*.csv")
