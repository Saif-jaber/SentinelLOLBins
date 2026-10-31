import os
import json
import time
import numpy as np
import pandas as pd
import joblib

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

val = df[df["record_id"].isin(load_ids("val"))].reset_index(drop=True)
test = df[df["record_id"].isin(load_ids("test"))].reset_index(drop=True)

p_val = model.predict_proba(pre.transform(val[features]))[:, 1]
p_test = model.predict_proba(pre.transform(test[features]))[:, 1]
y_val = val["label"].values
y_test = test["label"].values

# metrics that never divide by zero
def scores(y, pred):
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return prec, rec, f1, fpr, tp, fp, fn, tn

# threshold sweep on validation only
rows = []
for t in np.round(np.arange(0.05, 1.0, 0.05), 2):
    prec, rec, f1, fpr, tp, fp, fn, tn = scores(y_val, (p_val >= t).astype(int))
    rows.append({
        "threshold": float(t),
        "precision": round(prec, 3),
        "recall": round(rec, 3),
        "f1": round(f1, 3),
        "fpr": round(fpr, 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    })

sweep = pd.DataFrame(rows)
sweep.to_csv(os.path.join(RESULT_DIR, "threshold_sweep_val.csv"), index=False)

# pick by validation F1, tie-break to the higher threshold (fewer false alarms)
best = sweep.sort_values(["f1", "threshold"], ascending=[False, False]).iloc[0]
CHOSEN = float(best["threshold"])
print("chosen threshold (val F1):", CHOSEN)

with open(os.path.join(RESULT_DIR, "chosen_threshold.json"), "w") as f:
    json.dump({
        "threshold": CHOSEN,
        "selected_on": "validation",
        "criterion": "max F1, tie-break higher threshold",
        "val_precision": float(best["precision"]),
        "val_recall": float(best["recall"]),
        "val_f1": float(best["f1"]),
        "val_fpr": float(best["fpr"]),
        "seed": 42,
    }, f, indent=2)

# final test numbers at the chosen threshold
pred_test = (p_test >= CHOSEN).astype(int)
prec, rec, f1, fpr, tp, fp, fn, tn = scores(y_test, pred_test)
test_row = {
    "threshold": CHOSEN, "precision": round(prec, 3), "recall": round(rec, 3),
    "f1": round(f1, 3), "fpr": round(fpr, 4),
    "tp": tp, "fp": fp, "fn": fn, "tn": tn,
}
pd.DataFrame([test_row]).to_csv(os.path.join(RESULT_DIR, "threshold_test.csv"), index=False)
print("test:", test_row)

# grouped bootstrap: resample command-template groups, not rows
group_ids = test["cmd_normalized"].values
groups = {}
for i, g in enumerate(group_ids):
    groups.setdefault(g, []).append(i)
keys = np.array(list(groups.keys()))
idx_arrays = {g: np.asarray(v) for g, v in groups.items()}
print("test groups:", len(keys))

rng = np.random.default_rng(42)
boot = []
for _ in range(1000):
    samp = rng.choice(keys, size=len(keys), replace=True)
    idx = np.concatenate([idx_arrays[g] for g in samp])
    p, r, f, fp_rate, *_ = scores(y_test[idx], pred_test[idx])
    boot.append((p, r, f, fp_rate))
boot = np.array(boot)

point = (prec, rec, f1, fpr)
ci = pd.DataFrame([{
    "metric": m,
    "point": round(point[i], 3),
    "ci_low": round(float(np.percentile(boot[:, i], 2.5)), 3),
    "ci_high": round(float(np.percentile(boot[:, i], 97.5)), 3),
    "n_boot": 1000,
    "unit": "command template (grouped)",
} for i, m in enumerate(["precision", "recall", "f1", "fpr"])])
ci.to_csv(os.path.join(RESULT_DIR, "ci_test.csv"), index=False)
print(ci.to_string(index=False))

# inference latency: single-event path and batched path
X_test_mat = pre.transform(test[features])
model.predict_proba(X_test_mat[:10])  # warmup

t0 = time.perf_counter()
model.predict_proba(X_test_mat)
t1 = time.perf_counter()
batch_ms = (t1 - t0) * 1000 / len(X_test_mat)

single = []
for i in range(200):
    row = test.iloc[[i]]
    s = time.perf_counter()
    model.predict_proba(pre.transform(row[features]))
    single.append((time.perf_counter() - s) * 1000)
single = np.array(single)

lat = pd.DataFrame([
    {"mode": "single_event (preprocess + predict)", "n": len(single),
     "mean_ms": round(float(single.mean()), 3),
     "median_ms": round(float(np.median(single)), 3),
     "p95_ms": round(float(np.percentile(single, 95)), 3)},
    {"mode": "batch per-event (predict only)", "n": len(X_test_mat),
     "mean_ms": round(batch_ms, 5),
     "median_ms": round(batch_ms, 5),
     "p95_ms": round(batch_ms, 5)},
])
lat.to_csv(os.path.join(RESULT_DIR, "latency.csv"), index=False)
print(lat.to_string(index=False))
print("saved threshold_sweep_val.csv, chosen_threshold.json, threshold_test.csv, ci_test.csv, latency.csv")
