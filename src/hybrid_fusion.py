import os
import json
import time
import argparse
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# Repository paths.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
RESULT_DIR = os.path.join(BASE, "results")

p = argparse.ArgumentParser()
p.add_argument("--dataset", default=os.path.join(PROC, "sample_100k.parquet"))
p.add_argument("--splits", default=os.path.join(BASE, "data", "splits"))
p.add_argument("--emb-dir", default=os.path.join(PROC, "securebert"))
p.add_argument("--xgb-preprocessor", default=os.path.join(BASE, "results", "models", "preprocessor.joblib"))
p.add_argument("--xgb-model", default=os.path.join(BASE, "results", "models", "xgb_baseline.joblib"))
p.add_argument("--encoder-scaler", default=os.path.join(BASE, "results", "models", "encoder_scaler.joblib"))
p.add_argument("--encoder-head", default=os.path.join(BASE, "results", "models", "encoder_head.joblib"))
p.add_argument("--prefix", default="")
p.add_argument("--label", default="original")
p.add_argument("--debiased", action="store_true", help="use the debiased dataset, splits, embeddings and models")
args = p.parse_args()

if args.debiased:
    model_dir = os.path.join(RESULT_DIR, "models")
    args.dataset = os.path.join(PROC, "sample_100k_debiased.parquet")
    args.splits = os.path.join(BASE, "data", "splits_debiased")
    args.emb_dir = os.path.join(PROC, "securebert_debiased")
    args.xgb_preprocessor = os.path.join(model_dir, "debiased_preprocessor.joblib")
    args.xgb_model = os.path.join(model_dir, "debiased_xgb.joblib")
    args.encoder_scaler = os.path.join(model_dir, "debiased_encoder_scaler.joblib")
    args.encoder_head = os.path.join(model_dir, "debiased_encoder_head.joblib")
    args.prefix = "debiased_"
    args.label = "debiased"

os.makedirs(RESULT_DIR, exist_ok=True)

DROP = [
    "label",
    "mitre_technique", "command_source", "rule_category",
    "record_id", "dedup_key", "dataset_origin",
    "command_line", "cmd_normalized", "model_text",
]

def load_ids(name):
    with open(os.path.join(args.splits, f"{name}.json")) as f:
        return set(json.load(f)["record_ids"])

df = pd.read_parquet(args.dataset)
features = [c for c in df.columns if c not in DROP]

pre = joblib.load(args.xgb_preprocessor)
xgb = joblib.load(args.xgb_model)
scaler = joblib.load(args.encoder_scaler)
head = joblib.load(args.encoder_head)

def part(name):
    t0 = time.time()
    print(f"[part] {name}: loading subset", flush=True)
    sub = df[df["record_id"].isin(load_ids(name))].reset_index(drop=True)
    emb = np.load(os.path.join(args.emb_dir, f"{name}_emb.npy"))
    meta = pd.read_parquet(os.path.join(args.emb_dir, f"{name}_meta.parquet")).reset_index(drop=True)
    rid_to_idx = pd.Series(meta.index.values, index=meta.record_id.values)
    idx = rid_to_idx.loc[sub["record_id"].values].values
    assert (meta["label"].values[idx] == sub["label"].values).all(), f"{name} labels misaligned"
    print(f"[part] {name}: xgb transform ({len(sub)} rows)", flush=True)
    p_xgb = xgb.predict_proba(pre.transform(sub[features]))[:, 1]
    print(f"[part] {name}: encoder transform", flush=True)
    p_enc = head.predict_proba(scaler.transform(emb[idx]))[:, 1]
    print(f"[part] {name}: done in {time.time()-t0:.1f}s", flush=True)
    return sub, p_xgb, p_enc

data = {n: part(n) for n in ["train", "val", "test", "holdout"]}
y = {n: data[n][0]["label"].values for n in data}
print({n: len(y[n]) for n in y})

def scores(y_true, pred):
    tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
    return {
        "precision": precision_score(y_true, pred, zero_division=0),
        "recall": recall_score(y_true, pred, zero_division=0),
        "f1": f1_score(y_true, pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }

def choose_threshold(proba, y_true):
    best_t, best_f1 = 0.5, -1.0
    for t in [round(x * 0.05, 2) for x in range(1, 20)]:
        f1 = f1_score(y_true, (proba >= t).astype(int), zero_division=0)
        if f1 > best_f1:
            best_t, best_f1 = t, f1
    return best_t

# choose blend weight and threshold on validation only
best = None
for w in np.round(np.arange(0.0, 1.01, 0.05), 2):
    p_va = w * data["val"][1] + (1 - w) * data["val"][2]
    t = choose_threshold(p_va, y["val"])
    s = scores(y["val"], (p_va >= t).astype(int))
    key = (round(s["f1"], 6), -round(s["fpr"], 6), -abs(w - 0.5))
    if best is None or key > best[0]:
        best = (key, float(w), t, s)

_, W, T, val_s = best
print(f"chosen fusion: w_xgb={W} (w_encoder={round(1-W,2)}) threshold={T} val_f1={val_s['f1']:.4f}")

rows = []
def add(method, w, t, test_p, hold_p):
    s = scores(y["test"], (test_p >= t).astype(int))
    ho_rec = recall_score(y["holdout"], (hold_p >= t).astype(int), zero_division=0)
    ben = y["test"] == 0
    ben_fpr = float(((test_p >= t).astype(int)[ben]).mean())
    rows.append({
        "dataset": args.label, "method": method, "w_xgb": w, "threshold": t,
        "precision": round(s["precision"], 3), "recall": round(s["recall"], 3),
        "f1": round(s["f1"], 3), "fpr": round(s["fpr"], 4),
        "holdout_recall": round(ho_rec, 3), "holdout_benign_fpr": round(ben_fpr, 4),
    })

# ablations: each single arm gets its own validation threshold
t_xgb = choose_threshold(data["val"][1], y["val"])
t_enc = choose_threshold(data["val"][2], y["val"])
add("XGBoost only", 1.0, t_xgb, data["test"][1], data["holdout"][1])
add("SecureBERT only (no context)", 0.0, t_enc, data["test"][2], data["holdout"][2])

p_test = W * data["test"][1] + (1 - W) * data["test"][2]
p_hold = W * data["holdout"][1] + (1 - W) * data["holdout"][2]
add("Fusion (XGB + SecureBERT)", W, T, p_test, p_hold)

out = pd.DataFrame(rows)
out.to_csv(os.path.join(RESULT_DIR, f"{args.prefix}fusion_results.csv"), index=False)
print(out.to_string(index=False))

# grouped CI for the fusion arm
pred = (p_test >= T).astype(int)
gids = data["test"][0]["cmd_normalized"].values
groups = {}
for i, g in enumerate(gids):
    groups.setdefault(g, []).append(i)
keys = np.array(list(groups.keys()))
idx_arrays = {g: np.asarray(v) for g, v in groups.items()}
rng = np.random.default_rng(42)
boot = []
for i in range(1000):
    samp = rng.choice(keys, size=len(keys), replace=True)
    idx = np.concatenate([idx_arrays[g] for g in samp])
    s = scores(y["test"][idx], pred[idx])
    boot.append((s["precision"], s["recall"], s["f1"], s["fpr"]))
    if i % 200 == 0:
        print(f"[ci] {i}/1000 groups={len(keys)}", flush=True)
boot = np.array(boot)
point = scores(y["test"], pred)
pt = [point["precision"], point["recall"], point["f1"], point["fpr"]]
ci = pd.DataFrame([{
    "metric": m,
    "point": round(pt[i], 3),
    "ci_low": round(float(np.percentile(boot[:, i], 2.5)), 3),
    "ci_high": round(float(np.percentile(boot[:, i], 97.5)), 3),
    "n_boot": 1000,
    "unit": "command template (grouped)",
} for i, m in enumerate(["precision", "recall", "f1", "fpr"])])
ci.to_csv(os.path.join(RESULT_DIR, f"{args.prefix}fusion_ci.csv"), index=False)
print(ci.to_string(index=False))

with open(os.path.join(RESULT_DIR, f"{args.prefix}fusion_config.json"), "w") as f:
    json.dump({
        "dataset": args.label,
        "fusion": "weighted average of calibrated probabilities",
        "w_xgb": W, "w_encoder": round(1 - W, 2),
        "threshold": T,
        "selected_on": "validation (F1, tie-break lower FPR)",
        "seed": 42,
    }, f, indent=2)
print(f"\nsaved {args.prefix}fusion_results.csv, {args.prefix}fusion_ci.csv, {args.prefix}fusion_config.json")
