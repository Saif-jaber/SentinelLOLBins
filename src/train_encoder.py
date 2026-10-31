import os
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

#path stuff
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
OUT = os.path.join(PROC, "securebert")
RESULT_DIR = os.path.join(BASE, "results")

def load(name):
    emb = np.load(os.path.join(OUT, f"{name}_emb.npy"))
    meta = pd.read_parquet(os.path.join(OUT, f"{name}_meta.parquet"))
    assert len(emb) == len(meta), f"{name} embeddings/meta misaligned"
    return emb, meta

Xtr, mtr = load("train")
Xva, mva = load("val")
Xte, mte = load("test")
Xho, mho = load("holdout")

ytr, yva = mtr["label"].values, mva["label"].values
yte, yho = mte["label"].values, mho["label"].values
print("shapes:", Xtr.shape, Xva.shape, Xte.shape, Xho.shape)

# scale fit on train only
scaler = StandardScaler().fit(Xtr)
Ztr, Zva = scaler.transform(Xtr), scaler.transform(Xva)
Zte, Zho = scaler.transform(Xte), scaler.transform(Xho)

def scores(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }

def choose_threshold(proba, y):
    best_t, best_f1 = 0.5, -1.0
    for t in [round(x * 0.05, 2) for x in range(1, 20)]:
        f1 = f1_score(y, (proba >= t).astype(int), zero_division=0)
        if f1 > best_f1 or (f1 == best_f1 and t > best_t):
            best_t, best_f1 = t, f1
    return best_t

# small C grid chosen on validation F1 only
best = None
for C in [0.1, 1.0, 10.0]:
    clf = LogisticRegression(C=C, max_iter=2000, solver="lbfgs")
    clf.fit(Ztr, ytr)
    p_va = clf.predict_proba(Zva)[:, 1]
    t = choose_threshold(p_va, yva)
    f1 = f1_score(yva, (p_va >= t).astype(int), zero_division=0)
    print(f"C={C}: val threshold={t} val_f1={f1:.4f}")
    if best is None or f1 > best[0]:
        best = (f1, C, t, clf)
    else:
        pass

val_f1, CHOSEN_C, CHOSEN_T, clf = best
print("chosen C:", CHOSEN_C, "| threshold:", CHOSEN_T)

p_te = clf.predict_proba(Zte)[:, 1]
pred_te = (p_te >= CHOSEN_T).astype(int)
te = scores(yte, pred_te)

p_ho = clf.predict_proba(Zho)[:, 1]
pred_ho = (p_ho >= CHOSEN_T).astype(int)
ho_recall = recall_score(yho, pred_ho, zero_division=0)

# benign FPR for E4 uses test benign events only
ben_mask = yte == 0
ben_fpr = pred_te[ben_mask].mean()

row = {
    "model": "SecureBERT2.0 frozen + logistic",
    "checkpoint": json.load(open(os.path.join(OUT, "encoder_meta.json")))["checkpoint"],
    "C": CHOSEN_C,
    "threshold": CHOSEN_T,
    "precision": round(te["precision"], 3),
    "recall": round(te["recall"], 3),
    "f1": round(te["f1"], 3),
    "fpr": round(te["fpr"], 4),
    "holdout_recall": round(ho_recall, 3),
    "holdout_benign_fpr": round(float(ben_fpr), 4),
}
pd.DataFrame([row]).to_csv(os.path.join(RESULT_DIR, "e2_encoder.csv"), index=False)
print(row)

# Y. grouped bootstrap CI on test
group_ids = mte["cmd_normalized"].values
groups = {}
for i, g in enumerate(group_ids):
    groups.setdefault(g, []).append(i)
keys = np.array(list(groups.keys()))
idx_arrays = {g: np.asarray(v) for g, v in groups.items()}
rng = np.random.default_rng(42)
boot = []
for _ in range(1000):
    samp = rng.choice(keys, size=len(keys), replace=True)
    idx = np.concatenate([idx_arrays[g] for g in samp])
    p, r, f, fr = scores(yte[idx], pred_te[idx]).values()
    boot.append((p, r, f, fr))
boot = np.array(boot)

point = [te["precision"], te["recall"], te["f1"], te["fpr"]]
ci = pd.DataFrame([{
    "metric": m,
    "point": round(point[i], 3),
    "ci_low": round(float(np.percentile(boot[:, i], 2.5)), 3),
    "ci_high": round(float(np.percentile(boot[:, i], 97.5)), 3),
    "n_boot": 1000,
    "unit": "command template (grouped)",
} for i, m in enumerate(["precision", "recall", "f1", "fpr"])])
ci.to_csv(os.path.join(RESULT_DIR, "ci_encoder.csv"), index=False)
print(ci.to_string(index=False))

# E2 comparison table: XGBoost (validation threshold) vs encoder
xgb = pd.read_csv(os.path.join(RESULT_DIR, "threshold_test.csv")).iloc[0]
comp = pd.DataFrame([
    {"model": "XGBoost (full context)", "threshold": xgb["threshold"],
     "precision": xgb["precision"], "recall": xgb["recall"],
     "f1": xgb["f1"], "fpr": xgb["fpr"]},
    {"model": row["model"], "threshold": row["threshold"],
     "precision": row["precision"], "recall": row["recall"],
     "f1": row["f1"], "fpr": row["fpr"]},
])
comp.to_csv(os.path.join(RESULT_DIR, "e2_comparison.csv"), index=False)
print("\nE2 comparison:")
print(comp.to_string(index=False))

with open(os.path.join(RESULT_DIR, "encoder_config.json"), "w") as f:
    json.dump({
        "checkpoint": row["checkpoint"],
        "pooling": "mean",
        "scaler": "StandardScaler fit on train",
        "C": CHOSEN_C,
        "threshold": CHOSEN_T,
        "selected_on": "validation F1",
        "seed": 42,
    }, f, indent=2)
print("\nsaved results/e2_encoder.csv, ci_encoder.csv, e2_comparison.csv, encoder_config.json")
