import os
import json
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import precision_recall_curve, average_precision_score, confusion_matrix

#path stuff
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
SPLITS = os.path.join(BASE, "data", "splits")
MODEL_DIR = os.path.join(BASE, "results", "models")
RESULT_DIR = os.path.join(BASE, "results")
FIG_DIR = os.path.join(RESULT_DIR, "figures")

# using the same id loader so the rows match the xgb file
def load_ids(name):
    with open(os.path.join(SPLITS, f"{name}.json")) as f:
        return set(json.load(f)["record_ids"])

test_ids = load_ids("test")

raw = pd.read_parquet(os.path.join(PROC, "sample_100k.parquet"))
test = raw[raw["record_id"].isin(test_ids)].reset_index(drop=True)
mat = pd.read_parquet(os.path.join(PROC, "xgb_test.parquet"))

# making sure rows line up before trusting the join
assert (test["label"].values == mat["label"].values).all(), "rows are not aligned"

model = joblib.load(os.path.join(MODEL_DIR, "xgb_baseline.joblib"))
proba = model.predict_proba(mat.drop(columns=["label"]))[:, 1]
pred = (proba >= 0.5).astype(int)

tn, fp, fn, tp = confusion_matrix(test["label"], pred).ravel()
print(f"tn={tn} fp={fp} fn={fn} tp={tp}")

# table of every test event with its outcome to look at mistakes
events = pd.DataFrame({
    "record_id": test["record_id"],
    "process_name": test["process_name"],
    "parent_process": test["parent_process"],
    "command_line": test["command_line"],
    "mitre_technique": test["mitre_technique"],
    "true": test["label"],
    "proba": proba.round(4),
    "pred": pred,
})
events["outcome"] = "TN"
events.loc[(events.true == 1) & (events.pred == 1), "outcome"] = "TP"
events.loc[(events.true == 0) & (events.pred == 1), "outcome"] = "FP"
events.loc[(events.true == 1) & (events.pred == 0), "outcome"] = "FN"

def show(title, frame, n=5):
    print(f"\n{title}:")
    if frame.empty:
        print("  none")
        return
    for _, r in frame.head(n).iterrows():
        print(f"  proba={r.proba:.3f} proc={r.process_name} parent={r.parent_process}")
        print(f"    cmd={str(r.command_line)[:110]}")

show("false alarms (benign flagged, most confident first)",
     events[events.outcome == "FP"].sort_values("proba", ascending=False))
show("missed attacks (malicious passed, most confident benign first)",
     events[events.outcome == "FN"].sort_values("proba"))

# checking which techniques got missed
if fn > 0:
    print("\nmissed techniques:")
    print(events[events.outcome == "FN"]["mitre_technique"].value_counts().to_string())

os.makedirs(RESULT_DIR, exist_ok=True)
events.to_csv(os.path.join(RESULT_DIR, "test_event_outcomes.csv"), index=False)
print("\nsaved results/test_event_outcomes.csv")

# precision recall curve since the report asks for it in 4.1
prec, rec, thr = precision_recall_curve(test["label"], proba)
ap = average_precision_score(test["label"], proba)

fig, ax = plt.subplots(figsize=(6, 4))
ax.plot(rec, prec, label=f"XGBoost (AP={ap:.4f})")
for t, color in [(0.5, "tab:red"), (0.9, "tab:green")]:
    i = (thr >= t).argmax() if (thr >= t).any() else len(rec) - 1
    ax.scatter(rec[i], prec[i], color=color, zorder=3, label=f"t={t}")
ax.set_xlabel("Recall")
ax.set_ylabel("Precision")
ax.set_title("Precision-Recall, test set")
ax.legend()
ax.grid(alpha=0.3)
os.makedirs(FIG_DIR, exist_ok=True)
fig.tight_layout()
fig.savefig(os.path.join(FIG_DIR, "pr_curve_test.png"), dpi=150)
print("saved results/figures/pr_curve_test.png")
