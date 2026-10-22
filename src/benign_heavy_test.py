import os
import pandas as pd
import joblib
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

#path stuff
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
MODEL_DIR = os.path.join(BASE, "results", "models")
RESULT_DIR = os.path.join(BASE, "results")

# loading the trained model, no training here
model = joblib.load(os.path.join(MODEL_DIR, "xgb_baseline.joblib"))

test = pd.read_parquet(os.path.join(PROC, "xgb_test.parquet"))
X_test = test.drop(columns=["label"])
y_test = test["label"]

benign = test[test["label"] == 0]
mal = test[test["label"] == 1]

# realistic prevalence, 1 malicious per 100 benign (about 1%)
n_mal = max(1, len(benign) // 100)
mal_slice = mal.sample(n_mal, random_state=42)
heavy = pd.concat([benign, mal_slice], ignore_index=True)
Xh = heavy.drop(columns=["label"])
yh = heavy["label"]

print("benign-heavy set:", len(heavy), "| benign:", len(benign), "| malicious:", len(mal_slice))

proba = model.predict_proba(Xh)[:, 1]
pred = (proba >= 0.5).astype(int)

tn, fp, fn, tp = confusion_matrix(yh, pred).ravel()
print(f"precision={precision_score(yh, pred):.3f} recall={recall_score(yh, pred):.3f} "
      f"f1={f1_score(yh, pred):.3f} fpr={fp / (fp + tn):.4f}")
print(f"tn={tn} fp={fp} fn={fn} tp={tp}")
print(f"false alarms per 10,000 benign events: {fp / len(benign) * 10000:.1f}")

# checking higher thresholds to see how precision and recall move
for t in [0.5, 0.9, 0.99]:
    pred_t = (proba >= t).astype(int)
    tn_, fp_, fn_, tp_ = confusion_matrix(yh, pred_t).ravel()
    print(f"t={t:.2f} precision={precision_score(yh, pred_t):.3f} "
          f"recall={recall_score(yh, pred_t):.3f} fpr={fp_ / (fp_ + tn_):.4f}")

# saving the summary numbers
out = pd.DataFrame([{
    "n_benign": len(benign),
    "n_malicious": len(mal_slice),
    "precision": round(precision_score(yh, pred), 3),
    "recall": round(recall_score(yh, pred), 3),
    "f1": round(f1_score(yh, pred), 3),
    "fpr": round(fp / (fp + tn), 4),
    "fp": int(fp),
    "fn": int(fn),
}])
os.makedirs(RESULT_DIR, exist_ok=True)
out.to_csv(os.path.join(RESULT_DIR, "benign_heavy_results.csv"), index=False)
print("\nsaved results/benign_heavy_results.csv")
