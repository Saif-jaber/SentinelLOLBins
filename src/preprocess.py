import os
import json
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
import joblib

# Repository paths.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
SPLITS = os.path.join(BASE, "data", "splits")

df = pd.read_parquet(os.path.join(PROC, "sample_100k.parquet"))

# Load the record ids for each split from its manifest.
def load_ids(name):
    with open(os.path.join(SPLITS, f"{name}.json")) as f:
        return set(json.load(f)["record_ids"])

train_ids = load_ids("train")
val_ids = load_ids("val")
test_ids = load_ids("test")
holdout_ids = load_ids("holdout")

print("train ids:", len(train_ids))
print("val ids:", len(val_ids))
print("test ids:", len(test_ids))

# Select the rows that belong to each split.
train = df[df["record_id"].isin(train_ids)]
val = df[df["record_id"].isin(val_ids)]
test = df[df["record_id"].isin(test_ids)]
holdout = df[df["record_id"].isin(holdout_ids)] # withheld techniques for E4

print("train rows:", len(train))
print("val rows:", len(val))
print("test rows:", len(test))
print("holdout rows:", len(holdout))

# Drop the target, metadata, and text columns that must not reach the tabular model.
DROP = [
    "label",  # target
    "mitre_technique", "command_source", "rule_category",  # label leakage
    "record_id", "dedup_key", "dataset_origin",  # ids and provenance
    "command_line", "cmd_normalized", "model_text",  # text used by the encoder branch
]

features = [c for c in df.columns if c not in DROP]
print("n features:", len(features))
print(features)

CATS = ["process_name", "parent_process"]
NUMS = [c for c in features if c not in CATS]
print("n numeric:", len(NUMS))
print("n categorical:", len(CATS))

# Fit the encoder on train only, then transform every split.
pre = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False, min_frequency=50), CATS),
    ("num", "passthrough", NUMS),
])

X_train = pre.fit_transform(train[features])
X_val   = pre.transform(val[features])
X_test  = pre.transform(test[features])
X_holdout = pre.transform(holdout[features])

y_train = train["label"]
y_val   = val["label"]
y_test  = test["label"]
y_holdout = holdout["label"]

print("X_train:", X_train.shape)
print("X_val:", X_val.shape)
print("X_test:", X_test.shape)

# Save the fitted preprocessor for reuse.
MODEL_DIR = os.path.join(BASE, "results", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(pre, os.path.join(MODEL_DIR, "preprocessor.joblib"))

cols = pre.get_feature_names_out()
for name, X, y in [
    ("train", X_train, y_train),
    ("val", X_val, y_val),
    ("test", X_test, y_test),
    ("holdout", X_holdout, y_holdout),
]:
    out = pd.DataFrame(X, columns=cols)
    out["label"] = y.values
    out.to_parquet(os.path.join(PROC, f"xgb_{name}.parquet"), index=False)
    print(name, out.shape)

print("saved preprocessor + matrices") 