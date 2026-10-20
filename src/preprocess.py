import os
import json
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
import joblib

#pathing stuff
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")
SPLITS = os.path.join(BASE, "data", "splits")

df = pd.read_parquet(os.path.join(PROC, "sample_100k.parquet"))

# extracting the ids from json into python 
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

# extracting the rows using the matching record id for each metric/variable
train = df[df["record_id"].isin(train_ids)]
val = df[df["record_id"].isin(val_ids)]
test = df[df["record_id"].isin(test_ids)]
holdout = df[df["record_id"].isin(holdout_ids)] # withheld techniques for E4

print("train rows:", len(train))
print("val rows:", len(val))
print("test rows:", len(test))
print("holdout rows:", len(holdout))

# dropping the non useful / harmful data for processing
DROP = [
    "label",    # target
    "mitre_technique", "command_source", "rule_category",  # Data leakage
    "record_id", "dedup_key", "dataset_origin",          # ids/meta (doesnt add any meaning)
    "command_line", "cmd_normalized", "model_text",     # text (belong for other model)
]

features = [c for c in df.columns if c not in DROP] # storing the other features
print("n features:", len(features))
print(features)

CATS = ["process_name", "parent_process"] # categorical data
NUMS = [c for c in features if c not in CATS] # numirical data
print("n numeric:", len(NUMS))
print("n categorical:", len(CATS))

# preprocess the data + configuring the input and target variables
pre = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False, min_frequency=50), CATS),
    ("num", "passthrough", NUMS),
])

X_train = pre.fit_transform(train[features]) # the input features
X_val   = pre.transform(val[features])
X_test  = pre.transform(test[features])
X_holdout = pre.transform(holdout[features]) # transform only, never fit

y_train = train["label"] # the target labels for each 
y_val   = val["label"]
y_test  = test["label"]
y_holdout = holdout["label"]

print("X_train:", X_train.shape)
print("X_val:", X_val.shape)
print("X_test:", X_test.shape)

# folder for saved models
MODEL_DIR = os.path.join(BASE, "results", "models")
os.makedirs(MODEL_DIR, exist_ok=True) # create it if missing

joblib.dump(pre, os.path.join(MODEL_DIR, "preprocessor.joblib")) # save the preprocessor to reuse

cols = pre.get_feature_names_out() # real names of the encoded columns
for name, X, y in [
    ("train", X_train, y_train),
    ("val", X_val, y_val),
    ("test", X_test, y_test),
    ("holdout", X_holdout, y_holdout),
]:
    out = pd.DataFrame(X, columns=cols) # turns numpy matrix into a proper pandas table with proper columns names
    out["label"] = y.values # last column that has the targets
    out.to_parquet(os.path.join(PROC, f"xgb_{name}.parquet"), index=False) # save each split
    print(name, out.shape)

print("saved preprocessor + matrices") 