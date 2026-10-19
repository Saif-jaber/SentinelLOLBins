import os
import json
import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
df = pd.read_parquet(os.path.join(BASE, "data", "processed", "sample_100k.parquet"))

print("loaded:", df.shape)

#taking some pieces of data for testing the generalization later with every 4th step
mal = df[df["label"] == 1]
techs = sorted(mal["mitre_technique"].dropna().unique())
holdout_techs = techs[::4]
print("total techniques:", len(techs))
print("holdout:", holdout_techs)

# filter the rows for the holdouts + filter the rest
holdout = df[df["mitre_technique"].isin(holdout_techs)]
rest = df[~df["mitre_technique"].isin(holdout_techs)]
print("holdout rows:", len(holdout), "| rest rows:", len(rest))

# from the rest of the rows filter the benign ones + template groups
benign = rest[rest["label"] == 0]
groups = benign["cmd_normalized"].drop_duplicates().sample(frac=1, random_state=42)
print("benign rows:", len(benign))
print("benign templates:", len(groups))

# spliting the ditribution for the model + taking the rows which is the corosponding to the 3 metrics + prints for checking to make sure
n = len(groups)
train_g = groups[:int(0.70 * n)]
val_g   = groups[int(0.70 * n):int(0.85 * n)]
test_g  = groups[int(0.85 * n):]

ben_train = benign[benign["cmd_normalized"].isin(train_g)]
ben_val   = benign[benign["cmd_normalized"].isin(val_g)]
ben_test  = benign[benign["cmd_normalized"].isin(test_g)]

print("benign train:", len(ben_train))
print("benign val:", len(ben_val))
print("benign test:", len(ben_test))

# same logic above but make for malicious attacks
mal_rest = rest[rest["label"] == 1]
mal_groups = mal_rest["cmd_normalized"].drop_duplicates().sample(frac=1, random_state=42)

n = len(mal_groups)
mal_train_g = mal_groups[:int(0.70 * n)]
mal_val_g   = mal_groups[int(0.70 * n):int(0.85 * n)]
mal_test_g  = mal_groups[int(0.85 * n):]

mal_train = mal_rest[mal_rest["cmd_normalized"].isin(mal_train_g)]
mal_val   = mal_rest[mal_rest["cmd_normalized"].isin(mal_val_g)]
mal_test  = mal_rest[mal_rest["cmd_normalized"].isin(mal_test_g)]

print("malicious train:", len(mal_train))
print("malicious val:", len(mal_val))
print("malicious test:", len(mal_test))

# combine all sets into one set for each metric for model use
train = pd.concat([ben_train, mal_train], ignore_index=True)
val   = pd.concat([ben_val,   mal_val],   ignore_index=True)
test  = pd.concat([ben_test,  mal_test],  ignore_index=True)

sets = [set(s["cmd_normalized"]) for s in (train, val, test)]
print("train∩val:", len(sets[0] & sets[1]))
print("train∩test:", len(sets[0] & sets[2]))
print("val∩test:", len(sets[1] & sets[2]))

# manifest for the evidence and for later tracebility and later debugging or model use
SPLIT_DIR = os.path.join(BASE, "data", "splits")
os.makedirs(SPLIT_DIR, exist_ok=True)

def dump(name, d):
    payload = {
        "n_rows": int(len(d)),
        "n_templates": int(d["cmd_normalized"].nunique()),
        "benign": int((d["label"] == 0).sum()),
        "malicious": int((d["label"] == 1).sum()),
        "record_ids": d["record_id"].tolist(),
    }
    with open(os.path.join(SPLIT_DIR, f"{name}.json"), "w") as f:
        json.dump(payload, f)
    print(f"{name:8} rows={len(d):6} benign={(d['label']==0).sum():6} mal={(d['label']==1).sum():6}")

dump("train", train)
dump("val", val)
dump("test", test)
dump("holdout", holdout)

manifest = {
    "seed": 42,
    "source": "sample_100k.parquet",
    "group_key": "cmd_normalized",
    "ratios": [0.70, 0.15, 0.15],
    "holdout_techniques": holdout_techs,
}
with open(os.path.join(SPLIT_DIR, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2)

print("manifests written")