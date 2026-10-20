import os
import pandas as pd

# for finding the directory that contains the path for data 
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "data", "raw")

# for looking / picking the right file for data whixh is the 10m one
big = [f for f in os.listdir(RAW) if "processed_features_10m" in f][0]
PATH = os.path.join(RAW, big)
df = pd.read_csv(PATH, nrows=200000)

#checking the values for the dataset to make sure
print("=== SHAPE ===")
print(df.shape)

print("=== COLUMNS ===")
print(df.columns.tolist())

print("=== FIRST ROW ===")
print(df.iloc[0])

print("=== NULLS ===")
print(df.isna().sum().sort_values(ascending=False))

print("=== CLASS COUNTS ===")
print(df["label"].value_counts())

PROC_DIR = os.path.join(BASE, "data", "processed")
os.makedirs(PROC_DIR, exist_ok=True)

benign = df[df["label"] == 0]
malicious = df[df["label"] == 1]

benign_50k = benign.sample(50000, random_state=42)
malicious_50k = malicious.sample(50000, random_state=42)

# ignore index to not have messy row numbers
subset = pd.concat([benign_50k, malicious_50k], ignore_index=True)

OUT = os.path.join(PROC_DIR, "sample_100k.parquet")
subset.to_parquet(OUT, index=False)

print("=== SUBSET ===")
print(subset.shape)
print(subset["label"].value_counts())