import os
import pandas as pd

# Repository root and raw-data directory.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "data", "raw")

# Use the full 10m processed-features export and audit a 200k-row prefix.
big = [f for f in os.listdir(RAW) if "processed_features_10m" in f][0]
PATH = os.path.join(RAW, big)
df = pd.read_csv(PATH, nrows=200000)

# Quick profile of the source file.
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

# Reset row numbers after combining the two samples.
subset = pd.concat([benign_50k, malicious_50k], ignore_index=True)

OUT = os.path.join(PROC_DIR, "sample_100k.parquet")
subset.to_parquet(OUT, index=False)

print("=== SUBSET ===")
print(subset.shape)
print(subset["label"].value_counts())