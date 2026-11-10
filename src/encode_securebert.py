import os
import json
import time
import argparse
import numpy as np
import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModel

# Repository paths.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(BASE, "data", "processed")

p = argparse.ArgumentParser()
p.add_argument("--dataset", default=os.path.join(PROC, "sample_100k.parquet"))
p.add_argument("--splits", default=os.path.join(BASE, "data", "splits"))
p.add_argument("--out", default=os.path.join(PROC, "securebert"))
p.add_argument("--checkpoint", default="cisco-ai/SecureBERT2.0-base")
p.add_argument("--max-len", type=int, default=128)
p.add_argument("--batch", type=int, default=32)
args = p.parse_args()

OUT = args.out
os.makedirs(OUT, exist_ok=True)

CHECKPOINT = args.checkpoint  # fallback: ehsanaghaei/SecureBERT
MAX_LEN = args.max_len
BATCH = args.batch
POOLING = "mean"

os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

def load_ids(name):
    with open(os.path.join(args.splits, f"{name}.json")) as f:
        return set(json.load(f)["record_ids"])

df = pd.read_parquet(args.dataset)
print("dataset:", args.dataset, "| splits:", args.splits, "| out:", OUT)

print("loading", CHECKPOINT)
tok = AutoTokenizer.from_pretrained(CHECKPOINT)
model = AutoModel.from_pretrained(CHECKPOINT).eval()
print("loaded | threads", torch.get_num_threads())

def embed(texts):
    chunks = []
    t0 = time.time()
    with torch.inference_mode():
        for i in range(0, len(texts), BATCH):
            enc = tok(texts[i:i + BATCH], padding=True, truncation=True,
                      max_length=MAX_LEN, return_tensors="pt")
            out = model(**enc)
            mask = enc["attention_mask"].unsqueeze(-1).float()
            pooled = (out.last_hidden_state * mask).sum(1) / mask.sum(1)
            chunks.append(pooled.numpy().astype("float32"))
            if (i // BATCH) % 200 == 0:
                done = i + len(texts[i:i + BATCH])
                rate = done / max(time.time() - t0, 1e-9)
                print(f"  {done}/{len(texts)} rows | {rate:.1f} rows/s", flush=True)
    return np.vstack(chunks)

for name in ["train", "val", "test", "holdout"]:
    emb_path = os.path.join(OUT, f"{name}_emb.npy")
    meta_path = os.path.join(OUT, f"{name}_meta.parquet")
    if os.path.exists(emb_path) and os.path.exists(meta_path):
        print(f"{name}: exists, skipping")
        continue

    part = df[df["record_id"].isin(load_ids(name))].reset_index(drop=True)
    print(f"\n{name}: {len(part)} rows")
    t0 = time.time()
    emb = embed(part["model_text"].tolist())
    np.save(emb_path, emb)
    part[["record_id", "label", "mitre_technique", "cmd_normalized"]].to_parquet(meta_path, index=False)
    print(f"{name}: saved {emb.shape} in {time.time() - t0:.0f}s")

meta = {
    "checkpoint": CHECKPOINT,
    "dataset": os.path.relpath(args.dataset, BASE),
    "splits": os.path.relpath(args.splits, BASE),
    "max_length": MAX_LEN,
    "batch_size": BATCH,
    "pooling": POOLING,
    "hidden_size": int(np.load(os.path.join(OUT, "train_emb.npy"), mmap_mode="r").shape[1]),
    "transformers": __import__("transformers").__version__,
    "torch": torch.__version__,
    "seed": 42,
}
with open(os.path.join(OUT, "encoder_meta.json"), "w") as f:
    json.dump(meta, f, indent=2)
print("\nmeta:", meta)
