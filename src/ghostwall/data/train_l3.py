"""
Train the Layer 3 embedding ensemble.

Usage:
    python -m ghostwall.data.train_l3 data/synthetic/train.jsonl
"""

import argparse
import json
from pathlib import Path
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss


def load_dataset(path: str):
    texts, labels = [], []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            texts.append(obj["text"])
            labels.append(1 if obj.get("malicious") else 0)
    return texts, np.array(labels, dtype=np.int32)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", help="path to train.jsonl")
    parser.add_argument("--model", default="sentence-transformers/all-MiniLM-L6-v2")
    parser.add_argument("--output", default="models/faiss.index")
    parser.add_argument("--dim", type=int, default=384)
    args = parser.parse_args()

    print("Loading dataset...")
    texts, labels = load_dataset(args.dataset)

    print("Computing embeddings...")
    embedder = SentenceTransformer(args.model)
    embeddings = embedder.encode(texts, show_progress_bar=True, normalize_embeddings=True)

    print("Building FAISS index...")
    index = faiss.IndexFlatIP(args.dim)  # inner product = cosine for normalized vecs
    index.add(embeddings.astype("float32"))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(out))
    print(f"Saved index to {out}")

    # save labels for reference
    label_path = out.with_suffix(".labels.npy")
    np.save(label_path, labels)
    print(f"Saved labels to {label_path}")


if __name__ == "__main__":
    main()
