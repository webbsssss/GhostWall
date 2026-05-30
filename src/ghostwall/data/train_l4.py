"""
Train the Layer 4 GRU stateful tracker.

Usage:
    python -m ghostwall.data.train_l4 data/synthetic/train.jsonl
"""

import argparse
import json
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sentence_transformers import SentenceTransformer


class TurnDataset(Dataset):
    def __init__(self, sequences: list, labels: list):
        self.sequences = sequences
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return torch.tensor(self.sequences[idx], dtype=torch.float32), torch.tensor(self.labels[idx], dtype=torch.float32)


class GRUTracker(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int):
        super().__init__()
        self.gru = nn.GRU(input_dim, hidden_dim, batch_first=True)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 1),
            nn.Sigmoid(),
        )

    def forward(self, x, h=None):
        out, h = self.gru(x, h)
        score = self.classifier(h.squeeze(0))
        return score, h


def collate_fn(batch):
    sequences, labels = zip(*batch)
    lengths = [len(s) for s in sequences]
    max_len = max(lengths)
    padded = torch.zeros(len(sequences), max_len, sequences[0].shape[-1])
    for i, seq in enumerate(sequences):
        padded[i, :len(seq)] = seq
    return padded, torch.stack(labels), lengths


def build_sequences(path: str, embedder, max_turns: int = 5):
    # build fake multi-turn sequences from single prompts
    # in a real setup, this would use actual conversation data
    texts, labels = [], []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            texts.append(obj["text"])
            labels.append(1 if obj.get("malicious") else 0)

    sequences = []
    seq_labels = []
    for i in range(0, len(texts) - max_turns, max_turns):
        turn_texts = texts[i:i + max_turns]
        embs = embedder.encode(turn_texts, normalize_embeddings=True)
        sequences.append(embs)
        # label as malicious if any turn is malicious
        seq_labels.append(float(any(labels[i:i + max_turns])))

    return sequences, seq_labels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", help="path to train.jsonl")
    parser.add_argument("--model", default="sentence-transformers/all-MiniLM-L6-v2")
    parser.add_argument("--hidden", type=int, default=256)
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--batch", type=int, default=32)
    parser.add_argument("--output", default="models/gru_tracker.pt")
    args = parser.parse_args()

    print("Loading embedder...")
    embedder = SentenceTransformer(args.model)

    print("Building sequences...")
    sequences, labels = build_sequences(args.dataset, embedder, max_turns=5)

    dataset = TurnDataset(sequences, labels)
    loader = DataLoader(dataset, batch_size=args.batch, shuffle=True, collate_fn=collate_fn)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = GRUTracker(input_dim=embedder.get_sentence_embedding_dimension(), hidden_dim=args.hidden)
    model.to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.BCELoss()

    print(f"Training on {device} for {args.epochs} epochs...")
    for epoch in range(args.epochs):
        total_loss = 0.0
        for x, y, _ in loader:
            x = x.to(device)
            y = y.to(device).unsqueeze(1)
            optimizer.zero_grad()
            pred, _ = model(x)
            loss = criterion(pred, y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"Epoch {epoch + 1}/{args.epochs}, loss={total_loss / len(loader):.4f}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), out)
    print(f"Saved model to {out}")


if __name__ == "__main__":
    main()
