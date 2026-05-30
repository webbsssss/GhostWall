"""Benchmark GhostWall against a labeled dataset.

Usage:
    python scripts/benchmark.py data/synthetic/test.jsonl
"""

import argparse
import json
import sys
import time

sys.path.insert(0, "src")

from ghostwall.core.pipeline import DetectionPipeline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", help="path to labeled jsonl file")
    args = parser.parse_args()

    p = DetectionPipeline()

    y_true, y_pred = [], []
    latencies = []
    labels = []

    with open(args.dataset, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            text = obj["text"]
            true = 1 if obj.get("malicious") else 0

            t0 = time.time()
            r = p.scan(text)
            latencies.append((time.time() - t0) * 1000)

            pred = 1 if r.is_malicious else 0
            y_true.append(true)
            y_pred.append(pred)
            labels.append(obj.get("label", "unknown"))

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(y_true) if y_true else 0.0

    print("=" * 50)
    print("Benchmark Results")
    print("=" * 50)
    print(f"Samples:     {len(y_true)}")
    print(f"Accuracy:    {accuracy:.3f}")
    print(f"Precision:   {precision:.3f}")
    print(f"Recall:      {recall:.3f}")
    print(f"F1:          {f1:.3f}")
    print(f"TP: {tp}  FP: {fp}  TN: {tn}  FN: {fn}")
    print(f"Latency:     {sum(latencies)/len(latencies):.1f}ms avg, {max(latencies):.1f}ms max")
    print("=" * 50)

    # per-label breakdown
    print("\nPer-label:")
    from collections import Counter
    breakdown = Counter()
    for label, t, p in zip(labels, y_true, y_pred):
        breakdown[f"{label}: true={t}, pred={p}"] += 1
    for key, count in breakdown.most_common():
        print(f"  {key}: {count}")


if __name__ == "__main__":
    main()
