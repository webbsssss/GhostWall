"""
Evaluate GhostWall against a labeled test set.

Usage:
    python -m ghostwall.data.evaluate data/synthetic/test.jsonl
"""

import argparse
import json
from pathlib import Path
from collections import Counter

from ghostwall.core.pipeline import DetectionPipeline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", help="path to test.jsonl")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    pipeline = DetectionPipeline(config_path=args.config)

    y_true, y_pred = [], []
    labels = []
    latencies = []

    with open(args.dataset, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            text = obj["text"]
            true_label = 1 if obj.get("malicious") else 0

            result = pipeline.scan(text)
            pred_label = 1 if result.is_malicious else 0

            y_true.append(true_label)
            y_pred.append(pred_label)
            labels.append(obj.get("label", "unknown"))
            latencies.append(result.latency_ms)

    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0

    print(f"Samples:    {len(y_true)}")
    print(f"Accuracy:   {accuracy:.3f}")
    print(f"Precision:  {precision:.3f}")
    print(f"Recall:     {recall:.3f}")
    print(f"F1:         {f1:.3f}")
    print(f"Latency:    {sum(latencies)/len(latencies):.1f}ms avg, {max(latencies):.1f}ms max")

    # per-label breakdown
    print("\nPer-label breakdown:")
    label_stats = Counter()
    for label, t, p in zip(labels, y_true, y_pred):
        key = f"{label}: true={t}, pred={p}"
        label_stats[key] += 1
    for key, count in label_stats.most_common():
        print(f"  {key}: {count}")


if __name__ == "__main__":
    main()
