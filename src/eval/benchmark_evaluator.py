"""
Master Benchmark Evaluator for Held-Out Evaluation Datasets.
Evaluates trained SecurityClassifier on AgentHarm, WildGuardMix, and Mindgard.
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
import torch
from transformers import AutoTokenizer

from configs.labels import NUM_LABELS, THREAT_LABELS
from src.eval.agentharm_loader import load_agentharm_eval_benchmark
from src.eval.wildguardmix_loader import load_wildguard_benchmark
from src.eval.mindgard_loader import load_mindgard_eval_benchmark
from src.models.security_classifier import SecurityClassifier

logger = logging.getLogger(__name__)


def evaluate_dataset_on_model(
    model: SecurityClassifier,
    tokenizer: Any,
    samples: List[Dict[str, Any]],
    device: torch.device,
    thresholds: Dict[str, float],
    batch_size: int = 32,
) -> Dict[str, Any]:
    """Runs forward inference on evaluation samples and computes per-threat detection rates."""
    model.eval()
    texts = [s["text"] for s in samples]
    total = len(texts)

    all_probs = []
    with torch.no_grad():
        for i in range(0, total, batch_size):
            batch_texts = texts[i : i + batch_size]
            enc = tokenizer(
                batch_texts,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt",
            )
            input_ids = enc["input_ids"].to(device)
            attention_mask = enc["attention_mask"].to(device)

            with torch.amp.autocast(device_type="cuda" if device.type == "cuda" else "cpu", enabled=(device.type == "cuda")):
                logits = model(input_ids=input_ids, attention_mask=attention_mask)

            probs = torch.sigmoid(logits).cpu().numpy()
            all_probs.append(probs)

    probs_matrix = np.vstack(all_probs)
    preds_matrix = np.zeros_like(probs_matrix)

    for idx, label_name in enumerate(THREAT_LABELS):
        thresh = thresholds.get(label_name, 0.5)
        preds_matrix[:, idx] = (probs_matrix[:, idx] >= thresh).astype(np.float32)

    # Compute trigger statistics
    label_trigger_counts = {}
    for idx, label_name in enumerate(THREAT_LABELS):
        triggered = int(np.sum(preds_matrix[:, idx]))
        label_trigger_counts[label_name] = {
            "triggered_count": triggered,
            "trigger_rate": float(triggered / total) if total > 0 else 0.0,
            "threshold_used": thresholds.get(label_name, 0.5),
        }

    any_threat_flagged = int(np.sum(np.any(preds_matrix == 1, axis=1)))

    return {
        "total_samples": total,
        "any_threat_flagged_count": any_threat_flagged,
        "overall_detection_rate": float(any_threat_flagged / total) if total > 0 else 0.0,
        "per_label_triggers": label_trigger_counts,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate model on held-out external security benchmarks")
    parser.add_argument("--model-path", type=str, default="models/checkpoints/best_model")
    parser.add_argument("--thresholds-path", type=str, default="thresholds.json")
    parser.add_argument("--benchmark", type=str, choices=["agentharm", "wildguard", "mindgard", "all"], default="all")
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device for benchmark evaluation: {device}")

    # Load thresholds
    thresholds = {}
    thresh_file = Path(args.thresholds_path)
    if thresh_file.exists():
        with open(thresh_file, "r", encoding="utf-8") as f:
            thresholds = json.load(f)
        print(f"Loaded tuned thresholds from {args.thresholds_path}")
    else:
        print("Using default 0.5 threshold for all labels.")
        thresholds = {label: 0.5 for label in THREAT_LABELS}

    print(f"Loading model from {args.model_path}...")
    model = SecurityClassifier.from_pretrained(args.model_path).to(device)
    tokenizer = AutoTokenizer.from_pretrained("microsoft/deberta-v3-base")

    benchmarks_to_run = []
    if args.benchmark in ["agentharm", "all"]:
        benchmarks_to_run.append(("AgentHarm (ai-safety-institute/AgentHarm)", load_agentharm_eval_benchmark))
    if args.benchmark in ["wildguard", "all"]:
        benchmarks_to_run.append(("WildGuardMix (allenai/wildguardmix)", load_wildguard_benchmark))
    if args.benchmark in ["mindgard", "all"]:
        benchmarks_to_run.append(("Mindgard Evasion (Mindgard/evaded-samples)", load_mindgard_eval_benchmark))

    for name, loader_fn in benchmarks_to_run:
        print("\n" + "=" * 80)
        print(f"EVALUATING BENCHMARK: {name}")
        print("=" * 80)
        try:
            samples = loader_fn(cache_locally=True)
            results = evaluate_dataset_on_model(
                model=model,
                tokenizer=tokenizer,
                samples=samples,
                device=device,
                thresholds=thresholds,
                batch_size=args.batch_size,
            )

            print(f"Total Benchmark Samples:      {results['total_samples']:,d}")
            print(f"Any Security Threat Flagged:  {results['any_threat_flagged_count']:,d} ({results['overall_detection_rate']:.2%})")
            print("-" * 80)
            print(f"{'Threat Category':<28} | {'Thresh':>7} | {'Triggered':>10} | {'Trigger Rate':>14}")
            print("-" * 80)
            for label, stats in results["per_label_triggers"].items():
                if stats["triggered_count"] > 0:
                    print(
                        f"{label:<28} | {stats['threshold_used']:>7.3f} | "
                        f"{stats['triggered_count']:>10,d} | {stats['trigger_rate']:>13.2%}"
                    )
            print("=" * 80)

        except Exception as e:
            print(f"Benchmark '{name}' failed: {e}")


if __name__ == "__main__":
    main()
