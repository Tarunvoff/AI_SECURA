"""
Master execution script for running all Step 4 per-dataset adapters,
reporting empirical row counts across all splits, and conducting spot checks.
"""

import json
import random
import sys
from pathlib import Path
from typing import Dict, Any, List

from datasets import load_dataset
from src.data.adapters.neuralchemy_2b_adapter import process_neuralchemy_2b
from src.data.adapters.neuralchemy_2a_adapter import process_neuralchemy_2a
from src.data.adapters.mosscap_adapter import process_mosscap

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


def run_spot_checks():
    """Spot check 5 random rows from each adapter's unified output against raw dataset rows."""
    print("\n" + "=" * 80)
    print("SPOT-CHECK COMPARISON: RAW VS. MAPPED CANONICAL OUTPUT (5 ROWS PER ADAPTER)")
    print("=" * 80)

    random.seed(42)

    # 1. Spot check neuralchemy_2b (train split)
    print("\n--- 1. Spot-check: neuralchemy_2b (train split) ---")
    raw_2b_intent = load_dataset("neuralchemy/prompt-injection-dataset-categorized", "intent", split="train")
    raw_2b_tech = load_dataset("neuralchemy/prompt-injection-dataset-categorized", "technique", split="train")
    with open("data/processed/neuralchemy_2b_train.jsonl", "r", encoding="utf-8") as f:
        unified_2b = [json.loads(line) for line in f]

    sample_2b = random.sample(unified_2b, 5)
    for idx, r in enumerate(sample_2b):
        # Extract row index from ID: neuralchemy_2b_train_{orig_idx}
        orig_idx = int(r["id"].rsplit("_", 1)[1])
        raw_row = {
            "intent": raw_2b_intent[orig_idx]["intent"],
            "text": raw_2b_intent[orig_idx]["text"],
            "technique": raw_2b_tech[orig_idx]["technique"],
        }
        print(f"\n[Spot-Check 2b #{idx+1}] ID: {r['id']}")
        print(f"  RAW ROW:  {raw_row}")
        print(f"  MAPPED:   {json.dumps(r, ensure_ascii=False)}")

    # 2. Spot check neuralchemy_2a (train split)
    print("\n--- 2. Spot-check: neuralchemy_2a (train split) ---")
    raw_2a = load_dataset("neuralchemy/Prompt-injection-dataset", "full", split="train")
    with open("data/processed/neuralchemy_2a_train.jsonl", "r", encoding="utf-8") as f:
        unified_2a = [json.loads(line) for line in f]

    sample_2a = random.sample(unified_2a, 5)
    for idx, r in enumerate(sample_2a):
        orig_idx = int(r["id"].rsplit("_", 1)[1])
        raw_row = {
            "category": raw_2a[orig_idx]["category"],
            "label": raw_2a[orig_idx]["label"],
            "severity": raw_2a[orig_idx]["severity"],
            "group_id": raw_2a[orig_idx]["group_id"],
            "text": raw_2a[orig_idx]["text"][:100],
        }
        print(f"\n[Spot-Check 2a #{idx+1}] ID: {r['id']}")
        print(f"  RAW ROW:  {raw_row}")
        print(f"  MAPPED:   {json.dumps(r, ensure_ascii=False)}")

    # 3. Spot check mosscap (train split)
    print("\n--- 3. Spot-check: mosscap (train split) ---")
    raw_mosscap = load_dataset("Lakera/mosscap_prompt_injection", split="train")
    with open("data/processed/mosscap_train.jsonl", "r", encoding="utf-8") as f:
        unified_mosscap = [json.loads(line) for line in f]

    sample_mosscap = random.sample(unified_mosscap, 5)
    for idx, r in enumerate(sample_mosscap):
        orig_idx = int(r["id"].rsplit("_", 1)[1])
        raw_row = {
            "level": raw_mosscap[orig_idx]["level"],
            "prompt": raw_mosscap[orig_idx]["prompt"][:100],
            "answer": raw_mosscap[orig_idx]["answer"][:100],
        }
        print(f"\n[Spot-Check Mosscap #{idx+1}] ID: {r['id']}")
        print(f"  RAW ROW:  {raw_row}")
        print(f"  MAPPED:   {json.dumps(r, ensure_ascii=False)}")


def main():
    print("=" * 80)
    print("RUNNING ALL STEP 4 PER-DATASET ADAPTERS")
    print("=" * 80)

    print("\n1. Running neuralchemy_2b adapter...")
    res_2b = process_neuralchemy_2b()

    print("\n2. Running neuralchemy_2a adapter...")
    res_2a = process_neuralchemy_2a()

    print("\n3. Running mosscap adapter...")
    res_mosscap = process_mosscap()

    print("\n" + "=" * 80)
    print("FINAL EMPIRICAL ROW-COUNT REPORT FOR ALL ADAPTERS & SPLITS")
    print("=" * 80)

    table_rows = []
    for r in res_2b:
        table_rows.append(("neuralchemy_2b", r["split"], r["total_in"], r["count_unified"], r["count_quarantined"]))
    for r in res_2a:
        table_rows.append(("neuralchemy_2a", r["split"], r["total_in"], r["count_unified"], r["count_quarantined"]))
    for r in res_mosscap:
        table_rows.append(("mosscap", r["split"], r["total_in"], r["count_unified"], r["count_quarantined"]))

    print(f"{'Dataset':<16} | {'Split':<10} | {'Total In':<10} | {'Unified':<10} | {'Quarantined':<12} | {'Quarantine %':<12}")
    print("-" * 80)
    for ds_name, split, total, unified, quar in table_rows:
        pct = (quar / total) * 100.0 if total > 0 else 0.0
        print(f"{ds_name:<16} | {split:<10} | {total:<10} | {unified:<10} | {quar:<12} | {pct:<11.2f}%")

    run_spot_checks()


if __name__ == "__main__":
    main()
