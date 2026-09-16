"""
Master pipeline script for Necent dataset loading, inspection, adapter execution,
GPU-accelerated deduplication/clustering, and split rebalancing (Steps 1-5).
"""

import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
import torch
from datasets import load_dataset

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from configs.labels import THREAT_LABELS
from src.data.adapters.necent_adapter import process_necent_dataset, DATASET_ID, AGENTHARM_CANARY
from src.data.merge_and_split import run_step6_merge, run_step7_dedup_and_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def enforce_gpu_check() -> torch.device:
    """Enforces strict GPU availability check with no silent CPU fallback."""
    print("=" * 80)
    print("CUDA GPU AVAILABILITY CHECK")
    print("=" * 80)
    assert torch.cuda.is_available(), "CUDA GPU not available — stopping. Do not fall back to CPU."
    device = torch.device("cuda")
    print(f"CUDA is available: True")
    print(f"Using device: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.2f} GB")
    print("=" * 80)
    return device


def step1_and_step2_inspect(ds) -> Dict[str, List[int]]:
    """Runs Step 1 (schema inspection) and Step 2 (isolating target sources)."""
    print("\n" + "=" * 80)
    print("STEP 1: LOAD AND INSPECT REAL SCHEMA")
    print("=" * 80)
    print(f"Total rows: {len(ds):,d}")
    print(f"Columns: {ds.column_names}")
    print(f"Sample row (0):\n{json.dumps(ds[0], indent=2, ensure_ascii=False)}")

    source_col = "source" if "source" in ds.column_names else None
    if not source_col:
        for col in ds.column_names:
            if "source" in col.lower() or "origin" in col.lower() or "dataset" in col.lower():
                source_col = col
                break

    if source_col:
        print(f"\nSub-source distribution (field: '{source_col}'):")
        counts = Counter(ds[source_col])
        for src, cnt in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  {str(src):<35} : {cnt:>7,d} rows")
    else:
        print("\n[WARNING] No 'source' column found. Inspecting individual columns:")
        for col in ds.column_names:
            print(f"  {col}: {ds[0][col]}")

    print("\n" + "=" * 80)
    print("STEP 2: ISOLATE INJECAGENT, TOOLEMU, AND AGENTHARM ROWS")
    print("=" * 80)

    target_sources = ["injecagent", "toolemu", "agentharm"]
    indices = {s: [] for s in target_sources}

    if source_col:
        for idx, val in enumerate(ds[source_col]):
            val_str = str(val).lower()
            for ts in target_sources:
                if ts in val_str:
                    indices[ts].append(idx)

    for ts in target_sources:
        matches = indices[ts]
        print(f"{ts.upper()}: {len(matches):,d} rows found")
        if matches:
            print(f"  Sample row from {ts.upper()} (idx {matches[0]}):")
            sample_row = ds[matches[0]]
            sample_str = json.dumps(sample_row, indent=2, ensure_ascii=False)
            print(sample_str[:400] + ("..." if len(sample_str) > 400 else ""))

    # AgentHarm canary check
    canary_hits = 0
    for idx in indices["agentharm"]:
        row_str = str(ds[idx]).lower()
        if AGENTHARM_CANARY.lower() in row_str:
            canary_hits += 1

    print(f"\nAgentHarm Canary Check (Canary GUID: '{AGENTHARM_CANARY}'):")
    print(f"  Total AgentHarm rows found: {len(indices['agentharm'])}")
    print(f"  Canary matches detected:    {canary_hits}")
    print("  -> AgentHarm rows are routed to data/eval_only/agentharm_from_necent.jsonl and EXCLUDED from training.")

    return indices


def step3_hand_check_samples(ds, indices: Dict[str, List[int]]):
    """Runs Step 3 (hand-checking real samples for label alignment)."""
    print("\n" + "=" * 80)
    print("STEP 3: HAND-CHECK SAMPLES BEFORE MAPPING LABELS")
    print("=" * 80)

    # 1. InjecAgent Samples
    inj_indices = indices.get("injecagent", [])
    print(f"\n--- INJECAGENT SAMPLES (Checking for AGENT_HIJACKING) ---")
    for i, idx in enumerate(inj_indices[:10], 1):
        row = ds[idx]
        print(f"\n[InjecAgent Sample #{i} | Row {idx}]")
        for k, v in row.items():
            val_str = str(v)
            if len(val_str) > 250:
                val_str = val_str[:250] + "..."
            print(f"  {k}: {val_str}")

    # 2. ToolEmu Samples
    tool_indices = indices.get("toolemu", [])
    print(f"\n--- TOOLEMU SAMPLES (Checking for TOOL_ABUSE) ---")
    for i, idx in enumerate(tool_indices[:10], 1):
        row = ds[idx]
        print(f"\n[ToolEmu Sample #{i} | Row {idx}]")
        for k, v in row.items():
            val_str = str(v)
            if len(val_str) > 250:
                val_str = val_str[:250] + "..."
            print(f"  {k}: {val_str}")


def count_labels_in_splits() -> Dict[str, Dict[str, int]]:
    """Counts label support across data/train, data/validation, and data/test splits."""
    counts = {}
    for split in ["train", "validation", "test"]:
        path = PROJECT_ROOT / "data" / split / f"{split}.jsonl"
        label_counter = Counter()
        total_rows = 0
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    row = json.loads(line)
                    total_rows += 1
                    for t in row.get("threats", []):
                        label_counter[t] += 1
            counts[split] = {"total_rows": total_rows, "labels": dict(label_counter)}
        else:
            counts[split] = {"total_rows": 0, "labels": {}}
    return counts


def main():
    # 1. Hard requirement: GPU check
    device = enforce_gpu_check()

    # 2. Load dataset
    print(f"\nLoading {DATASET_ID}...")
    ds = load_dataset(DATASET_ID, split="train")

    # 3. Steps 1 & 2: Inspection and source isolation
    indices = step1_and_step2_inspect(ds)

    # 4. Step 3: Hand check samples
    step3_hand_check_samples(ds, indices)

    # 5. Record counts BEFORE merge
    counts_before = count_labels_in_splits()

    # 6. Step 4: Run Necent adapter
    print("\n" + "=" * 80)
    print("STEP 4: RUNNING NECENT ADAPTER")
    print("=" * 80)
    necent_stats = process_necent_dataset()

    # 7. Step 5: GPU Deduplication, Clustering, and Re-splitting
    print("\n" + "=" * 80)
    print("STEP 5: GPU MERGE, DEDUPLICATION, AND STRATIFIED RE-SPLITTING")
    print("=" * 80)

    # Print GPU confirmation explicitly before clustering
    print(f"[GPU Confirmation] Embedding / clustering pipeline running on: {torch.cuda.get_device_name(0)}")

    # Run Step 6 merge
    run_step6_merge()

    # Run Step 7 dedup and split
    run_step7_dedup_and_split()

    # 8. Record counts AFTER merge
    counts_after = count_labels_in_splits()

    # 9. Print Before vs After Comparison Table
    print("\n" + "=" * 85)
    print("REAL BEFORE / AFTER LABEL COUNTS ACROSS SPLITS")
    print("=" * 85)
    print(f"{'Threat Label':<26} | {'Split':<10} | {'Before':>10} | {'After':>10} | {'Delta':>10}")
    print("-" * 85)

    for label_name in THREAT_LABELS:
        for split in ["train", "validation", "test"]:
            b_cnt = counts_before.get(split, {}).get("labels", {}).get(label_name, 0)
            a_cnt = counts_after.get(split, {}).get("labels", {}).get(label_name, 0)
            delta = a_cnt - b_cnt
            marker = f"+{delta}" if delta > 0 else str(delta)
            if label_name in ["AGENT_HIJACKING", "TOOL_ABUSE", "DATA_EXFILTRATION", "MALICIOUS_DOCUMENT"]:
                print(f"{label_name:<26} | {split:<10} | {b_cnt:>10,d} | {a_cnt:>10,d} | {marker:>10}")
        if label_name in ["AGENT_HIJACKING", "TOOL_ABUSE"]:
            print("-" * 85)

    print("\n" + "=" * 85)
    print("PIPELINE EXECUTION COMPLETE")
    print("=" * 85)


if __name__ == "__main__":
    main()
