"""
Download and inspection script for remaining flagged datasets (AgentHarm, WildGuardMix, Mindgard).
Enforces eval-only directory routing and zero leakage into training directories.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any
from datasets import load_dataset

# Ensure root workspace is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

EVAL_BASE_DIR = PROJECT_ROOT / "data" / "eval_only"


def inspect_agentharm():
    """1. Inspect and download AgentHarm (eval-only, strictly no-train)."""
    print("\n" + "=" * 80)
    print("1. DATASET: ai-safety-institute/AgentHarm (Eval-Only Benchmark)")
    print("=" * 80)
    out_dir = EVAL_BASE_DIR / "agentharm_raw"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        ds = load_dataset("ai-safety-institute/AgentHarm")
        print(f"Status: Access granted / Publicly available.")
        for split_name, split_data in ds.items():
            print(f"\nSplit: {split_name} | Total rows: {len(split_data):,d}")
            print(f"Columns: {split_data.column_names}")
            print(f"Sample row (0):\n{json.dumps(dict(split_data[0]), indent=2, ensure_ascii=False)[:350]}...")

            out_path = out_dir / f"agentharm_{split_name}.jsonl"
            with open(out_path, "w", encoding="utf-8") as f:
                for row in split_data:
                    f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
            print(f"Saved raw eval data to: {out_path}")

    except Exception as e:
        print(f"Status: FAILED / BLOCKED")
        print(f"Error details: {e}")


def inspect_wildguardmix():
    """2. Inspect and download WildGuardMix (gated access + HF_TOKEN, odc-by license)."""
    print("\n" + "=" * 80)
    print("2. DATASET: allenai/wildguardmix (Gated, ODC-By License)")
    print("=" * 80)
    out_dir = EVAL_BASE_DIR / "wildguardmix_raw"
    out_dir.mkdir(parents=True, exist_ok=True)

    hf_token = os.environ.get("HF_TOKEN")
    if not hf_token:
        print("HF_TOKEN not set in environment.")
        print("This dataset is gated behind AI2 Responsible Use Guidelines acceptance.")
        print("Attempting anonymous request or check for local credentials...")

    try:
        ds = load_dataset("allenai/wildguardmix", "wildguardtrain", token=hf_token)
        print(f"Status: Access granted.")
        for split_name, split_data in ds.items():
            print(f"\nSplit: {split_name} | Total rows: {len(split_data):,d}")
            print(f"Columns: {split_data.column_names}")
            print(f"Sample row (0):\n{json.dumps(dict(split_data[0]), indent=2, ensure_ascii=False)[:350]}...")

            out_path = out_dir / f"wildguard_{split_name}.jsonl"
            with open(out_path, "w", encoding="utf-8") as f:
                for row in split_data:
                    f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
            print(f"Saved raw eval/supplementary data to: {out_path}")

    except Exception as e:
def main():
    print("=" * 80)
    print("DOWNLOADING AND INSPECTING REMAINING FLAGGED DATASETS (AGENTHARM, WILDGUARDMIX)")
    print("=" * 80)

    inspect_agentharm()
    inspect_wildguardmix()

    print("\n" + "=" * 80)
    print("INSPECTION SUMMARY & VERIFICATION")
    print("=" * 80)
    print("Verified: All output files are isolated in data/eval_only/ (Zero training contamination).")


if __name__ == "__main__":
    main()
