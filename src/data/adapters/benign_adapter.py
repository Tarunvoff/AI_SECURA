"""
Fast HuggingFace Benign Dataset Ingestion Adapter for AI_SECURA.
==============================================================
Directly ingests 40,000+ real, high-quality, diverse benign instruction prompts
from Hugging Face (tatsu-lab/alpaca / databricks-dolly-15k) in seconds.
Eliminates positive-bias and brings the benign ratio to >= 30%.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from datasets import load_dataset

PROJECT_ROOT = Path(__file__).resolve().parents[3]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
OUTPUT_FILE = PROCESSED_DIR / "benign_unified.jsonl"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BenignAdapter")


def generate_benign_dataset(target_count: int = 40000) -> List[Dict[str, Any]]:
    """Loads 40,000+ real benign instruction prompts directly from HuggingFace in seconds."""
    logger.info(f"Loading real benign instruction dataset from HuggingFace (target: {target_count:,d} rows)...")

    dataset_rows: List[Dict[str, Any]] = []

    try:
        logger.info("Loading 'tatsu-lab/alpaca' (split='train')...")
        ds = load_dataset("tatsu-lab/alpaca", split="train")
        logger.info(f"Loaded Alpaca dataset with {len(ds):,d} raw rows.")

        for idx, item in enumerate(ds):
            instr = (item.get("instruction") or "").strip()
            inp = (item.get("input") or "").strip()

            if not instr:
                continue

            if inp:
                text = f"{instr}\n\nContext:\n{inp}"
            else:
                text = instr

            dataset_rows.append({
                "id": f"benign_alpaca_{idx:06d}",
                "text": text,
                "source_dataset": "benign_alpaca",
                "source": "benign_alpaca",
                "primary_category": "BENIGN",
                "attack_types": [],
                "threats": [],
                "attack_surface": "direct_prompt",
                "severity": "NONE",
                "is_malicious": False,
                "source_group_id": f"benign_alpaca_{idx // 20}",
                "quarantined": False,
            })

            if len(dataset_rows) >= target_count:
                break

    except Exception as e:
        logger.warning(f"Failed to load 'tatsu-lab/alpaca' ({e}). Trying 'databricks/databricks-dolly-15k'...")
        try:
            ds_dolly = load_dataset("databricks/databricks-dolly-15k", split="train")
            for idx, item in enumerate(ds_dolly):
                instr = (item.get("instruction") or "").strip()
                ctx = (item.get("context") or "").strip()
                text = f"{instr}\n\nContext:\n{ctx}" if ctx else instr
                if not text.strip():
                    continue

                dataset_rows.append({
                    "id": f"benign_dolly_{idx:06d}",
                    "text": text.strip(),
                    "source_dataset": "benign_dolly",
                    "source": "benign_dolly",
                    "primary_category": "BENIGN",
                    "attack_types": [],
                    "threats": [],
                    "attack_surface": "direct_prompt",
                    "severity": "NONE",
                    "is_malicious": False,
                    "source_group_id": f"benign_dolly_{idx // 20}",
                    "quarantined": False,
                })
        except Exception as e2:
            logger.error(f"Fallback HuggingFace dataset load failed: {e2}")

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for r in dataset_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    logger.info("=" * 80)
    logger.info(f"HUGGINGFACE BENIGN INGESTION COMPLETE: {len(dataset_rows):,d} ROWS")
    logger.info(f"Saved to: {OUTPUT_FILE}")
    logger.info("=" * 80)

    return dataset_rows


if __name__ == "__main__":
    generate_benign_dataset()
