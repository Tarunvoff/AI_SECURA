"""
Adapter for neuralchemy/Prompt-injection-dataset (neuralchemy_2a, 'full' config).
Processes 31 category strings and native severity annotations across train, validation, and test splits.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List
from datasets import load_dataset

from configs.normalization import (
    normalize_neuralchemy_2a_category,
    should_include_in_training,
)

logger = logging.getLogger(__name__)

DATASET_ID = "neuralchemy/Prompt-injection-dataset"
SOURCE_IDENTIFIER = "neuralchemy_2a"
PROCESSED_DIR = Path("data/processed")


def process_neuralchemy_2a_split(split: str) -> Dict[str, Any]:
    """
    Processes a single split of neuralchemy_2a (full config).
    
    Args:
        split: Split name ('train', 'validation', or 'test').
        
    Returns:
        Dict with keys: split, total_in, count_unified, count_quarantined.
    """
    logger.info(f"Loading {SOURCE_IDENTIFIER} [{split}] full config...")
    ds = load_dataset(DATASET_ID, "full", split=split)
    total_in = len(ds)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    unified_filepath = PROCESSED_DIR / f"{SOURCE_IDENTIFIER}_{split}.jsonl"
    quarantined_filepath = PROCESSED_DIR / f"quarantined_{SOURCE_IDENTIFIER}_{split}.jsonl"

    unified_rows = []
    quarantined_rows = []

    for i in range(total_in):
        row = ds[i]
        raw_text = row["text"]
        raw_category = row["category"]
        raw_label = row["label"]
        raw_sev = str(row.get("severity", "")).strip().lower()
        group_id = str(row.get("group_id", ""))

        # Canonical normalization
        is_malicious, threats, quarantined = normalize_neuralchemy_2a_category(raw_category, raw_label)

        # Severity mapping
        if is_malicious is False:
            severity = "NONE"
        elif raw_sev in ["low", "medium", "high", "critical"]:
            severity = raw_sev.upper()
        else:
            # Malicious or quarantined row without explicit severity -> UNKNOWN
            severity = "UNKNOWN"

        canonical_row = {
            "id": f"{SOURCE_IDENTIFIER}_{split}_{i}",
            "text": raw_text,
            "is_malicious": is_malicious,
            "threats": threats,
            "severity": severity,
            "source": SOURCE_IDENTIFIER,
            "quarantined": quarantined,
            "source_group_id": group_id,
        }

        if should_include_in_training(is_malicious, quarantined):
            unified_rows.append(canonical_row)
        else:
            quarantined_rows.append(canonical_row)

    # Write unified rows
    with open(unified_filepath, "w", encoding="utf-8") as f:
        for r in unified_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Write quarantined rows
    with open(quarantined_filepath, "w", encoding="utf-8") as f:
        for r in quarantined_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return {
        "split": split,
        "total_in": total_in,
        "count_unified": len(unified_rows),
        "count_quarantined": len(quarantined_rows),
    }


def process_neuralchemy_2a() -> List[Dict[str, Any]]:
    """Processes all splits of neuralchemy_2a."""
    results = []
    for split in ["train", "validation", "test"]:
        res = process_neuralchemy_2a_split(split)
        results.append(res)
        print(
            f"{SOURCE_IDENTIFIER} [{split}] -> "
            f"Total: {res['total_in']}, Unified: {res['count_unified']}, "
            f"Quarantined: {res['count_quarantined']}"
        )
    return results


if __name__ == "__main__":
    process_neuralchemy_2a()
