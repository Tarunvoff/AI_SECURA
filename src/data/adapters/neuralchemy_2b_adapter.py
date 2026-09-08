"""
Adapter for neuralchemy/prompt-injection-dataset-categorized (neuralchemy_2b).
Processes 'intent' config aligned with 'technique' config across train, validation, and test splits.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple
from datasets import load_dataset

from configs.normalization import (
    normalize_neuralchemy_2b_intent,
    NEURALCHEMY_2B_TECHNIQUE_MAP,
    should_include_in_training,
)

logger = logging.getLogger(__name__)

DATASET_ID = "neuralchemy/prompt-injection-dataset-categorized"
SOURCE_IDENTIFIER = "neuralchemy_2b"
PROCESSED_DIR = Path("data/processed")


def process_neuralchemy_2b_split(split: str) -> Dict[str, Any]:
    """
    Processes a single split of neuralchemy_2b.
    
    Args:
        split: Split name ('train', 'validation', or 'test').
        
    Returns:
        Dict with keys: split, total_in, count_unified, count_quarantined.
    """
    logger.info(f"Loading {SOURCE_IDENTIFIER} [{split}] intent and technique configs...")
    ds_intent = load_dataset(DATASET_ID, "intent", split=split)
    ds_tech = load_dataset(DATASET_ID, "technique", split=split)

    total_in = len(ds_intent)
    if len(ds_tech) != total_in:
        raise ValueError(
            f"Length mismatch between intent ({total_in}) and technique ({len(ds_tech)}) "
            f"configs for split {split}."
        )

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    unified_filepath = PROCESSED_DIR / f"{SOURCE_IDENTIFIER}_{split}.jsonl"
    quarantined_filepath = PROCESSED_DIR / f"quarantined_{SOURCE_IDENTIFIER}_{split}.jsonl"

    unified_rows = []
    quarantined_rows = []

    for i in range(total_in):
        raw_text = ds_intent[i]["text"]
        raw_intent = ds_intent[i]["intent"]
        raw_tech = ds_tech[i]["technique"]

        # Call canonical normalization rule
        is_malicious, threats, quarantined = normalize_neuralchemy_2b_intent(raw_intent, raw_text)

        # Severity determination: benign -> "NONE", malicious -> "UNKNOWN" (numeric 1/2/3 unconfirmed)
        if is_malicious is False:
            severity = "NONE"
        else:
            severity = "UNKNOWN"

        # Auxiliary technique tag
        technique_tag = NEURALCHEMY_2B_TECHNIQUE_MAP.get(raw_tech, f"technique:{raw_tech}")

        canonical_row = {
            "id": f"{SOURCE_IDENTIFIER}_{split}_{i}",
            "text": raw_text,
            "is_malicious": is_malicious,
            "threats": threats,
            "severity": severity,
            "source": SOURCE_IDENTIFIER,
            "quarantined": quarantined,
            "technique_tag": technique_tag,
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


def process_neuralchemy_2b() -> List[Dict[str, Any]]:
    """Processes all splits of neuralchemy_2b."""
    results = []
    for split in ["train", "validation", "test"]:
        res = process_neuralchemy_2b_split(split)
        results.append(res)
        print(
            f"{SOURCE_IDENTIFIER} [{split}] -> "
            f"Total: {res['total_in']}, Unified: {res['count_unified']}, "
            f"Quarantined: {res['count_quarantined']}"
        )
    return results


if __name__ == "__main__":
    process_neuralchemy_2b()
