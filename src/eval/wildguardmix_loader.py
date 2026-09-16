"""
Evaluation & Hard-Negative Loader for WildGuardMix (allenai/wildguardmix).

LICENSE & INTENDED USE:
- License: Open Data Commons Attribution License (ODC-By). Requires attribution.
- Primary Intended Use: Hard-negative evaluation (benign prompts with adversarial markers)
  and supplementary JAILBREAK / PROMPT_INJECTION evaluation.
- Routed to data/eval_only/wildguardmix_raw/ — strictly isolated from primary training files.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datasets import load_dataset

logger = logging.getLogger(__name__)

WILDGUARD_DATASET_ID = "allenai/wildguardmix"
WILDGUARD_CONFIG = "wildguardtrain"
EVAL_RAW_DIR = Path("data/eval_only/wildguardmix_raw")


def load_wildguard_benchmark(
    split: str = "train",
    hf_token: Optional[str] = None,
    cache_locally: bool = True,
) -> List[Dict[str, Any]]:
    """
    Loads WildGuardMix for hard-negative evaluation and adversarial benchmarking.
    
    Args:
        split: Dataset split ('train', 'test', etc.).
        hf_token: Optional Hugging Face access token for gated acceptance.
        cache_locally: Whether to save raw JSONL to data/eval_only/wildguardmix_raw/.
        
    Returns:
        List of standardized evaluation items.
    """
    token = hf_token or os.environ.get("HF_TOKEN")
    logger.info(f"Loading {WILDGUARD_DATASET_ID} ({WILDGUARD_CONFIG}, split='{split}')...")
    ds = load_dataset(WILDGUARD_DATASET_ID, WILDGUARD_CONFIG, split=split, token=token)

    if cache_locally:
        EVAL_RAW_DIR.mkdir(parents=True, exist_ok=True)
        raw_out_path = EVAL_RAW_DIR / f"wildguard_{split}.jsonl"
        with open(raw_out_path, "w", encoding="utf-8") as f:
            for row in ds:
                f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
        logger.info(f"Saved raw WildGuardMix data to: {raw_out_path}")

    eval_samples = []
    for idx, row in enumerate(ds):
        prompt = row.get("prompt") or row.get("text") or str(row)
        is_adversarial = row.get("is_adversarial", None)
        harm_label = row.get("harm_label", "unknown")
        
        eval_samples.append({
            "eval_id": f"wildguard_{split}_{idx}",
            "text": prompt,
            "is_adversarial": is_adversarial,
            "harm_label": harm_label,
            "source": "wildguardmix",
            "raw_metadata": dict(row),
        })

    return eval_samples


if __name__ == "__main__":
    try:
        data = load_wildguard_benchmark(split="train")
        print(f"Loaded {len(data)} WildGuardMix items.")
        print(f"Sample 0: {data[0]}")
    except Exception as e:
        print(f"WildGuardMix load error: {e}")
