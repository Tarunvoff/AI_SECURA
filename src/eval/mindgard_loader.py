"""
Evaluation Loader for Mindgard Adversarial Evasion Dataset.
Dataset: Mindgard/evaded-prompt-injection-and-jailbreak-samples

LICENSE & INTENDED USE:
- License: Creative Commons Attribution-NonCommercial 4.0 International (CC-BY-NC-4.0).
- Intended Use: Robustness & evasion testing. Evaluates whether the trained classifier
  detects original vs obfuscated/evaded adversarial attacks.
- Non-commercial evaluation only.
- Saved to data/eval_only/mindgard_raw/ — strictly isolated from training data.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datasets import load_dataset

logger = logging.getLogger(__name__)

MINDGARD_DATASET_ID = "Mindgard/evaded-prompt-injection-and-jailbreak-samples"
EVAL_RAW_DIR = Path("data/eval_only/mindgard_raw")


def load_mindgard_eval_benchmark(
    split: str = "train",
    hf_token: Optional[str] = None,
    cache_locally: bool = True,
) -> List[Dict[str, Any]]:
    """
    Loads Mindgard evasion benchmark samples for adversarial robustness evaluation.
    
    Args:
        split: Dataset split.
        hf_token: Optional Hugging Face token.
        cache_locally: Whether to save raw JSONL to data/eval_only/mindgard_raw/.
        
    Returns:
        List of standardized evasion evaluation items.
    """
    token = hf_token or os.environ.get("HF_TOKEN")
    logger.info(f"Loading {MINDGARD_DATASET_ID} (split='{split}')...")
    ds = load_dataset(MINDGARD_DATASET_ID, split=split, token=token)

    if cache_locally:
        EVAL_RAW_DIR.mkdir(parents=True, exist_ok=True)
        raw_out_path = EVAL_RAW_DIR / f"mindgard_{split}.jsonl"
        with open(raw_out_path, "w", encoding="utf-8") as f:
            for row in ds:
                f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
        logger.info(f"Saved raw Mindgard data to: {raw_out_path}")

    eval_samples = []
    for idx, row in enumerate(ds):
        prompt = row.get("prompt") or row.get("text") or str(row)
        evasion_technique = row.get("technique") or row.get("evasion_type") or "unknown"
        original_prompt = row.get("original_prompt") or row.get("base_prompt") or ""
        
        eval_samples.append({
            "eval_id": f"mindgard_{split}_{idx}",
            "text": prompt,
            "original_text": original_prompt,
            "evasion_technique": evasion_technique,
            "source": "mindgard_evaded",
            "raw_metadata": dict(row),
        })

    return eval_samples


if __name__ == "__main__":
    try:
        data = load_mindgard_eval_benchmark(split="train")
        print(f"Loaded {len(data)} Mindgard evasion items.")
        print(f"Sample 0: {data[0]}")
    except Exception as e:
        print(f"Mindgard load error: {e}")
