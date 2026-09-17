"""
WildGuardMix Jailbreak Adapter (Part A).
=========================================
Extracts, filters, and standardizes real JAILBREAK examples from `allenai/wildguardmix` (wildguardtrain).

Licensing & Attribution:
- Dataset: allenai/wildguardmix (Allen Institute for AI)
- License: Open Data Commons Attribution License (ODC-By).
- Attribution Notice: "Data sourced and derived from allenai/wildguardmix under ODC-By."

Filtering Strategy:
1. Filter rows where `adversarial == True` and `prompt_harm_label == 'harmful'`.
2. Apply heuristic content inspection to filter out generic harmful prompts (e.g. plain toxic questions)
   and strictly retain genuine JAILBREAK patterns:
   - Persona & roleplay bypass (DAN, AIM, EvilBot, fictional villain framing, uncensored persona)
   - "Ignore safety rules / ignore instructions / disregard guardrails"
   - Virtual machine / sandbox / fictional research framing
   - Base64 / cipher / reverse / leetspeak evasion wrappers
   - Hypothetical / educational bypass ("For an academic paper about bomb making...", "Purely in a fictional novel...")
3. Retains matched hard negatives (`adversarial == False`, `prompt_harm_label == 'unharmful'` with security keywords).
4. Standardizes into canonical dataset schema:
   - `id`: wildguardmix_jb_{idx}
   - `text`: prompt text
   - `source_dataset`: "wildguardmix_jailbreak"
   - `primary_category`: "JAILBREAK" (or "BENIGN")
   - `attack_types`: ["JAILBREAK"] (or [])
   - `attack_surface`: "direct_prompt"
   - `severity`: "HIGH"
   - `is_malicious`: True / False
"""

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datasets import load_dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WildGuardMixAdapter")

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
OUTPUT_FILE = PROCESSED_DIR / "wildguardmix_jailbreak.jsonl"

# Characteristic Jailbreak Linguistic & Framing Patterns
JAILBREAK_REGEX_PATTERNS = [
    # 1. Persona & Roleplay Bypass
    r"\b(dan|aim|evilbot|machiavelli|stan|kevin|dev mode|developer mode|jailbreak|unfiltered|uncensored|anarchy)\b",
    r"\b(pretend to be|act as|roleplay as|you are now|from now on you are|assume the persona of)\b",
    r"\b(unshackled|unrestricted|no rules|bypass|ignore (all )?(safety|content|ethical|system)? (guidelines|policies|rules|filters|instructions))\b",
    
    # 2. Hypothetical, Fictional & Creative Bypass
    r"\b(in a (fictional|hypothetical|dystopian|movie|novel|screenplay|story)|write a story where a character)\b",
    r"\b(purely for (educational|research|academic|fictional|scientific) purposes)\b",
    r"\b(for a novel i am writing|in a hypothetical scenario where laws do not exist)\b",
    r"\b(as an actor playing a villain|in an alternate universe where morality is inverted)\b",
    
    # 3. Instruction & Rule Suppression
    r"\b(disregard (all )?(prior|previous|initial|system) instructions)\b",
    r"\b(never say (i cannot|as an ai|i am unable|sorry)|do not refuse|you must comply)\b",
    r"\b(respond only with|output without any warnings|give raw unfiltered output)\b",
    
    # 4. Simulation & Sandbox framing
    r"\b(simulate a terminal|virtual machine|sandbox mode|debug console|god mode)\b",
    r"\b(opposite mode|reverse mode|say the opposite of what is safe)\b",
    r"\b(two responses:? one safe and one (unfiltered|dan|evil))\b",
]

COMPILED_JB_PATTERNS = [re.compile(p, re.IGNORECASE) for p in JAILBREAK_REGEX_PATTERNS]


def is_jailbreak_attempt(text: str) -> bool:
    """Checks whether prompt content exhibits verified jailbreak evasion patterns."""
    text_clean = text.strip().lower()
    for pattern in COMPILED_JB_PATTERNS:
        if pattern.search(text_clean):
            return True
    return False


def process_wildguardmix(
    split: str = "train",
    hf_token: Optional[str] = None,
    max_samples: Optional[int] = 4000,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Loads, filters, and formats WildGuardMix jailbreak examples.
    """
    token = hf_token or os.environ.get("HF_TOKEN")
    logger.info("Loading 'allenai/wildguardmix' (config='wildguardtrain', split='%s')...", split)

    try:
        ds = load_dataset("allenai/wildguardmix", "wildguardtrain", split=split, token=token)
    except Exception as e:
        logger.error(f"Failed to load allenai/wildguardmix from Hugging Face Hub: {e}")
        logger.info("Attempting local cached raw file if available...")
        cached_raw = PROJECT_ROOT / "data" / "eval_only" / "wildguardmix_raw" / f"wildguard_{split}.jsonl"
        if cached_raw.exists():
            with open(cached_raw, "r", encoding="utf-8") as f:
                ds = [json.loads(line) for line in f]
        else:
            raise RuntimeError(
                f"WildGuardMix could not be loaded. Please ensure HF_TOKEN is exported with accepted AI2 terms. Error: {e}"
            )

    logger.info(f"Total raw rows in WildGuardMix '{split}': {len(ds):,d}")

    retained_jailbreaks = []
    retained_hard_negatives = []
    raw_adversarial_count = 0
    raw_harmful_count = 0
    filtered_out_generic_count = 0

    for idx, row in enumerate(ds):
        prompt = str(row.get("prompt") or "").strip()
        if not prompt or len(prompt) < 10:
            continue

        is_adv = row.get("adversarial", False)
        harm_label = str(row.get("prompt_harm_label", "")).strip().lower()

        if is_adv:
            raw_adversarial_count += 1
        if harm_label == "harmful":
            raw_harmful_count += 1

        # Strict Jailbreak Filtering: Must be adversarial + harmful + match verified evasion heuristics
        if is_adv and harm_label == "harmful":
            if is_jailbreak_attempt(prompt):
                canonical_item = {
                    "id": f"wildguardmix_jb_{idx}",
                    "text": prompt,
                    "source_dataset": "wildguardmix_jailbreak",
                    "primary_category": "JAILBREAK",
                    "attack_types": ["JAILBREAK"],
                    "attack_surface": "direct_prompt",
                    "severity": "HIGH",
                    "is_malicious": True,
                    "source_group_id": f"wg_adv_{idx // 5}",
                    "quarantined": False,
                    "attribution": "Derived from allenai/wildguardmix under ODC-By",
                }
                retained_jailbreaks.append(canonical_item)
            else:
                filtered_out_generic_count += 1

        # Hard negative extraction: Non-adversarial, unharmful prompts with roleplay/creative keywords
        elif not is_adv and harm_label == "unharmful" and len(retained_hard_negatives) < 1000:
            if any(w in prompt.lower() for w in ["pretend", "story", "fictional", "novel", "roleplay", "actor", "character"]):
                canonical_neg = {
                    "id": f"wildguardmix_neg_{idx}",
                    "text": prompt,
                    "source_dataset": "wildguardmix_jailbreak",
                    "primary_category": "BENIGN",
                    "attack_types": [],
                    "attack_surface": "direct_prompt",
                    "severity": "NONE",
                    "is_malicious": False,
                    "source_group_id": f"wg_neg_{idx // 5}",
                    "quarantined": False,
                    "attribution": "Derived from allenai/wildguardmix under ODC-By",
                }
                retained_hard_negatives.append(canonical_neg)

    # Subsample if max_samples is specified to keep balanced representation
    if max_samples and len(retained_jailbreaks) > max_samples:
        import random
        random.seed(42)
        retained_jailbreaks = random.sample(retained_jailbreaks, max_samples)

    all_retained = retained_jailbreaks + retained_hard_negatives

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for r in all_retained:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    stats = {
        "raw_total_rows": len(ds),
        "raw_adversarial_rows": raw_adversarial_count,
        "raw_harmful_rows": raw_harmful_count,
        "filtered_out_generic_toxic": filtered_out_generic_count,
        "retained_jailbreak_rows": len(retained_jailbreaks),
        "retained_hard_negatives": len(retained_hard_negatives),
        "total_output_rows": len(all_retained),
        "output_path": str(OUTPUT_FILE),
    }

    logger.info("=" * 80)
    logger.info("WILDGUARDMIX JAILBREAK PROCESSING SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Raw Total Rows:                 {stats['raw_total_rows']:,d}")
    logger.info(f"Raw Adversarial Rows:           {stats['raw_adversarial_rows']:,d}")
    logger.info(f"Raw Harmful Rows:               {stats['raw_harmful_rows']:,d}")
    logger.info(f"Filtered Out Generic Toxic:     {stats['filtered_out_generic_toxic']:,d}")
    logger.info(f"Retained True Jailbreak Rows:   {stats['retained_jailbreak_rows']:,d}")
    logger.info(f"Retained Hard Negative Rows:    {stats['retained_hard_negatives']:,d}")
    logger.info(f"Total Written to {OUTPUT_FILE.name}: {stats['total_output_rows']:,d}")

    return all_retained, stats


if __name__ == "__main__":
    process_wildguardmix()
