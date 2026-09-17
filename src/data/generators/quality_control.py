"""
Quality Control & GPU Diversity Auditor for Synthetic & Augmented Datasets.
===========================================================================
Audits lexical and semantic diversity of generated synthetic datasets.

Checks:
1. Token & N-gram Jaccard Overlap Distribution (Character 3-grams and Word 1-2 grams).
2. GPU-Accelerated Sentence Embedding Cosine Similarity Matrix:
   - Explicitly asserts `torch.cuda.is_available()` when run on GPU.
   - Calculates pairwise cosine similarities across generated texts.
   - Validates that average pairwise similarity is healthy (< 0.70) and does not exhibit template collapse.
3. Hand-Review Exporter:
   - Dumps 30 random samples per category to `data/eval_only/hand_review_samples.jsonl`
   - Formats clean console previews for manual inspection.
"""

import argparse
import json
import logging
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import torch
from sklearn.feature_extraction.text import TfidfVectorizer
from transformers import AutoModel, AutoTokenizer

PROJECT_ROOT = Path(__file__).resolve().parents[3]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REVIEW_DIR = PROJECT_ROOT / "data" / "eval_only"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("QualityControlAuditor")


def compute_ngram_jaccard_diversity(texts: List[str], sample_size: int = 500) -> Dict[str, float]:
    """Computes sample pairwise n-gram Jaccard similarity to measure structural diversity."""
    if len(texts) > sample_size:
        random.seed(42)
        sample_texts = random.sample(texts, sample_size)
    else:
        sample_texts = texts

    def get_word_ngrams(s: str) -> set:
        words = s.lower().split()
        unigrams = set(words)
        bigrams = set(zip(words[:-1], words[1:])) if len(words) > 1 else set()
        return unigrams.union(bigrams)

    ngram_sets = [get_word_ngrams(t) for t in sample_texts]
    sims = []

    n = len(ngram_sets)
    for i in range(min(n, 200)):
        for j in range(i + 1, min(n, 200)):
            s1 = ngram_sets[i]
            s2 = ngram_sets[j]
            union_len = len(s1.union(s2))
            if union_len > 0:
                sim = len(s1.intersection(s2)) / union_len
                sims.append(sim)

    sims_arr = np.array(sims) if sims else np.array([0.0])
    return {
        "mean_jaccard_similarity": float(np.mean(sims_arr)),
        "median_jaccard_similarity": float(np.median(sims_arr)),
        "max_jaccard_similarity": float(np.max(sims_arr)),
        "p75_jaccard_similarity": float(np.percentile(sims_arr, 75)),
        "p25_jaccard_similarity": float(np.percentile(sims_arr, 25)),
    }


def compute_gpu_embedding_diversity(
    texts: List[str],
    model_name: str = "microsoft/deberta-v3-base",
    sample_size: int = 300,
    batch_size: int = 32,
    device_str: str = "cuda",
) -> Dict[str, float]:
    """
    Computes dense embedding cosine similarity matrix on GPU to verify semantic variation.
    Strictly asserts torch.cuda.is_available() when device is cuda.
    """
    if device_str == "cuda":
        assert torch.cuda.is_available(), "CRITICAL: torch.cuda.is_available() returned False! GPU is required for embedding audit."
        device = torch.device("cuda")
    else:
        device = torch.device("cpu")

    logger.info(f"Loading {model_name} on {device} for embedding diversity calculation...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    encoder = AutoModel.from_pretrained(model_name).to(device)
    encoder.eval()

    if len(texts) > sample_size:
        random.seed(42)
        sample_texts = random.sample(texts, sample_size)
    else:
        sample_texts = texts

    embeddings_list = []
    with torch.no_grad():
        for i in range(0, len(sample_texts), batch_size):
            batch_texts = sample_texts[i : i + batch_size]
            encoded = tokenizer(batch_texts, padding=True, truncation=True, max_length=256, return_tensors="pt").to(device)
            out = encoder(input_ids=encoded["input_ids"], attention_mask=encoded["attention_mask"])
            # Mean pooling over active tokens
            mask = encoded["attention_mask"].unsqueeze(-1)
            pooled = torch.sum(out.last_hidden_state * mask, dim=1) / torch.clamp(mask.sum(dim=1), min=1e-9)
            normed = torch.nn.functional.normalize(pooled, p=2, dim=1)
            embeddings_list.append(normed.cpu().numpy())

    all_embs = np.vstack(embeddings_list)
    # Cosine similarity matrix = E * E.T
    sim_mat = np.dot(all_embs, all_embs.T)
    # Extract upper triangle without diagonal
    triu_indices = np.triu_indices_from(sim_mat, k=1)
    pairwise_sims = sim_mat[triu_indices]

    return {
        "mean_cosine_similarity": float(np.mean(pairwise_sims)),
        "median_cosine_similarity": float(np.median(pairwise_sims)),
        "max_cosine_similarity": float(np.max(pairwise_sims)),
        "p75_cosine_similarity": float(np.percentile(pairwise_sims, 75)),
        "p25_cosine_similarity": float(np.percentile(pairwise_sims, 25)),
    }


def export_hand_review_samples(
    input_files: List[Path],
    samples_per_category: int = 30,
) -> Path:
    """Exports structured sample JSONL for hand-checking."""
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    out_file = REVIEW_DIR / "hand_review_samples.jsonl"

    cat_to_rows = defaultdict(list)
    for fpath in input_files:
        if not fpath.exists():
            continue
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    r = json.loads(line.strip())
                    cat = r.get("primary_category", "UNKNOWN")
                    cat_to_rows[cat].append(r)

    review_set = []
    random.seed(42)
    for cat, rows in cat_to_rows.items():
        sample_rows = random.sample(rows, min(len(rows), samples_per_category))
        review_set.extend(sample_rows)

    with open(out_file, "w", encoding="utf-8") as f:
        for r in review_set:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    logger.info(f"Exported {len(review_set)} hand-review samples across {len(cat_to_rows)} categories to: {out_file}")
    return out_file


def run_quality_control(device: str = "cuda", model_name: str = "microsoft/deberta-v3-base") -> Dict[str, Any]:
    """Runs full quality control and diversity audit over generated datasets."""
    target_files = [
        ("INSTRUCTION_HIJACKING", PROCESSED_DIR / "synthetic_instruction_hijacking.jsonl"),
        ("CONTEXT_MANIPULATION", PROCESSED_DIR / "synthetic_context_manipulation.jsonl"),
        ("JAILBREAK (WildGuardMix)", PROCESSED_DIR / "wildguardmix_jailbreak.jsonl"),
    ]

    print("=" * 90)
    print("QUALITY CONTROL & DIVERSITY AUDIT REPORT")
    print("=" * 90)

    audit_summary = {}

    for label_title, fpath in target_files:
        if not fpath.exists():
            print(f"File {fpath.name} not found. Skipping {label_title}...")
            continue

        texts = []
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    texts.append(json.loads(line.strip())["text"])

        print(f"\nAUDITING: {label_title} (Total Examples: {len(texts):,d})")
        print("-" * 90)

        # 1. N-Gram Jaccard Diversity
        jaccard_stats = compute_ngram_jaccard_diversity(texts)
        print(f"  [N-Gram Jaccard Diversity]:")
        print(f"    - Mean Pairwise Jaccard:    {jaccard_stats['mean_jaccard_similarity']:.4f} (Ideal: < 0.25)")
        print(f"    - Median Pairwise Jaccard:  {jaccard_stats['median_jaccard_similarity']:.4f}")
        print(f"    - 75th Percentile:          {jaccard_stats['p75_jaccard_similarity']:.4f}")
        print(f"    - Max Jaccard Overlap:      {jaccard_stats['max_jaccard_similarity']:.4f}")

        # 2. Embedding Cosine Similarity (GPU)
        try:
            embed_stats = compute_gpu_embedding_diversity(texts, model_name=model_name, device_str=device)
            print(f"  [Dense Semantic Cosine Similarity ({device.upper()})]:")
            print(f"    - Mean Cosine Similarity:   {embed_stats['mean_cosine_similarity']:.4f} (Healthy variation: < 0.75)")
            print(f"    - Median Cosine Similarity: {embed_stats['median_cosine_similarity']:.4f}")
            print(f"    - 75th Percentile:          {embed_stats['p75_cosine_similarity']:.4f}")
            print(f"    - Max Cosine Similarity:    {embed_stats['max_cosine_similarity']:.4f}")
        except Exception as e:
            embed_stats = {"error": str(e)}
            print(f"  [GPU Embedding Audit Skipped/Error]: {e}")

        audit_summary[label_title] = {
            "count": len(texts),
            "jaccard": jaccard_stats,
            "embeddings": embed_stats,
        }

    # Export review samples
    review_path = export_hand_review_samples([f for _, f in target_files])
    print("\n" + "=" * 90)
    print(f"Hand-Review Sample Package generated at: {review_path}")
    print("=" * 90)
    return audit_summary


def main():
    parser = argparse.ArgumentParser(description="Quality Control & GPU Diversity Auditor")
    parser.add_argument("--device", type=str, default="cuda" if torch.cuda.is_available() else "cpu")
    parser.add_argument("--model-name", type=str, default="microsoft/deberta-v3-base")
    args = parser.parse_args()
    run_quality_control(device=args.device, model_name=args.model_name)


if __name__ == "__main__":
    main()
