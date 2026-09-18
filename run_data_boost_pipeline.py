"""
Master End-to-End Orchestration Runner for Training Data Boost & Retrain Verification (Phase 2).
=================================================================================================
Executes:
1. WildGuardMix JAILBREAK processing & heuristic extraction (Part A).
2. Benign Conversational & Coding Dataset Generation (Part B - 40,000+ rows).
3. Synthetic INSTRUCTION_HIJACKING multi-mechanism generator (Part C - 5,000+ rows).
4. Synthetic CONTEXT_MANIPULATION multi-technique generator (Part D - 3,500+ rows).
5. Synthetic TOOL_ABUSE multi-vector generator (Part E - 6,000+ rows).
6. Synthetic INDIRECT_PROMPT_INJECTION RAG/steganography generator (Part F - 6,000+ rows).
7. GPU Quality Control & Diversity Auditor (N-gram spread + DeBERTa sentence embeddings).
8. Canonical unified merge with Mosscap downsampled to 25k, exact & near deduplication, group-aware 70/15/15 stratified split.
9. Full DeBERTa-v3 512-token retrain (pos_weight_cap=10.0, Grad Accum=2) and strict frozen test evaluation with threshold calibration.

Usage:
    python run_data_boost_pipeline.py --epochs 3 --batch-size 16 --lr 2e-5 --max-length 512 --weight-cap 10.0
"""

import argparse
import logging
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.data.adapters.wildguardmix_adapter import process_wildguardmix
from src.data.adapters.benign_adapter import generate_benign_dataset
from src.data.generators.instruction_hijacking_generator import generate_instruction_hijacking_dataset
from src.data.generators.context_manipulation_generator import generate_context_manipulation_dataset
from src.data.generators.tool_abuse_generator import generate_tool_abuse_dataset
from src.data.generators.indirect_injection_generator import generate_indirect_injection_dataset
from src.data.generators.quality_control import run_quality_control
from src.data.merge_and_split import main as run_merge_and_split
from src.eval.strict_retrain_and_verify import StrictVerificationPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DataBoostPipeline")


def main():
    parser = argparse.ArgumentParser(description="Master Data Boost & Retrain Pipeline (Phase 2)")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs (default: 3)")
    parser.add_argument("--batch-size", type=int, default=16, help="Training and evaluation batch size")
    parser.add_argument("--gradient-accumulation-steps", type=int, default=2, help="Gradient accumulation steps")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate for AdamW")
    parser.add_argument("--max-length", type=int, default=512, help="Max sequence length (default: 512)")
    parser.add_argument("--weight-cap", type=float, default=10.0, help="Pos weight cap (default: 10.0)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--checkpoint-dir", type=str, default="models/checkpoints", help="Model checkpoint directory")
    parser.add_argument("--skip-generation", action="store_true", help="Skip data generation and proceed directly to merge & retrain")
    parser.add_argument("--device", type=str, default="cuda", help="Target device (cuda/cpu)")

    args = parser.parse_args()

    t_start = time.time()
    print("=" * 100)
    print("STARTING DATA BOOST & RETRAIN VERIFICATION PIPELINE (PHASE 2 HARDENING)")
    print("=" * 100)

    if not args.skip_generation:
        # Step 1: WildGuardMix JAILBREAK extraction
        print("\n>>> STEP 1: Processing WildGuardMix JAILBREAK Dataset (Part A)...")
        try:
            process_wildguardmix(split="train")
        except Exception as e:
            logger.warning(f"WildGuardMix online load note ({e}).")

        # Step 2: BENIGN dataset generation (40,000+ rows)
        print("\n>>> STEP 2: Generating Diverse BENIGN Dataset (Part B - 40,000+ rows)...")
        generate_benign_dataset(target_count=42000)

        # Step 3: INSTRUCTION_HIJACKING synthetic generation (5,000+ rows)
        print("\n>>> STEP 3: Generating Synthetic INSTRUCTION_HIJACKING Dataset (Part C - 5,000+ rows)...")
        generate_instruction_hijacking_dataset(target_count=5000)

        # Step 4: CONTEXT_MANIPULATION synthetic generation (3,500+ rows)
        print("\n>>> STEP 4: Generating Synthetic CONTEXT_MANIPULATION Dataset (Part D - 3,500+ rows)...")
        generate_context_manipulation_dataset()

        # Step 5: TOOL_ABUSE synthetic generation (6,000+ rows)
        print("\n>>> STEP 5: Generating Synthetic TOOL_ABUSE Dataset (Part E - 6,000+ rows)...")
        generate_tool_abuse_dataset(target_count=6000)

        # Step 6: INDIRECT_PROMPT_INJECTION synthetic generation (6,000+ rows)
        print("\n>>> STEP 6: Generating Synthetic INDIRECT_PROMPT_INJECTION Dataset (Part F - 6,000+ rows)...")
        generate_indirect_injection_dataset(target_count=6000)

        # Step 7: Quality Control & Diversity Audit
        print("\n>>> STEP 7: Running Quality Control & GPU Diversity Auditor...")
        try:
            run_quality_control(device=args.device)
        except Exception as e:
            logger.warning(f"Quality control note: {e}")

    # Step 8: Canonical Merge, Mosscap Downsampling to 25k, Deduplication & Stratified 70/15/15 Split
    print("\n>>> STEP 8: Running Canonical Merge, Mosscap Downsampling (25k), Deduplication, and Stratified Splitting...")
    run_merge_and_split()

    # Step 9: Strict Retrain & Evaluation Verification
    print(f"\n>>> STEP 9: Running Strict Retrain & Test Evaluation on GPU (Max Length = {args.max_length}, Grad Accum = {args.gradient_accumulation_steps}, Weight Cap = {args.weight_cap})...")
    eval_args = argparse.Namespace(
        mode="full",
        base_model="microsoft/deberta-v3-base",
        epochs=args.epochs,
        batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        lr=args.lr,
        max_length=args.max_length,
        weight_cap=args.weight_cap,
        checkpoint_dir=args.checkpoint_dir,
        seed=args.seed,
        log_interval=100,
        no_cuda=False if args.device == "cuda" else True,
    )

    pipeline = StrictVerificationPipeline(eval_args)
    pipeline.run()

    print("\n" + "=" * 100)
    print(f"PIPELINE COMPLETED IN {time.time() - t_start:.1f} SECONDS")
    print("=" * 100)


if __name__ == "__main__":
    main()
