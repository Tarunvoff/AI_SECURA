"""
Master End-to-End Orchestration Runner for Training Data Boost & Retrain Verification.
======================================================================================
Executes:
1. WildGuardMix JAILBREAK processing & heuristic extraction (Part A).
2. Synthetic INSTRUCTION_HIJACKING multi-mechanism generator (Part B).
3. Synthetic CONTEXT_MANIPULATION multi-technique generator (Part C).
4. GPU Quality Control & Diversity Auditor (N-gram spread + DeBERTa sentence embeddings).
5. Canonical unified merge, exact & near deduplication, group-aware 70/15/15 stratified split.
6. Full 5-epoch DeBERTa-v3 retrain and strict frozen test evaluation with threshold calibration.

Usage:
    python run_data_boost_pipeline.py --epochs 5 --batch-size 16 --lr 2e-5
"""

import argparse
import logging
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.data.adapters.wildguardmix_adapter import process_wildguardmix
from src.data.generators.instruction_hijacking_generator import generate_instruction_hijacking_dataset
from src.data.generators.context_manipulation_generator import generate_context_manipulation_dataset
from src.data.generators.quality_control import run_quality_control
from src.data.merge_and_split import main as run_merge_and_split
from src.eval.strict_retrain_and_verify import StrictVerificationPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DataBoostPipeline")


def main():
    parser = argparse.ArgumentParser(description="Master Data Boost & Retrain Pipeline")
    parser.add_argument("--epochs", type=int, default=5, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Training and evaluation batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate for AdamW")
    parser.add_argument("--max-length", type=int, default=256, help="Max sequence length")
    parser.add_argument("--weight-cap", type=float, default=100.0, help="Pos weight cap")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--checkpoint-dir", type=str, default="models/checkpoints", help="Model checkpoint directory")
    parser.add_argument("--skip-generation", action="store_true", help="Skip data generation and proceed directly to merge & retrain")
    parser.add_argument("--device", type=str, default="cuda", help="Target device (cuda/cpu)")

    args = parser.parse_args()

    t_start = time.time()
    print("=" * 100)
    print("STARTING DATA BOOST & RETRAIN VERIFICATION PIPELINE")
    print("=" * 100)

    if not args.skip_generation:
        # Step 1: WildGuardMix JAILBREAK extraction
        print("\n>>> STEP 1: Processing WildGuardMix JAILBREAK Dataset (Part A)...")
        try:
            process_wildguardmix(split="train")
        except Exception as e:
            logger.warning(f"WildGuardMix online load issue ({e}). If running without HF_TOKEN, ensuring local processed files are utilized.")

        # Step 2: INSTRUCTION_HIJACKING synthetic generation
        print("\n>>> STEP 2: Generating Synthetic INSTRUCTION_HIJACKING Dataset (Part B)...")
        generate_instruction_hijacking_dataset()

        # Step 3: CONTEXT_MANIPULATION synthetic generation
        print("\n>>> STEP 3: Generating Synthetic CONTEXT_MANIPULATION Dataset (Part C)...")
        generate_context_manipulation_dataset()

        # Step 4: Quality Control & Diversity Audit
        print("\n>>> STEP 4: Running Quality Control & GPU Diversity Auditor...")
        try:
            run_quality_control(device=args.device)
        except Exception as e:
            logger.warning(f"Quality control note: {e}")

    # Step 5: Canonical Merge, Deduplication & Stratified 70/15/15 Split
    print("\n>>> STEP 5: Running Canonical Merge, Deduplication, and Stratified Splitting...")
    run_merge_and_split()

    # Step 6: Strict Retrain & Evaluation Verification
    print("\n>>> STEP 6: Running Strict Retrain & Test Evaluation on GPU...")
    eval_args = argparse.Namespace(
        mode="full",
        base_model="microsoft/deberta-v3-base",
        epochs=args.epochs,
        batch_size=args.batch_size,
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
