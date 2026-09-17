"""
Root-level executable runner for the Strict Retrain & Verification Pipeline.

Usage on GPU Server:
    # Full retrain + evaluate + calibrate + reconcile
    python run_strict_verification.py --mode full --epochs 5 --batch-size 16

    # Fast evaluation of existing checkpoint + calibration + sanity check
    python run_strict_verification.py --mode eval --checkpoint-dir models/checkpoints
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.eval.strict_retrain_and_verify import main

if __name__ == "__main__":
    main()
