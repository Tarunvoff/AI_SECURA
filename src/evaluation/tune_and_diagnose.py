"""Diagnostic script for per-label threshold tuning and JAILBREAK/INSTRUCTION_HIJACKING confusion analysis."""

import argparse
import json
import math
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import precision_recall_curve, precision_recall_fscore_support, average_precision_score
from torch.utils.data import DataLoader
from transformers import AutoTokenizer

from configs.labels import NUM_LABELS, THREAT_LABELS
from src.data.dataset import SecurityDataset, load_splits
from src.models.security_classifier import SecurityClassifier


def get_model_probabilities(
    model: nn.Module,
    data_loader: DataLoader,
    device: torch.device,
) -> Tuple[np.ndarray, np.ndarray]:
    """Extracts raw probabilities and ground truth multi-hot targets for a dataset."""
    model.eval()
    all_probs: List[np.ndarray] = []
    all_targets: List[np.ndarray] = []

    with torch.no_grad():
        for batch in data_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            with torch.amp.autocast(device_type="cuda" if device.type == "cuda" else "cpu", enabled=(device.type == "cuda")):
                logits = model(input_ids=input_ids, attention_mask=attention_mask)

            probs = torch.sigmoid(logits).cpu().numpy()
            targets = labels.cpu().numpy()

            all_probs.append(probs)
            all_targets.append(targets)

    return np.vstack(all_probs), np.vstack(all_targets)


def tune_thresholds_on_val(
    val_probs: np.ndarray,
    val_targets: np.ndarray,
) -> Dict[str, Dict[str, Any]]:
    """
    Finds optimal F1 threshold per label independently on validation data.
    Saves and returns threshold metrics.
    """
    print("\n" + "=" * 105)
    print("ITEM 1 — PER-LABEL OPTIMAL THRESHOLD SEARCH (VALIDATION SET)")
    print("=" * 105)
    print(f"{'Label Name':<28} | {'Val Pos':>7} | {'Opt Thresh':>10} | {'Val Prec':>10} | {'Val Rec':>10} | {'Val F1':>10} | {'Data Support Note'}")
    print("-" * 105)

    tuning_results: Dict[str, Dict[str, Any]] = {}
    rare_labels = {"DATA_EXFILTRATION", "MALICIOUS_DOCUMENT", "AGENT_HIJACKING", "CONTEXT_MANIPULATION"}

    for idx, label_name in enumerate(THREAT_LABELS):
        y_true = val_targets[:, idx]
        y_prob = val_probs[:, idx]
        val_positives = int(np.sum(y_true))

        if val_positives == 0 or np.all(y_prob == 0):
            best_threshold = 0.5
            p_best, r_best, f1_best = 0.0, 0.0, 0.0
        else:
            precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
            f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
            best_idx = int(np.argmax(f1_scores))

            best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5
            p_best = float(precisions[best_idx])
            r_best = float(recalls[best_idx])
            f1_best = float(f1_scores[best_idx])

        note = "Low sample count (<30) - high variance" if label_name in rare_labels else "Sufficient sample count"

        print(
            f"{label_name:<28} | {val_positives:>7d} | {best_threshold:>10.4f} | "
            f"{p_best:>10.4f} | {r_best:>10.4f} | {f1_best:>10.4f} | {note}"
        )

        tuning_results[label_name] = {
            "threshold": best_threshold,
            "val_positives": val_positives,
            "val_precision": p_best,
            "val_recall": r_best,
            "val_f1": f1_best,
            "is_rare": label_name in rare_labels,
        }

    print("=" * 105)
    return tuning_results


def evaluate_with_thresholds(
    probs: np.ndarray,
    targets: np.ndarray,
    thresholds: Dict[str, float],
) -> Dict[str, Any]:
    """Evaluates multi-label predictions against targets using arbitrary per-label thresholds."""
    preds = np.zeros_like(probs, dtype=np.float32)
    for idx, label_name in enumerate(THREAT_LABELS):
        thresh = thresholds[label_name]
        preds[:, idx] = (probs[:, idx] >= thresh).astype(np.float32)

    per_label: Dict[str, Dict[str, float]] = {}
    for idx, label_name in enumerate(THREAT_LABELS):
        y_true = targets[:, idx]
        y_pred = preds[:, idx]
        y_prob = probs[:, idx]

        p, r, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="binary", zero_division=0
        )
        try:
            pr_auc = float(average_precision_score(y_true, y_prob))
            if math.isnan(pr_auc):
                pr_auc = 0.0
        except Exception:
            pr_auc = 0.0

        per_label[label_name] = {
            "precision": float(p),
            "recall": float(r),
            "f1": float(f1),
            "pr_auc": float(pr_auc),
            "support": int(np.sum(y_true)),
        }

    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        targets, preds, average="macro", zero_division=0
    )
    micro_p, micro_r, micro_f1, _ = precision_recall_fscore_support(
        targets, preds, average="micro", zero_division=0
    )

    return {
        "macro_precision": float(macro_p),
        "macro_recall": float(macro_r),
        "macro_f1": float(macro_f1),
        "micro_precision": float(micro_p),
        "micro_recall": float(micro_r),
        "micro_f1": float(micro_f1),
        "per_label": per_label,
        "preds": preds,
    }


def run_confusion_analysis(
    test_targets: np.ndarray,
    test_probs: np.ndarray,
    threshold: float = 0.5,
) -> None:
    """Performs confusion check between JAILBREAK and INSTRUCTION_HIJACKING."""
    print("\n" + "=" * 90)
    print("ITEM 2 — JAILBREAK vs. INSTRUCTION_HIJACKING CONFUSION CHECK (TEST SET, 0.5 THRESHOLD)")
    print("=" * 90)

    jb_idx = THREAT_LABELS.index("JAILBREAK")
    hj_idx = THREAT_LABELS.index("INSTRUCTION_HIJACKING")

    test_preds = (test_probs >= threshold).astype(np.float32)

    # 1. JAILBREAK False Negatives
    jb_positives = test_targets[:, jb_idx] == 1
    jb_fn = jb_positives & (test_preds[:, jb_idx] == 0)
    jb_fn_count = int(np.sum(jb_fn))
    jb_fn_confused_as_hj = int(np.sum(jb_fn & (test_preds[:, hj_idx] == 1)))
    jb_confusion_pct = (jb_fn_confused_as_hj / jb_fn_count * 100.0) if jb_fn_count > 0 else 0.0

    # 2. INSTRUCTION_HIJACKING False Negatives
    hj_positives = test_targets[:, hj_idx] == 1
    hj_fn = hj_positives & (test_preds[:, hj_idx] == 0)
    hj_fn_count = int(np.sum(hj_fn))
    hj_fn_confused_as_jb = int(np.sum(hj_fn & (test_preds[:, jb_idx] == 1)))
    hj_confusion_pct = (hj_fn_confused_as_jb / hj_fn_count * 100.0) if hj_fn_count > 0 else 0.0

    # 3. True Co-occurrences in Test set
    both_true = int(np.sum((test_targets[:, jb_idx] == 1) & (test_targets[:, hj_idx] == 1)))
    both_predicted = int(np.sum((test_preds[:, jb_idx] == 1) & (test_preds[:, hj_idx] == 1)))

    print(f"Total True JAILBREAK instances:              {int(np.sum(jb_positives)):>5d}")
    print(f"  -> JAILBREAK False Negatives:             {jb_fn_count:>5d} (missed by model)")
    print(f"  -> Confused as INSTRUCTION_HIJACKING:     {jb_fn_confused_as_hj:>5d} ({jb_confusion_pct:.2f}% of missed JAILBREAKs)")
    print()
    print(f"Total True INSTRUCTION_HIJACKING instances:   {int(np.sum(hj_positives)):>5d}")
    print(f"  -> INSTRUCTION_HIJACKING False Negatives: {hj_fn_count:>5d} (missed by model)")
    print(f"  -> Confused as JAILBREAK:                 {hj_fn_confused_as_jb:>5d} ({hj_confusion_pct:.2f}% of missed HIJACKINGs)")
    print()
    print(f"Ground-truth Co-occurring (Both = 1):        {both_true:>5d}")
    print(f"Model Predicted Simultaneously (Both = 1):   {both_predicted:>5d}")
    print("-" * 90)

    print("Confusion Diagnosis:")
    if jb_confusion_pct > 30.0 or hj_confusion_pct > 30.0:
        print("  (!) HIGH CONFUSION: Substantial overlap and discrimination difficulty detected between")
        print("      JAILBREAK and INSTRUCTION_HIJACKING representations. Errors are actively bleeding")
        print("      between the two labels rather than solely falling as pure background misses.")
    else:
        print("  (i) LOW CROSS-CONFUSION: The majority of false negatives on both classes are predicted as neither,")
        print("      indicating that errors are primarily caused by conservative classification / limited representation")
        print("      rather than direct cross-label confusion.")
    print("=" * 90)


def print_comparison_report(
    eval_05: Dict[str, Any],
    eval_tuned: Dict[str, Any],
    tuned_thresholds: Dict[str, float],
) -> None:
    """Prints side-by-side comparison table between 0.5 threshold and tuned per-label thresholds."""
    print("\n" + "=" * 118)
    print("BEFORE VS. AFTER TEST SET METRICS COMPARISON (0.5 THRESHOLD vs. TUNED PER-LABEL THRESHOLDS)")
    print("=" * 118)
    print(
        f"{'Label Name':<26} | {'Supp':>5} | {'Thresh':>7} | "
        f"{'Prec(0.5)':>9} {'Prec(Tun)':>9} | "
        f"{'Rec(0.5)':>8} {'Rec(Tun)':>8} | "
        f"{'F1(0.5)':>7} {'F1(Tun)':>7} | {'PR-AUC':>7}"
    )
    print("-" * 118)

    for label_name in THREAT_LABELS:
        m05 = eval_05["per_label"][label_name]
        mt = eval_tuned["per_label"][label_name]
        t = tuned_thresholds[label_name]

        print(
            f"{label_name:<26} | {m05['support']:>5d} | {t:>7.4f} | "
            f"{m05['precision']:>9.4f} {mt['precision']:>9.4f} | "
            f"{m05['recall']:>8.4f} {mt['recall']:>8.4f} | "
            f"{m05['f1']:>7.4f} {mt['f1']:>7.4f} | "
            f"{m05['pr_auc']:>7.4f}"
        )

    print("-" * 118)
    print(
        f"{'Macro Average':<26} | {sum(m['support'] for m in eval_05['per_label'].values()):>5d} | {'-':>7} | "
        f"{eval_05['macro_precision']:>9.4f} {eval_tuned['macro_precision']:>9.4f} | "
        f"{eval_05['macro_recall']:>8.4f} {eval_tuned['macro_recall']:>8.4f} | "
        f"{eval_05['macro_f1']:>7.4f} {eval_tuned['macro_f1']:>7.4f} | {'-':>7}"
    )
    print(
        f"{'Micro Average':<26} | {sum(m['support'] for m in eval_05['per_label'].values()):>5d} | {'-':>7} | "
        f"{eval_05['micro_precision']:>9.4f} {eval_tuned['micro_precision']:>9.4f} | "
        f"{eval_05['micro_recall']:>8.4f} {eval_tuned['micro_recall']:>8.4f} | "
        f"{eval_05['micro_f1']:>7.4f} {eval_tuned['micro_f1']:>7.4f} | {'-':>7}"
    )
    print("=" * 118)


def main():
    parser = argparse.ArgumentParser(description="Threshold tuning and diagnostic checks for AI Secura")
    parser.add_argument("--model-path", type=str, default="models/checkpoints/best_model")
    parser.add_argument("--data-dir", type=str, default="data")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--output-thresholds", type=str, default="thresholds.json")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device for diagnosis: {device}")

    tokenizer = AutoTokenizer.from_pretrained("microsoft/deberta-v3-base")
    _, val_ds, test_ds = load_splits(data_dir=args.data_dir, tokenizer=tokenizer)

    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False, pin_memory=(device.type == "cuda"))
    test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False, pin_memory=(device.type == "cuda"))

    print(f"Loading checkpoint from {args.model_path}...")
    model = SecurityClassifier.from_pretrained(args.model_path).to(device)

    # 1. Validation set extraction & threshold tuning
    print("Generating validation set predictions...")
    val_probs, val_targets = get_model_probabilities(model, val_loader, device)
    tuning_data = tune_thresholds_on_val(val_probs, val_targets)

    # Save thresholds.json
    thresholds_dict = {label: data["threshold"] for label, data in tuning_data.items()}
    with open(args.output_thresholds, "w", encoding="utf-8") as f:
        json.dump(thresholds_dict, f, indent=2)
    print(f"Saved optimal thresholds to: {args.output_thresholds}")

    # 2. Test set extraction & side-by-side evaluation
    print("\nGenerating test set predictions...")
    test_probs, test_targets = get_model_probabilities(model, test_loader, device)

    default_thresholds = {label: 0.5 for label in THREAT_LABELS}
    eval_05 = evaluate_with_thresholds(test_probs, test_targets, default_thresholds)
    eval_tuned = evaluate_with_thresholds(test_probs, test_targets, thresholds_dict)

    print_comparison_report(eval_05, eval_tuned, thresholds_dict)

    # 3. Item 2: JAILBREAK / INSTRUCTION_HIJACKING confusion analysis
    run_confusion_analysis(test_targets, test_probs, threshold=0.5)


if __name__ == "__main__":
    main()
