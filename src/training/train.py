"""Training and evaluation pipeline for AI Security Threat Classifier (DeBERTa-v3-base)."""

import argparse
import json
import math
import os
import random
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Subset
from transformers import (
    AutoTokenizer,
    get_cosine_schedule_with_warmup,
    get_linear_schedule_with_warmup,
)
from sklearn.metrics import precision_recall_fscore_support, average_precision_score

from configs.labels import NUM_LABELS, THREAT_LABELS
from src.data.dataset import SecurityDataset, compute_pos_weights, load_splits
from src.models.security_classifier import SecurityClassifier


def set_seed(seed: int = 42) -> None:
    """Sets random seeds for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def evaluate_model(
    model: nn.Module,
    data_loader: DataLoader,
    device: torch.device,
    criterion: Optional[nn.Module] = None,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Evaluates the model over a dataloader.
    
    Computes:
    - Average validation loss (if criterion provided)
    - Per-label precision, recall, F1, PR-AUC, and support count
    - Micro and Macro F1/Precision/Recall averages
    """
    model.eval()
    total_loss = 0.0
    all_preds_list: List[np.ndarray] = []
    all_targets_list: List[np.ndarray] = []
    all_probs_list: List[np.ndarray] = []

    with torch.no_grad():
        for batch in data_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            with torch.amp.autocast(device_type="cuda" if device.type == "cuda" else "cpu", enabled=(device.type == "cuda")):
                logits = model(input_ids=input_ids, attention_mask=attention_mask)
                if criterion is not None:
                    loss = criterion(logits, labels)
                    total_loss += loss.item() * input_ids.size(0)

            probs = torch.sigmoid(logits).cpu().numpy()
            targets = labels.cpu().numpy()

            all_probs_list.append(probs)
            all_targets_list.append(targets)

    all_probs = np.vstack(all_probs_list)
    all_targets = np.vstack(all_targets_list)
    all_preds = (all_probs >= threshold).astype(np.float32)

    total_samples = len(all_targets)
    avg_loss = (total_loss / total_samples) if (criterion is not None and total_samples > 0) else 0.0

    # Per-label metrics
    per_label_metrics: Dict[str, Dict[str, float]] = {}
    for idx, label_name in enumerate(THREAT_LABELS):
        y_true = all_targets[:, idx]
        y_pred = all_preds[:, idx]
        y_prob = all_probs[:, idx]

        p, r, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="binary", zero_division=0
        )
        support = int(np.sum(y_true))

        # Calculate PR-AUC (Average Precision)
        try:
            pr_auc = float(average_precision_score(y_true, y_prob))
            if math.isnan(pr_auc):
                pr_auc = 0.0
        except Exception:
            pr_auc = 0.0

        per_label_metrics[label_name] = {
            "precision": float(p),
            "recall": float(r),
            "f1": float(f1),
            "pr_auc": float(pr_auc),
            "support": support,
        }

    # Macro & Micro averages
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        all_targets, all_preds, average="macro", zero_division=0
    )
    micro_p, micro_r, micro_f1, _ = precision_recall_fscore_support(
        all_targets, all_preds, average="micro", zero_division=0
    )

    return {
        "loss": avg_loss,
        "macro_precision": float(macro_p),
        "macro_recall": float(macro_r),
        "macro_f1": float(macro_f1),
        "micro_precision": float(micro_p),
        "micro_recall": float(micro_r),
        "micro_f1": float(micro_f1),
        "per_label": per_label_metrics,
        "all_probs": all_probs,
        "all_targets": all_targets,
    }


def print_evaluation_report(eval_results: Dict[str, Any], split_name: str = "Test") -> None:
    """Formats and prints comprehensive per-label classification metrics table."""
    print("\n" + "=" * 92)
    print(f"EVALUATION REPORT — {split_name.upper()} SET")
    print("=" * 92)
    print(f"Loss: {eval_results['loss']:.4f} | Macro F1: {eval_results['macro_f1']:.4f} | Micro F1: {eval_results['micro_f1']:.4f}")
    print("-" * 92)
    print(f"{'Label Name':<28} | {'Support':>8} | {'Precision':>10} | {'Recall':>10} | {'F1-Score':>10} | {'PR-AUC':>10}")
    print("-" * 92)

    rare_labels = {"DATA_EXFILTRATION", "MALICIOUS_DOCUMENT", "AGENT_HIJACKING", "CONTEXT_MANIPULATION"}

    for label_name in THREAT_LABELS:
        m = eval_results["per_label"][label_name]
        marker = " (!)" if label_name in rare_labels else "    "
        print(
            f"{label_name + marker:<28} | "
            f"{m['support']:>8,d} | "
            f"{m['precision']:>10.4f} | "
            f"{m['recall']:>10.4f} | "
            f"{m['f1']:>10.4f} | "
            f"{m['pr_auc']:>10.4f}"
        )

    print("-" * 92)
    print(f"{'Macro Average':<28} | {sum(m['support'] for m in eval_results['per_label'].values()):>8,d} | "
          f"{eval_results['macro_precision']:>10.4f} | {eval_results['macro_recall']:>10.4f} | {eval_results['macro_f1']:>10.4f} | {'-':>10}")
    print(f"{'Micro Average':<28} | {sum(m['support'] for m in eval_results['per_label'].values()):>8,d} | "
          f"{eval_results['micro_precision']:>10.4f} | {eval_results['micro_recall']:>10.4f} | {eval_results['micro_f1']:>10.4f} | {'-':>10}")
    print("=" * 92)
    print("Note: '(!)' marks the 4 rare underrepresented classes in the dataset taxonomy.\n")


def train_epoch(
    model: nn.Module,
    train_loader: DataLoader,
    optimizer: torch.optim.Optimizer,
    scheduler: Any,
    criterion: nn.Module,
    scaler: torch.amp.GradScaler,
    device: torch.device,
    epoch: int,
    log_interval: int = 50,
) -> float:
    """Runs a single training epoch with gradient scaling and step logging."""
    model.train()
    running_loss = 0.0
    total_tokens = 0
    step_loss = 0.0
    start_time = time.time()

    total_steps = len(train_loader)
    for step, batch in enumerate(train_loader, start=1):
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["labels"].to(device)

        optimizer.zero_grad()

        with torch.amp.autocast(device_type="cuda" if device.type == "cuda" else "cpu", enabled=(device.type == "cuda")):
            logits = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = criterion(logits, labels)

        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        scaler.step(optimizer)
        scaler.update()
        scheduler.step()

        running_loss += loss.item() * input_ids.size(0)
        step_loss += loss.item()

        if step % log_interval == 0 or step == total_steps:
            avg_step_loss = step_loss / (log_interval if step % log_interval == 0 else (step % log_interval))
            lr = optimizer.param_groups[0]["lr"]
            elapsed = time.time() - start_time
            print(f"  [Epoch {epoch} | Step {step:>5d}/{total_steps:>5d}]  Loss: {avg_step_loss:.4f}  |  LR: {lr:.2e}  |  Elapsed: {elapsed:.1f}s")
            step_loss = 0.0

    epoch_loss = running_loss / len(train_loader.dataset)
    return epoch_loss


def run_smoke_test(
    train_ds: SecurityDataset,
    val_ds: SecurityDataset,
    device: torch.device,
    train_size: int = 2000,
    val_size: int = 500,
    batch_size: int = 16,
    lr: float = 2e-5,
) -> None:
    """
    Executes smoke test on 2,000 train rows and 500 val rows.
    Verifies loss descent and compares weighted vs unweighted loss.
    """
    print("\n" + "#" * 80)
    print("STAGE 1: SMOKE TEST (2,000 Train / 500 Val)")
    print("#" * 80)

    set_seed(42)
    train_indices = random.sample(range(len(train_ds)), min(train_size, len(train_ds)))
    val_indices = random.sample(range(len(val_ds)), min(val_size, len(val_ds)))

    smoke_train_ds = Subset(train_ds, train_indices)
    smoke_val_ds = Subset(val_ds, val_indices)

    smoke_train_loader = DataLoader(smoke_train_ds, batch_size=batch_size, shuffle=True)
    smoke_val_loader = DataLoader(smoke_val_ds, batch_size=batch_size, shuffle=False)

    print(f"Smoke train batches: {len(smoke_train_loader)} (Batch size: {batch_size})")
    print(f"Smoke val batches:   {len(smoke_val_loader)}")

    # 1. Run Weighted Loss Smoke Test
    print("\n--- Running Smoke Test 1: Weighted BCEWithLogitsLoss (pos_weight capped at 100) ---")
    pos_weights, weights_dict = compute_pos_weights(train_ds, cap=100.0)
    pos_weights_device = pos_weights.to(device)
    criterion_weighted = nn.BCEWithLogitsLoss(pos_weight=pos_weights_device)

    model_weighted = SecurityClassifier().to(device)
    optimizer = torch.optim.AdamW(model_weighted.parameters(), lr=lr, weight_decay=0.01)
    total_steps = len(smoke_train_loader)
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=10, num_training_steps=total_steps)
    scaler = torch.amp.GradScaler("cuda", enabled=(device.type == "cuda"))

    train_loss = train_epoch(
        model=model_weighted,
        train_loader=smoke_train_loader,
        optimizer=optimizer,
        scheduler=scheduler,
        criterion=criterion_weighted,
        scaler=scaler,
        device=device,
        epoch=1,
        log_interval=20,
    )
    print(f"Smoke Test 1 Weighted Epoch 1 Average Loss: {train_loss:.4f}")

    eval_weighted = evaluate_model(
        model=model_weighted,
        data_loader=smoke_val_loader,
        device=device,
        criterion=criterion_weighted,
    )
    print_evaluation_report(eval_weighted, split_name="Smoke Val (Weighted)")

    # 2. Run Unweighted Loss Smoke Test for comparison
    print("\n--- Running Smoke Test 2: Unweighted BCEWithLogitsLoss (Baseline) ---")
    criterion_unweighted = nn.BCEWithLogitsLoss()
    model_unweighted = SecurityClassifier().to(device)
    optimizer_unweighted = torch.optim.AdamW(model_unweighted.parameters(), lr=lr, weight_decay=0.01)
    scheduler_unweighted = get_linear_schedule_with_warmup(optimizer_unweighted, num_warmup_steps=10, num_training_steps=total_steps)
    scaler_unweighted = torch.amp.GradScaler("cuda", enabled=(device.type == "cuda"))

    train_loss_unweighted = train_epoch(
        model=model_unweighted,
        train_loader=smoke_train_loader,
        optimizer=optimizer_unweighted,
        scheduler=scheduler_unweighted,
        criterion=criterion_unweighted,
        scaler=scaler_unweighted,
        device=device,
        epoch=1,
        log_interval=20,
    )
    print(f"Smoke Test 2 Unweighted Epoch 1 Average Loss: {train_loss_unweighted:.4f}")

    eval_unweighted = evaluate_model(
        model=model_unweighted,
        data_loader=smoke_val_loader,
        device=device,
        criterion=criterion_unweighted,
    )
    print_evaluation_report(eval_unweighted, split_name="Smoke Val (Unweighted)")

    print("\n[Smoke Test Verification Summary]")
    print(f"Weighted Model Val Loss:   {eval_weighted['loss']:.4f} | Macro F1: {eval_weighted['macro_f1']:.4f}")
    print(f"Unweighted Model Val Loss: {eval_unweighted['loss']:.4f} | Macro F1: {eval_unweighted['macro_f1']:.4f}")
    print("Smoke test successfully completed! Ready for full training run.")


def run_full_training(
    train_ds: SecurityDataset,
    val_ds: SecurityDataset,
    test_ds: SecurityDataset,
    device: torch.device,
    epochs: int = 5,
    batch_size: int = 16,
    lr: float = 2e-5,
    weight_cap: float = 100.0,
    checkpoint_dir: str = "models/checkpoints",
) -> Tuple[SecurityClassifier, Dict[str, Any]]:
    """
    Executes full 5-epoch training run on the entire dataset.
    Logs per-epoch train and validation loss, saves best checkpoint, and evaluates on test split.
    """
    print("\n" + "#" * 80)
    print("STAGE 2: FULL TRAINING RUN (5 Epochs)")
    print("#" * 80)

    set_seed(42)
    checkpoint_path = Path(checkpoint_dir)
    checkpoint_path.mkdir(parents=True, exist_ok=True)

    # Compute pos_weight vector
    pos_weights, weights_dict = compute_pos_weights(train_ds, cap=weight_cap)
    pos_weights_device = pos_weights.to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weights_device)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, pin_memory=(device.type == "cuda"))
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, pin_memory=(device.type == "cuda"))
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False, pin_memory=(device.type == "cuda"))

    model = SecurityClassifier().to(device)
    total_params, trainable_params = model.count_parameters()
    print(f"\nModel Initialized:")
    print(f"  Total parameters:     {total_params:>12,d}")
    print(f"  Trainable parameters: {trainable_params:>12,d}")
    print(f"  Device:               {device}")
    print(f"  Batch size:           {batch_size}")
    print(f"  Learning rate:        {lr}")
    print(f"  Epochs:               {epochs}")
    print(f"  Total train steps:    {len(train_loader) * epochs:,d}")

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    total_training_steps = len(train_loader) * epochs
    warmup_steps = int(0.1 * total_training_steps)
    scheduler = get_cosine_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_training_steps
    )
    scaler = torch.amp.GradScaler("cuda", enabled=(device.type == "cuda"))

    best_val_loss = float("inf")
    best_val_macro_f1 = 0.0
    history: List[Dict[str, float]] = []

    for epoch in range(1, epochs + 1):
        print(f"\n" + "=" * 60)
        print(f"EPOCH {epoch}/{epochs}")
        print("=" * 60)

        epoch_start = time.time()
        train_loss = train_epoch(
            model=model,
            train_loader=train_loader,
            optimizer=optimizer,
            scheduler=scheduler,
            criterion=criterion,
            scaler=scaler,
            device=device,
            epoch=epoch,
            log_interval=200,
        )

        val_results = evaluate_model(
            model=model,
            data_loader=val_loader,
            device=device,
            criterion=criterion,
        )
        epoch_time = time.time() - epoch_start

        epoch_record = {
            "epoch": epoch,
            "train_loss": train_loss,
            "val_loss": val_results["loss"],
            "val_macro_f1": val_results["macro_f1"],
            "val_micro_f1": val_results["micro_f1"],
            "epoch_time_seconds": epoch_time,
        }
        history.append(epoch_record)

        print(f"\n[Epoch {epoch} Summary] ({epoch_time:.1f}s)")
        print(f"  Train Loss:     {train_loss:.4f}")
        print(f"  Val Loss:       {val_results['loss']:.4f}")
        print(f"  Val Macro F1:   {val_results['macro_f1']:.4f}")
        print(f"  Val Micro F1:   {val_results['micro_f1']:.4f}")

        # Save best checkpoint
        if val_results["loss"] < best_val_loss:
            best_val_loss = val_results["loss"]
            best_val_macro_f1 = val_results["macro_f1"]
            model.save_pretrained(checkpoint_path / "best_model")
            print(f"  -> Saved new best model checkpoint (Val Loss: {best_val_loss:.4f})")

    # Save final model
    model.save_pretrained(checkpoint_path / "final_model")
    with open(checkpoint_path / "training_history.json", "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    print("\n" + "=" * 80)
    print("TRAINING COMPLETE — EVALUATING ON TEST SET")
    print("=" * 80)

    # Load best model for evaluation
    best_model = SecurityClassifier.from_pretrained(checkpoint_path / "best_model").to(device)
    test_results = evaluate_model(
        model=best_model,
        data_loader=test_loader,
        device=device,
        criterion=criterion,
    )

    print_evaluation_report(test_results, split_name="Test")

    return best_model, test_results


def main():
    parser = argparse.ArgumentParser(description="Train AI Security Threat Classifier (DeBERTa-v3-base)")
    parser.add_argument("--mode", type=str, choices=["smoke", "full", "both"], default="both")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--data-dir", type=str, default="data")
    parser.add_argument("--weight-cap", type=float, default=100.0)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    set_seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    if device.type == "cuda":
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.2f} GB")
    else:
        print("WARNING: GPU is NOT available. Running on CPU. Training will take longer.")

    tokenizer = AutoTokenizer.from_pretrained("microsoft/deberta-v3-base")
    print("\nLoading dataset splits from canonical JSONL files...")
    train_ds, val_ds, test_ds = load_splits(data_dir=args.data_dir, tokenizer=tokenizer)

    if args.mode in ["smoke", "both"]:
        run_smoke_test(
            train_ds=train_ds,
            val_ds=val_ds,
            device=device,
            train_size=2000,
            val_size=500,
            batch_size=args.batch_size,
            lr=args.lr,
        )

    if args.mode in ["full", "both"]:
        run_full_training(
            train_ds=train_ds,
            val_ds=val_ds,
            test_ds=test_ds,
            device=device,
            epochs=args.epochs,
            batch_size=args.batch_size,
            lr=args.lr,
            weight_cap=args.weight_cap,
        )


if __name__ == "__main__":
    main()
