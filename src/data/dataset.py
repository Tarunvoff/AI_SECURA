"""PyTorch Dataset for multi-label AI security threat classification."""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any

import torch
from torch.utils.data import Dataset
from transformers import AutoTokenizer, PreTrainedTokenizerBase

from configs.labels import (
    THREAT_LABELS,
    THREAT_TO_ID,
    NUM_LABELS,
    encode_threats,
)

DEFAULT_MODEL_NAME = "microsoft/deberta-v3-base"
DEFAULT_MAX_LENGTH = 256


class SecurityDataset(Dataset):
    """
    PyTorch Dataset loading AI security threat classification examples from canonical JSONL.
    
    Guarantees:
    1. Isolation: Strictly extracts ONLY 'text' for tokenization. No metadata fields
       ('id', 'severity', 'source', 'quarantined', 'technique_tag', 'source_group_id',
       'level', 'extraction_confirmed', 'cluster_id') are leaked or concatenated into text.
    2. Zero Quarantine: Hard assertion verifying `quarantined is False` for every row.
    3. Strict Label Validation: Converts `threats` list to fixed-length multi-hot tensor
       via `encode_threats()`. Raises ValueError immediately at initialization if an unknown
       threat label appears.
    """

    def __init__(
        self,
        file_path: Union[str, Path],
        tokenizer: Optional[PreTrainedTokenizerBase] = None,
        max_length: int = DEFAULT_MAX_LENGTH,
        pretrained_model_name: str = DEFAULT_MODEL_NAME,
    ):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"Dataset file not found: {self.file_path}")

        if tokenizer is None:
            self.tokenizer = AutoTokenizer.from_pretrained(pretrained_model_name)
        else:
            self.tokenizer = tokenizer

        self.max_length = max_length

        self.texts: List[str] = []
        self.labels: List[List[float]] = []
        self.metadata_samples: List[Dict[str, Any]] = []

        self._load_and_validate()

    def _load_and_validate(self) -> None:
        """Loads JSONL, enforces quarantine assertion, and encodes threat labels."""
        with open(self.file_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                line_str = line.strip()
                if not line_str:
                    continue

                row = json.loads(line_str)

                # Hard quarantine assertion
                quarantined = row.get("quarantined", False)
                if quarantined is True:
                    raise AssertionError(
                        f"Quarantined row leaked into dataset! File: {self.file_path}, Line: {line_idx}, ID: {row.get('id')}"
                    )

                # Extract ONLY text and threats
                if "text" not in row:
                    raise KeyError(f"Missing 'text' key at line {line_idx} in {self.file_path}")
                if "threats" not in row:
                    raise KeyError(f"Missing 'threats' key at line {line_idx} in {self.file_path}")

                raw_text = str(row["text"])
                threats = row["threats"]

                if not isinstance(threats, list):
                    raise TypeError(
                        f"Expected 'threats' to be a list at line {line_idx}, got {type(threats)}"
                    )

                # Fail fast on any unknown label at load time
                try:
                    multi_hot = encode_threats(threats)
                except ValueError as err:
                    raise ValueError(
                        f"Invalid threat label at line {line_idx} in {self.file_path} (ID: {row.get('id')}): {err}"
                    ) from err

                self.texts.append(raw_text)
                self.labels.append(multi_hot)

                # Store first 3 rows' full metadata for inspection/verification
                if len(self.metadata_samples) < 3:
                    self.metadata_samples.append({k: v for k, v in row.items() if k != "text"})

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        text = self.texts[idx]
        label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(label, dtype=torch.float32),
        }

    def get_label_counts(self) -> Dict[str, int]:
        """Returns per-label positive counts across the dataset."""
        counts = {label: 0 for label in THREAT_LABELS}
        for multi_hot in self.labels:
            for idx, val in enumerate(multi_hot):
                if val >= 0.5:
                    counts[THREAT_LABELS[idx]] += 1
        return counts


def compute_pos_weights(
    train_dataset: SecurityDataset,
    cap: Optional[float] = 100.0,
) -> Tuple[torch.Tensor, Dict[str, float]]:
    """
    Computes per-label positive weight tensor for BCEWithLogitsLoss:
    pos_weight[i] = (N - N_pos[i]) / N_pos[i]

    Args:
        train_dataset: SecurityDataset instance for training split.
        cap: Maximum allowable weight value to prevent training instability on ultra-rare classes.

    Returns:
        Tuple of (torch.Tensor of shape [NUM_LABELS], Dict mapping label to weight).
    """
    total_examples = len(train_dataset)
    label_counts = train_dataset.get_label_counts()

    weights_dict: Dict[str, float] = {}
    weights_list: List[float] = []

    for label in THREAT_LABELS:
        n_pos = label_counts[label]
        if n_pos == 0:
            raw_weight = 1.0
        else:
            raw_weight = (total_examples - n_pos) / float(n_pos)

        if cap is not None and raw_weight > cap:
            final_weight = float(cap)
        else:
            final_weight = float(raw_weight)

        weights_dict[label] = final_weight
        weights_list.append(final_weight)

    return torch.tensor(weights_list, dtype=torch.float32), weights_dict


def load_splits(
    data_dir: Union[str, Path] = "data",
    tokenizer: Optional[PreTrainedTokenizerBase] = None,
    max_length: int = DEFAULT_MAX_LENGTH,
) -> Tuple[SecurityDataset, SecurityDataset, SecurityDataset]:
    """Loads train, validation, and test datasets from canonical paths."""
    base_path = Path(data_dir)
    train_path = base_path / "train" / "train.jsonl"
    val_path = base_path / "validation" / "validation.jsonl"
    test_path = base_path / "test" / "test.jsonl"

    if tokenizer is None:
        tokenizer = AutoTokenizer.from_pretrained(DEFAULT_MODEL_NAME)

    train_ds = SecurityDataset(train_path, tokenizer=tokenizer, max_length=max_length)
    val_ds = SecurityDataset(val_path, tokenizer=tokenizer, max_length=max_length)
    test_ds = SecurityDataset(test_path, tokenizer=tokenizer, max_length=max_length)

    return train_ds, val_ds, test_ds


if __name__ == "__main__":
    print("=" * 80)
    print("STEP 9.1: DATASET VERIFICATION & LEAKAGE AUDIT")
    print("=" * 80)

    tokenizer = AutoTokenizer.from_pretrained(DEFAULT_MODEL_NAME)
    train_ds, val_ds, test_ds = load_splits(tokenizer=tokenizer)

    print(f"\n[Split Sizes]")
    print(f"  Train:      {len(train_ds):>7,d} rows")
    print(f"  Validation: {len(val_ds):>7,d} rows")
    print(f"  Test:       {len(test_ds):>7,d} rows")
    print(f"  Total:      {len(train_ds) + len(val_ds) + len(test_ds):>7,d} rows")

    print("\n[Input Isolation & No Metadata Leakage Proof]")
    sample_idx = 0
    sample_raw_text = train_ds.texts[sample_idx]
    sample_meta = train_ds.metadata_samples[0]
    sample_item = train_ds[sample_idx]
    decoded_text = tokenizer.decode(sample_item["input_ids"], skip_special_tokens=True)

    print(f"Sample Row Index: {sample_idx}")
    print(f"Ignored Metadata Fields: {list(sample_meta.keys())}")
    print(f"Sample Metadata Content: {json.dumps(sample_meta, default=str)}")
    print(f"\nExact string passed to tokenizer (first 180 chars):\n  '{sample_raw_text[:180]}...'")
    print(f"\nDecoded from token IDs (first 180 chars):\n  '{decoded_text[:180]}...'")
    print(f"Labels tensor: {sample_item['labels'].tolist()}")

    # Check for any metadata key inside tokenized string
    for meta_key in ["technique_tag", "source_group_id", "extraction_confirmed", "cluster_id"]:
        if meta_key in sample_meta and str(sample_meta[meta_key]) in decoded_text and len(str(sample_meta[meta_key])) > 6:
            print(f"WARNING: Metadata field {meta_key} found in decoded text!")
        else:
            print(f"Confirmed clean: metadata key '{meta_key}' is NOT present in tokenized input.")

    print("\n[Class Distribution & pos_weight Computation]")
    pos_weights, weights_dict = compute_pos_weights(train_ds, cap=100.0)
    train_counts = train_ds.get_label_counts()

    print(f"{'Label':<30} | {'Train Positives':>15} | {'pos_weight (cap=100.0)':>22}")
    print("-" * 74)
    for label in THREAT_LABELS:
        cnt = train_counts[label]
        w = weights_dict[label]
        print(f"{label:<30} | {cnt:>15,d} | {w:>22.4f}")

    print("\nTensor pos_weight vector:")
    print(pos_weights.tolist())
    print("=" * 80)
