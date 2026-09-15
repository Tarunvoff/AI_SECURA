"""Neural architecture for multi-label AI security threat classification using DeBERTa-v3."""

from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import torch
import torch.nn as nn
from transformers import AutoConfig, AutoModel

from configs.labels import NUM_LABELS, THREAT_LABELS

DEFAULT_PRETRAINED_MODEL = "microsoft/deberta-v3-base"


class SecurityClassifier(nn.Module):
    """
    DeBERTa-v3-base multi-label sequence classifier with custom classification head.
    
    Architecture:
    - Base Encoder: microsoft/deberta-v3-base (~86M backbone parameters + embedding layers)
    - Classification Head: Dropout(0.1) -> Linear(hidden_size, NUM_LABELS)
    - Output: Raw logits (batch_size, NUM_LABELS) for BCEWithLogitsLoss
    """

    def __init__(
        self,
        pretrained_model_name: str = DEFAULT_PRETRAINED_MODEL,
        dropout_rate: float = 0.1,
        num_labels: int = NUM_LABELS,
    ):
        super().__init__()
        self.num_labels = num_labels
        self.pretrained_model_name = pretrained_model_name

        self.config = AutoConfig.from_pretrained(pretrained_model_name)
        self.encoder = AutoModel.from_pretrained(pretrained_model_name, config=self.config)

        self.dropout = nn.Dropout(dropout_rate)
        self.classifier = nn.Linear(self.config.hidden_size, self.num_labels)

        # Initialize head weights with small standard deviation
        nn.init.normal_(self.classifier.weight, std=0.02)
        nn.init.zeros_(self.classifier.bias)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        token_type_ids: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Forward pass producing raw multi-label logits.
        
        Args:
            input_ids: (batch_size, seq_len)
            attention_mask: (batch_size, seq_len)
            token_type_ids: (batch_size, seq_len), optional
            
        Returns:
            torch.Tensor of raw logits of shape (batch_size, NUM_LABELS).
        """
        encoder_outputs = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            return_dict=True,
        )

        # Use first token [CLS] representation (last_hidden_state[:, 0, :])
        cls_rep = encoder_outputs.last_hidden_state[:, 0, :]
        dropped = self.dropout(cls_rep)
        logits = self.classifier(dropped)
        return logits

    def count_parameters(self) -> Tuple[int, int]:
        """Returns (total_params, trainable_params)."""
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        return total, trainable

    def save_pretrained(self, save_directory: Union[str, Path]) -> None:
        """Saves model weights and configuration."""
        save_path = Path(save_directory)
        save_path.mkdir(parents=True, exist_ok=True)
        torch.save(self.state_dict(), save_path / "model.pt")
        self.config.save_pretrained(save_path)

    @classmethod
    def from_pretrained(
        cls,
        load_directory: Union[str, Path],
        pretrained_model_name: str = DEFAULT_PRETRAINED_MODEL,
        dropout_rate: float = 0.1,
        num_labels: int = NUM_LABELS,
        map_location: Optional[str] = None,
    ) -> "SecurityClassifier":
        """Loads model weights from a saved directory."""
        load_path = Path(load_directory)
        model = cls(
            pretrained_model_name=pretrained_model_name,
            dropout_rate=dropout_rate,
            num_labels=num_labels,
        )
        pt_path = load_path / "model.pt"
        if not pt_path.exists():
            raise FileNotFoundError(f"Model checkpoint not found at {pt_path}")
        state_dict = torch.load(pt_path, map_location=map_location, weights_only=True)
        model.load_state_dict(state_dict)
        return model


if __name__ == "__main__":
    print("=" * 80)
    print("STEP 9.2: SECURITY CLASSIFIER ARCHITECTURE & PARAMETER COUNT")
    print("=" * 80)

    model = SecurityClassifier()
    total_params, trainable_params = model.count_parameters()

    print(f"\nModel: {DEFAULT_PRETRAINED_MODEL} + Linear Classification Head")
    print(f"Number of output labels (from configs.labels.NUM_LABELS): {model.num_labels}")
    print(f"Hidden size: {model.config.hidden_size}")
    print(f"\n[Parameter Counts]")
    print(f"  Total parameters:     {total_params:>12,d} ({total_params / 1e6:.2f} M)")
    print(f"  Trainable parameters: {trainable_params:>12,d} ({trainable_params / 1e6:.2f} M)")

    # Test a dummy forward pass
    dummy_input_ids = torch.randint(0, 1000, (2, 64))
    dummy_mask = torch.ones((2, 64), dtype=torch.long)
    logits = model(input_ids=dummy_input_ids, attention_mask=dummy_mask)

    print(f"\nDummy forward pass:")
    print(f"  Input IDs shape:       {dummy_input_ids.shape}")
    print(f"  Output logits shape:   {logits.shape}  (Expected: [2, {NUM_LABELS}])")
    assert logits.shape == (2, NUM_LABELS), f"Expected shape (2, {NUM_LABELS}), got {logits.shape}"
    print("  Output shape assertion passed!")
    print("=" * 80)
