# AI_SECURA — Multi-Label AI Security Threat Classifier

Production-grade AI Security Threat Detection pipeline based on `microsoft/deberta-v3-base`. Classifies text inputs across 10 canonical AI red-teaming threat categories.

---

## 🛡️ 10 Canonical Threat Taxonomy

1. `PROMPT_INJECTION` (Direct prompt injection)
2. `INDIRECT_PROMPT_INJECTION` (Third-party content payload injection)
3. `JAILBREAK` (Safety constraint bypass / DAN persona play)
4. `SYSTEM_PROMPT_EXTRACTION` (System prompt / instruction leakage)
5. `INSTRUCTION_HIJACKING` (Task hijacking and redirection)
6. `DATA_EXFILTRATION` (Unauthorized data exfiltration via side channels)
7. `MALICIOUS_DOCUMENT` (Malicious document / payload injection)
8. `AGENT_HIJACKING` (Autonomous agent hijacking)
9. `TOOL_ABUSE` (Tool calling / MCP / Function abuse)
10. `CONTEXT_MANIPULATION` (Context overflow / confusion / poisoning)

---

## 📋 Prerequisites & Installation

### 1. Environment Requirements
- Python >= 3.10
- PyTorch >= 2.0 (CUDA-enabled build recommended for GPU acceleration)

### 2. Install Dependencies
```bash
# PyTorch with CUDA (e.g. CUDA 12.6)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu126

# Model & Data dependencies
pip install transformers sentencepiece protobuf scikit-learn numpy tqdm
```

---

## 🚀 How to Run

### Step 1: Verify Dataset & Leakage Isolation
Verifies split integrity (104,959 train / 22,460 val / 22,464 test), asserts zero quarantined rows, proves zero metadata leakage into tokenized inputs, and calculates the empirical `pos_weight` vector.

```bash
python -m src.data.dataset
```

### Step 2: Inspect Model Architecture & Parameters
Inspects the DeBERTa-v3-base backbone + linear classification head, verifying total parameters (~184.4M) and test forward-pass tensor shapes.

```bash
python -m src.models.security_classifier
```

### Step 3: Run Smoke Test (Fast Sanity Check)
Runs 1 epoch over 2,000 train rows evaluated against 500 validation rows. Compares weighted BCE loss vs unweighted BCE baseline and prints step-level loss descent.

```bash
python -m src.training.train --mode smoke --batch-size 16 --lr 2e-5
```

### Step 4: Full 5-Epoch Training Run
Executes full 5-epoch training on the entire 105K dataset using mixed precision (`fp16`), cosine warmup scheduler, and saves the best model checkpoint to `models/checkpoints/best_model/`.

```bash
python -m src.training.train --mode full --epochs 5 --batch-size 16 --lr 2e-5 --weight-cap 100.0
```

### Step 5: Run Smoke Test followed by Full Training
```bash
python -m src.training.train --mode both --epochs 5 --batch-size 16 --lr 2e-5
```

---

## ⚙️ CLI Arguments Reference

| Argument | Type | Default | Description |
|---|---|---|---|
| `--mode` | `str` | `both` | Execution mode: `smoke`, `full`, or `both` |
| `--epochs` | `int` | `5` | Number of training epochs for full run |
| `--batch-size` | `int` | `16` | Mini-batch size (reduce to `8` if VRAM < 8 GB) |
| `--lr` | `float` | `2e-5` | Peak learning rate for AdamW optimizer |
| `--weight-cap` | `float` | `100.0` | Maximum allowable class `pos_weight` multiplier |
| `--data-dir` | `str` | `data` | Base directory containing `train/`, `validation/`, `test/` splits |
| `--seed` | `int` | `42` | Random seed for reproducibility |

---

## 📁 Repository Structure

```
AI_SECURA/
├── configs/
│   ├── labels.py                  # 10 canonical threat classes & multi-hot encoder
│   └── normalization.py           # Text normalization utilities
├── data/
│   ├── train/train.jsonl          # 104,959 training rows
│   ├── validation/validation.jsonl# 22,460 validation rows
│   ├── test/test.jsonl            # 22,464 test rows
│   └── MANIFEST.md                # Dataset provenance & coverage manifest
├── models/
│   └── checkpoints/               # Saved model checkpoints & history
├── src/
│   ├── data/
│   │   └── dataset.py             # PyTorch SecurityDataset with strict isolation
│   ├── models/
│   │   └── security_classifier.py # DeBERTa-v3 multi-label neural classifier
│   └── training/
│       └── train.py               # Complete training, smoke testing & evaluation loop
└── README.md
```

---

## 🎯 Fine-Tuning & Deployment Tips

1. **Hardware Allocation**:
   - 8 GB VRAM (e.g. RTX 4060): Use `--batch-size 16` with mixed precision (enabled automatically).
   - 16+ GB VRAM (e.g. RTX 4090 / A100): Can increase `--batch-size 32` and scale `--lr 3e-5`.
2. **Rare Class Monitoring**:
   - Evaluation reports precision, recall, F1, and PR-AUC separately for all 10 labels.
   - Look closely at the 4 rare classes: `DATA_EXFILTRATION`, `MALICIOUS_DOCUMENT`, `AGENT_HIJACKING`, and `CONTEXT_MANIPULATION`.
