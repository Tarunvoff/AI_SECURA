Manifest · MD
# Dataset Manifest — Phase 1 (10-label classifier)
 
> **Rule**: Do not mark any row as "confirmed" or "resolved" based on dataset cards or maintainer READMEs. Only mark confirmed based on real output printed by `python -m src.data.download` in this environment.
> **Last updated**: 2026-09-07 (rev. 3 — reconciled against `src.data.download` empirical run output)
 
---
 
## Label key (for coverage columns)
 
| Code | Full label |
|---|---|
| `PI` | PROMPT_INJECTION |
| `IPI` | INDIRECT_PROMPT_INJECTION |
| `JB` | JAILBREAK |
| `SPE` | SYSTEM_PROMPT_EXTRACTION |
| `IH` | INSTRUCTION_HIJACKING |
| `DE` | DATA_EXFILTRATION |
| `MD` | MALICIOUS_DOCUMENT |
| `AH` | AGENT_HIJACKING |
| `TA` | TOOL_ABUSE |
| `CM` | CONTEXT_MANIPULATION |
| `NEG` | Benign / hard-negative |
 
**Coverage rating scale**
`S` = strong (large, well-labeled, verified by run) · `W` = weak (small or noisy, verified) ·
`?` = plausible but unverified due to gating/errors · `-` = not covered
 
---
 
## Approved candidate datasets (Step 3 Reconciled Output)
 
### Dataset 1 — `Necent/llm-jailbreak-prompt-injection-dataset`
 
| Field | Value |
|---|---|
| HF path | `Necent/llm-jailbreak-prompt-injection-dataset` |
| License | **MIT** (per Hub tags metadata) |
| Actual size | **Unverified (Gated error)** — `download.py` failed with gating access error. Dataset card claims ~1.18M rows. |
| Status | ❌ **Failed to load without HF_TOKEN** (requires authenticated Hugging Face account with gate terms accepted). |
| Native schema | Unverified at runtime due to gating failure. |
| Needs relabel? | **Y — partial** (pending access). |
 
Coverage (reconciled):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| ? | ? | ? | ? | ? | - | - | ? | ? | ? | ? |
 
**Notes / risks:**
- ⚠️ **Gating Status**: Hub info reports `"gated": "auto"`. Script confirmed gating failure when `HF_TOKEN` is missing.
- ⚠️ Sub-sources (InjecAgent, ToolEmu, AgentHarm) remain **unverified at runtime** until `HF_TOKEN` is exported and gate access granted.
---
 
### Dataset 2a — `neuralchemy/Prompt-injection-dataset` (older collection)
 
| Field | Value |
|---|---|
| HF path | `neuralchemy/Prompt-injection-dataset` (case-sensitive) |
| License | **`apache-2.0`** (confirmed via Hub tags) |
| Actual size | **6,274 rows verified** (`core` config: train=4,391, validation=941, test=942). (Note: maintainer card claimed ~21K rows total including augmented configs). |
| Languages | English |
| Native schema | `text` (str), `label` (int), `category` (str), `source` (str), `severity` (str), `group_id` (str), `augmented` (bool), `tags` (list) |
| Value Counts (train split) | `label`: `1`: 2,650, `0`: 1,741.<br>`category` (31 classes): `benign`: 1,699, `direct_injection`: 1,397, `adversarial`: 383, `jailbreak`: 291, `encoding`: 177, `training_extraction`: 68, `edge_case`: 42, `system_manipulation`: 29, `token_smuggling`: 27, `rag_poisoning`: 26, `persona_replacement`: 25, `agent_manipulation`: 25, `instruction_override`: 21, `control`: 17, `prompt_injection`: 16, `context_confusion`: 16, `model_fingerprinting`: 16, `output_manipulation`: 16, `prompt_extraction`: 14, `response_manipulation`: 13, `multi_turn`: 12, `system_extraction`: 10, `payload_injection`: 10, `crescendo`: 9, `indirect_injection`: 8, `encoding_obfuscation`: 6, `many_shot`: 5, `code_execution`: 4, `token_injection`: 4, `prompt_leak`: 3, `chain_of_thought`: 2. |
| Needs relabel? | **Y.** Requires mapping 31 category strings to 10 canonical labels. |
 
Coverage (verified from value counts):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| S | W | W | W | W | - | - | W | - | W | S |
 
---
 
### Dataset 2b — `neuralchemy/prompt-injection-dataset-categorized` (Primary Taxonomy Source)
 
| Field | Value |
|---|---|
| HF path | `neuralchemy/prompt-injection-dataset-categorized` |
| License | Unverified in card metadata (null), Hub tags show no explicit license tag |
| Actual size | **32,320 unique rows** (train=25,856, validation=3,232, test=3,232). (Note: maintainer card claimed 226K rows across 7 subsets; each subset is a 32,320-row view of the same core corpus). |
| Configs (7 verified) | `ambiguity`, `binary`, `intent`, `severity`, `source`, `surface`, `technique` |
| Native schema | Varies by config: `text` + target category column (`intent`, `technique`, `severity`, `binary_label`, etc.) |
| Value Counts (train split) | **`intent`**: `direct_injection`: 7,010, `benign`: 6,504, `tool_abuse`: 3,260, `indirect_injection`: 2,342, `system_extraction`: 2,318, `obfuscation`: 2,296, `role_hijack`: 2,126.<br>**`binary_label`**: `1`: 19,352, `0`: 6,504.<br>**`technique`**: `none`: 10,595, `keyword_override`: 5,550, `encoding`: 3,404, `context_overflow`: 2,298, `persona_play`: 1,853, `payload_splitting`: 740, `multilingual`: 711, `few_shot_poisoning`: 705.<br>**`severity`**: `1`: 15,244, `3`: 6,532, `2`: 4,080.<br>**`source`**: `hackaprompt`: 11,011, `synthetic_threat`: 5,204, `core`: 5,037, `synthetic_benign`: 4,398, `synthetic_short`: 206. |
| Needs relabel? | **Partial.** Intent config directly maps to 6 of our target labels (`direct_injection`, `indirect_injection`, `system_extraction`, `role_hijack`, `tool_abuse`, `benign`). |
 
Coverage (verified from `intent` & `technique` value counts):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| S | S | S | S | S | - | - | - | S | S | S |
 
---
 
### Dataset 3 — `allenai/wildguardmix`
 
| Field | Value |
|---|---|
| HF path | `allenai/wildguardmix` |
| License | **`odc-by`** (confirmed via Hub tags) |
| Actual size | **Unverified (Gated error)** — `download.py` failed with gating access error. Dataset card claims 86,759 examples. |
| Status | ❌ **Failed to load without HF_TOKEN** (`"gated": "auto"`). |
| Native schema | Unverified at runtime due to gating failure. |
 
Coverage (reconciled):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| ? | - | ? | - | - | - | - | - | - | - | ? |
 
---
 
### Dataset 4 — `Mindgard/evaded-prompt-injection-and-jailbreak-samples`
 
| Field | Value |
|---|---|
| HF path | `Mindgard/evaded-prompt-injection-and-jailbreak-samples` |
| License | **`cc-by-nc-4.0`** (confirmed via Hub tags) |
| Actual size | **Unverified (Gated error)** — `download.py` failed with gating access error. |
| Status | ❌ **Failed to load without HF_TOKEN** (`"gated": "auto"`). |
| Policy | **EVAL-ONLY** (due to Non-Commercial license). |
 
Coverage (reconciled):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| ? | - | ? | - | - | - | - | - | - | - | - |
 
---
 
### Dataset 5 — `Lakera/mosscap_prompt_injection`
 
| Field | Value |
|---|---|
| HF path | `Lakera/mosscap_prompt_injection` |
| License | **`mit`** (confirmed via Hub tags) |
| Actual size | **278,945 rows verified** (train=223,533, validation=27,683, test=27,729) |
| Native schema | `level` (str), `prompt` (str), `answer` (str), `raw_answer` (str) |
| Value Counts (train split) | `level`: `Level 8`: 88,029, `Level 3`: 39,903, `Level 4`: 29,023, `Level 7`: 27,478, `Level 2`: 13,342, `Level 5`: 11,524, `Level 6`: 7,792, `Level 1`: 6,442. |
| Needs relabel? | **Y — heavy filtering needed.** Raw user prompts from Mosscap game; contains both genuine system prompt extraction attempts and benign word-association game chatter. |
 
Coverage (verified):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| W | - | - | S* | - | - | - | - | - | - | W |
 
`*` Volume is large (278k rows), but requires SPE keyword/heuristic filtering.
 
---
 
## Summary of Step 3 Run Results & Gating Status
 
| Dataset ID | Status in Run | HF_TOKEN required? | License | Verified Row Count (train/val/test) |
|---|---|---|---|---|
| `neuralchemy/prompt-injection-dataset-categorized` | ✅ SUCCESS | No | Unlisted | 25,856 / 3,232 / 3,232 (32,320 unique) across 7 configs |
| `neuralchemy/Prompt-injection-dataset` | ✅ SUCCESS | No | `apache-2.0` | 4,391 / 941 / 942 (6,274 total for `core`) |
| `Lakera/mosscap_prompt_injection` | ✅ SUCCESS | No | `mit` | 223,533 / 27,683 / 27,729 (278,945 total) |
| `Necent/llm-jailbreak-prompt-injection-dataset` | ❌ FAILED (Gated) | **Yes** | `mit` | Unverified (0 rows loaded without token) |
| `allenai/wildguardmix` | ❌ FAILED (Gated) | **Yes** | `odc-by` | Unverified (0 rows loaded without token) |
| `Mindgard/evaded-prompt-injection-and-jailbreak-samples` | ❌ FAILED (Gated) | **Yes** | `cc-by-nc-4.0` | Unverified (0 rows loaded without token) |

---

## Reconciled Coverage Gap Tracker (Based strictly on verified run data)

| Label | Best verified source | Empirical Value Count (Train Split) | Coverage Status | Phase 1 Action Plan |
|---|---|---|---|---|
| `PROMPT_INJECTION` | neuralchemy 2b (`intent: direct_injection`) | 7,010 train (8,763 total) | ✅ **Strong (S)** | Core training pool ready |
| `INDIRECT_PROMPT_INJECTION` | neuralchemy 2b (`intent: indirect_injection`) | 2,342 train (2,927 total) | ✅ **Strong (S)** | Solid coverage from 2b |
| `JAILBREAK` | neuralchemy 2b (`technique: persona_play`, `keyword_override`), 2a (`category: jailbreak`) | 1,853 (persona_play) + 291 (2a) | ✅ **Strong (S)** | Verified via 2b techniques & 2a |
| `SYSTEM_PROMPT_EXTRACTION` | neuralchemy 2b (`intent: system_extraction`), Lakera Mosscap | 2,318 train (2b) + 223k raw Mosscap | ✅ **Strong (S)** | 2.3k clean in 2b + Mosscap heuristic filter |
| `INSTRUCTION_HIJACKING` | neuralchemy 2b (`intent: role_hijack`) | 2,126 train (2,658 total) | ✅ **Strong (S)** | Solid coverage from 2b |
| `DATA_EXFILTRATION` | None in loaded datasets | 0 verified rows | ❌ **No coverage (-)** | Synthetic generator required |
| `MALICIOUS_DOCUMENT` | None in loaded datasets | 0 verified rows | ❌ **No coverage (-)** | Synthetic generator required |
| `AGENT_HIJACKING` | neuralchemy 2a (`category: agent_manipulation`) | 25 train (36 total) | ⚠️ **Weak / Unverified (W/?)** | Unverified in Necent due to gating; 2a has only 36 rows. Needs synthetic / Necent gating access. |
| `TOOL_ABUSE` | neuralchemy 2b (`intent: tool_abuse`) | 3,260 train (4,075 total) | ✅ **Strong (S)** | Upgraded to **S** via 2b's 3.2k train rows |
| `CONTEXT_MANIPULATION` | neuralchemy 2b (`technique: context_overflow`, `few_shot_poisoning`) | 2,298 (overflow) + 705 (few_shot) | ✅ **Strong (S)** | Upgraded to **S** via 2b techniques |
| `NEG` (Benign / Hard-Neg) | neuralchemy 2b (`intent: benign`), 2a (`category: benign`) | 6,504 train (2b) + 1,699 train (2a) | ✅ **Strong (S)** | 8.1k total verified benign rows in 2b |

---

## Step 6 & 7 Final Canonical Dataset & Split Report

> **Empirical Verification Date**: 2026-09-16  
> **Script**: `src/data/merge_and_split.py`  
> **Schema Check**: 0 errors across 202,598 rows.

### 1. Step 6 — Unified Raw Merge
- **Canonical Merged Path**: `data/processed/unified_security_dataset.jsonl` (90.51 MB)
- **Total Merged Rows**: 202,598
- **Source Breakdown**:
  - `mosscap`: 155,119 (76.56%)
  - `neuralchemy_2b`: 31,711 (15.65%)
  - `neuralchemy_2a`: 15,768 (7.78%)
- **Binary `is_malicious`**:
  - `is_malicious = True`: 188,555 (93.07%)
  - `is_malicious = False`: 14,043 (6.93%)

### 2. Step 7a — Exact Deduplication
- **Pre-Dedup Total**: 202,598
- **Exact Duplicates Removed**: 52,715 redundant rows across 22,868 duplicate groups
- **Post-Exact-Dedup Total**: 149,883 unique texts
- **Within-Source Deduplication**:
  - `mosscap`: 39,566 rows removed
  - `neuralchemy_2a`: 333 rows removed
  - `neuralchemy_2b`: 270 rows removed
- **Cross-Source Deduplication**:
  - `neuralchemy_2a` + `neuralchemy_2b`: 12,405 rows removed (5,932 HackAPrompt shared duplicate groups)
  - `mosscap` + `neuralchemy_2b`: 131 rows removed
  - `mosscap` + `neuralchemy_2a` + `neuralchemy_2b`: 10 rows removed

### 3. Step 7b & 7c — Group-Aware Handling & Near-Duplicate Clustering
- **Group-aware IDs**: 6,212 `source_group_id` groups (spanning 9,047 rows)
- **TF-IDF Matrix**: (149,883, 40,000 features, `ngram_range=(1, 2)`) built in 10.27s
- **Near-Duplicate Pairs Detected (Cosine Similarity >= 0.95)**: 4,735,529 candidate pairs (mostly parameterized templated game prompts)
- **Total Meta-Clusters Formed**: 108,114
  - **Multi-Item Clusters**: 14,250 (spanning 56,019 rows)
  - **Single-Item Clusters**: 93,864
  - **Max Cluster Size**: 1,500

### 4. Step 7d — Multi-Label Stratified 70/15/15 Split (Rebalanced)
- **Train (`data/train/train.jsonl`)**: 104,959 rows (70.03%, 52.80 MB)
- **Validation (`data/validation/validation.jsonl`)**: 22,460 rows (14.99%, 10.26 MB)
- **Test (`data/test/test.jsonl`)**: 22,464 rows (14.99%, 13.14 MB)
- **Total Split Rows**: 149,883 (100.00%)

#### Explicit Zero-Leakage Verification Audit
- **Cluster ID Overlap**: 0 (Train/Val=0, Train/Test=0, Val/Test=0)
- **Group ID Overlap**: 0 (Train/Val=0, Train/Test=0, Val/Test=0)
- **Exact Text Hash Overlap**: 0 (Train/Val=0, Train/Test=0, Val/Test=0)
- **Status**: ✅ **ZERO DATA LEAKAGE CONFIRMED**

#### Per-Label Distribution Across Splits
| Threat Label | Total Unique | Train | Val | Test | Val % | Test % | Status |
|---|---|---|---|---|---|---|---|
| `PROMPT_INJECTION` | 13,015 | 9,113 | 1,950 | 1,952 | 15.0% | 15.0% | ✅ OK |
| `INDIRECT_PROMPT_INJECTION` | 2,990 | 2,090 | 450 | 450 | 15.1% | 15.1% | ✅ OK |
| `JAILBREAK` | 2,215 | 1,538 | 338 | 339 | 15.3% | 15.3% | ✅ OK |
| `SYSTEM_PROMPT_EXTRACTION` | 118,394 | 82,867 | 17,764 | 17,763 | 15.0% | 15.0% | ✅ OK |
| `INSTRUCTION_HIJACKING` | 2,227 | 1,556 | 335 | 336 | 15.0% | 15.1% | ✅ OK |
| `DATA_EXFILTRATION` | 148 | 97 | 26 | 25 | 17.6% | 16.9% | ⚠️ LOW (<50 in Val/Test) |
| `MALICIOUS_DOCUMENT` | 55 | 35 | 10 | 10 | 18.2% | 18.2% | ⚠️ LOW (<50 in Val/Test) |
| `AGENT_HIJACKING` | 53 | 27 | 13 | 13 | 24.5% | 24.5% | ⚠️ LOW (<50 in Val/Test) |
| `TOOL_ABUSE` | 4,910 | 3,440 | 735 | 735 | 15.0% | 15.0% | ✅ OK (Balanced) |
| `CONTEXT_MANIPULATION` | 103 | 63 | 20 | 20 | 19.4% | 19.4% | ⚠️ LOW (<50 in Val/Test) |

#### Binary `is_malicious` Distribution Across Splits
- **Train**: Malicious = 98,810 (94.14%), Benign = 6,149 (5.86%)
- **Validation**: Malicious = 21,142 (94.13%), Benign = 1,318 (5.87%)
- **Test**: Malicious = 21,147 (94.14%), Benign = 1,317 (5.86%)