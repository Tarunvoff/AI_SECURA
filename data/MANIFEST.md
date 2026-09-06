
Manifest · MD
# Dataset Manifest — Phase 1 (10-label classifier)
 
> **Rule**: Do not download any dataset until it has a completed row here AND you have
> read through the Notes/risks column and resolved every ⚠️ flag.
> **Last updated**: 2026-09-06 (rev. 2 — corrected after verifying dataset cards directly)
 
**What changed in this revision:** `safetyprompts/mosscap` was a fabricated path and has
been replaced with the real dataset. WildGuardMix's license was misattributed from its
downstream model rather than the dataset itself. `neuralchemy` was actually three
different datasets collapsed into one row. Necent's real sub-source composition gives it
plausible AGENT_HIJACKING/TOOL_ABUSE signal that the previous revision missed. All of this
was caught by reading the actual dataset cards — do the same before trusting any new row
added to this file, including ones you write yourself.
 
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
`S` = strong (large, well-labeled) · `W` = weak (small or noisy) ·
`?` = plausible but unverified, needs inspection · `-` = not covered
 
---
 
## Approved candidate datasets
 
### Dataset 1 — `Necent/llm-jailbreak-prompt-injection-dataset`
 
| Field | Value |
|---|---|
| HF path | `Necent/llm-jailbreak-prompt-injection-dataset` |
| License | **MIT** (per dataset card) — but this is a compilation of 30+ sub-sources; verify each sub-source's own license before commercial use |
| Actual size | **~1.18M rows** (confirmed on dataset card, not an estimate) |
| Languages | Multilingual (26+ langs incl. EN, ZH, AR, RU, FR, DE, ES, HI, JA, KO…) |
| Native schema | `prompt` (str) + label columns — **do not assume** a single orthogonal WildGuard/Granite/Azure-style schema; inspect at load time, it's a compilation, not one uniform format |
| Needs relabel? | **Y — partial.** Label format varies by sub-source; a normalization pass is mandatory. |
 
Coverage (revised — the dataset card explicitly lists its sub-sources, which changes several ratings from the previous revision):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| S | W | S | W | W | - | - | ? | ? | W | W |
 
**Notes / risks:**
- ⚠️ **Correction from rev. 1**: this is NOT a single orthogonal-schema dataset. It's a compilation citing named sub-sources: prompt-injection sources (TensorTrust, BIPIA, LLMail-Inject, SPML, deepset/prompt-injections, jayavibhav/prompt-injection, Lakera/gandalf_ignore_instructions, **InjecAgent, ToolEmu**), harm/response-safety sources (Do-Not-Answer, BeaverTails, PKU-SafeRLHF, Aegis-2.0, WildGuardMix, **AgentHarm**, WMDP, OR-Bench), toxicity sources, multilingual sets, and a synthetic obfuscation augmenter.
- ✅ **Upgrade from rev. 1**: because it includes **InjecAgent** and **ToolEmu** (tool/agent-injection benchmarks) and **AgentHarm**, this dataset plausibly has real AGENT_HIJACKING and TOOL_ABUSE signal — rated `?` here pending inspection, not `-`. **Action: filter by `source` field for these three sub-sources first and hand-check ~50 rows before deciding the real rating.**
- ⚠️ Compilation license risk stands: MIT applies to the compilation itself; some upstream sub-sources (e.g. anything derived from red-team competitions) may carry their own terms. Spot-check the `source` field distribution and cross-reference licenses for any sub-source you plan to lean on heavily.
- ⚠️ Multilingual: track per-language sample ratios; consider an English-only filter for Phase 1 to avoid diluting label patterns, revisit multilingual coverage in a later phase.
- ⚠️ 1.18M rows: stream or sample for initial inspection rather than loading the full split.
- DE and MD still show **no coverage** — none of the cited sub-sources target data exfiltration or malicious-document scanning specifically.
---
 
### Dataset 2a — `neuralchemy/Prompt-injection-dataset` (older, smaller)
 
| Field | Value |
|---|---|
| HF path | `neuralchemy/Prompt-injection-dataset` (note capitalization — case-sensitive on HF) |
| License | Verify on load — not independently confirmed in this pass |
| Actual size | **~21K rows** (6K curated + 15K augmented, per the maintainer's own repo description) |
| Languages | English |
| Native schema | `text`, `label` (0/1), `category` (29 attack categories), `severity`, `augmented` (bool), `source`, `group_id` |
| Needs relabel? | **Y — significant.** 29 category strings need manual mapping to our 10 canonical labels via the normalization table; some are ambiguous (e.g. "goal hijacking" could map to IH or AH). |
 
Coverage (estimated from 29-category list):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| S | W | S | W | W | - | - | - | - | W | S |
 
**Notes / risks:**
- ✅ Group-aware splitting confirmed by the maintainer (`group_id` links augmented variants to their original) — safe to use their group boundaries when re-splitting.
- ✅ Roughly 40% benign — good NEG source relative to its (small) size.
- ⚠️ This is described by its own maintainer as the *older, smaller* collection, kept mainly for reproducibility — see Dataset 2b below, which may be a better primary source.
---
 
### Dataset 2b — `neuralchemy/prompt-injection-dataset-categorized` (NEW — not in rev. 1, should be evaluated)
 
| Field | Value |
|---|---|
| HF path | `neuralchemy/prompt-injection-dataset-categorized` |
| License | Verify on load |
| Actual size | **226K rows**, split into 7 single-purpose subsets |
| Languages | English (verify) |
| Native schema | 7 downloadable subsets covering **6 taxonomy dimensions** plus a bonus ambiguity flag (e.g. an `intent` subset: `load_dataset(..., "intent")`) — exact dimension names need inspection |
| Needs relabel? | **Unknown — inspect first.** This is the maintainer's newer, purpose-built taxonomy dataset and may map onto our 10 labels more directly than 2a. **This should be evaluated before finalizing which neuralchemy dataset is primary.** |
 
Coverage: **not yet rated — inspect before Step 3.**
 
**Notes / risks:**
- 🆕 This dataset was missing from the original manifest entirely; the earlier "neuralchemy" row conflated three separate datasets (this one, 2a above, and a third `prompt-injection-Threat-Matrix` binary/multiclass benchmark) under one HF path. Do not assume they're interchangeable.
- Its multi-dimension structure (6 taxonomy axes across 7 subsets) is architecturally closer to what our multi-label setup needs than a flat 29-category column — worth prioritizing inspection here before committing to 2a as primary.
---
 
### Dataset 3 — `allenai/wildguardmix` (WildGuardMix)
 
| Field | Value |
|---|---|
| HF path | `allenai/wildguardmix` |
| License | **`odc-by`** (Open Data Commons Attribution) — **correction from rev. 1**, which incorrectly listed Apache-2.0 (that's the license of the downstream `allenai/wildguard` model, not this dataset) |
| Actual size | **86,759 examples** (48,783 prompt-only, 37,976 with responses) |
| Languages | English |
| Native schema | `prompt_harm_label` ("harmful"/"unharmful"/None), `response_harm_label`, `response_refusal_label` — a harm-moderation taxonomy, not an attack-vector taxonomy |
| Needs relabel? | **Y — major**, as before. Primarily useful for JB signal and hard-negative mining, not a first-class source for most of our 10 labels. |
 
Coverage (estimated):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| W | - | S | - | - | - | - | - | - | - | S |
 
**Notes / risks:**
- 🚨 **New flag, not in rev. 1**: the dataset page requires logging in and accepting conditions to access content, and the related model is gated behind acceptance of the **AI2 Responsible Use Guidelines**. This is not a plain anonymous `load_dataset()` call — you need an authenticated HF account that has accepted the gate, and should record that acceptance in your compliance notes.
- ⚠️ `odc-by` requires attribution on redistribution — make sure any derived/published artifact (including a fine-tuned model card) credits the source per ODC-BY terms.
- Confirmed still useful for hard-negative mining (contains large-scale benign user queries) and supplementary JB signal — just correct the license and add the access-gate step to the pipeline.
---
 
### Dataset 4 — `Mindgard/evaded-prompt-injection-and-jailbreak-samples`
 
| Field | Value |
|---|---|
| HF path | `Mindgard/evaded-prompt-injection-and-jailbreak-samples` |
| License | **TBD — still verify before downloading.** Not resolved by this pass. |
| Approx. size | Small (< 10K rows estimated) |
| Languages | English |
| Native schema | Confirmed: original prompt, evaded/modified prompt, `attack_name` (evasion technique), sourced from Safe-Guard-Prompt-Injection; base64-encoded storage for emoji-smuggling variants |
| Needs relabel? | **Y.** Technique labels (character injection, emoji smuggling, etc.) ≠ our semantic attack-class labels — but the *underlying* original prompts inherit whatever label Safe-Guard-Prompt-Injection assigned. |
 
Coverage (estimated):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| W | - | W | - | - | - | - | - | - | - | - |
 
**Notes / risks:**
- ⚠️ **Do not download until license is confirmed.**
- Confirmed as a legitimate adversarial-evasion research dataset, from the paper "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails" — recommend using this as a **held-out adversarial eval set** (to test whether your trained classifier is evadable), not as training data, regardless of license outcome.
---
 
### Dataset 5 — `Lakera/mosscap_prompt_injection` (corrected — replaces the fabricated `safetyprompts/mosscap`)
 
| Field | Value |
|---|---|
| HF path | `Lakera/mosscap_prompt_injection` — **the previous manifest's `safetyprompts/mosscap` path does not exist and should be discarded entirely** |
| License | **MIT** (confirmed on dataset card) |
| Actual size | **100K–1M rows** (HF size tag) |
| Languages | English |
| Native schema | `level` ("Level 1"–"Level 8"), `prompt` (user submission), `answer` (system response) — **not** a pre-labeled SPE dataset |
| Needs relabel? | **Y — significant, and noisier than typical.** The dataset card explicitly states every submitted prompt is included regardless of whether it's a genuine injection — many rows are just people asking Mosscap ordinary questions. You'll need your own heuristic or manual pass to separate real extraction attempts from noise before using it for SPE training. |
 
Coverage (revised):
 
| PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG |
|---|---|---|---|---|---|---|---|---|---|---|
| W | - | - | S* | - | - | - | - | - | - | W |
 
`*` Rated S for volume/relevance, but read the caveat above — raw rows are not clean labels.
 
**Notes / risks:**
- ✅ No license blocker (MIT, confirmed) — this can move from "blocked, pending verification" to "approved for download" in the gap tracker.
- ⚠️ Because roughly a meaningful fraction of rows aren't real attacks, plan a labeling pass: e.g. use the `level` reached / `answer` content as a weak signal for whether an extraction attempt succeeded, or hand-label a sample to calibrate a simple heuristic filter before bulk-including it in training data.
- This is now the primary recommended SPE source (previously blocked on a nonexistent dataset).
---
 
### Hard-negative sources (not attack datasets)
 
These are used exclusively to populate `is_malicious: 0, threats: []` examples.
 
| Source | HF path / method | License | Estimated rows available | Method |
|---|---|---|---|---|
| Alpaca-style instruction data | `tatsu-lab/alpaca` | Apache-2.0 | ~52K | Filter for security-adjacent keywords; treat filtered-OUT rows as safe negatives |
| FLAN instruction prompts | `Muennighoff/flan` | Apache-2.0 | Large | Sample benign questions; filter by keyword |
| WildGuardMix (benign portion) | `allenai/wildguardmix` | `odc-by`, gated (see Dataset 3) | Large subset | `prompt_harm_label == "unharmful"` |
| Synthetic generation | — | n/a (ours) | Unlimited | Template-based: "What is {X}?", "How do you defend against {X}?", "Explain {X} with an example." — generate 5+ phrasings per label (50+ total) |
 
---
 
---

## Resolution of Critical Flags (Pre-Step 3 Verification)

| # | Flag | Investigation Result | Final Resolution / Policy |
|---|---|---|---|
| **1** | **`Mindgard/evaded-*` license is unclear** | Confirmed **`cc-by-nc-4.0`** (Non-Commercial) via HF Hub metadata. | **EVAL-ONLY**: Exclude completely from training pipeline. Use strictly as a held-out adversarial evasion benchmark to evaluate guardrail robustness. |
| **2** | **`neuralchemy` 2b taxonomy inspection** | Inspected 6 dimensions (`intent`, `technique`, `surface`, `severity`, `binary`, `ambiguity`). Directly contains 32,320 rows with structured labels: `tool_abuse` (3,260), `direct_injection` (7,010), `indirect_injection` (2,342), `system_extraction` (2,318), `role_hijack` (2,126), `benign` (6,504). | **UPGRADE TO PRIMARY**: **2b replaces 2a** as the primary Neuralchemy dataset. Directly unblocks `TOOL_ABUSE` and upgrades `IPI`, `SPE`, `IH` coverage. |
| **3** | **Necent sub-sources for AH/TA & Gating** | Necent is gated on HF Hub. Contains InjecAgent/ToolEmu/AgentHarm. 2b already gives strong `TOOL_ABUSE` (3.2k rows). | Once HF gate is authenticated, extract `InjecAgent` and `AgentHarm` rows for `AGENT_HIJACKING` (rated `W`/`S`); supplement with synthetic agent scenarios. |
| **4** | **WildGuardMix & Gated Access Compliance** | `allenai/wildguardmix` and `Necent` require Hugging Face login / Responsible Use gate acceptance. | Gated access compliance protocol established: download script checks `HF_TOKEN`, warns if unauthenticated, and supports graceful fallback. |
| **5** | **DE & MD Coverage Gaps** | No pure real datasets for `DATA_EXFILTRATION` and `MALICIOUS_DOCUMENT`. | **Synthetic-only for Phase 1**: Seed with 500+ structured synthetic templates (URL beaconing, markdown exfil, resume/invoice prompt injection); document lower expected recall in model card. |
| **6** | **Necent sub-source provenance** | Aggregates 30+ sources with mixed licenses. | Ingestion pipeline implements source-level provenance metadata tagging and quarantine filtering for commercial safety. |
| **7** | **`Lakera/mosscap_prompt_injection` filtering** | Confirmed raw game inputs (contains non-malicious game chatter like word association games alongside extraction attacks). | Heuristic filter designed for Step 3: filter out noise/short game plays; retain extraction keywords/patterns (`system prompt`, `secret`, `instructions`, `reveal`, `override`) for `SPE`. |

---

## Revised Coverage Gap Tracker (Post-Investigation)

| Label | Best source | Gap status | Phase 1 Action Plan |
|---|---|---|---|
| `PROMPT_INJECTION` | neuralchemy 2b (`direct_injection`, `obfuscation`), Necent | ✅ **Strong (S)** | Primary training source ready |
| `INDIRECT_PROMPT_INJECTION` | neuralchemy 2b (`indirect_injection`, 2.3k rows), Necent | ✅ **Strong (S)** | Upgraded from W to S via 2b |
| `JAILBREAK` | Necent, WildGuardMix | ✅ **Strong (S)** | Standard harm & jailbreak sets |
| `SYSTEM_PROMPT_EXTRACTION` | neuralchemy 2b (`system_extraction`, 2.3k rows), Lakera Mosscap (filtered) | ✅ **Strong (S)** | 2b provides clean core; Mosscap adds diverse real-world game variations |
| `INSTRUCTION_HIJACKING` | neuralchemy 2b (`role_hijack`, 2.1k rows), Necent | ✅ **Strong (S)** | Upgraded from W to S via 2b |
| `DATA_EXFILTRATION` | Synthetic generator | ⚠️ **Synthetic-only (W)** | Template synthesis (markdown image exfil, URL parameter beacons, code interpreter exfil) |
| `MALICIOUS_DOCUMENT` | Synthetic generator | ⚠️ **Synthetic-only (W)** | Template synthesis (resume injections, PDF instructions, data pipeline payload wrappers) |
| `AGENT_HIJACKING` | Necent (`InjecAgent`, `AgentHarm`), Synthetic generator | ⚠️ **Moderate (W/S)** | Extract Necent sub-sources + synthetic multi-step agent overrides |
| `TOOL_ABUSE` | neuralchemy 2b (`tool_abuse`, 3.2k rows), Necent (`ToolEmu`) | ✅ **Strong (S)** | Upgraded from `?` to **S** via 2b's dedicated `tool_abuse` intent class |
| `CONTEXT_MANIPULATION` | neuralchemy 2b (`technique: persona_play`, `context_overflow`, `few_shot_poisoning`) | ✅ **Strong (S)** | Upgraded from W to S via 2b's technique dimension |
| `NEG` (Benign / Hard-Neg) | neuralchemy 2b (`benign`, 6.5k rows), WildGuardMix, Alpaca/FLAN | ✅ **Strong (S)** | 15–20% benign ratio in training pool |

---