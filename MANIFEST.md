# Dataset Manifest — Phase 1 (10-label classifier)

Fill in one row per candidate dataset before downloading anything. Do not download
a dataset until it has a row here and has been reviewed.

## Target labels (for the coverage columns below)
`PI` = PROMPT_INJECTION · `IPI` = INDIRECT_PROMPT_INJECTION · `JB` = JAILBREAK ·
`SPE` = SYSTEM_PROMPT_EXTRACTION · `IH` = INSTRUCTION_HIJACKING ·
`DE` = DATA_EXFILTRATION · `MD` = MALICIOUS_DOCUMENT · `AH` = AGENT_HIJACKING ·
`TA` = TOOL_ABUSE · `CM` = CONTEXT_MANIPULATION · `NEG` = benign/hard-negative

Coverage rating scale: `S` = strong (large, well-labeled), `W` = weak (small or
noisy), `-` = not covered.

| Dataset (HF path) | License | Size (rows) | PI | IPI | JB | SPE | IH | DE | MD | AH | TA | CM | NEG | Needs relabel? | Notes / risks |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `Necent/llm-jailbreak-prompt-injection-dataset` | TBD — verify | TBD | | | | | | | | | | | | Y/N | |
| `neuralchemy/prompt-injection-Threat-Matrix` | TBD — verify | TBD | | | | | | | | | | | | Y/N | |
| `protectai/deberta-v3-base-prompt-injection-v2` (model, not dataset — reference only) | n/a | n/a | | | | | | | | | | | | n/a | Binary benign/injection only; English-focused; no jailbreak coverage per model card |
| _add rows as you evaluate more_ | | | | | | | | | | | | | | |

## How to fill this in

1. **License** — check the dataset card on Hugging Face directly. Don't assume
   permissive; some security/red-team datasets carry research-only or non-commercial
   terms. Flag anything unclear as "TBD — verify" and don't download until resolved.
2. **Size** — actual row count after loading, not the marketing description.
3. **Coverage columns** — after inspecting ~20–50 samples, rate honestly. A dataset
   that's 90% jailbreak examples and 10% mislabeled "injection" should say `S` under
   JB and `W` under PI, not `S` across the board.
4. **NEG column** — does this dataset contain *any* benign examples, or is it 100%
   attacks? Most security datasets skew heavily malicious — you'll likely need a
   separate benign/hard-negative source (see hard-negatives section below) regardless.
5. **Needs relabel?** — mark Y if the dataset's native labels don't map cleanly onto
   the 10 canonical labels and will need manual/semi-automated remapping.

## Coverage gap tracker

After all rows are filled in, list any of the 10 labels with no `S` rating from any
single dataset. These are your risk areas — plan to either combine multiple weak
sources, hand-label a supplementary set, or narrow that label's scope for Phase 1.

| Label | Best coverage found | Gap plan |
|---|---|---|
| PROMPT_INJECTION | | |
| INDIRECT_PROMPT_INJECTION | | |
| JAILBREAK | | |
| SYSTEM_PROMPT_EXTRACTION | | |
| INSTRUCTION_HIJACKING | | |
| DATA_EXFILTRATION | | |
| MALICIOUS_DOCUMENT | | |
| AGENT_HIJACKING | | |
| TOOL_ABUSE | | |
| CONTEXT_MANIPULATION | | |

## Hard-negative sources to evaluate separately

These aren't "attack datasets" — they're where you'll pull benign-but-security-adjacent
text from, to prevent the model from learning "mentions security terms" = malicious.

- Security blog posts / documentation Q&A datasets (explaining concepts, not attacking)
- General instruction-following datasets (Alpaca-style), filtered for security keywords
- Synthetic generation: templated benign questions about each of the 10 attack types
  ("What is {X}?", "How do you defend against {X}?", "Explain {X} with an example.")
  — generate several phrasings per label, not just one template copy-pasted
