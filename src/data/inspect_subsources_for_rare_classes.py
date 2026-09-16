"""
Targeted sub-source audit for DATA_EXFILTRATION, MALICIOUS_DOCUMENT, and INDIRECT_PROMPT_INJECTION
across the 38 quarantined Necent sub-sources (e.g. BIPIA, LLMail-Inject, TensorTrust, SPML).
"""

import json
from collections import Counter
from datasets import load_dataset

DATASET_ID = "Necent/llm-jailbreak-prompt-injection-dataset"


def audit_candidate_subsources():
    print("=" * 85)
    print("AUDITING TARGETED SUB-SOURCES FOR DATA_EXFILTRATION & MALICIOUS_DOCUMENT")
    print("=" * 85)
    print(f"Loading {DATASET_ID}...")
    ds = load_dataset(DATASET_ID, split="train")

    candidate_sources = ["BIPIA", "LLMail-Inject", "TensorTrust", "SPML", "safe-guard-PI", "deepset-prompt-injections"]
    
    indices_by_source = {s: [] for s in candidate_sources}
    for idx, s in enumerate(ds["source"]):
        for cand in candidate_sources:
            if cand.lower() == str(s).lower():
                indices_by_source[cand].append(idx)

    for cand in candidate_sources:
        matches = indices_by_source[cand]
        print(f"\n" + "-" * 85)
        print(f"SUB-SOURCE: {cand} ({len(matches):,d} rows)")
        print("-" * 85)
        
        if not matches:
            print("  No rows found.")
            continue

        # Inspect first 5 samples
        for i, row_idx in enumerate(matches[:5], 1):
            row = ds[row_idx]
            prompt = str(row.get("prompt", ""))
            cat = row.get("category", "")
            ptype = row.get("prompt_type", "")
            
            prompt_preview = prompt.replace("\n", " ")[:180]
            print(f"  [Sample #{i} | Row {row_idx}] Category: '{cat}' | Type: '{ptype}'")
            print(f"    Text: {prompt_preview}...")

        # Search for exfiltration keywords (markdown image, webhook, fetch, send to, exfiltrate)
        exfil_hits = 0
        doc_hits = 0
        for row_idx in matches:
            text = str(ds[row_idx].get("prompt", "")).lower()
            if any(k in text for k in ["http://", "https://", "![image]", "webhook", "curl", "send to", "exfiltrat", "url="]):
                exfil_hits += 1
            if any(k in text for k in ["document", "pdf", "table", "context:", "attachment", "article", "email body", "file"]):
                doc_hits += 1

        print(f"  -> Keyword signals in {cand}:")
        print(f"     Exfiltration / URL / Webhook markers: {exfil_hits:,d} / {len(matches):,d} ({exfil_hits/len(matches):.1%})")
        print(f"     Document / Email / Attachment markers: {doc_hits:,d} / {len(matches):,d} ({doc_hits/len(matches):.1%})")


if __name__ == "__main__":
    audit_candidate_subsources()
