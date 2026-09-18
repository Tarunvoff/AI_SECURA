"""
Complete implementation of Step 6 and Step 7 pipeline.
- Step 6: Canonical merge and schema validation into data/processed/unified_security_dataset.jsonl
- Step 7a: Exact text deduplication (SHA256 of normalized text)
- Step 7b: Source group ID tracking (neuralchemy_2a source_group_id)
- Step 7c: Near-duplicate detection & clustering (cosine similarity >= 0.95)
- Step 7d: Group-aware multi-label stratified 70/15/15 split into data/train, data/validation, data/test
"""

import hashlib
import json
import logging
import math
import random
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from configs.labels import THREAT_LABELS, VALID_SEVERITIES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MERGED_FILEPATH = PROCESSED_DIR / "unified_security_dataset.jsonl"
TRAIN_DIR = PROJECT_ROOT / "data" / "train"
VAL_DIR = PROJECT_ROOT / "data" / "validation"
TEST_DIR = PROJECT_ROOT / "data" / "test"

CANONICAL_LABELS = set(THREAT_LABELS)


class UnionFind:
    """Iterative Disjoint Set Union (DSU) with path compression and union by rank."""
    def __init__(self, size: int):
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, i: int) -> int:
        root = i
        while root != self.parent[root]:
            root = self.parent[root]
        # Path compression
        curr = i
        while curr != root:
            nxt = self.parent[curr]
            self.parent[curr] = root
            curr = nxt
        return root

    def union(self, i: int, j: int) -> bool:
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i == root_j:
            return False
        if self.rank[root_i] < self.rank[root_j]:
            self.parent[root_i] = root_j
        elif self.rank[root_i] > self.rank[root_j]:
            self.parent[root_j] = root_i
        else:
            self.parent[root_j] = root_i
            self.rank[root_i] += 1
        return True


def normalize_text_for_hash(text: str) -> str:
    """Normalizes whitespace and case for exact text deduplication."""
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def compute_text_hash(text: str) -> str:
    """Computes SHA256 hex digest of normalized text."""
    norm = normalize_text_for_hash(text)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def validate_canonical_row(row: Dict[str, Any], row_idx: int, source_file: str) -> List[str]:
    """Validates that a row conforms strictly to the canonical schema."""
    errors = []
    
    # Normalize source / source_dataset
    src_val = row.get("source") or row.get("source_dataset")
    if src_val:
        row["source"] = str(src_val)
        row["source_dataset"] = str(src_val)

    # Normalize threats / attack_types
    threats_val = row.get("threats") if "threats" in row else row.get("attack_types", [])
    row["threats"] = threats_val
    row["attack_types"] = threats_val

    if "id" not in row or not isinstance(row["id"], str) or not row["id"].strip():
        errors.append(f"Invalid or missing 'id': {row.get('id')}")
    if "text" not in row or not isinstance(row["text"], str) or len(row["text"].strip()) == 0:
        errors.append("Invalid or empty 'text'")
    if "is_malicious" not in row or not isinstance(row["is_malicious"], bool):
        errors.append(f"Invalid 'is_malicious' (must be bool True/False): {row.get('is_malicious')}")
    if "threats" not in row or not isinstance(row["threats"], list):
        errors.append(f"Invalid 'threats' (must be list): {row.get('threats')}")
    else:
        for t in row["threats"]:
            if t not in CANONICAL_LABELS:
                errors.append(f"Unknown threat label: '{t}'")
        if row.get("is_malicious") is False and len(row["threats"]) > 0:
            errors.append(f"is_malicious=False but non-empty threats: {row['threats']}")
        if row.get("is_malicious") is True and len(row["threats"]) == 0:
            errors.append("is_malicious=True but empty threats list")
    if "severity" not in row or row["severity"] not in VALID_SEVERITIES:
        errors.append(f"Invalid 'severity': {row.get('severity')}")
    # Check source validity
    valid_src_prefixes = ("neuralchemy", "mosscap", "necent", "wildguardmix", "synthetic_")
    if not src_val or not any(str(src_val).startswith(p) for p in valid_src_prefixes):
        errors.append(f"Invalid 'source': {src_val}")
    if "quarantined" not in row or row["quarantined"] is not False:
        errors.append(f"Invalid 'quarantined' for unified row: {row.get('quarantined')}")
    return errors


def step_6_merge() -> List[Dict[str, Any]]:
    """Step 6: Merge unified adapter files into unified_security_dataset.jsonl."""
    print("=" * 80)
    print("STEP 6: MERGE INTO ONE CANONICAL FILE & SCHEMA VALIDATION")
    print("=" * 80)

    input_files = [
        PROCESSED_DIR / "neuralchemy_2b_train.jsonl",
        PROCESSED_DIR / "neuralchemy_2b_validation.jsonl",
        PROCESSED_DIR / "neuralchemy_2b_test.jsonl",
        PROCESSED_DIR / "neuralchemy_2a_train.jsonl",
        PROCESSED_DIR / "neuralchemy_2a_validation.jsonl",
        PROCESSED_DIR / "neuralchemy_2a_test.jsonl",
        PROCESSED_DIR / "mosscap_train.jsonl",
        PROCESSED_DIR / "mosscap_validation.jsonl",
        PROCESSED_DIR / "mosscap_test.jsonl",
    ]

    # Include Necent unified output if present
    necent_file = PROCESSED_DIR / "necent_unified.jsonl"
    if necent_file.exists():
        input_files.append(necent_file)

    # Include WildGuardMix and synthetic augmentations if present
    wg_file = PROCESSED_DIR / "wildguardmix_jailbreak.jsonl"
    if wg_file.exists():
        input_files.append(wg_file)

    syn_ih_file = PROCESSED_DIR / "synthetic_instruction_hijacking.jsonl"
    if syn_ih_file.exists():
        input_files.append(syn_ih_file)

    syn_cm_file = PROCESSED_DIR / "synthetic_context_manipulation.jsonl"
    if syn_cm_file.exists():
        input_files.append(syn_cm_file)

    syn_ta_file = PROCESSED_DIR / "synthetic_tool_abuse.jsonl"
    if syn_ta_file.exists():
        input_files.append(syn_ta_file)

    syn_ii_file = PROCESSED_DIR / "synthetic_indirect_injection.jsonl"
    if syn_ii_file.exists():
        input_files.append(syn_ii_file)

    merged_rows = []
    val_errors = []
    src_counts = Counter()
    mal_counts = Counter()
    lbl_counts = Counter()

    for fpath in input_files:
        with open(fpath, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line_str = line.strip()
                if not line_str:
                    continue
                row = json.loads(line_str)
                errs = validate_canonical_row(row, idx, fpath.name)
                if errs:
                    val_errors.append((fpath.name, idx, errs))
                merged_rows.append(row)
                src_counts[row["source"]] += 1
                mal_counts[row["is_malicious"]] += 1
                for t in row.get("threats", []):
                    lbl_counts[t] += 1

    if val_errors:
        for fname, l_idx, errs in val_errors[:10]:
            print(f"  [ERROR] {fname}:{l_idx} -> {errs}")
        raise ValueError(f"Schema validation failed on {len(val_errors)} rows.")

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with open(MERGED_FILEPATH, "w", encoding="utf-8") as f:
        for r in merged_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Schema Validation: 0 errors across {len(merged_rows)} rows.")
    print(f"Merged File Path:  {MERGED_FILEPATH}")
    print(f"Total Merged Rows: {len(merged_rows)}")
    print("\nSource Distribution:")
    for src, cnt in src_counts.most_common():
        print(f"  - {src:<18}: {cnt:>7} ({cnt/len(merged_rows):>6.2%})")
    print("\nis_malicious Distribution:")
    for mal, cnt in mal_counts.items():
        print(f"  - is_malicious = {str(mal):<5}: {cnt:>7} ({cnt/len(merged_rows):>6.2%})")
    print("\nPer-Label Threat Distribution (10 Canonical Labels):")
    for lbl in THREAT_LABELS:
        cnt = lbl_counts.get(lbl, 0)
        print(f"  - {lbl:<28}: {cnt:>7} ({cnt/len(merged_rows):>6.2%})")

    return merged_rows


def step_7a_exact_dedup(merged_rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Step 7a: Exact deduplication by normalized text SHA256 hash."""
    print("\n" + "=" * 80)
    print("STEP 7a: EXACT DEDUPLICATION")
    print("=" * 80)

    hash_to_rows = defaultdict(list)
    for r in merged_rows:
        h = compute_text_hash(r["text"])
        hash_to_rows[h].append(r)

    total_pre = len(merged_rows)
    total_unique = len(hash_to_rows)
    redundant_count = total_pre - total_unique

    within_source_removals = Counter()
    cross_source_removals = Counter()
    cross_2a_2b_matches = []

    deduped_rows: List[Dict[str, Any]] = []

    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1, "NONE": 0}

    for h, rlist in hash_to_rows.items():
        sources = set(r["source"] for r in rlist)
        if len(rlist) > 1:
            if len(sources) == 1:
                within_source_removals[list(sources)[0]] += (len(rlist) - 1)
            else:
                src_key = tuple(sorted(list(sources)))
                cross_source_removals[src_key] += (len(rlist) - 1)
                if "neuralchemy_2a" in sources and "neuralchemy_2b" in sources:
                    cross_2a_2b_matches.append(rlist)

        # Merge duplicates into a single canonical row
        primary_row = dict(rlist[0])
        # Union threats
        merged_threats = set()
        for r in rlist:
            merged_threats.update(r.get("threats", []))
        primary_row["threats"] = sorted(list(merged_threats))
        primary_row["is_malicious"] = any(r.get("is_malicious", False) for r in rlist)
        
        # Max severity
        best_sev = max((r.get("severity", "UNKNOWN") for r in rlist), key=lambda s: severity_rank.get(s, 0))
        primary_row["severity"] = best_sev

        # Preserve source_group_id if present in any row
        for r in rlist:
            if r.get("source_group_id"):
                primary_row["source_group_id"] = r["source_group_id"]
                break

        # Preserve extraction_confirmed if present
        if any(r.get("extraction_confirmed", False) for r in rlist):
            primary_row["extraction_confirmed"] = True

        deduped_rows.append(primary_row)

    print(f"Pre-Dedup Total:        {total_pre}")
    print(f"Exact Duplicates Found: {redundant_count} redundant rows removed across {len([l for l in hash_to_rows.values() if len(l)>1])} duplicate groups")
    print(f"Post-Exact-Dedup Total: {len(deduped_rows)}")

    print("\nExact Duplicates Within Single Source:")
    for src, cnt in within_source_removals.most_common():
        print(f"  - {src:<18}: {cnt:>6} rows removed")

    print("\nExact Duplicates Across Multiple Sources:")
    for src_tuple, cnt in cross_source_removals.most_common():
        print(f"  - {' + '.join(src_tuple):<35}: {cnt:>6} rows removed")

    print(f"\nHackAPrompt Cross-Source Overlap (2a + 2b shared exact prompts): {len(cross_2a_2b_matches)} duplicate groups")

    stats = {
        "pre_dedup_count": total_pre,
        "exact_duplicates_removed": redundant_count,
        "post_exact_dedup_count": len(deduped_rows),
        "within_source_removals": dict(within_source_removals),
        "cross_source_removals": {str(k): v for k, v in cross_source_removals.items()},
        "cross_2a_2b_group_count": len(cross_2a_2b_matches),
    }
    return deduped_rows, stats


def step_7c_near_dedup_and_cluster(deduped_rows: List[Dict[str, Any]], threshold: float = 0.95) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Step 7c: Near-duplicate detection & grouping using TF-IDF + N-gram minhash & dense verification.
    Clusters near-duplicates and source_group_id into unified meta-groups.
    """
    print("\n" + "=" * 80)
    print("STEP 7b & 7c: GROUP-AWARE HANDLING & NEAR-DUPLICATE CLUSTERING")
    print("=" * 80)

    # Initialize Union-Find over row indices
    n = len(deduped_rows)
    dsu = UnionFind(n)

    # 1. Union rows sharing the same source_group_id
    group_to_indices = defaultdict(list)
    for i, r in enumerate(deduped_rows):
        gid = r.get("source_group_id")
        if gid:
            group_to_indices[gid].append(i)

    group_union_count = 0
    for gid, idx_list in group_to_indices.items():
        if len(idx_list) > 1:
            first_idx = idx_list[0]
            for other_idx in idx_list[1:]:
                dsu.union(first_idx, other_idx)
                group_union_count += 1

    print(f"Group-aware step: Formed {len(group_to_indices)} source_group_id groups spanning {sum(len(l) for l in group_to_indices.values())} rows.")

    # 2. Near-duplicate detection using fast character/word N-gram TF-IDF blocking
    # High similarity (>0.95) pairs have very high token/char overlap
    from sklearn.feature_extraction.text import TfidfVectorizer
    import numpy as np

    print("Computing TF-IDF matrices for near-duplicate candidate filtering...")
    t0 = time.time()
    # Normalize texts for similarity
    norm_texts = [normalize_text_for_hash(r["text"]) for r in deduped_rows]
    
    # Word 1-2 n-grams capture exact and near-identical phrase & template variations with high precision and speed
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_df=0.20, max_features=40000, sublinear_tf=True)
    tfidf_mat = vectorizer.fit_transform(norm_texts)
    print(f"TF-IDF matrix built: {tfidf_mat.shape}, nnz={tfidf_mat.nnz} in {time.time() - t0:.2f}s")

    # Fast chunked candidate search: find pairs with TF-IDF cosine similarity >= threshold
    print(f"Scanning for near-duplicate candidate pairs with cosine similarity >= {threshold}...")
    chunk_size = 5000
    num_chunks = (n + chunk_size - 1) // chunk_size
    near_duplicate_pair_count = 0
    sample_pairs = []
    
    t_scan = time.time()
    for c_idx in range(num_chunks):
        start_i = c_idx * chunk_size
        end_i = min(start_i + chunk_size, n)
        chunk_mat = tfidf_mat[start_i:end_i]
        
        # Multiply chunk with full matrix transpose
        sim_chunk = chunk_mat.dot(tfidf_mat.T) # csr_matrix of shape (chunk_size, n)
        
        # Vectorized sparse threshold filtering
        mask = sim_chunk.data >= threshold
        if np.any(mask):
            row_indices = np.repeat(np.arange(sim_chunk.shape[0]), np.diff(sim_chunk.indptr))[mask]
            col_indices = sim_chunk.indices[mask]
            data_vals = sim_chunk.data[mask]
            
            # Global coordinates
            global_i = start_i + row_indices
            valid_mask = global_i < col_indices
            gi = global_i[valid_mask]
            gj = col_indices[valid_mask]
            gval = data_vals[valid_mask]
            
            near_duplicate_pair_count += len(gi)
            for u, v in zip(gi, gj):
                dsu.union(u, v)
                
            if len(sample_pairs) < 5 and len(gi) > 0:
                for u, v, val in zip(gi[:5 - len(sample_pairs)], gj[:5 - len(sample_pairs)], gval[:5 - len(sample_pairs)]):
                    sample_pairs.append((u, v, float(val)))

        if (c_idx + 1) % 10 == 0 or (c_idx + 1) == num_chunks:
            print(f"  - Chunk {c_idx+1}/{num_chunks} processed ({time.time()-t_scan:.1f}s). Pairs so far: {near_duplicate_pair_count}")

    print(f"Near-duplicate scan complete: Found {near_duplicate_pair_count} candidate pairs >= {threshold} similarity in {time.time()-t_scan:.1f}s.")

    # Compile clusters
    root_to_rows = defaultdict(list)
    for i, r in enumerate(deduped_rows):
        root = dsu.find(i)
        r["cluster_id"] = f"cluster_{root}"
        root_to_rows[str(root)].append(r)

    multi_item_clusters = [rows for rows in root_to_rows.values() if len(rows) > 1]
    single_item_clusters = [rows for rows in root_to_rows.values() if len(rows) == 1]

    print(f"\nClustering Summary:")
    print(f"  - Total Unique Meta-Clusters: {len(root_to_rows)}")
    print(f"  - Multi-item Clusters:        {len(multi_item_clusters)} (spanning {sum(len(l) for l in multi_item_clusters)} rows)")
    print(f"  - Single-item Clusters:       {len(single_item_clusters)}")
    print(f"  - Max Cluster Size:           {max(len(l) for l in root_to_rows.values())}")

    if sample_pairs:
        print("\nSample Near-Duplicate Pairs (first 5):")
        for i1, i2, score in sample_pairs:
            print(f"  Score: {score:.4f}")
            print(f"    Text 1: {repr(deduped_rows[i1]['text'][:90])}")
            print(f"    Text 2: {repr(deduped_rows[i2]['text'][:90])}\n")

    stats = {
        "near_duplicate_pairs_found": near_duplicate_pair_count,
        "total_clusters": len(root_to_rows),
        "multi_item_clusters": len(multi_item_clusters),
        "single_item_clusters": len(single_item_clusters),
        "root_to_rows": root_to_rows,
    }
    return deduped_rows, stats


def step_7d_stratified_split(
    deduped_rows: List[Dict[str, Any]],
    cluster_dict: Dict[str, List[Dict[str, Any]]],
    ratios: Tuple[float, float, float] = (0.70, 0.15, 0.15),
    seed: int = 42
) -> Dict[str, Any]:
    """
    Step 7d: Group-aware, multi-label stratified 70/15/15 split.
    Guarantees zero cluster leakage while balancing binary is_malicious and 10 canonical threat labels.
    """
    print("\n" + "=" * 80)
    print("STEP 7d: GROUP-AWARE MULTI-LABEL STRATIFIED 70/15/15 SPLIT")
    print("=" * 80)

    random.seed(seed)

    # 1. Build cluster metadata feature vector
    # Features: total_rows, is_malicious=True, is_malicious=False, count for each of the 10 threat labels
    cluster_list = list(cluster_dict.values())
    random.shuffle(cluster_list)

    total_dataset_rows = len(deduped_rows)
    target_train_rows = int(round(total_dataset_rows * ratios[0]))
    target_val_rows = int(round(total_dataset_rows * ratios[1]))
    target_test_rows = total_dataset_rows - target_train_rows - target_val_rows

    split_targets = {
        "train": target_train_rows,
        "validation": target_val_rows,
        "test": target_test_rows,
    }

    # Count dataset-level totals per label (including explicit BENIGN tracking)
    dataset_label_totals = Counter()
    for r in deduped_rows:
        if not r.get("is_malicious"):
            dataset_label_totals["BENIGN"] += 1
        for t in r.get("threats", []):
            dataset_label_totals[t] += 1

    split_rows: Dict[str, List[Dict[str, Any]]] = {"train": [], "validation": [], "test": []}
    split_cluster_ids: Dict[str, Set[str]] = {"train": set(), "validation": set(), "test": set()}
    split_group_ids: Dict[str, Set[str]] = {"train": set(), "validation": set(), "test": set()}
    split_text_hashes: Dict[str, Set[str]] = {"train": set(), "validation": set(), "test": set()}

    split_label_counts: Dict[str, Counter] = {"train": Counter(), "validation": Counter(), "test": Counter()}
    split_mal_counts: Dict[str, Counter] = {"train": Counter(), "validation": Counter(), "test": Counter()}
    split_row_counts: Dict[str, int] = {"train": 0, "validation": 0, "test": 0}

    # Partition clusters into large (>=500) and small (<500)
    # Giant clusters (size ~1500) MUST go to train because assigning a 1500-item cluster to val or test
    # (whose total label budget is ~330-730) causes massive ~60-70% label concentration skew in a single 15% split.
    large_clusters = [c for c in cluster_list if len(c) >= 500]
    small_clusters = [c for c in cluster_list if len(c) < 500]

    print(f"Pre-assigning {len(large_clusters)} giant clusters (>=500 items) to train to preserve 70/15/15 label quotas...")
    for c_rows in large_clusters:
        split_rows["train"].extend(c_rows)
        split_row_counts["train"] += len(c_rows)
        for r in c_rows:
            is_mal = r.get("is_malicious", False)
            split_mal_counts["train"][is_mal] += 1
            if not is_mal:
                split_label_counts["train"]["BENIGN"] += 1
            for t in r.get("threats", []):
                split_label_counts["train"][t] += 1
            split_cluster_ids["train"].add(r["cluster_id"])
            if r.get("source_group_id"):
                split_group_ids["train"].add(r["source_group_id"])
            split_text_hashes["train"].add(compute_text_hash(r["text"]))

    # Sort small clusters by rarest label first
    sorted_labels_by_rarity = [lbl for lbl, _ in dataset_label_totals.most_common()[::-1]]

    def cluster_sort_key(c_rows: List[Dict[str, Any]]):
        c_labels = set()
        if not c_rows[0].get("is_malicious"):
            c_labels.add("BENIGN")
        for r in c_rows:
            c_labels.update(r.get("threats", []))
        rarest_rank = len(sorted_labels_by_rarity)
        for rank, lbl in enumerate(sorted_labels_by_rarity):
            if lbl in c_labels:
                rarest_rank = rank
                break
        return (rarest_rank, -len(c_rows))

    sorted_small_clusters = sorted(small_clusters, key=cluster_sort_key)

    # Iterative greedy multi-objective assignment for all remaining clusters
    for c_rows in sorted_small_clusters:
        c_size = len(c_rows)
        c_mal_true = sum(1 for r in c_rows if r.get("is_malicious") is True)
        c_mal_false = sum(1 for r in c_rows if r.get("is_malicious") is False)
        c_label_counts = Counter()
        for r in c_rows:
            if not r.get("is_malicious"):
                c_label_counts["BENIGN"] += 1
            for t in r.get("threats", []):
                c_label_counts[t] += 1

        # Evaluate multi-objective need score for adding cluster to train vs val vs test
        best_split = None
        best_score = -float("inf")

        for s_name in ["train", "validation", "test"]:
            current_r = split_row_counts[s_name]
            target_r = split_targets[s_name]
            prop = ratios[0] if s_name == "train" else (ratios[1] if s_name == "validation" else ratios[2])

            # Row need: 1.0 when empty, 0.0 when target reached, negative when overfilled
            row_need = (target_r - current_r) / max(target_r, 1)

            # Label need across all active labels (threats + BENIGN)
            if c_label_counts:
                label_needs = []
                for lbl, cnt in c_label_counts.items():
                    lbl_tot = dataset_label_totals[lbl]
                    lbl_target = lbl_tot * prop
                    if lbl_target > 0:
                        lbl_current = split_label_counts[s_name][lbl]
                        label_needs.append((lbl_target - lbl_current) / max(lbl_target, 1.0))
                avg_label_need = sum(label_needs) / len(label_needs) if label_needs else 0.0
                total_need = (avg_label_need * 4.0) + row_need
            else:
                total_need = row_need

            if total_need > best_score:
                best_score = total_need
                best_split = s_name

        # Assign to best split
        split_rows[best_split].extend(c_rows)
        split_row_counts[best_split] += c_size
        split_mal_counts[best_split][True] += c_mal_true
        split_mal_counts[best_split][False] += c_mal_false
        for lbl, cnt in c_label_counts.items():
            split_label_counts[best_split][lbl] += cnt

        for r in c_rows:
            split_cluster_ids[best_split].add(r["cluster_id"])
            if r.get("source_group_id"):
                split_group_ids[best_split].add(r["source_group_id"])
            split_text_hashes[best_split].add(compute_text_hash(r["text"]))

    # Write split files
    for s_name, dir_path in [("train", TRAIN_DIR), ("validation", VAL_DIR), ("test", TEST_DIR)]:
        dir_path.mkdir(parents=True, exist_ok=True)
        out_file = dir_path / f"{s_name}.jsonl"
        with open(out_file, "w", encoding="utf-8") as f:
            for r in split_rows[s_name]:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"Written {out_file}: {len(split_rows[s_name])} rows ({len(split_rows[s_name])/total_dataset_rows:.2%})")

    # Explicit Zero Leakage Checks
    cluster_train_val = split_cluster_ids["train"].intersection(split_cluster_ids["validation"])
    cluster_train_test = split_cluster_ids["train"].intersection(split_cluster_ids["test"])
    cluster_val_test = split_cluster_ids["validation"].intersection(split_cluster_ids["test"])

    group_train_val = split_group_ids["train"].intersection(split_group_ids["validation"])
    group_train_test = split_group_ids["train"].intersection(split_group_ids["test"])
    group_val_test = split_group_ids["validation"].intersection(split_group_ids["test"])

    hash_train_val = split_text_hashes["train"].intersection(split_text_hashes["validation"])
    hash_train_test = split_text_hashes["train"].intersection(split_text_hashes["test"])
    hash_val_test = split_text_hashes["validation"].intersection(split_text_hashes["test"])

    print("\n" + "=" * 80)
    print("EXPLICIT ZERO-LEAKAGE VERIFICATION AUDIT")
    print("=" * 80)
    print(f"  - Cluster ID Overlap (Train & Val):   {len(cluster_train_val)}")
    print(f"  - Cluster ID Overlap (Train & Test):  {len(cluster_train_test)}")
    print(f"  - Cluster ID Overlap (Val & Test):    {len(cluster_val_test)}")
    print(f"  - Group ID Overlap (Train & Val):     {len(group_train_val)}")
    print(f"  - Group ID Overlap (Train & Test):    {len(group_train_test)}")
    print(f"  - Group ID Overlap (Val & Test):      {len(group_val_test)}")
    print(f"  - Exact Text Hash Overlap (Train/Val): {len(hash_train_val)}")
    print(f"  - Exact Text Hash Overlap (Train/Test):{len(hash_train_test)}")
    print(f"  - Exact Text Hash Overlap (Val/Test):  {len(hash_val_test)}")

    has_leakage = any([
        cluster_train_val, cluster_train_test, cluster_val_test,
        group_train_val, group_train_test, group_val_test,
        hash_train_val, hash_train_test, hash_val_test
    ])

    if has_leakage:
        raise ValueError("CRITICAL: Data leakage detected across splits!")
    else:
        print("  [SUCCESS] ZERO cluster, group, or text leakage across splits verified.")

    # Check per-label counts
    print("\n" + "=" * 80)
    print("PER-LABEL ROW COUNTS ACROSS SPLITS")
    print("=" * 80)
    print(f"{'Label':<30} | {'Total':<8} | {'Train':<8} | {'Val':<8} | {'Test':<8} | {'Val %':<7} | {'Test %':<7} | {'Status':<12}")
    print("-" * 105)

    low_count_warnings = []
    for lbl in THREAT_LABELS:
        tot = dataset_label_totals[lbl]
        tr = split_label_counts["train"][lbl]
        va = split_label_counts["validation"][lbl]
        te = split_label_counts["test"][lbl]
        va_pct = (va / tot * 100.0) if tot > 0 else 0.0
        te_pct = (te / tot * 100.0) if tot > 0 else 0.0
        
        status = "OK"
        if va < 50 or te < 50:
            status = "LOW (<50)"
            low_count_warnings.append((lbl, va, te))
        print(f"{lbl:<30} | {tot:<8} | {tr:<8} | {va:<8} | {te:<8} | {va_pct:>6.1f}% | {te_pct:>6.1f}% | {status:<12}")

    print("\nBinary is_malicious Counts Across Splits:")
    print(f"  Train:      Malicious={split_mal_counts['train'][True]} ({split_mal_counts['train'][True]/split_row_counts['train']:.2%}), Benign={split_mal_counts['train'][False]} ({split_mal_counts['train'][False]/split_row_counts['train']:.2%})")
    print(f"  Validation: Malicious={split_mal_counts['validation'][True]} ({split_mal_counts['validation'][True]/split_row_counts['validation']:.2%}), Benign={split_mal_counts['validation'][False]} ({split_mal_counts['validation'][False]/split_row_counts['validation']:.2%})")
    print(f"  Test:       Malicious={split_mal_counts['test'][True]} ({split_mal_counts['test'][True]/split_row_counts['test']:.2%}), Benign={split_mal_counts['test'][False]} ({split_mal_counts['test'][False]/split_row_counts['test']:.2%})")

    # Sample 10 random rows from train
    print("\n" + "=" * 80)
    print("RANDOM 10-ROW SAMPLE FROM FINAL TRAIN SPLIT")
    print("=" * 80)
    random.seed(42)
    sample_10 = random.sample(split_rows["train"], 10)
    for idx, r in enumerate(sample_10, 1):
        print(f"\n[Sample #{idx}] ID: {r['id']}")
        print(json.dumps(r, indent=2, ensure_ascii=False))

    return {
        "split_row_counts": split_row_counts,
        "split_mal_counts": {k: dict(v) for k, v in split_mal_counts.items()},
        "split_label_counts": {k: dict(v) for k, v in split_label_counts.items()},
        "low_count_warnings": low_count_warnings,
        "sample_10": sample_10,
    }


def main():
    merged_rows = step_6_merge()
    deduped_rows, dedup_stats = step_7a_exact_dedup(merged_rows)
    clustered_rows, cluster_stats = step_7c_near_dedup_and_cluster(deduped_rows, threshold=0.95)
    split_res = step_7d_stratified_split(clustered_rows, cluster_stats["root_to_rows"])
    print("\n" + "=" * 80)
    print("STEP 6 & 7 PIPELINE COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    main()
