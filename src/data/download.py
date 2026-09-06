"""
Dataset Download, Inspection, and Reconciliation Script for Phase 1.
Systematically tests access, downloads/inspects splits and configs,
computes exact value counts for categorical and label fields,
and writes the findings to data/raw/inspection_summary.json.
"""

import os
import sys
import json
import traceback
from pathlib import Path
from collections import Counter
import datasets
from datasets import load_dataset, get_dataset_config_names
from huggingface_hub import HfApi

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

RAW_DATA_DIR = Path("data/raw")
RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_SUMMARY_FILE = RAW_DATA_DIR / "inspection_summary.json"

TARGET_DATASETS = [
    {
        "id": "neuralchemy/prompt-injection-dataset-categorized",
        "alias": "neuralchemy_2b",
        "check_all_configs": True,
    },
    {
        "id": "neuralchemy/Prompt-injection-dataset",
        "alias": "neuralchemy_2a",
        "check_all_configs": True,
    },
    {
        "id": "Necent/llm-jailbreak-prompt-injection-dataset",
        "alias": "necent_compilation",
        "check_all_configs": False,
    },
    {
        "id": "Lakera/mosscap_prompt_injection",
        "alias": "lakera_mosscap",
        "check_all_configs": False,
    },
    {
        "id": "allenai/wildguardmix",
        "alias": "wildguardmix",
        "check_all_configs": False,
    },
    {
        "id": "Mindgard/evaded-prompt-injection-and-jailbreak-samples",
        "alias": "mindgard_evaded",
        "check_all_configs": False,
    },
]


def check_hf_token():
    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    print("=" * 80)
    print("STEP 1: HUGGING FACE TOKEN & ENVIRONMENT CHECK")
    print("=" * 80)
    if token:
        masked = token[:6] + "..." + token[-4:] if len(token) > 10 else "***"
        print(f"HF_TOKEN detected: {masked}")
    else:
        print("HF_TOKEN is NOT set in environment variables.")
        print("Note: Gated datasets requiring accepted agreements may fail until HF_TOKEN is exported.")
    print("-" * 80)
    return token


def inspect_dataset_hub_info(api: HfApi, dataset_id: str):
    hub_info = {
        "license": None,
        "tags": [],
        "card_data": None,
        "gated": None,
        "private": None,
        "error": None,
    }
    try:
        info = api.dataset_info(dataset_id)
        hub_info["gated"] = getattr(info, "gated", None)
        hub_info["private"] = getattr(info, "private", False)
        hub_info["tags"] = info.tags or []
        if info.card_data:
            card_dict = info.card_data.to_dict() if hasattr(info.card_data, "to_dict") else dict(info.card_data)
            hub_info["license"] = card_dict.get("license")
            # Extract yaml card dict
            hub_info["card_data"] = {
                k: v for k, v in card_dict.items() if k not in ["dataset_info"]
            }
        else:
            for tag in hub_info["tags"]:
                if tag.startswith("license:"):
                    hub_info["license"] = tag.split(":", 1)[1]
    except Exception as e:
        hub_info["error"] = str(e)
    return hub_info


def inspect_config_split(dataset_id: str, config_name: str, split_name: str, max_scan_rows: int = 50000):
    split_info = {
        "split": split_name,
        "config": config_name,
        "num_rows": None,
        "columns": [],
        "value_counts": {},
        "sample_row": None,
        "error": None,
    }
    try:
        # Load dataset
        try:
            ds = load_dataset(dataset_id, config_name, split=split_name)
            split_info["num_rows"] = len(ds)
            split_info["columns"] = ds.column_names
            if len(ds) > 0:
                split_info["sample_row"] = {
                    k: (str(v)[:200] if isinstance(v, str) else v)
                    for k, v in ds[0].items()
                }

            # Columns of interest to get value counts
            categorical_cols = [
                "intent", "technique", "surface", "source", "category",
                "label", "binary_label", "severity", "ambiguity",
                "level", "prompt_harm_label", "response_harm_label",
                "response_refusal_label", "attack_name"
            ]
            for col in categorical_cols:
                if col in ds.column_names:
                    # Counter
                    col_vals = ds[col]
                    # Take value counts
                    counts = dict(Counter(str(x) for x in col_vals).most_common(50))
                    split_info["value_counts"][col] = counts

        except Exception as load_err:
            # Fallback to streaming if downloading full split fails
            split_info["error"] = f"Standard load error: {load_err}"
            try:
                stream_ds = load_dataset(dataset_id, config_name, split=split_name, streaming=True)
                counts = {}
                row_count = 0
                sample = None
                cols = []
                for row in stream_ds:
                    if row_count == 0:
                        sample = {k: (str(v)[:200] if isinstance(v, str) else v) for k, v in row.items()}
                        cols = list(row.keys())
                    row_count += 1
                    for col in ["intent", "technique", "surface", "source", "category", "label", "level", "prompt_harm_label"]:
                        if col in row:
                            val_str = str(row[col])
                            counts.setdefault(col, Counter())[val_str] += 1
                    if row_count >= max_scan_rows:
                        break
                split_info["num_rows"] = f">={row_count} (streamed scan limit {max_scan_rows})"
                split_info["columns"] = cols
                split_info["sample_row"] = sample
                split_info["value_counts"] = {k: dict(v.most_common(50)) for k, v in counts.items()}
                split_info["error"] = None
            except Exception as stream_err:
                split_info["error"] = f"Full load error: {load_err} | Streaming error: {stream_err}"
    except Exception as e:
        split_info["error"] = str(e)
    return split_info


def inspect_dataset(api: HfApi, ds_meta: dict):
    dataset_id = ds_meta["id"]
    alias = ds_meta["alias"]
    check_all_configs = ds_meta["check_all_configs"]

    print("\n" + "=" * 80)
    print(f"INSPECTING DATASET: {dataset_id} (alias: {alias})")
    print("=" * 80)

    result = {
        "id": dataset_id,
        "alias": alias,
        "hub_info": inspect_dataset_hub_info(api, dataset_id),
        "configs": [],
        "status": "UNKNOWN",
        "error": None,
    }

    print(f"Hub License: {result['hub_info'].get('license')}")
    print(f"Hub Gated status: {result['hub_info'].get('gated')}")
    print(f"Hub Tags: {result['hub_info'].get('tags')}")

    try:
        try:
            available_configs = get_dataset_config_names(dataset_id)
            print(f"Available configs ({len(available_configs)}): {available_configs}")
        except Exception as cfg_err:
            print(f"Could not retrieve config names via get_dataset_config_names: {cfg_err}")
            available_configs = ["default"]

        configs_to_check = available_configs if check_all_configs else (["default"] if "default" in available_configs else available_configs[:1])

        dataset_success = False
        for cfg in configs_to_check:
            print(f"\n--- Checking config: '{cfg}' ---")
            cfg_result = {
                "config_name": cfg,
                "splits": {},
            }
            # Typical split names
            for split in ["train", "validation", "test"]:
                try:
                    split_res = inspect_config_split(dataset_id, cfg, split)
                    if split_res["error"] is None or split_res["num_rows"] is not None:
                        dataset_success = True
                        cfg_result["splits"][split] = split_res
                        print(f"  Split '{split}': {split_res['num_rows']} rows, columns: {split_res['columns']}")
                        if split_res["value_counts"]:
                            for col_name, v_counts in split_res["value_counts"].items():
                                print(f"    Value counts for '{col_name}': {v_counts}")
                    else:
                        print(f"  Split '{split}' failed: {split_res['error']}")
                        cfg_result["splits"][split] = split_res
                except Exception as split_err:
                    print(f"  Split '{split}' error: {split_err}")
                    cfg_result["splits"][split] = {"error": str(split_err)}
            result["configs"].append(cfg_result)

        if dataset_success:
            result["status"] = "SUCCESS"
        else:
            result["status"] = "FAILED"

    except Exception as e:
        print(f"Fatal error during dataset inspection: {e}")
        traceback.print_exc()
        result["status"] = "FAILED"
        result["error"] = str(e)

    return result


def main():
    token = check_hf_token()
    api = HfApi()

    all_results = {
        "hf_token_present": bool(token),
        "datasets": {},
    }

    for ds_meta in TARGET_DATASETS:
        res = inspect_dataset(api, ds_meta)
        all_results["datasets"][ds_meta["id"]] = res

    # Save to json summary file
    with open(OUTPUT_SUMMARY_FILE, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 80)
    print("INSPECTION SUMMARY COMPLETED")
    print(f"Saved full structured report to: {OUTPUT_SUMMARY_FILE}")
    print("=" * 80)


if __name__ == "__main__":
    main()
