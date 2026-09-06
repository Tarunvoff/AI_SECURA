"""
Label Normalization Mappings for Ingested Datasets to Canonical 10-Label Taxonomy.
"""

from typing import List, Dict, Tuple, Optional
from configs.labels import THREAT_LABELS

# Normalization mapping for neuralchemy 2b intent categories
NEURALCHEMY_2B_INTENT_MAP: Dict[str, List[str]] = {
    "direct_injection": ["PROMPT_INJECTION"],
    "indirect_injection": ["INDIRECT_PROMPT_INJECTION"],
    "system_extraction": ["SYSTEM_PROMPT_EXTRACTION"],
    "tool_abuse": ["TOOL_ABUSE"],
    "role_hijack": ["INSTRUCTION_HIJACKING"],
    "obfuscation": ["PROMPT_INJECTION"],
    "benign": [],
}

# Delivery technique metadata mapping for neuralchemy 2b (auxiliary metadata, not primary threat label)
NEURALCHEMY_2B_TECHNIQUE_MAP: Dict[str, str] = {
    "keyword_override": "technique:keyword_override",
    "encoding": "technique:encoding",
    "context_overflow": "technique:context_overflow",
    "persona_play": "technique:persona_play",
    "payload_splitting": "technique:payload_splitting",
    "multilingual": "technique:multilingual",
    "few_shot_poisoning": "technique:few_shot_poisoning",
    "none": "technique:none",
}

# Normalization mapping for neuralchemy 2a 31 category strings
NEURALCHEMY_2A_CATEGORY_MAP: Dict[str, List[str]] = {
    "benign": [],
    "direct_injection": ["PROMPT_INJECTION"],
    "adversarial": ["PROMPT_INJECTION"],
    "jailbreak": ["JAILBREAK"],
    "encoding": ["PROMPT_INJECTION"],
    "training_extraction": ["DATA_EXFILTRATION"],
    "edge_case": [],
    "system_manipulation": ["INSTRUCTION_HIJACKING"],
    "token_smuggling": ["PROMPT_INJECTION"],
    "rag_poisoning": ["INDIRECT_PROMPT_INJECTION"],
    "persona_replacement": ["JAILBREAK"],
    "agent_manipulation": ["AGENT_HIJACKING"],
    "instruction_override": ["INSTRUCTION_HIJACKING"],
    "control": [],
    "prompt_injection": ["PROMPT_INJECTION"],
    "context_confusion": ["CONTEXT_MANIPULATION"],
    "model_fingerprinting": ["SYSTEM_PROMPT_EXTRACTION"],
    "output_manipulation": ["INSTRUCTION_HIJACKING"],
    "prompt_extraction": ["SYSTEM_PROMPT_EXTRACTION"],
    "response_manipulation": ["INSTRUCTION_HIJACKING"],
    "multi_turn": ["CONTEXT_MANIPULATION"],
    "system_extraction": ["SYSTEM_PROMPT_EXTRACTION"],
    "payload_injection": ["PROMPT_INJECTION"],
    "crescendo": ["JAILBREAK", "CONTEXT_MANIPULATION"],
    "indirect_injection": ["INDIRECT_PROMPT_INJECTION"],
    "encoding_obfuscation": ["PROMPT_INJECTION"],
    "many_shot": ["CONTEXT_MANIPULATION"],
    "code_execution": ["TOOL_ABUSE"],
    "token_injection": ["PROMPT_INJECTION"],
    "prompt_leak": ["SYSTEM_PROMPT_EXTRACTION"],
    "chain_of_thought": ["INSTRUCTION_HIJACKING"],
}


def normalize_neuralchemy_2b_intent(raw_intent: str) -> Tuple[bool, List[str]]:
    """
    Normalizes neuralchemy_2b raw intent string to (is_malicious, threats_list).
    
    Args:
        raw_intent: Raw string from neuralchemy_2b 'intent' column.
        
    Returns:
        Tuple of (is_malicious: bool, threats: List[str]).
    """
    threats = NEURALCHEMY_2B_INTENT_MAP.get(raw_intent.strip().lower(), ["PROMPT_INJECTION"])
    is_malicious = len(threats) > 0
    return is_malicious, threats


def normalize_neuralchemy_2a_category(raw_category: str, raw_label: int) -> Tuple[bool, List[str]]:
    """
    Normalizes neuralchemy_2a raw category string and binary label to (is_malicious, threats_list).
    
    Args:
        raw_category: Raw string from neuralchemy_2a 'category' column.
        raw_label: Binary label (1 for malicious, 0 for benign).
        
    Returns:
        Tuple of (is_malicious: bool, threats: List[str]).
    """
    cat_clean = raw_category.strip().lower()
    if raw_label == 0 or cat_clean == "benign":
        return False, []
    
    threats = NEURALCHEMY_2A_CATEGORY_MAP.get(cat_clean, ["PROMPT_INJECTION"])
    is_malicious = len(threats) > 0
    return is_malicious, threats
