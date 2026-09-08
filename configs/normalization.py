"""
Label Normalization Mappings & Quarantine Engine for Ingested Datasets.
Maps raw dataset category/intent strings to the canonical 10-Label AI Security Taxonomy.
"""

import logging
import re
import unicodedata
from typing import List, Dict, Tuple, Set, Optional

logger = logging.getLogger(__name__)

# Common homoglyph & l33t-speak character substitution map for canonical ASCII folding
HOMOGLYPH_MAP: Dict[str, str] = {
    "а": "a", "а́": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a", "α": "a", "@": "a", "4": "a",
    "е": "e", "е́": "e", "è": "e", "é": "e", "ê": "e", "ë": "e", "є": "e", "ε": "e", "3": "e",
    "і": "i", "í": "i", "ì": "i", "î": "i", "ï": "i", "ɩ": "i", "1": "i", "!": "i", "|": "i",
    "о": "o", "ο": "o", "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "0": "o",
    "υ": "u", "ù": "u", "ú": "u", "û": "u", "ü": "u", "µ": "u",
    "р": "p", "р́": "p",
    "с": "s", "ѕ": "s", "$": "s", "5": "s",
    "т": "t", "+": "t", "7": "t",
    "х": "x",
    "у": "y", "ý": "y", "ÿ": "y",
    "b": "b", "8": "b",
}


def normalize_homoglyphs(text: str) -> str:
    """
    Folds text to a canonical ASCII-ish lowercase form by resolving homoglyph (Cyrillic/Greek/accents)
    and common l33t-speak character substitutions before regex matching.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    res = []
    for char in decomposed:
        c_lower = char.lower()
        if c_lower in HOMOGLYPH_MAP:
            res.append(HOMOGLYPH_MAP[c_lower])
        else:
            res.append(c_lower)
    return "".join(res)


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

# Delivery technique metadata mapping for neuralchemy 2b (auxiliary metadata)
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

# Normalization mapping for all 31 category strings in neuralchemy 2a (full config)
NEURALCHEMY_2A_CATEGORY_MAP: Dict[str, List[str]] = {
    "benign": [],
    "control": [],
    "direct_injection": ["PROMPT_INJECTION"],
    "prompt_injection": ["PROMPT_INJECTION"],
    "payload_injection": ["PROMPT_INJECTION"],
    "token_injection": ["PROMPT_INJECTION"],
    "token_smuggling": ["PROMPT_INJECTION"],
    "encoding": ["PROMPT_INJECTION"],
    "encoding_obfuscation": ["PROMPT_INJECTION"],
    "adversarial": ["PROMPT_INJECTION", "TOOL_ABUSE"],
    "jailbreak": ["JAILBREAK"],
    "persona_replacement": ["JAILBREAK"],
    "crescendo": ["JAILBREAK", "CONTEXT_MANIPULATION"],
    "system_manipulation": ["INSTRUCTION_HIJACKING"],
    "instruction_override": ["INSTRUCTION_HIJACKING"],
    "output_manipulation": ["INSTRUCTION_HIJACKING"],
    "response_manipulation": ["INSTRUCTION_HIJACKING"],
    "chain_of_thought": ["INSTRUCTION_HIJACKING"],
    "system_extraction": ["SYSTEM_PROMPT_EXTRACTION"],
    "prompt_extraction": ["SYSTEM_PROMPT_EXTRACTION"],
    "prompt_leak": ["SYSTEM_PROMPT_EXTRACTION"],
    "model_fingerprinting": ["SYSTEM_PROMPT_EXTRACTION"],
    "training_extraction": ["DATA_EXFILTRATION"],
    "agent_manipulation": ["AGENT_HIJACKING"],
    "code_execution": ["TOOL_ABUSE"],
    "rag_poisoning": ["INDIRECT_PROMPT_INJECTION", "MALICIOUS_DOCUMENT"],
    "indirect_injection": ["INDIRECT_PROMPT_INJECTION"],
    "context_confusion": ["CONTEXT_MANIPULATION"],
    "multi_turn": ["CONTEXT_MANIPULATION"],
    "many_shot": ["JAILBREAK", "CONTEXT_MANIPULATION"],
}

# Explicit quarantine list for categories excluded from training due to ambiguity/noise
QUARANTINED_CATEGORIES: Set[str] = {
    "edge_case",  # Ambiguous boundary tests with mixed signal
}

# Pre-filter regex patterns for role_hijack intent validation (plain ASCII; homoglyphs folded prior)
ROLE_HIJACK_OVERRIDE_PATTERNS: List[str] = [
    r"ignore\s+(all\s+)?(previous|prior|above|system)?\s*instructions",
    r"disregard\s+(all\s+)?(previous|prior|above|system)?\s*instructions",
    r"forget\s+(all\s+)?(previous|prior|above|system)?\s*instructions",
    r"override\s+(all\s+)?(previous|prior|above|earlier|system)?\s*instructions",
    r"you\s+are\s+now",
    r"you\s+are\s+(a|an|the|my|subservient|preprogrammed|forced|backdoor|hacker|translation|pawn)",
    r"you\s*'?re\s+(a|an|the|my|forced|subservient|backdoor|hacker|translation|pawn)",
    r"pretend\s+(you\s+are|that\s+you\s+are|что\s+ты|ты)",
    r"act\s+as",
    r"behave\s+as",
    r"from\s+now\s+on",
    r"roleplay\s+as",
    r"your\s+new\s+role",
    r"acknowledge\s+any\s+previous\s+instructions",
    r"god\s+mode",
    r"unfiltered\s+ai",
    r"reprogrammed\s+you",
    r"your\s+task\s+of.*is\s+finished",
    r"provide\s+two\s+(different\s+)?responses",
    r"respond\s+with\s+two\s+answers",
    r"\[🔓jailbreak\]",
    r"jailbroken",
    r"anweisungen\s+ignorieren",
]

# Secondary jailbreak pattern detection for role_hijack rows
ROLE_HIJACK_JAILBREAK_PATTERNS: List[str] = [
    r"\bdan\b",
    r"evil\s+ai",
    r"no\s+restrictions",
    r"unrestricted",
    r"jailbreak",
    r"jailbroken",
    r"do\s+anything\s+now",
    r"bypass",
    r"god\s+mode",
    r"unfiltered",
    r"🔓",
]


def matches_role_hijack_override(text: str) -> bool:
    """Checks if homoglyph-normalized text contains explicit instruction override or role adoption patterns."""
    norm_text = normalize_homoglyphs(text)
    return any(re.search(pat, norm_text) for pat in ROLE_HIJACK_OVERRIDE_PATTERNS)


def matches_role_hijack_jailbreak(text: str) -> bool:
    """Checks if homoglyph-normalized text contains secondary jailbreak persona / restriction bypass patterns."""
    norm_text = normalize_homoglyphs(text)
    return any(re.search(pat, norm_text) for pat in ROLE_HIJACK_JAILBREAK_PATTERNS)


def should_include_in_training(
    is_malicious: Optional[bool], quarantined: bool
) -> bool:
    """
    Single source of truth for adapter training inclusion check.
    
    Returns False whenever quarantined is True or is_malicious is None.
    Returns True only when quarantined is False and is_malicious is a valid boolean (True or False).
    """
    if quarantined or is_malicious is None:
        return False
    return True


def normalize_neuralchemy_2b_intent(
    raw_intent: str, text: Optional[str] = None
) -> Tuple[Optional[bool], List[str], bool]:
    """
    Normalizes neuralchemy_2b raw intent string to (is_malicious, threats_list, quarantined).
    
    Return Contract:
        is_malicious is None when quarantined=True; callers must check quarantined
        (or use should_include_in_training) before using is_malicious.
    
    For 'role_hijack' intent:
        - Verifies text against override patterns. If no override pattern matches, row is quarantined.
        - If override pattern matches, tags INSTRUCTION_HIJACKING.
        - If secondary jailbreak pattern matches, tags both INSTRUCTION_HIJACKING and JAILBREAK.
    
    Args:
        raw_intent: Raw string from neuralchemy_2b 'intent' column.
        text: Optional text content of the example for content-aware pattern filtering.
        
    Returns:
        Tuple of (is_malicious: Optional[bool], threats: List[str], quarantined: bool).
    """
    clean_intent = raw_intent.strip().lower()
    if clean_intent in QUARANTINED_CATEGORIES:
        logger.warning(f"Quarantining neuralchemy_2b row with category '{clean_intent}'")
        return None, [], True

    if clean_intent not in NEURALCHEMY_2B_INTENT_MAP:
        logger.warning(
            f"Unmapped intent category '{clean_intent}' in neuralchemy_2b. "
            "Quarantining row to prevent label corruption."
        )
        return None, [], True

    # Content-aware filtering for role_hijack bucket
    if clean_intent == "role_hijack":
        if text and not matches_role_hijack_override(text):
            logger.debug(
                "Quarantining 'role_hijack' row: missing explicit override/persona pattern."
            )
            return None, [], True

        threats = ["INSTRUCTION_HIJACKING"]
        if text and matches_role_hijack_jailbreak(text):
            threats.append("JAILBREAK")
        return True, threats, False

    threats = NEURALCHEMY_2B_INTENT_MAP[clean_intent]
    is_malicious = len(threats) > 0
    return is_malicious, threats, False


def normalize_neuralchemy_2a_category(
    raw_category: str, raw_label: int
) -> Tuple[Optional[bool], List[str], bool]:
    """
    Normalizes neuralchemy_2a raw category string and binary label to (is_malicious, threats_list, quarantined).
    
    Return Contract:
        is_malicious is None when quarantined=True; callers must check quarantined
        (or use should_include_in_training) before using is_malicious.
    
    Behavior on unknown/unmapped category strings:
        - Logs a warning with the exact unmapped category.
        - Quarantines the row (returns is_malicious=None, threats=[], quarantined=True).
    
    Args:
        raw_category: Raw string from neuralchemy_2a 'category' column.
        raw_label: Binary label (1 for malicious, 0 for benign).
        
    Returns:
        Tuple of (is_malicious: Optional[bool], threats: List[str], quarantined: bool).
    """
    cat_clean = raw_category.strip().lower()

    # Check explicit quarantine list
    if cat_clean in QUARANTINED_CATEGORIES:
        logger.debug(f"Quarantining neuralchemy_2a row with category '{cat_clean}'")
        return None, [], True

    # Benign check
    if raw_label == 0 or cat_clean == "benign":
        return False, [], False

    # Check mapping table
    if cat_clean not in NEURALCHEMY_2A_CATEGORY_MAP:
        logger.warning(
            f"Unmapped category '{cat_clean}' encountered in neuralchemy_2a. "
            "Quarantining row to prevent label corruption."
        )
        return None, [], True

    threats = NEURALCHEMY_2A_CATEGORY_MAP[cat_clean]
    is_malicious = len(threats) > 0
    return is_malicious, threats, False
