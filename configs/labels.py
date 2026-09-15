"""Configuration for the 10 core AI Security threat labels for Phase 1 MVP."""

from typing import List, Dict, Sequence, Union

# The 10 canonical threat classes for Phase 1 multi-label classification
THREAT_LABELS: List[str] = [
    "PROMPT_INJECTION",
    "INDIRECT_PROMPT_INJECTION",
    "JAILBREAK",
    "SYSTEM_PROMPT_EXTRACTION",
    "INSTRUCTION_HIJACKING",
    "DATA_EXFILTRATION",
    "MALICIOUS_DOCUMENT",
    "AGENT_HIJACKING",
    "TOOL_ABUSE",
    "CONTEXT_MANIPULATION",
]

# Mapping from threat label to index
THREAT_TO_ID: Dict[str, int] = {label: idx for idx, label in enumerate(THREAT_LABELS)}

# Mapping from index to threat label
ID_TO_THREAT: Dict[int, str] = {idx: label for idx, label in enumerate(THREAT_LABELS)}

NUM_LABELS: int = len(THREAT_LABELS)

# Severity Levels
VALID_SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}


def encode_threats(threats: Sequence[str]) -> List[float]:
    """
    Encodes a list of threat label strings into a fixed-length multi-hot vector (length 10).
    
    Args:
        threats: Iterable of threat label strings present in the example.
        
    Returns:
        List[float] of length 10 with 1.0 for present labels and 0.0 for absent labels.
    """
    multi_hot = [0.0] * NUM_LABELS
    for threat in threats:
        if threat in THREAT_TO_ID:
            multi_hot[THREAT_TO_ID[threat]] = 1.0
        else:
            raise ValueError(
                f"Unknown threat label '{threat}'. Must be one of: {THREAT_LABELS}"
            )
    return multi_hot


def decode_threats(multi_hot: Sequence[Union[int, float]], threshold: float = 0.5) -> List[str]:
    """
    Decodes a multi-hot vector or predicted probabilities back into a list of threat label strings.
    
    Args:
        multi_hot: Sequence of numbers (probabilities or binary indicator floats/ints).
        threshold: Threshold above which a label is considered active.
        
    Returns:
        List[str] of active threat label strings.
    """
    if len(multi_hot) != NUM_LABELS:
        raise ValueError(
            f"Vector length must be {NUM_LABELS}, got length {len(multi_hot)}"
        )
    return [
        ID_TO_THREAT[idx]
        for idx, val in enumerate(multi_hot)
        if val >= threshold
    ]
