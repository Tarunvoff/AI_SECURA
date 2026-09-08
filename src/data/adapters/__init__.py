"""
Per-dataset adapters package for converting raw Hugging Face datasets into canonical schema.
"""

from src.data.adapters.neuralchemy_2b_adapter import process_neuralchemy_2b
from src.data.adapters.neuralchemy_2a_adapter import process_neuralchemy_2a
from src.data.adapters.mosscap_adapter import process_mosscap

__all__ = [
    "process_neuralchemy_2b",
    "process_neuralchemy_2a",
    "process_mosscap",
]
