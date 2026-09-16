"""Statistics models."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Statistics:
    total_packets: int = 0
    total_bytes: int = 0
    # Additional fields to be added
    pass