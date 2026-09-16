"""Data models for packets."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Packet:
    raw_bytes: bytes
    timestamp: float
    # Additional fields to be added
    pass