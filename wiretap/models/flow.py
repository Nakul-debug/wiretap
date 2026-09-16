"""Data models for network flows."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    # Additional fields to be added
    pass