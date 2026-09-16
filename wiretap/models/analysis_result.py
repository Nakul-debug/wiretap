"""Analysis result models."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class AnalysisResult:
    rtt: Optional[float] = None
    retransmissions: int = 0
    # Additional fields to be added
    pass