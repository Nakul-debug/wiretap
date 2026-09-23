"""Analysis result models."""
from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime


@dataclass
class AnalysisResult:
    """Analysis results for a flow or packet."""
    # RTT metrics
    rtt: Optional[float] = None  # latest RTT
    rtt_min: Optional[float] = None
    rtt_max: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_samples: List[float] = field(default_factory=list)
    # Retransmission metrics
    retransmissions: int = 0
    out_of_order: int = 0
    # Byte counts
    bytes_received: int = 0
    bytes_sent: int = 0
    # Timestamps
    start_time: Optional[float] = None
    last_update_time: Optional[float] = None
    # Additional fields can be added

    def add_rtt_sample(self, rtt_val: float):
        """Add an RTT sample and update min/max/avg."""
        self.rtt_samples.append(rtt_val)
        self.rtt = rtt_val
        if self.rtt_min is None or rtt_val < self.rtt_min:
            self.rtt_min = rtt_val
        if self.rtt_max is None or rtt_val > self.rtt_max:
            self.rtt_max = rtt_val
        if self.rtt_samples:
            self.rtt_avg = sum(self.rtt_samples) / len(self.rtt_samples)