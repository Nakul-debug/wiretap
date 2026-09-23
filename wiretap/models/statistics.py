"""Statistics models."""
from dataclasses import dataclass, field
from typing import Dict, Optional
from datetime import datetime


@dataclass
class Statistics:
    """Overall capture statistics."""
    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = field(default_factory=datetime.now().timestamp)
    last_update_time: float = field(default_factory=datetime.now().timestamp)
    # Protocol distribution
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    # Top talkers (by packet count)
    top_source_ips: Dict[str, int] = field(default_factory=dict)
    top_destination_ips: Dict[str, int] = field(default_factory=dict)
    # Additional metrics can be added

    def update(self, packet_length: int, protocol: str, src_ip: str, dst_ip: str):
        """Update statistics with a new packet."""
        self.total_packets += 1
        self.total_bytes += packet_length
        self.last_update_time = datetime.now().timestamp()
        self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + 1
        self.top_source_ips[src_ip] = self.top_source_ips.get(src_ip, 0) + 1
        self.top_destination_ips[dst_ip] = self.top_destination_ips.get(dst_ip, 0) + 1

    def packets_per_second(self) -> float:
        """Calculate packets per second since start."""
        elapsed = self.last_update_time - self.start_time
        if elapsed > 0:
            return self.total_packets / elapsed
        return 0.0

    def bytes_per_second(self) -> float:
        """Calculate bytes per second since start."""
        elapsed = self.last_update_time - self.start_time
        if elapsed > 0:
            return self.total_bytes / elapsed
        return 0.0