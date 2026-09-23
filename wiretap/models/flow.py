"""Data models for network flows."""
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class Flow:
    """Represents a network flow."""
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  # e.g., 'TCP', 'UDP', 'ICMP'
    # Additional fields
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = field(default_factory=datetime.now().timestamp)
    last_seen: float = field(default_factory=datetime.now().timestamp)
    # TCP state (if applicable)
    tcp_state: Optional[str] = None  # e.g., 'ESTABLISHED', 'FIN_WAIT'
    # Application protocol guess
    application_protocol: Optional[str] = None  # e.g., 'HTTP', 'DNS'
    # Per-direction statistics
    forward_packet_count: int = 0
    reverse_packet_count: int = 0
    forward_byte_count: int = 0
    reverse_byte_count: int = 0

    def update(self, packet_length: int, timestamp: float, direction: str = "forward"):
        """Update flow statistics with a new packet."""
        self.packet_count += 1
        self.byte_count += packet_length
        self.last_seen = timestamp
        if direction == "forward":
            self.forward_packet_count += 1
            self.forward_byte_count += packet_length
        else:
            self.reverse_packet_count += 1
            self.reverse_byte_count += packet_length