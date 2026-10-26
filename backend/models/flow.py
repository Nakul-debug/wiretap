"""Data models for network flows."""
from dataclasses import dataclass, field
from typing import Optional, List
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
    # RTT metrics
    smoothed_rtt: Optional[float] = None  # EWMA smoothed RTT in seconds
    rtt: Optional[float] = None  # latest RTT sample in seconds
    rtt_min: Optional[float] = None
    rtt_max: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_samples: List[float] = field(default_factory=list)
    # Retransmission metrics
    retransmission_count: int = 0
    out_of_order_count: int = 0

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

    def add_rtt_sample(self, rtt_val: float, alpha: float = 0.875):
        """Add an RTT sample and update min/max/avg/smoothed."""
        self.rtt_samples.append(rtt_val)
        self.rtt = rtt_val
        if self.rtt_min is None or rtt_val < self.rtt_min:
            self.rtt_min = rtt_val
        if self.rtt_max is None or rtt_val > self.rtt_max:
            self.rtt_max = rtt_val
        if self.rtt_samples:
            self.rtt_avg = sum(self.rtt_samples) / len(self.rtt_samples)
        # EWMA smoothed RTT
        if self.smoothed_rtt is None:
            self.smoothed_rtt = rtt_val
        else:
            self.smoothed_rtt = alpha * self.smoothed_rtt + (1.0 - alpha) * rtt_val