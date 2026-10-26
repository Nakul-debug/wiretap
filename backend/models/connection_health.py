"""Data models for TCP connection health diagnostics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class HandshakeInfo:
    """Results of TCP handshake analysis for a connection."""

    completed: bool = False
    syn_time: Optional[float] = None      # timestamp of first SYN
    syn_ack_time: Optional[float] = None  # timestamp of SYN-ACK
    ack_time: Optional[float] = None      # timestamp of final ACK
    handshake_time_ms: Optional[float] = None  # SYN -> SYN-ACK latency in ms
    failed: bool = False                  # SYN sent but no SYN-ACK within window
    incomplete: bool = False              # SYN-ACK received but no final ACK
    syn_retries: int = 0                  # number of SYN retransmissions


@dataclass
class ConnectionHealthReport:
    """Comprehensive health assessment for a single TCP connection."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    # Overall health
    health_score: float = 100.0           # 0-100, higher = healthier
    health_grade: str = "A"               # A-F letter grade
    health_label: str = "Excellent"       # human-readable label

    # Handshake metrics
    handshake: HandshakeInfo = field(default_factory=HandshakeInfo)

    # Reliability metrics
    total_segments: int = 0               # total TCP segments observed
    retransmission_count: int = 0         # segments flagged as retransmissions
    retransmission_rate: float = 0.0      # retransmissions / total segments (0-1)
    duplicate_ack_count: int = 0          # duplicate ACKs observed
    duplicate_ack_frequency: float = 0.0  # duplicate ACKs per second

    # Flow control metrics
    zero_window_count: int = 0            # zero-window advertisements
    window_full_count: int = 0            # near-full window conditions

    # Termination metrics
    rst_count: int = 0                    # RST flags observed
    premature_termination: bool = False   # connection ended with RST instead of FIN

    # RTT metrics
    rtt_samples: List[float] = field(default_factory=list)  # seconds
    median_rtt_ms: Optional[float] = None
    rtt_min_ms: Optional[float] = None
    rtt_max_ms: Optional[float] = None
    rtt_avg_ms: Optional[float] = None
    rtt_variation_ms: Optional[float] = None  # std dev of RTT samples
    rtt_trend: str = "stable"             # improving, degrading, stable, insufficient

    # Timing
    duration_seconds: float = 0.0         # connection lifespan
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    # Evidence and summary
    evidence: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "health_score": self.health_score,
            "health_grade": self.health_grade,
            "health_label": self.health_label,
            "handshake": {
                "completed": self.handshake.completed,
                "failed": self.handshake.failed,
                "incomplete": self.handshake.incomplete,
                "handshake_time_ms": self.handshake.handshake_time_ms,
                "syn_retries": self.handshake.syn_retries,
            },
            "retransmission_count": self.retransmission_count,
            "retransmission_rate": self.retransmission_rate,
            "duplicate_ack_count": self.duplicate_ack_count,
            "duplicate_ack_frequency": self.duplicate_ack_frequency,
            "zero_window_count": self.zero_window_count,
            "window_full_count": self.window_full_count,
            "rst_count": self.rst_count,
            "premature_termination": self.premature_termination,
            "median_rtt_ms": self.median_rtt_ms,
            "rtt_min_ms": self.rtt_min_ms,
            "rtt_max_ms": self.rtt_max_ms,
            "rtt_avg_ms": self.rtt_avg_ms,
            "rtt_variation_ms": self.rtt_variation_ms,
            "rtt_trend": self.rtt_trend,
            "duration_seconds": self.duration_seconds,
            "evidence": self.evidence,
            "summary": self.summary,
        }
