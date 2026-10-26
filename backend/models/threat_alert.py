"""Data model for threat detection alerts."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any


@dataclass
class ThreatAlert:
    """Represents a detected malicious or suspicious network activity.

    Attributes:
        source_ip: The source IP address implicated in the alert.
        threat_type: Category of threat (e.g. 'port_scan', 'flood', 'syn_flood',
            'brute_force', 'dns_amplification', 'beaconing').
        severity: One of 'low', 'medium', 'high', 'critical'.
        confidence: Confidence score between 0.0 and 1.0.
        timestamp: Unix timestamp when the alert was raised.
        description: Human-readable description of the detected activity.
        evidence: Supporting metrics (packet counts, rates, ports, etc.).
        is_malicious: Whether the source should be treated as malicious.
    """

    source_ip: str
    threat_type: str
    severity: str
    confidence: float
    timestamp: float = field(default_factory=datetime.now().timestamp)
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    is_malicious: bool = True
