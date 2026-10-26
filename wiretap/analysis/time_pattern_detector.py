"""Time-of-day pattern detector for network traffic.

Builds a baseline of "normal" communication hours per source IP and flags
activity that occurs outside those established windows. This catches:

* A host that normally communicates during business hours (9am-5pm) but
  suddenly starts sending traffic at 3am.
* A server that only talks to external hosts during maintenance windows
  but is active at unexpected times.
* Beaconing or C2 activity that occurs at unusual intervals.

The detector is unsupervised: it learns each source's active hours from
observed traffic and marks deviations as anomalies.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Deque, Dict, List, Optional, Set

from wiretap.models.packet import Packet
from wiretap.models.threat_alert import ThreatAlert

logger = logging.getLogger(__name__)


@dataclass
class TimeAnomalyResult:
    """Result of a single time-pattern evaluation."""

    source_ip: str
    is_anomaly: bool
    hour: int                     # hour of day (0-23) when packet was seen
    normal_hours: Set[int]        # learned baseline hours for this source
    confidence: float             # 0.0 to 1.0
    sample_count: int             # how many samples established the baseline
    trained: bool                 # whether baseline has been established


class TimePatternDetector:
    """Detects communication outside a source's normal active hours.

    Parameters
    ----------
    alert_callback:
        Optional callback invoked whenever a time anomaly is detected.
    min_samples:
        Minimum packets observed from a source before its baseline is
        considered trained. Default 20.
    anomaly_threshold:
        Confidence threshold (0.0-1.0) above which an alert is raised.
    cooldown_seconds:
        Minimum seconds between alerts for the same source to avoid
        alert storms.
    """

    def __init__(
        self,
        alert_callback: Optional[Callable[[ThreatAlert], None]] = None,
        min_samples: int = 20,
        anomaly_threshold: float = 0.6,
        cooldown_seconds: float = 300.0,
    ) -> None:
        self.alert_callback = alert_callback
        self.min_samples = min_samples
        self.anomaly_threshold = anomaly_threshold
        self.cooldown_seconds = cooldown_seconds

        # Per-source tracking
        self._source_hours: Dict[str, Set[int]] = defaultdict(set)
        self._source_sample_count: Dict[str, int] = defaultdict(int)
        # Hours that were flagged as unusual (for query engine lookup)
        self._anomalous_hours: Dict[str, Set[int]] = defaultdict(set)
        self._last_alert_time: Dict[str, float] = {}

        # All detected anomalies
        self._anomalies: List[ThreatAlert] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def is_trained(self, source_ip: str) -> bool:
        """Return True if the source has enough samples for a baseline."""
        return self._source_sample_count.get(source_ip, 0) >= self.min_samples

    def analyse(self, packet: Packet) -> Optional[ThreatAlert]:
        """Process one packet and return an alert if it's outside normal hours."""
        src_ip = self._extract_source_ip(packet)
        if not src_ip:
            return None

        timestamp = packet.timestamp
        hour = self._hour_of_day(timestamp)

        # Read current baseline BEFORE adding this packet's hour
        with self._lock:
            self._source_sample_count[src_ip] += 1
            sample_count = self._source_sample_count[src_ip]
            normal_hours_before = set(self._source_hours.get(src_ip, set()))
            trained = sample_count >= self.min_samples

        # If not yet trained, just record the hour and return
        if not trained:
            with self._lock:
                self._source_hours[src_ip].add(hour)
            return None

        # If this hour is already in the normal baseline, it's not an anomaly
        if hour in normal_hours_before:
            # Still record the hour (idempotent since it's a set)
            with self._lock:
                self._source_hours[src_ip].add(hour)
            return None

        # This hour is outside the baseline - potential anomaly
        # Check cooldown
        now = time.time()
        last_alert = self._last_alert_time.get(src_ip, 0.0)
        if now - last_alert < self.cooldown_seconds:
            # Still record the hour so it becomes part of baseline going forward
            with self._lock:
                self._source_hours[src_ip].add(hour)
            return None

        # Calculate confidence: how unusual is this hour?
        distinct_hours = len(normal_hours_before)
        # Base confidence: more distinct hours seen = lower surprise for a new one
        base_confidence = max(0.3, 1.0 - (distinct_hours / 24.0))
        # Boost if we have a solid baseline
        baseline_boost = min(0.4, sample_count / 100.0)
        confidence = min(1.0, base_confidence + baseline_boost)

        if confidence < self.anomaly_threshold:
            # Record the hour even if below threshold
            with self._lock:
                self._source_hours[src_ip].add(hour)
            return None

        # Record the anomaly
        alert = ThreatAlert(
            source_ip=src_ip,
            threat_type="unusual_time",
            severity=self._severity_from_confidence(confidence),
            confidence=confidence,
            timestamp=timestamp,
            description=(
                f"Communication from {src_ip} at {hour}:00 outside normal "
                f"hours ({', '.join(str(h) for h in sorted(normal_hours_before))})."
            ),
            evidence={
                "hour": hour,
                "normal_hours": sorted(normal_hours_before),
                "sample_count": sample_count,
                "distinct_hours": distinct_hours,
            },
            is_malicious=True,
        )

        # Record the hour in baseline so future packets at this hour are normal
        with self._lock:
            self._source_hours[src_ip].add(hour)
            self._anomalous_hours[src_ip].add(hour)
            self._anomalies.append(alert)
            self._last_alert_time[src_ip] = now

        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as exc:  # pragma: no cover - callback safety
                logger.error("Time anomaly callback raised: %s", exc)

        return alert

    def analyse_batch(self, packets: List[Packet]) -> List[ThreatAlert]:
        """Process multiple packets, returning all alerts raised."""
        alerts: List[ThreatAlert] = []
        for pkt in packets:
            alert = self.analyse(pkt)
            if alert:
                alerts.append(alert)
        return alerts

    def get_anomalies(self, source_ip: Optional[str] = None) -> List[ThreatAlert]:
        with self._lock:
            if source_ip is None:
                return list(self._anomalies)
            return [a for a in self._anomalies if a.source_ip == source_ip]

    def get_source_profile(self, source_ip: str) -> dict:
        """Return the learned baseline for a source."""
        with self._lock:
            return {
                "sample_count": self._source_sample_count.get(source_ip, 0),
                "normal_hours": sorted(self._source_hours.get(source_ip, set())),
                "anomalous_hours": sorted(self._anomalous_hours.get(source_ip, set())),
                "trained": self.is_trained(source_ip),
            }

    def get_anomalous_hours(self, source_ip: str) -> Set[int]:
        """Return the set of hours flagged as unusual for a source."""
        with self._lock:
            return set(self._anomalous_hours.get(source_ip, set()))

    def reset(self) -> None:
        with self._lock:
            self._source_hours.clear()
            self._source_sample_count.clear()
            self._last_alert_time.clear()
            self._anomalies.clear()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_source_ip(packet: Packet) -> Optional[str]:
        ip = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if not ip:
            return None
        src = ip.get_field("src_addr") or ip.get_field("source")
        return str(src) if src else None

    @staticmethod
    def _hour_of_day(timestamp: float) -> int:
        return datetime.fromtimestamp(timestamp).hour

    @staticmethod
    def _severity_from_confidence(confidence: float) -> str:
        if confidence >= 0.8:
            return "high"
        if confidence >= 0.6:
            return "medium"
        return "low"
