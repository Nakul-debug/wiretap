"""Threat detection model for analysing packet trends and flagging malicious sources."""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Set

from wiretap.models.packet import Packet
from wiretap.models.threat_alert import ThreatAlert

logger = logging.getLogger(__name__)


@dataclass
class SourceProfile:
    """Aggregated per-source metrics used for trend analysis and detection."""

    source_ip: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Destination ports contacted (used for port-scan detection)
    destination_ports: Set[int] = field(default_factory=set)
    destination_ips: Set[str] = field(default_factory=set)

    # Protocol distribution
    protocol_counts: Dict[str, int] = field(default_factory=dict)

    # TCP flag counters (used for SYN flood detection)
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0

    # Recent packet timestamps (used for rate/trend analysis)
    timestamps: Deque[float] = field(default_factory=deque)

    # Recent packet sizes (used for anomaly trend analysis)
    sizes: Deque[int] = field(default_factory=deque)

    # Connection attempts to closed/unreachable destinations (heuristic)
    failed_connections: int = 0

    def update(self, packet: Packet, timestamp: float) -> None:
        """Ingest a single packet into this source's profile."""
        self.packet_count += 1
        self.last_seen = timestamp
        self.timestamps.append(timestamp)
        self.sizes.append(packet.raw_bytes and len(packet.raw_bytes) or 0)

        layer = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if layer:
            # Field names used by wiretap decoders: src_addr / dst_addr
            dst_ip = layer.get_field("dst_addr") or layer.get_field("destination")
            if dst_ip:
                self.destination_ips.add(str(dst_ip))

        tcp = packet.get_layer("TCP")
        if tcp:
            self._update_tcp_fields(tcp)

        udp = packet.get_layer("UDP")
        if udp:
            dst_port = udp.get_field("dst_port") or udp.get_field("destination_port")
            if dst_port:
                self.destination_ports.add(int(dst_port))

        proto = "ARP"
        if tcp:
            proto = "TCP"
        elif udp:
            proto = "UDP"
        elif packet.get_layer("ICMP"):
            proto = "ICMP"
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        # Trim history windows
        while self.timestamps and self.timestamps[0] < timestamp - 60:
            self.timestamps.popleft()
        while len(self.sizes) > 100:
            self.sizes.popleft()

    def _update_tcp_fields(self, tcp) -> None:
        # TCP decoder uses individual boolean fields: flags_syn, flags_ack, etc.
        flags_syn = tcp.get_field("flags_syn") or False
        flags_ack = tcp.get_field("flags_ack") or False

        if flags_syn and not flags_ack:
            self.syn_count += 1
        elif flags_syn and flags_ack:
            self.syn_ack_count += 1
        elif flags_ack:
            self.ack_count += 1

        dst_port = tcp.get_field("dst_port") or tcp.get_field("destination_port")
        if dst_port:
            self.destination_ports.add(int(dst_port))

    def packet_rate(self, window_seconds: float = 10.0) -> float:
        """Packets per second over the recent window."""
        if not self.timestamps:
            return 0.0
        now = self.timestamps[-1] if self.timestamps else time.time()
        cutoff = now - window_seconds
        recent = sum(1 for t in self.timestamps if t >= cutoff)
        elapsed = max(now - cutoff, 1e-6)
        return recent / elapsed

    def recent_mean_size(self) -> float:
        """Mean packet size over recent history."""
        if not self.sizes:
            return 0.0
        return sum(self.sizes) / len(self.sizes)

    def unique_destination_port_count(self) -> int:
        return len(self.destination_ports)

    def unique_destination_ip_count(self) -> int:
        return len(self.destination_ips)

    def duration(self) -> float:
        return max(self.last_seen - self.first_seen, 1e-6)


@dataclass
class DetectionRule:
    """A single detection rule with its thresholds and metadata."""

    name: str
    threat_type: str
    severity: str
    enabled: bool = True
    # Thresholds are evaluated by the detector; this is metadata for reporting.
    description: str = ""


class ThreatDetector:
    """Analyses packet streams for malicious trends and emits ThreatAlerts.

    Detection heuristics (rule-based, educational):
      * Port scan: many distinct destination ports from one source.
      * SYN flood: high rate of SYN packets without completing handshakes.
      * Packet flood: abnormally high packets-per-second from one source.
      * Brute force: many connection attempts to a single port (e.g. SSH/22).
      * Beaconing: regular, periodic connections to an external host.
      * Large-packet anomaly: sudden spike in average packet size (exfiltration hint).

    The detector is not a replacement for a real IDS; it is an educational model
    that demonstrates how packet trends can be analysed in real time.
    """

    def __init__(
        self,
        alert_callback: Optional[Callable[[ThreatAlert], None]] = None,
        window_seconds: float = 60.0,
        max_sources: int = 10_000,
    ) -> None:
        self.alert_callback = alert_callback
        self.window_seconds = window_seconds
        self.max_sources = max_sources

        self._profiles: Dict[str, SourceProfile] = {}
        self._lock = threading.Lock()
        self._alerts: List[ThreatAlert] = []
        self._alerted_sources: Set[str] = set()

        # Detection thresholds (tune as needed for your environment)
        self.thresholds = {
            "port_scan_unique_ports": 20,
            "syn_flood_rate": 50.0,          # SYNs per second
            "syn_to_ack_ratio": 0.8,
            "flood_pps": 100.0,              # packets per second
            "brute_force_attempts": 15,      # to same port
            "beacon_interval_variance": 0.15,
            "size_spike_factor": 3.0,
        }

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def analyse(self, packet: Packet) -> Optional[ThreatAlert]:
        """Process a single packet and return an alert if a threat is detected."""
        timestamp = packet.timestamp
        src_ip = self._extract_source_ip(packet)
        if not src_ip:
            return None

        with self._lock:
            profile = self._profiles.get(src_ip)
            if profile is None:
                if len(self._profiles) >= self.max_sources:
                    # Evict the oldest profile to keep memory bounded.
                    oldest = min(self._profiles, key=lambda ip: self._profiles[ip].last_seen)
                    self._profiles.pop(oldest, None)
                profile = SourceProfile(source_ip=src_ip)
                self._profiles[src_ip] = profile

            profile.update(packet, timestamp)

            # One alert per source IP — skip if already alerted
            if src_ip in self._alerted_sources:
                return None

            alert = self._evaluate(src_ip, profile)
            if alert:
                self._alerts.append(alert)
                self._alerted_sources.add(src_ip)
                if self.alert_callback:
                    try:
                        self.alert_callback(alert)
                    except Exception as exc:  # pragma: no cover - callback safety
                        logger.error("Alert callback raised: %s", exc)
                return alert
        return None

    def analyse_batch(self, packets: List[Packet]) -> List[ThreatAlert]:
        """Process multiple packets, returning all alerts raised."""
        alerts: List[ThreatAlert] = []
        for pkt in packets:
            alert = self.analyse(pkt)
            if alert:
                alerts.append(alert)
        return alerts

    def get_alerts(self, source_ip: Optional[str] = None) -> List[ThreatAlert]:
        """Return recorded alerts, optionally filtered by source IP."""
        with self._lock:
            if source_ip is None:
                return list(self._alerts)
            return [a for a in self._alerts if a.source_ip == source_ip]

    def is_malicious(self, source_ip: str) -> bool:
        """Return True if the source has ever triggered a malicious alert."""
        with self._lock:
            return source_ip in self._alerted_sources

    def get_profile(self, source_ip: str) -> Optional[SourceProfile]:
        with self._lock:
            return self._profiles.get(source_ip)

    def get_all_profiles(self) -> Dict[str, SourceProfile]:
        with self._lock:
            return dict(self._profiles)

    def reset(self) -> None:
        with self._lock:
            self._profiles.clear()
            self._alerts.clear()
            self._alerted_sources.clear()

    # ------------------------------------------------------------------ #
    # Internal detection logic
    # ------------------------------------------------------------------ #
    def _extract_source_ip(self, packet: Packet) -> Optional[str]:
        ip = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if not ip:
            return None
        src = ip.get_field("src_addr") or ip.get_field("source")
        return str(src) if src else None

    def _evaluate(self, source_ip: str, profile: SourceProfile) -> Optional[ThreatAlert]:
        # Port scan
        if profile.unique_destination_port_count() >= self.thresholds["port_scan_unique_ports"]:
            return ThreatAlert(
                source_ip=source_ip,
                threat_type="port_scan",
                severity="high",
                confidence=0.85,
                description=(
                    f"Source contacted {profile.unique_destination_port_count()} "
                    f"distinct destination ports (possible port scan)."
                ),
                evidence={
                    "unique_ports": profile.unique_destination_port_count(),
                    "ports": sorted(profile.destination_ports)[:50],
                    "packet_count": profile.packet_count,
                },
                is_malicious=True,
            )

        # SYN flood
        if (
            profile.syn_count >= 10
            and profile.packet_rate(window_seconds=10.0)
            >= self.thresholds["syn_flood_rate"]
        ):
            syn_ratio = profile.syn_count / max(profile.packet_count, 1)
            return ThreatAlert(
                source_ip=source_ip,
                threat_type="syn_flood",
                severity="critical",
                confidence=0.9,
                description=(
                    f"High SYN packet rate ({profile.syn_count} SYNs, "
                    f"{syn_ratio:.0%} of traffic) — possible SYN flood."
                ),
                evidence={
                    "syn_count": profile.syn_count,
                    "packet_count": profile.packet_count,
                    "syn_ratio": syn_ratio,
                    "pps": profile.packet_rate(window_seconds=10.0),
                },
                is_malicious=True,
            )

        # Packet flood
        pps = profile.packet_rate(window_seconds=10.0)
        if pps >= self.thresholds["flood_pps"]:
            return ThreatAlert(
                source_ip=source_ip,
                threat_type="flood",
                severity="high",
                confidence=0.8,
                description=(
                    f"High packet rate from source: {pps:.1f} packets/sec "
                    f"(threshold {self.thresholds['flood_pps']})."
                ),
                evidence={
                    "pps": pps,
                    "packet_count": profile.packet_count,
                    "byte_count": profile.byte_count,
                },
                is_malicious=True,
            )

        # Brute force: many attempts to the same destination port
        for port in profile.destination_ports:
            # Approximate via SYN count to that port if we tracked per-port;
            # fall back to total SYN count against common service ports.
            if port in {22, 23, 3389, 445, 1433, 3306} and profile.syn_count >= self.thresholds["brute_force_attempts"]:
                return ThreatAlert(
                    source_ip=source_ip,
                    threat_type="brute_force",
                    severity="high",
                    confidence=0.75,
                    description=(
                        f"Repeated connection attempts to service port {port} "
                        f"({profile.syn_count} SYNs) — possible brute force."
                    ),
                    evidence={
                        "target_port": port,
                        "syn_count": profile.syn_count,
                    },
                    is_malicious=True,
                )

        # Beaconing: regular periodic connections
        beacon = self._detect_beaconing(profile)
        if beacon:
            return beacon

        # Large-packet anomaly (possible exfiltration)
        size_alert = self._detect_size_anomaly(profile)
        if size_alert:
            return size_alert

        return None

    def _detect_beaconing(self, profile: SourceProfile) -> Optional[ThreatAlert]:
        if len(profile.timestamps) < 10:
            return None

        timestamps = list(profile.timestamps)
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        intervals = [i for i in intervals if i > 0]
        if not intervals:
            return None

        mean_interval = sum(intervals) / len(intervals)
        variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / mean_interval if mean_interval else float("inf")

        # Low coefficient of variation = very regular timing = beaconing
        if cv < self.thresholds["beacon_interval_variance"] and mean_interval < 300:
            return ThreatAlert(
                source_ip=profile.source_ip,
                threat_type="beaconing",
                severity="medium",
                confidence=0.7,
                description=(
                    f"Regular, periodic connections every {mean_interval:.1f}s "
                    f"(possible C2 beaconing)."
                ),
                evidence={
                    "mean_interval": mean_interval,
                    "coefficient_of_variation": cv,
                    "connection_count": len(timestamps),
                    "destination_ips": sorted(profile.destination_ips)[:10],
                },
                is_malicious=True,
            )
        return None

    def _detect_size_anomaly(self, profile: SourceProfile) -> Optional[ThreatAlert]:
        if len(profile.sizes) < 20:
            return None

        sizes = list(profile.sizes)
        baseline = sum(sizes[: len(sizes) // 2]) / max(len(sizes) // 2, 1)
        recent = sum(sizes[len(sizes) // 2:]) / max(len(sizes) - len(sizes) // 2, 1)

        if baseline > 0 and recent >= baseline * self.thresholds["size_spike_factor"]:
            return ThreatAlert(
                source_ip=profile.source_ip,
                threat_type="large_packet_anomaly",
                severity="medium",
                confidence=0.65,
                description=(
                    f"Average packet size spiked from {baseline:.0f} to {recent:.0f} bytes "
                    f"(possible data exfiltration)."
                ),
                evidence={
                    "baseline_mean_size": baseline,
                    "recent_mean_size": recent,
                    "spike_factor": recent / baseline if baseline else 0.0,
                },
                is_malicious=True,
            )
        return None
