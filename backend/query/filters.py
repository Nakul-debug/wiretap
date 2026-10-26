"""Structured filter representations for parsed natural language queries."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any


@dataclass
class PacketFilter:
    """Filter that can be applied to individual captured packets."""

    protocol: Optional[str] = None          # e.g. "DNS", "TCP", "UDP", "ICMP", "ARP"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    min_rtt_ms: Optional[float] = None      # RTT > threshold (ms)
    max_rtt_ms: Optional[float] = None      # RTT < threshold (ms)
    has_retransmission: Optional[bool] = None
    dns_unanswered: Optional[bool] = None   # DNS query with no matching response
    min_bytes: Optional[int] = None
    max_bytes: Optional[int] = None
    unusual_time: Optional[bool] = None   # Packet at unusual time for its source IP
    min_health_score: Optional[float] = None   # Minimum connection health score
    max_health_score: Optional[float] = None   # Maximum connection health score
    unhealthy_only: Optional[bool] = None    # Only unhealthy connections (score < 70)
    handshake_failed: Optional[bool] = None  # Filter by failed handshake
    has_rst: Optional[bool] = None           # Filter by connection resets
    has_zero_window: Optional[bool] = None   # Filter by zero-window events

    def matches(self, packet, flow_context=None, dns_context=None, time_context=None, trained=False, health_context=None) -> bool:
        """Return True if the packet matches this filter.

        Args:
            packet: wiretap.models.packet.Packet
            flow_context: optional dict mapping flow_key -> Flow (for RTT/retransmission)
            dns_context: optional DNS context (query/response matching)
            time_context: optional dict mapping source_ip -> set of normal hours
            trained: whether the time baseline has been trained
            health_context: optional dict mapping flow_key -> ConnectionHealthReport
        """
        from backend.models.packet import Packet

        if not isinstance(packet, Packet):
            return False

        # Protocol filter
        if self.protocol:
            layer = packet.get_layer(self.protocol)
            if layer is None:
                # Also check case-insensitively / common aliases
                proto_map = {"dns": "DNS", "tcp": "TCP", "udp": "UDP",
                             "icmp": "ICMP", "arp": "ARP", "ipv4": "IPv4",
                             "ipv6": "IPv6", "http": "HTTP", "ethernet": "Ethernet"}
                layer = packet.get_layer(proto_map.get(self.protocol.lower(), self.protocol))
            if layer is None:
                return False

        # IP filters
        ip_layer = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if ip_layer:
            if self.src_ip and self.dst_ip and self.src_ip == self.dst_ip:
                # "Involving X" query: match if either source or destination is X
                src = ip_layer.get_field("src_addr")
                dst = ip_layer.get_field("dst_addr")
                if str(src) != self.src_ip and str(dst) != self.src_ip:
                    return False
            else:
                if self.src_ip:
                    src = ip_layer.get_field("src_addr")
                    if src and str(src) != self.src_ip:
                        return False
                if self.dst_ip:
                    dst = ip_layer.get_field("dst_addr")
                    if dst and str(dst) != self.dst_ip:
                        return False

        # Port filters (TCP/UDP)
        tcp = packet.get_layer("TCP")
        udp = packet.get_layer("UDP")
        transport = tcp or udp
        if transport and (self.src_port is not None or self.dst_port is not None):
            sport = transport.get_field("src_port")
            dport = transport.get_field("dst_port")
            if self.src_port is not None and sport != self.src_port:
                return False
            if self.dst_port is not None and dport != self.dst_port:
                return False

        # RTT filter (needs flow context)
        if self.min_rtt_ms is not None or self.max_rtt_ms is not None:
            if flow_context is None:
                return False
            rtt = self._get_rtt(packet, flow_context)
            if rtt is None:
                return False
            rtt_ms = rtt * 1000.0
            if self.min_rtt_ms is not None and rtt_ms < self.min_rtt_ms:
                return False
            if self.max_rtt_ms is not None and rtt_ms > self.max_rtt_ms:
                return False

        # Retransmission filter (needs flow context)
        if self.has_retransmission is not None:
            if flow_context is None:
                return False
            is_retrans = self._is_retransmission(packet, flow_context)
            if is_retrans != self.has_retransmission:
                return False

        # DNS unanswered filter (needs DNS context)
        if self.dns_unanswered is not None:
            if dns_context is None:
                return False
            dns_layer = packet.get_layer("DNS")
            if not dns_layer:
                return False
            is_query = dns_layer.get_field("query_response") == "Query"
            if not is_query:
                return False
            tx_id = dns_layer.get_field("transaction_id")
            answered = tx_id in dns_context.get("answered_tx_ids", set())
            if self.dns_unanswered and answered:
                return False
            if not self.dns_unanswered and not answered:
                return False

        # Unusual time filter (needs time context)
        if self.unusual_time is not None:
            if time_context is None:
                return False
            ip_layer = packet.get_layer("IPv4") or packet.get_layer("IPv6")
            if not ip_layer:
                return False
            src_ip = ip_layer.get_field("src_addr")
            if not src_ip:
                return False
            src_ip = str(src_ip)
            # Check if this packet's hour was flagged as unusual for this source
            anomalous_hours = time_context.get("anomalous_hours", {}).get(src_ip, set())
            timestamp = packet.timestamp
            hour = datetime.fromtimestamp(timestamp).hour
            is_unusual = hour in anomalous_hours
            if self.unusual_time and not is_unusual:
                return False
            if not self.unusual_time and is_unusual:
                return False

        # Connection health filter (needs health context)
        if self.min_health_score is not None or self.max_health_score is not None or \
           self.unhealthy_only is not None or self.handshake_failed is not None or \
           self.has_rst is not None or self.has_zero_window is not None:
            if health_context is None:
                return False
            ip_layer = packet.get_layer("IPv4") or packet.get_layer("IPv6")
            if not ip_layer:
                return False
            src_ip = str(ip_layer.get_field("src_addr") or "")
            dst_ip = str(ip_layer.get_field("dst_addr") or "")
            tcp = packet.get_layer("TCP")
            src_port = tcp.get_field("src_port") if tcp else None
            dst_port = tcp.get_field("dst_port") if tcp else None
            if not src_ip or not dst_ip or src_port is None or dst_port is None:
                return False
            flow_key = (src_ip, dst_ip, int(src_port), int(dst_port))
            report = health_context.get(flow_key)
            if report is None:
                # Try reverse direction
                flow_key_rev = (dst_ip, src_ip, int(dst_port), int(src_port))
                report = health_context.get(flow_key_rev)
            if report is None:
                return False

            if self.min_health_score is not None and report.health_score < self.min_health_score:
                return False
            if self.max_health_score is not None and report.health_score > self.max_health_score:
                return False
            if self.unhealthy_only and report.health_score >= 70.0:
                return False
            if self.handshake_failed is not None and report.handshake.failed != self.handshake_failed:
                return False
            if self.has_rst is not None and (report.rst_count > 0) != self.has_rst:
                return False
            if self.has_zero_window is not None and (report.zero_window_count > 0) != self.has_zero_window:
                return False

        # Byte filters
        if self.min_bytes is not None or self.max_bytes is not None:
            pkt_len = len(packet.raw_bytes) if packet.raw_bytes else 0
            if self.min_bytes is not None and pkt_len < self.min_bytes:
                return False
            if self.max_bytes is not None and pkt_len > self.max_bytes:
                return False

        return True

    @staticmethod
    def _get_rtt(packet, flow_context) -> Optional[float]:
        """Best-effort RTT extraction from flow context."""
        # RTT is stored per-flow; look up by source/destination IP pair
        ip_layer = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if not ip_layer:
            return None
        src = ip_layer.get_field("src_addr")
        dst = ip_layer.get_field("dst_addr")
        if not src or not dst:
            return None
        for flow in flow_context.values():
            if (flow.src_ip == str(src) and flow.dst_ip == str(dst)) or \
               (flow.src_ip == str(dst) and flow.dst_ip == str(src)):
                # Return a smoothed RTT estimate if available
                return getattr(flow, "smoothed_rtt", None) or getattr(flow, "rtt", None)
        return None

    @staticmethod
    def _is_retransmission(packet, flow_context) -> bool:
        """Best-effort retransmission detection from flow context."""
        tcp = packet.get_layer("TCP")
        if not tcp:
            return False
        # Check if TCP layer has a retransmission flag set by analysis
        return bool(tcp.get_field("retransmission") or False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "min_rtt_ms": self.min_rtt_ms,
            "max_rtt_ms": self.max_rtt_ms,
            "has_retransmission": self.has_retransmission,
            "dns_unanswered": self.dns_unanswered,
            "min_bytes": self.min_bytes,
            "max_bytes": self.max_bytes,
            "unusual_time": self.unusual_time,
            "min_health_score": self.min_health_score,
            "max_health_score": self.max_health_score,
            "unhealthy_only": self.unhealthy_only,
            "handshake_failed": self.handshake_failed,
            "has_rst": self.has_rst,
            "has_zero_window": self.has_zero_window,
        }

    def __str__(self) -> str:
        parts = []
        if self.protocol:
            parts.append(f"protocol={self.protocol}")
        if self.src_ip:
            parts.append(f"src_ip={self.src_ip}")
        if self.dst_ip:
            parts.append(f"dst_ip={self.dst_ip}")
        if self.src_port is not None:
            parts.append(f"src_port={self.src_port}")
        if self.dst_port is not None:
            parts.append(f"dst_port={self.dst_port}")
        if self.min_rtt_ms is not None:
            parts.append(f"min_rtt_ms={self.min_rtt_ms}")
        if self.max_rtt_ms is not None:
            parts.append(f"max_rtt_ms={self.max_rtt_ms}")
        if self.has_retransmission is not None:
            parts.append(f"retransmission={self.has_retransmission}")
        if self.dns_unanswered is not None:
            parts.append(f"dns_unanswered={self.dns_unanswered}")
        if self.min_bytes is not None:
            parts.append(f"min_bytes={self.min_bytes}")
        if self.max_bytes is not None:
            parts.append(f"max_bytes={self.max_bytes}")
        if self.unusual_time is not None:
            parts.append(f"unusual_time={self.unusual_time}")
        if self.min_health_score is not None:
            parts.append(f"min_health_score={self.min_health_score}")
        if self.max_health_score is not None:
            parts.append(f"max_health_score={self.max_health_score}")
        if self.unhealthy_only is not None:
            parts.append(f"unhealthy_only={self.unhealthy_only}")
        if self.handshake_failed is not None:
            parts.append(f"handshake_failed={self.handshake_failed}")
        if self.has_rst is not None:
            parts.append(f"has_rst={self.has_rst}")
        if self.has_zero_window is not None:
            parts.append(f"has_zero_window={self.has_zero_window}")
        return "PacketFilter(" + ", ".join(parts) + ")"


@dataclass
class FlowFilter:
    """Filter that can be applied to network flows."""

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    min_packets: Optional[int] = None
    min_bytes: Optional[int] = None
    min_duration_sec: Optional[float] = None
    involves_ip: Optional[str] = None  # flow involves this IP (either direction)

    def matches(self, flow) -> bool:
        from backend.models.flow import Flow
        if not isinstance(flow, Flow):
            return False

        if self.src_ip and flow.src_ip != self.src_ip:
            return False
        if self.dst_ip and flow.dst_ip != self.dst_ip:
            return False
        if self.involves_ip:
            if flow.src_ip != self.involves_ip and flow.dst_ip != self.involves_ip:
                return False
        if self.protocol and flow.protocol != self.protocol:
            return False
        if self.min_packets is not None and flow.packet_count < self.min_packets:
            return False
        if self.min_bytes is not None and flow.byte_count < self.min_bytes:
            return False
        if self.min_duration_sec is not None:
            duration = flow.last_seen - flow.first_seen
            if duration < self.min_duration_sec:
                return False
        return True


@dataclass
class ParsedQuery:
    """Result of parsing a natural language query."""

    raw_query: str
    packet_filter: Optional[PacketFilter] = None
    flow_filter: Optional[FlowFilter] = None
    description: str = ""
    confidence: float = 1.0
    suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_query": self.raw_query,
            "packet_filter": self.packet_filter.to_dict() if self.packet_filter else None,
            "flow_filter": {
                "src_ip": self.flow_filter.src_ip,
                "dst_ip": self.flow_filter.dst_ip,
                "protocol": self.flow_filter.protocol,
                "min_packets": self.flow_filter.min_packets,
                "min_bytes": self.flow_filter.min_bytes,
                "min_duration_sec": self.flow_filter.min_duration_sec,
                "involves_ip": self.flow_filter.involves_ip,
            } if self.flow_filter else None,
            "description": self.description,
            "confidence": self.confidence,
        }
