"""Query engine: applies structured filters to captured packets, flows, and alerts."""

from __future__ import annotations

from typing import List, Optional, Dict, Any, Callable, Tuple

from wiretap.models.packet import Packet
from wiretap.models.flow import Flow
from wiretap.models.threat_alert import ThreatAlert
from wiretap.query.filters import PacketFilter, FlowFilter, ParsedQuery
from wiretap.analysis import ConnectionDiagnosticEngine, TimePatternDetector


class QueryEngine:
    """Applies ParsedQuery filters to captured data.

    The engine works on in-memory collections of packets, flows, and alerts.
    It is designed to be called from the GUI after a query is parsed.
    """

    def __init__(
        self,
        packets: Optional[List[Packet]] = None,
        flows: Optional[Dict[str, Flow]] = None,
        alerts: Optional[List[ThreatAlert]] = None,
    ) -> None:
        self.packets: List[Packet] = packets or []
        self.flows: Dict[str, Flow] = flows or {}
        self.alerts: List[ThreatAlert] = alerts or []

        # DNS context built lazily: maps transaction_id -> True if answered
        self._dns_context: Optional[Dict[str, Any]] = None
        # Time pattern detector for unusual time detection
        self.time_detector: Optional[TimePatternDetector] = None
        # Connection diagnostic engine for health queries
        self.connection_diagnostic: Optional[ConnectionDiagnosticEngine] = None

    # ------------------------------------------------------------------ #
    # Data setters
    # ------------------------------------------------------------------ #
    def set_packets(self, packets: List[Packet]) -> None:
        self.packets = list(packets)
        self._dns_context = None  # invalidate

    def set_flows(self, flows: Dict[str, Flow]) -> None:
        self.flows = dict(flows)

    def set_alerts(self, alerts: List[ThreatAlert]) -> None:
        self.alerts = list(alerts)

    def set_time_detector(self, detector: TimePatternDetector) -> None:
        self.time_detector = detector

    def set_connection_diagnostic(self, diagnostic: ConnectionDiagnosticEngine) -> None:
        self.connection_diagnostic = diagnostic

    def set_capture_data(self, packets: List[Packet], flows: Dict[str, Flow]) -> None:
        self.set_packets(packets)
        self.set_flows(flows)

    # ------------------------------------------------------------------ #
    # DNS context
    # ------------------------------------------------------------------ #
    def _build_dns_context(self) -> Dict[str, Any]:
        """Build DNS query/response context from captured packets.

        Returns a dict with 'answered_tx_ids' set of transaction IDs
        that have a matching response packet.
        """
        if self._dns_context is not None:
            return self._dns_context

        answered_tx_ids = set()
        dns_packets = [p for p in self.packets if p.get_layer("DNS")]

        for p in dns_packets:
            dns_layer = p.get_layer("DNS")
            if not dns_layer:
                continue
            qr = dns_layer.get_field("query_response")
            tx_id = dns_layer.get_field("transaction_id")
            if qr == "Response" and tx_id is not None:
                answered_tx_ids.add(tx_id)

        self._dns_context = {"answered_tx_ids": answered_tx_ids}
        return self._dns_context

    # ------------------------------------------------------------------ #
    # Execution
    # ------------------------------------------------------------------ #
    def execute(self, parsed: ParsedQuery) -> dict:
        """Execute a ParsedQuery and return results.

        Returns a dict with keys:
            'packets': List[Packet] matching the packet filter
            'flows': List[Flow] matching the flow filter
            'alerts': List[ThreatAlert] matching (if alert filter present)
            'parsed': the ParsedQuery (for display)
            'packet_count': int
            'flow_count': int
        """
        dns_context = self._build_dns_context()

        # Build time context from the detector if available
        time_context = {"anomalous_hours": {}, "trained": {}}
        if self.time_detector is not None:
            for pkt in self.packets:
                src_ip = self._extract_source_ip(pkt)
                if src_ip:
                    profile = self.time_detector.get_source_profile(src_ip)
                    time_context["anomalous_hours"][src_ip] = set(
                        profile.get("anomalous_hours", [])
                    )
                    time_context["trained"][src_ip] = profile.get("trained", False)

        # Build health context from the connection diagnostic engine if available
        health_context: Dict[Tuple[str, str, int, int], Any] = {}
        if self.connection_diagnostic is not None:
            for report in self.connection_diagnostic.get_all_reports():
                health_context[(report.src_ip, report.dst_ip, report.src_port, report.dst_port)] = report

        matching_packets: List[Packet] = []
        if parsed.packet_filter:
            pf = parsed.packet_filter
            for pkt in self.packets:
                src_ip = self._extract_source_ip(pkt)
                if pf.matches(pkt, flow_context=self.flows, dns_context=dns_context,
                              time_context=time_context, trained=time_context["trained"].get(
                                  src_ip or "", False),
                              health_context=health_context):
                    matching_packets.append(pkt)
        else:
            matching_packets = list(self.packets)

        matching_flows: List[Flow] = []
        if parsed.flow_filter:
            ff = parsed.flow_filter
            for flow in self.flows.values():
                if ff.matches(flow):
                    matching_flows.append(flow)
        else:
            matching_flows = list(self.flows.values())

        # Alerts: if the query mentions threats or malicious sources, filter alerts
        matching_alerts: List[ThreatAlert] = []
        q_lower = parsed.raw_query.lower()
        if any(word in q_lower for word in ("threat", "malicious", "alert", "suspicious")):
            for alert in self.alerts:
                if parsed.packet_filter and parsed.packet_filter.src_ip:
                    if alert.source_ip == parsed.packet_filter.src_ip:
                        matching_alerts.append(alert)
                elif parsed.flow_filter and parsed.flow_filter.involves_ip:
                    if alert.source_ip == parsed.flow_filter.involves_ip:
                        matching_alerts.append(alert)
                else:
                    matching_alerts.append(alert)

        return {
            "parsed": parsed,
            "packets": matching_packets,
            "flows": matching_flows,
            "alerts": matching_alerts,
            "packet_count": len(matching_packets),
            "flow_count": len(matching_flows),
            "alert_count": len(matching_alerts),
            "health_reports": list(health_context.values()),
            "health_report_count": len(health_context),
        }

    @staticmethod
    def _extract_source_ip(packet: Packet) -> Optional[str]:
        ip = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if not ip:
            return None
        src = ip.get_field("src_addr") or ip.get_field("source")
        return str(src) if src else None

    # ------------------------------------------------------------------ #
    # Helper: describe a filter in plain English
    # ------------------------------------------------------------------ #
    @staticmethod
    def describe_filter(parsed: ParsedQuery) -> str:
        """Return a human-readable description of what the query does."""
        parts = [parsed.description]
        if parsed.packet_filter:
            pf = parsed.packet_filter
            details = []
            if pf.protocol:
                details.append(f"protocol: {pf.protocol}")
            if pf.src_ip:
                details.append(f"source IP: {pf.src_ip}")
            if pf.dst_ip:
                details.append(f"destination IP: {pf.dst_ip}")
            if pf.src_port is not None:
                details.append(f"source port: {pf.src_port}")
            if pf.dst_port is not None:
                details.append(f"destination port: {pf.dst_port}")
            if pf.min_rtt_ms is not None:
                details.append(f"RTT > {pf.min_rtt_ms} ms")
            if pf.max_rtt_ms is not None:
                details.append(f"RTT < {pf.max_rtt_ms} ms")
            if pf.has_retransmission:
                details.append("TCP retransmissions")
            if pf.dns_unanswered:
                details.append("DNS queries with no response")
            if pf.min_bytes is not None:
                details.append(f"size > {pf.min_bytes} bytes")
            if details:
                parts.append("Filter: " + "; ".join(details))
        if parsed.flow_filter:
            ff = parsed.flow_filter
            details = []
            if ff.involves_ip:
                details.append(f"involves IP: {ff.involves_ip}")
            if ff.src_ip:
                details.append(f"source IP: {ff.src_ip}")
            if ff.dst_ip:
                details.append(f"destination IP: {ff.dst_ip}")
            if ff.protocol:
                details.append(f"protocol: {ff.protocol}")
            if ff.min_packets is not None:
                details.append(f"min packets: {ff.min_packets}")
            if ff.min_bytes is not None:
                details.append(f"min bytes: {ff.min_bytes}")
            if details:
                parts.append("Flow filter: " + "; ".join(details))
        return " | ".join(parts)
