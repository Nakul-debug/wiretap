"""Natural language query parser for wiretap.

Translates plain-English questions into structured PacketFilter / FlowFilter
objects using keyword and pattern matching. No external NLP dependencies
are required — this keeps the dependency footprint small and the behavior
transparent and easy to extend.

Supported query patterns (examples):
    * "Show connections that took more than 500 milliseconds."
    * "Find DNS requests that received no response."
    * "Show TCP retransmissions involving 192.168.1.50."
    * "Find devices that communicated with 10.0.0.1."
    * "Show HTTP traffic from 192.168.1.10."
    * "Find large packets over 1500 bytes."
    * "Show UDP packets to port 53."
    * "Show connections at unusual times from 10.0.0.5."
    * "Find abnormal time activity from 192.168.1.10."
"""

from __future__ import annotations

import re
from typing import Optional

from backend.query.filters import PacketFilter, FlowFilter, ParsedQuery


class QueryParser:
    """Parses natural language queries into structured filters."""

    def __init__(self) -> None:
        # Protocols recognised by wiretap decoders
        self._protocols = {
            "dns": "DNS", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP",
            "arp": "ARP", "ipv4": "IPv4", "ipv6": "IPv6", "http": "HTTP",
            "ethernet": "Ethernet",
        }

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def parse(self, query: str) -> ParsedQuery:
        """Parse a natural language query into a ParsedQuery.

        Returns a ParsedQuery with packet_filter and/or flow_filter populated.
        If the query is not recognised, returns a ParsedQuery with empty filters
        and suggestions for the user.
        """
        q = query.strip()
        if not q:
            return ParsedQuery(
                raw_query=query,
                description="Empty query.",
                confidence=0.0,
                suggestions=["Try: 'Show DNS requests with no response'",
                             "Try: 'Show TCP retransmissions involving 10.0.0.1'"],
            )

        q_lower = q.lower()

        # Try each pattern in order of specificity
        result = self._try_patterns(q, q_lower)
        if result is not None:
            return result

        # Fallback: keyword-based heuristic extraction
        return self._heuristic_parse(q, q_lower)

    # ------------------------------------------------------------------ #
    # Pattern matchers
    # ------------------------------------------------------------------ #
    def _try_patterns(self, query: str, q_lower: str) -> Optional[ParsedQuery]:
        # 1. "Show connections that took more than X milliseconds" / "less than X ms"
        m = re.search(
            r"connections?\s+that\s+took\s+(more\s+than|over|greater\s+than|>)\s+(\d+(?:\.\d+)?)\s*(milliseconds?|ms)",
            q_lower,
        )
        if m:
            ms = float(m.group(2))
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(min_rtt_ms=ms),
                description=f"Connections with RTT greater than {ms} ms",
                confidence=0.95,
            )

        m = re.search(
            r"connections?\s+that\s+took\s+(less\s+than|under|below|<)\s+(\d+(?:\.\d+)?)\s*(milliseconds?|ms)",
            q_lower,
        )
        if m:
            ms = float(m.group(2))
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(max_rtt_ms=ms),
                description=f"Connections with RTT less than {ms} ms",
                confidence=0.95,
            )

        # 2. "Find DNS requests that received no response" / "unanswered DNS"
        if re.search(r"dns.*(no\s+response|unanswered|without\s+response)", q_lower) or \
           re.search(r"(no\s+response|unanswered).*dns", q_lower):
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(protocol="DNS", dns_unanswered=True),
                description="DNS queries with no matching response",
                confidence=0.95,
            )

        # 3. "Show TCP retransmissions involving <IP>"
        m = re.search(
            r"(tcp\s+)?retransmission[s]?\s+(involving|with|for)\s+(\d{1,3}(?:\.\d{1,3}){3})",
            q_lower,
        )
        if m:
            ip = m.group(3)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(
                    protocol="TCP", src_ip=ip, dst_ip=ip, has_retransmission=True
                ),
                description=f"TCP retransmissions involving {ip}",
                confidence=0.9,
            )

        # 4. "Find devices that communicated with <IP>" / "talked to <IP>"
        m = re.search(
            r"(devices|hosts|machines)\s+(that\s+)?(communicated|talked|spoke)\s+(with|to)\s+(\d{1,3}(?:\.\d{1,3}){3})",
            q_lower,
        )
        if m:
            ip = m.group(5)
            return ParsedQuery(
                raw_query=query,
                flow_filter=FlowFilter(involves_ip=ip),
                description=f"Flows involving {ip}",
                confidence=0.9,
            )

        # 5. "Show <protocol> traffic from <IP>"
        m = re.search(
            r"show\s+(\w+)\s+traffic\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})", q_lower
        )
        if m:
            proto = self._protocols.get(m.group(1), m.group(1).upper())
            ip = m.group(2)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(protocol=proto, src_ip=ip),
                description=f"{proto} traffic from {ip}",
                confidence=0.85,
            )

        # 6. "Show <protocol> traffic to <IP>"
        m = re.search(
            r"show\s+(\w+)\s+traffic\s+to\s+(\d{1,3}(?:\.\d{1,3}){3})", q_lower
        )
        if m:
            proto = self._protocols.get(m.group(1), m.group(1).upper())
            ip = m.group(2)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(protocol=proto, dst_ip=ip),
                description=f"{proto} traffic to {ip}",
                confidence=0.85,
            )

        # 7. "Find large packets over X bytes" / "packets larger than X bytes"
        m = re.search(
            r"(large\s+packets?|packets?)\s+(over|larger\s+than|>)\s+(\d+(?:\.\d+)?)\s*bytes?",
            q_lower,
        )
        if m:
            n = float(m.group(3))
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(min_bytes=int(n)),
                description=f"Packets larger than {int(n)} bytes",
                confidence=0.8,
            )

        # 8. "Show UDP/TCP packets to port X"
        m = re.search(
            r"(tcp|udp)\s+packets?\s+to\s+port\s+(\d+)", q_lower
        )
        if m:
            proto = m.group(1).upper()
            port = int(m.group(2))
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(protocol=proto, dst_port=port),
                description=f"{proto} packets to port {port}",
                confidence=0.9,
            )

        # 8b. "Show connections at unusual times from <IP>"
        #     "Find abnormal time activity from <IP>"
        #     "Show traffic outside normal hours for <IP>"
        m = re.search(
            r"(unusual\s+time|abnormal\s+time|outside\s+normal\s+hours).*(from|for)\s+(\d{1,3}(?:\.\d{1,3}){3})",
            q_lower,
        )
        if m:
            ip = m.group(3)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(src_ip=ip, unusual_time=True),
                description=f"Connections at unusual times from {ip}",
                confidence=0.9,
            )

        # 8c. "Show unhealthy connections from <IP>"
        #     "Show connections with health score below <N>"
        #     "Show connections with failed handshake from <IP>"
        #     "Show connections with resets from <IP>"
        #     "Show connections with zero window from <IP>"
        m = re.search(
            r"(unhealthy|poor|critical|bad)\s+(connections|tcp\s+connections)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})",
            q_lower,
        )
        if m:
            ip = m.group(3)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(src_ip=ip, unhealthy_only=True),
                description=f"Unhealthy connections from {ip}",
                confidence=0.9,
            )

        m = re.search(
            r"health\s+score\s+(below|under|less\s+than|<)\s+(\d+(?:\.\d+)?)",
            q_lower,
        )
        if m:
            score = float(m.group(2))
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(max_health_score=score),
                description=f"Connections with health score below {score}",
                confidence=0.9,
            )

        m = re.search(
            r"(failed\s+handshake|handshake\s+failure).*(from|for)\s+(\d{1,3}(?:\.\d{1,3}){3})",
            q_lower,
        )
        if m:
            ip = m.group(3)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(src_ip=ip, handshake_failed=True),
                description=f"Connections with failed handshake from {ip}",
                confidence=0.9,
            )

        m = re.search(
            r"(connections?\s+with\s+|tcp\s+connections?\s+with\s+)(resets?|rst).*(from|for)\s+(\d{1,3}(?:\.\d{1,3}){3})",
            q_lower,
        )
        if m:
            ip = m.group(4)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(src_ip=ip, has_rst=True),
                description=f"Connections with resets from {ip}",
                confidence=0.9,
            )

        m = re.search(
            r"(connections?\s+with\s+|tcp\s+connections?\s+with\s+)(zero.window|window.full).*(from|for)\s+(\d{1,3}(?:\.\d{1,3}){3})",
            q_lower,
        )
        if m:
            ip = m.group(4)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(src_ip=ip, has_zero_window=True),
                description=f"Connections with zero-window from {ip}",
                confidence=0.9,
            )

        # 9. "Find DNS requests for <domain>"
        m = re.search(r"dns\s+requests?\s+for\s+([\w.\-]+)", q_lower)
        if m:
            domain = m.group(1)
            return ParsedQuery(
                raw_query=query,
                packet_filter=PacketFilter(protocol="DNS"),
                description=f"DNS requests for {domain}",
                confidence=0.8,
                suggestions=[
                    f"Note: domain '{domain}' filtering requires DNS question parsing; "
                    f"currently showing all DNS queries.",
                ],
            )

        return None

    # ------------------------------------------------------------------ #
    # Heuristic fallback
    # ------------------------------------------------------------------ #
    def _heuristic_parse(self, query: str, q_lower: str) -> ParsedQuery:
        """Best-effort keyword extraction when no pattern matches."""
        pkt_filter = PacketFilter()
        flow_filter = FlowFilter()
        matched_anything = False
        description_parts: list[str] = []

        # Extract IP addresses
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query)
        if ips:
            # Use first IP as involves_ip for flow filter
            flow_filter.involves_ip = ips[0]
            matched_anything = True
            description_parts.append(f"involving {ips[0]}")

        # Extract protocol mentions
        for key, val in self._protocols.items():
            if key in q_lower:
                pkt_filter.protocol = val
                matched_anything = True
                description_parts.append(val)
                break

        # Extract port numbers
        ports = re.findall(r"port\s+(\d+)", q_lower)
        if ports:
            pkt_filter.dst_port = int(ports[0])
            matched_anything = True
            description_parts.append(f"port {ports[0]}")

        # Extract byte thresholds
        bytes_m = re.search(r"(\d+(?:\.\d+)?)\s*bytes?", q_lower)
        if bytes_m:
            pkt_filter.min_bytes = int(float(bytes_m.group(1)))
            matched_anything = True
            description_parts.append(f"larger than {bytes_m.group(1)} bytes")

        if not matched_anything:
            return ParsedQuery(
                raw_query=query,
                description="I couldn't understand that query.",
                confidence=0.0,
                suggestions=[
                    "Try: 'Show DNS requests with no response'",
                    "Try: 'Show TCP retransmissions involving 10.0.0.1'",
                    "Try: 'Find devices that communicated with 192.168.1.1'",
                    "Try: 'Show connections that took more than 500 milliseconds'",
                    "Try: 'Show HTTP traffic from 10.0.0.5'",
                ],
            )

        description = "Matches: " + ", ".join(description_parts)
        return ParsedQuery(
            raw_query=query,
            packet_filter=pkt_filter,
            flow_filter=flow_filter,
            description=description,
            confidence=0.6,
            suggestions=[
                "For more precise results, try phrasing like:",
                "'Show DNS requests that received no response'",
                "'Show TCP retransmissions involving 10.0.0.1'",
            ],
        )
