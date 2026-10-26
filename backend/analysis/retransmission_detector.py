"""TCP retransmission detector.

Detects likely retransmissions by tracking TCP sequence numbers per flow.
A segment is flagged as a retransmission if its sequence number (and length)
overlaps with previously seen data in the same direction, or if duplicate
ACKs indicate a fast-retransmit scenario.

Detection heuristics:
1. Duplicate sequence number: same seq number seen twice in same direction.
2. Overlapping sequence range: new segment's seq range overlaps a previous
   segment's range but isn't identical.
3. Duplicate ACKs: 3+ duplicate ACKs for the same sequence number suggest
   fast retransmission.

Classifications:
- "retransmission": exact duplicate sequence + payload
- "possible_retransmission": overlapping but not identical range
- "out_of_order": segment arrives outside expected sequence order
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from backend.models.packet import Packet

logger = logging.getLogger(__name__)


@dataclass
class RetransmissionEvent:
    """A detected retransmission or related anomaly."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq_number: int
    ack_number: Optional[int]
    classification: str  # 'retransmission', 'possible_retransmission', 'out_of_order', 'duplicate_ack'
    timestamp: float = field(default_factory=time.time)
    description: str = ""


class RetransmissionDetector:
    """Detects TCP retransmissions by tracking sequence numbers per flow."""

    def __init__(self, dup_ack_threshold: int = 3, max_history: int = 5000):
        """
        Args:
            dup_ack_threshold: Number of duplicate ACKs before flagging
                               fast retransmission.
            max_history: Maximum sequence entries to keep per flow.
        """
        self.dup_ack_threshold = dup_ack_threshold
        self.max_history = max_history

        # Per-flow state: key = (src_ip, dst_ip, src_port, dst_port)
        # Value: dict with seen sequence ranges and ACK history
        self._flow_state: Dict[Tuple[str, str, int, int], dict] = {}

        # All detected events
        self._events: Deque[RetransmissionEvent] = deque(maxlen=10_000)

        # Per-flow counts
        self._retransmission_counts: Dict[Tuple[str, str, int, int], int] = defaultdict(int)
        self._out_of_order_counts: Dict[Tuple[str, str, int, int], int] = defaultdict(int)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def analyse(self, packet: Packet) -> Optional[RetransmissionEvent]:
        """Process a single TCP packet.

        Returns a RetransmissionEvent if an anomaly is detected,
        otherwise None.
        """
        tcp = packet.get_layer("TCP")
        ip = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if not tcp or not ip:
            return None

        src_ip = ip.get_field("src_addr")
        dst_ip = ip.get_field("dst_addr")
        src_port = tcp.get_field("src_port")
        dst_port = tcp.get_field("dst_port")
        seq = tcp.get_field("seq_num")
        ack = tcp.get_field("ack_num")
        flags_syn = bool(tcp.get_field("flags_syn") or False)
        flags_ack = bool(tcp.get_field("flags_ack") or False)

        if src_ip is None or dst_ip is None or src_port is None or dst_port is None:
            return None

        flow_key = (str(src_ip), str(dst_ip), int(src_port), int(dst_port))
        timestamp = packet.timestamp

        # Estimate payload length
        payload_len = self._payload_length(packet, tcp)
        seq_consumes = payload_len > 0 or flags_syn

        state = self._flow_state.setdefault(flow_key, {
            "seen_seqs": [],           # list of (seq, end_seq, timestamp)
            "ack_history": deque(maxlen=100),  # list of ack numbers
            "last_seq": None,
            "last_end_seq": None,
        })

        event: Optional[RetransmissionEvent] = None

        # --- Check for retransmission / out-of-order on data segments ---
        if seq_consumes and seq is not None:
            end_seq = seq + max(payload_len, 1)  # SYN consumes 1

            # Check against previously seen segments in this direction
            seen = state["seen_seqs"]
            for prev_seq, prev_end, prev_ts in seen:
                # Exact duplicate
                if prev_seq == seq and prev_end == end_seq:
                    event = RetransmissionEvent(
                        src_ip=str(src_ip),
                        dst_ip=str(dst_ip),
                        src_port=int(src_port),
                        dst_port=int(dst_port),
                        seq_number=int(seq),
                        ack_number=int(ack) if ack is not None else None,
                        classification="retransmission",
                        timestamp=timestamp,
                        description=(
                            f"Duplicate TCP segment seq={seq} len={payload_len} "
                            f"from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                        ),
                    )
                    self._retransmission_counts[flow_key] += 1
                    break

                # Overlapping range (possible retransmission)
                if seq < prev_end and end_seq > prev_seq:
                    if not (prev_seq == seq and prev_end == end_seq):
                        event = RetransmissionEvent(
                            src_ip=str(src_ip),
                            dst_ip=str(dst_ip),
                            src_port=int(src_port),
                            dst_port=int(dst_port),
                            seq_number=int(seq),
                            ack_number=int(ack) if ack is not None else None,
                            classification="possible_retransmission",
                            timestamp=timestamp,
                            description=(
                                f"Overlapping TCP segment seq={seq} len={payload_len} "
                                f"overlaps previous seq={prev_seq} len={prev_end - prev_seq} "
                                f"from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                            ),
                        )
                        self._retransmission_counts[flow_key] += 1
                        break

            # Check out-of-order: if seq < last expected end_seq
            if event is None and state["last_end_seq"] is not None and seq is not None:
                if seq < state["last_end_seq"]:
                    event = RetransmissionEvent(
                        src_ip=str(src_ip),
                        dst_ip=str(dst_ip),
                        src_port=int(src_port),
                        dst_port=int(dst_port),
                        seq_number=int(seq),
                        ack_number=int(ack) if ack is not None else None,
                        classification="out_of_order",
                        timestamp=timestamp,
                        description=(
                            f"Out-of-order TCP segment seq={seq} "
                            f"(expected >= {state['last_end_seq']}) "
                            f"from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                        ),
                    )
                    self._out_of_order_counts[flow_key] += 1

            # Record this segment
            if seq is not None:
                seen.append((seq, end_seq, timestamp))
                if len(seen) > self.max_history:
                    seen.pop(0)
                state["last_seq"] = seq
                state["last_end_seq"] = end_seq

        # --- Check for duplicate ACKs ---
        # Only flag duplicate ACKs if we haven't already detected a
        # retransmission for this packet.
        if event is None and flags_ack and ack is not None:
            ack_hist = state["ack_history"]
            ack_hist.append(int(ack))
            # Count occurrences of this ack number
            dup_count = sum(1 for a in ack_hist if a == int(ack))
            if dup_count >= self.dup_ack_threshold:
                event = RetransmissionEvent(
                    src_ip=str(src_ip),
                    dst_ip=str(dst_ip),
                    src_port=int(src_port),
                    dst_port=int(dst_port),
                    seq_number=0,
                    ack_number=int(ack),
                    classification="duplicate_ack",
                    timestamp=timestamp,
                    description=(
                        f"Duplicate ACK #{dup_count} for ack={ack} "
                        f"from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                    ),
                )
                # Don't count duplicate_ack as retransmission count

        if event:
            self._events.append(event)

        return event

    def analyse_batch(self, packets: List[Packet]) -> List[RetransmissionEvent]:
        """Process multiple packets, returning all events found."""
        events: List[RetransmissionEvent] = []
        for pkt in packets:
            evt = self.analyse(pkt)
            if evt:
                events.append(evt)
        return events

    def get_flow_events(self, src_ip: str, dst_ip: str,
                        src_port: int, dst_port: int) -> List[RetransmissionEvent]:
        """Return all events for a specific flow direction."""
        flow_key = (str(src_ip), str(dst_ip), int(src_port), int(dst_port))
        return [e for e in self._events
                if (e.src_ip, e.dst_ip, e.src_port, e.dst_port) == flow_key]

    def get_flow_counts(self, src_ip: str, dst_ip: str,
                        src_port: int, dst_port: int) -> dict:
        """Return retransmission and out-of-order counts for a flow."""
        flow_key = (str(src_ip), str(dst_ip), int(src_port), int(dst_port))
        return {
            "retransmission_count": self._retransmission_counts.get(flow_key, 0),
            "out_of_order_count": self._out_of_order_counts.get(flow_key, 0),
        }

    def get_all_events(self) -> List[RetransmissionEvent]:
        return list(self._events)

    def reset(self) -> None:
        self._flow_state.clear()
        self._events.clear()
        self._retransmission_counts.clear()
        self._out_of_order_counts.clear()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _payload_length(packet: Packet, tcp) -> int:
        """Estimate TCP payload length."""
        ip = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if not ip:
            return 0
        total_len = ip.get_field("total_length")
        ip_header_len = ip.get_field("header_length") or 20
        tcp_header_len = (tcp.get_field("data_offset") or 5) * 4
        if total_len is None:
            return 0
        payload = total_len - ip_header_len - tcp_header_len
        return max(payload, 0)
