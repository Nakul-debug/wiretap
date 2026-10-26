"""RTT estimator for TCP connections.

Estimates Round-Trip Time (RTT) by matching TCP data segments with their
corresponding ACKs. Uses sequence/acknowledgment numbers to track when
data was sent and when it was acknowledged.

Algorithm:
1. Record timestamp and sequence number when a data-bearing segment is sent.
2. When an ACK arrives that acknowledges that sequence range, compute
   RTT = ACK_timestamp - segment_timestamp.
3. Maintain per-flow RTT samples and an exponentially weighted moving
   average (smoothed RTT).

This is an educational implementation — it handles basic cases and is
not a replacement for production TCP stack measurements.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Deque, List, Optional, Tuple

from backend.models.flow import Flow
from backend.models.packet import Packet

logger = logging.getLogger(__name__)


@dataclass
class RTTSample:
    """A single RTT measurement."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq_number: int
    ack_number: int
    rtt: float  # seconds
    timestamp: float = field(default_factory=time.time)


class RTTEstimator:
    """Estimates RTT for TCP flows using sequence/ACK matching."""

    def __init__(self, alpha: float = 0.875, max_samples: int = 1000):
        """
        Args:
            alpha: EWMA smoothing factor (0.0-1.0). Higher = more weight
                   on historical samples, lower = more weight on recent.
            max_samples: Maximum RTT samples to keep per flow.
        """
        self.alpha = alpha
        self.max_samples = max_samples

        # Per-flow state: key = (src_ip, dst_ip, src_port, dst_port)
        # Value: dict with outstanding segments and RTT history
        self._flow_state: Dict[Tuple[str, str, int, int], dict] = {}

        # All RTT samples across flows (for global statistics)
        self._all_samples: Deque[RTTSample] = deque(maxlen=10_000)

        self._lock = None  # type: ignore - set by GUI if needed

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def analyse(self, packet: Packet) -> Optional[RTTSample]:
        """Process a single TCP packet.

        Returns an RTTSample if an RTT measurement was completed,
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
        payload_len = self._payload_length(packet, tcp)

        if src_ip is None or dst_ip is None or src_port is None or dst_port is None:
            return None

        # Normalise flow key (direction-agnostic for bidirectional RTT)
        # We track each direction separately for RTT estimation.
        flow_key = (str(src_ip), str(dst_ip), int(src_port), int(dst_port))
        reverse_key = (str(dst_ip), str(src_ip), int(dst_port), int(src_port))

        timestamp = packet.timestamp

        # --- Outgoing data: record outstanding segment ---
        # If this packet has data payload (or is a SYN, which consumes
        # one sequence number), record it as outstanding.
        seq_consumes = payload_len > 0 or flags_syn
        if seq_consumes:
            self._record_outstanding(flow_key, seq, timestamp)

        # --- Incoming ACK: match against outstanding segments ---
        if flags_ack and ack is not None:
            # Look in the reverse direction's outstanding segments
            # (data sent by dst -> src, now being acked by src -> dst)
            rtt_sample = self._match_ack(reverse_key, ack, timestamp)
            if rtt_sample:
                self._all_samples.append(rtt_sample)
                # Update flow state with the RTT sample
                self._apply_rtt_to_flow(flow_key, rtt_sample)
                return rtt_sample

        return None

    def analyse_batch(self, packets: List[Packet]) -> List[RTTSample]:
        """Process multiple packets, returning all RTT samples found."""
        samples: List[RTTSample] = []
        for pkt in packets:
            sample = self.analyse(pkt)
            if sample:
                samples.append(sample)
        return samples

    def get_flow_rtt(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[dict]:
        """Return RTT stats for a specific flow direction."""
        flow_key = (str(src_ip), str(dst_ip), int(src_port), int(dst_port))
        state = self._flow_state.get(flow_key)
        if not state:
            return None
        return {
            "rtt": state.get("rtt"),
            "smoothed_rtt": state.get("smoothed_rtt"),
            "rtt_min": state.get("rtt_min"),
            "rtt_max": state.get("rtt_max"),
            "rtt_avg": state.get("rtt_avg"),
            "sample_count": len(state.get("samples", [])),
        }

    def get_all_samples(self) -> List[RTTSample]:
        return list(self._all_samples)

    def reset(self) -> None:
        self._flow_state.clear()
        self._all_samples.clear()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _payload_length(packet: Packet, tcp) -> int:
        """Estimate TCP payload length from IP total length and headers."""
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

    def _record_outstanding(self, flow_key: Tuple[str, str, int, int],
                            seq: int, timestamp: float) -> None:
        """Record an outstanding segment awaiting ACK."""
        state = self._flow_state.setdefault(flow_key, {
            "outstanding": {},   # seq -> timestamp
            "samples": [],
            "rtt": None,
            "smoothed_rtt": None,
            "rtt_min": None,
            "rtt_max": None,
            "rtt_avg": None,
        })
        outstanding = state["outstanding"]
        # Keep only the most recent outstanding entry per seq to avoid unbounded growth
        outstanding[seq] = timestamp
        # Trim old outstanding entries (older than 30 seconds)
        cutoff = timestamp - 30.0
        stale = [s for s, t in outstanding.items() if t < cutoff]
        for s in stale:
            outstanding.pop(s, None)

    def _match_ack(self, flow_key: Tuple[str, str, int, int],
                   ack_num: int, ack_timestamp: float) -> Optional[RTTSample]:
        """Match an ACK against outstanding segments and compute RTT.

        An ACK acknowledges all bytes up to (but not including) ack_num.
        We find the oldest outstanding segment whose sequence range is
        fully acknowledged.
        """
        state = self._flow_state.get(flow_key)
        if not state:
            return None

        outstanding = state["outstanding"]
        if not outstanding:
            return None

        # Find segments fully acknowledged by this ACK
        matched_seq = None
        matched_ts = None
        for seq, ts in list(outstanding.items()):
            # Determine segment length (SYN consumes 1 seq number)
            # We don't store length here, so approximate: if ack > seq,
            # the segment is acknowledged.
            if ack_num > seq:
                matched_seq = seq
                matched_ts = ts
                break  # oldest first

        if matched_seq is None or matched_ts is None:
            return None

        rtt = ack_timestamp - matched_ts
        if rtt < 0:
            rtt = 0.0

        # Remove the matched segment from outstanding
        outstanding.pop(matched_seq, None)

        # Also remove any segments older than the matched one (cumulative ACK)
        older = [s for s in outstanding if s < matched_seq]
        for s in older:
            outstanding.pop(s, None)

        sample = RTTSample(
            src_ip=flow_key[0],
            dst_ip=flow_key[1],
            src_port=flow_key[2],
            dst_port=flow_key[3],
            seq_number=matched_seq,
            ack_number=ack_num,
            rtt=rtt,
            timestamp=ack_timestamp,
        )

        # Update flow state samples
        samples = state["samples"]
        samples.append(rtt)
        if len(samples) > self.max_samples:
            samples.pop(0)

        state["rtt"] = rtt
        state["rtt_min"] = min(samples) if samples else None
        state["rtt_max"] = max(samples) if samples else None
        state["rtt_avg"] = sum(samples) / len(samples) if samples else None
        if state["smoothed_rtt"] is None:
            state["smoothed_rtt"] = rtt
        else:
            state["smoothed_rtt"] = (
                self.alpha * state["smoothed_rtt"] + (1.0 - self.alpha) * rtt
            )

        return sample

    def _apply_rtt_to_flow(self, flow_key: Tuple[str, str, int, int],
                           sample: RTTSample) -> None:
        """Hook for applying RTT sample to a Flow object (called by engine)."""
        # This is a placeholder; the engine layer maps RTT samples to Flow objects.
        pass
