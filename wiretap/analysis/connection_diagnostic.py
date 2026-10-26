"""Unified TCP connection diagnostic engine.

Evaluates each TCP connection holistically by combining:
- Handshake timing (SYN -> SYN-ACK latency, failures, incomplete connections)
- Reliability (retransmission rate, duplicate ACK frequency)
- Flow control (zero-window advertisements, window-full conditions)
- Termination (RST flags, premature termination)
- RTT statistics (median, min, max, avg, variation, trend)

Produces a per-flow health score (0-100) with supporting evidence and a
human-readable summary.

Example output:
    "Connection health: Poor. Retransmissions affected 8% of observed TCP
    segments, and the connection had a median estimated RTT of 180 ms."
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from wiretap.models.connection_health import ConnectionHealthReport, HandshakeInfo
from wiretap.models.flow import Flow
from wiretap.models.packet import Packet

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Health scoring thresholds
# --------------------------------------------------------------------------- #
RETRANSMISSION_RATE_POOR = 0.05      # >5% retransmissions is concerning
RETRANSMISSION_RATE_CRITICAL = 0.15  # >15% is critical

DUP_ACK_RATE_POOR = 0.03             # >3% duplicate ACKs
DUP_ACK_RATE_CRITICAL = 0.10         # >10% is critical

RTT_MEDIAN_POOR_MS = 200.0           # >200ms median RTT
RTT_MEDIAN_CRITICAL_MS = 500.0       # >500ms median RTT

RTT_VARIATION_POOR_MS = 100.0        # >100ms std dev
RTT_VARIATION_CRITICAL_MS = 300.0    # >300ms std dev

ZERO_WINDOW_POOR = 3                 # >3 zero-window events
ZERO_WINDOW_CRITICAL = 10            # >10 is critical

RST_COUNT_POOR = 1                   # any RST is concerning
RST_COUNT_CRITICAL = 3               # >3 RSTs is critical

HANDSHAKE_TIMEOUT_S = 5.0            # SYN without SYN-ACK after 5s = failed


@dataclass
class _FlowState:
    """Internal per-flow tracking state for the diagnostic engine."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    # Handshake tracking
    syn_seen: bool = False
    syn_ack_seen: bool = False
    final_ack_seen: bool = False
    syn_time: Optional[float] = None
    syn_ack_time: Optional[float] = None
    ack_time: Optional[float] = None
    handshake_time_ms: Optional[float] = None
    syn_retries: int = 0
    handshake_completed: bool = False
    handshake_failed: bool = False
    handshake_incomplete: bool = False

    # Segment tracking
    total_segments: int = 0
    data_segments: int = 0               # segments with payload or SYN/FIN
    retransmission_segments: int = 0
    duplicate_ack_count: int = 0
    ack_numbers_seen: Deque[int] = field(default_factory=lambda: deque(maxlen=1000))

    # Flow control
    zero_window_count: int = 0
    window_full_count: int = 0
    min_window_size: Optional[int] = None

    # Termination
    rst_count: int = 0
    fin_seen: bool = False
    premature_termination: bool = False

    # RTT
    rtt_samples: List[float] = field(default_factory=list)

    # RTT estimation - outstanding segments awaiting ACK
    outstanding_segments: List[Tuple[int, int, float]] = field(default_factory=list)
    rtt_samples: List[float] = field(default_factory=list)

    # Timing
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    # Retransmission detection (sequence tracking per direction)
    seen_sequences: Dict[Tuple[str, str, int, int], List[Tuple[int, int]]] = field(
        default_factory=dict
    )  # (src_ip, dst_ip, src_port, dst_port) -> [(seq, end_seq)]


class ConnectionDiagnosticEngine:
    """Unified diagnostic engine for TCP connection health.

    Processes individual TCP packets and maintains per-flow state to produce
    ConnectionHealthReport objects. Can be called incrementally as packets
    arrive, or in batch mode on a captured set of packets.

    Usage::

        engine = ConnectionDiagnosticEngine()

        # As packets arrive:
        for packet in captured_packets:
            report = engine.analyse(packet)
            if report:
                print(report.summary)

        # Or get all reports at once:
        reports = engine.get_all_reports()
    """

    def __init__(
        self,
        health_score_weights: Optional[Dict[str, float]] = None,
    ) -> None:
        """
        Args:
            health_score_weights: Optional custom weights for health score
                components. Keys: 'retransmission', 'duplicate_ack', 'rtt',
                'rtt_variation', 'zero_window', 'rst', 'handshake'.
                Values should sum to 1.0.
        """
        self._flows: Dict[Tuple[str, str, int, int], _FlowState] = {}
        self._reports: Dict[Tuple[str, str, int, int], ConnectionHealthReport] = {}
        self._lock = None  # type: ignore - set by GUI if needed

        # Default weights for health score computation
        self._weights = health_score_weights or {
            "retransmission": 0.25,
            "duplicate_ack": 0.15,
            "rtt": 0.20,
            "rtt_variation": 0.10,
            "zero_window": 0.10,
            "rst": 0.10,
            "handshake": 0.10,
        }

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def analyse(self, packet: Packet) -> Optional[ConnectionHealthReport]:
        """Process a single TCP packet and return an updated health report
        for its flow if enough data has been collected.

        Returns None for non-TCP packets or flows with insufficient data.
        """
        tcp = packet.get_layer("TCP")
        ip = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if not tcp or not ip:
            return None

        src_ip = str(ip.get_field("src_addr") or "")
        dst_ip = str(ip.get_field("dst_addr") or "")
        src_port = tcp.get_field("src_port")
        dst_port = tcp.get_field("dst_port")
        seq = tcp.get_field("seq_num")
        ack = tcp.get_field("ack_num")
        window_size = tcp.get_field("window_size")
        flags_syn = bool(tcp.get_field("flags_syn") or False)
        flags_ack = bool(tcp.get_field("flags_ack") or False)
        flags_fin = bool(tcp.get_field("flags_fin") or False)
        flags_rst = bool(tcp.get_field("flags_rst") or False)
        timestamp = packet.timestamp

        if not src_ip or not dst_ip or src_port is None or dst_port is None:
            return None

        # Normalize flow key (direction-agnostic for reporting, but we track
        # each direction separately for handshake/seq analysis)
        flow_key = (src_ip, dst_ip, int(src_port), int(dst_port))
        reverse_key = (dst_ip, src_ip, int(dst_port), int(src_port))

        state = self._flows.get(flow_key)
        if state is None:
            state = _FlowState(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(src_port),
                dst_port=int(dst_port),
            )
            self._flows[flow_key] = state

        state.total_segments += 1
        state.last_seen = timestamp
        if state.first_seen is None:
            state.first_seen = timestamp

        # --- Handshake analysis ---
        self._analyse_handshake(state, flags_syn, flags_ack, seq, timestamp, reverse_key)

        # --- Retransmission / out-of-order detection ---
        # Only data-bearing segments (payload, SYN, or FIN) can be retransmissions
        payload_len = self._payload_length(packet, tcp)
        is_data_segment = payload_len > 0 or flags_syn or flags_fin
        if is_data_segment and seq is not None:
            is_retrans = self._detect_retransmission(
                state, seq, payload_len, flags_syn, flags_fin, timestamp, flow_key
            )
            if is_retrans:
                state.retransmission_segments += 1

        # --- Duplicate ACK detection ---
        # Only pure ACK packets (no data) can be duplicate ACKs in the TCP sense
        if (
            flags_ack
            and ack is not None
            and not flags_syn
            and not flags_fin
            and not flags_rst
            and payload_len == 0
        ):
            ack_int = int(ack)
            # Count how many times we've seen this ACK number
            dup_count = sum(1 for a in state.ack_numbers_seen if a == ack_int)
            if dup_count >= 1:  # already seen once = duplicate
                state.duplicate_ack_count += 1
            state.ack_numbers_seen.append(ack_int)

        # --- Flow control (window size) ---
        if window_size is not None:
            wsize = int(window_size)
            if state.min_window_size is None or wsize < state.min_window_size:
                state.min_window_size = wsize
            if wsize == 0:
                state.zero_window_count += 1
                # Propagate zero-window to reverse flow
                rev_state = self._flows.get(reverse_key)
                if rev_state is not None:
                    rev_state.zero_window_count += 1
            elif wsize <= 64:  # near-full window
                state.window_full_count += 1

        # --- Termination ---
        if flags_rst:
            state.rst_count += 1
            state.premature_termination = True
            # Propagate RST to reverse flow
            rev_state = self._flows.get(reverse_key)
            if rev_state is not None:
                rev_state.rst_count += 1
                rev_state.premature_termination = True
        if flags_fin:
            state.fin_seen = True
            # Propagate FIN to reverse flow
            rev_state = self._flows.get(reverse_key)
            if rev_state is not None:
                rev_state.fin_seen = True

        # --- RTT estimation: match ACKs with outstanding segments ---
        # When an ACK arrives from the reverse direction, look up outstanding
        # segments in the original sender's flow state (reverse_key).
        if flags_ack and ack is not None and not flags_syn and not flags_fin and not flags_rst:
            ack_int = int(ack)
            # Look up outstanding segments in the reverse flow (the sender)
            rtt_state = self._flows.get(reverse_key, state)
            newly_acked = []
            for seg_seq, seg_end, seg_ts in rtt_state.outstanding_segments:
                if ack_int > seg_seq:  # ACK acknowledges at least part of this segment
                    newly_acked.append((seg_seq, seg_end, seg_ts))
            # Compute RTT for the oldest acknowledged segment
            if newly_acked:
                # Use the oldest acknowledged segment for RTT
                oldest = min(newly_acked, key=lambda x: x[2])
                rtt = timestamp - oldest[2]
                if rtt >= 0:
                    state.rtt_samples.append(rtt)
                    if len(state.rtt_samples) > 100:
                        state.rtt_samples.pop(0)
            # Remove acknowledged segments from the sender's outstanding list
            rtt_state.outstanding_segments = [
                s for s in rtt_state.outstanding_segments
                if not (ack_int > s[0])
            ]

        # --- Record outstanding segments for RTT estimation ---
        payload_len = self._payload_length(packet, tcp)
        is_data = payload_len > 0 or flags_syn or flags_fin
        if is_data and seq is not None:
            seq_int = int(seq)
            end_seq = seq_int + max(payload_len, 1)  # SYN/FIN consume 1
            state.outstanding_segments.append((seq_int, end_seq, timestamp))
            # Trim old outstanding segments
            cutoff = timestamp - 30.0
            state.outstanding_segments = [
                s for s in state.outstanding_segments if s[2] >= cutoff
            ]
            if len(state.outstanding_segments) > 500:
                state.outstanding_segments = state.outstanding_segments[-500:]

        # --- Data segment tracking ---
        if payload_len > 0 or flags_syn or flags_fin:
            state.data_segments += 1

        # Generate report if we have enough data
        reverse_state = self._flows.get(reverse_key)
        report = self._build_report(state, reverse_state)
        if report:
            self._reports[flow_key] = report
            # Store the same aggregated report under the reverse key too,
            # so lookups from either direction return consistent data.
            if reverse_state is not None:
                self._reports[reverse_key] = report
        return report

    def analyse_batch(self, packets: List[Packet]) -> List[ConnectionHealthReport]:
        """Process multiple packets, returning all reports generated."""
        reports: List[ConnectionHealthReport] = []
        for pkt in packets:
            report = self.analyse(pkt)
            if report:
                reports.append(report)
        return reports

    def get_report(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> Optional[ConnectionHealthReport]:
        """Return the latest health report for a specific flow direction."""
        flow_key = (str(src_ip), str(dst_ip), int(src_port), int(dst_port))
        report = self._reports.get(flow_key)
        if report is None:
            # Try reverse direction
            reverse_key = (str(dst_ip), str(src_ip), int(dst_port), int(src_port))
            report = self._reports.get(reverse_key)
        return report

    def get_all_reports(self) -> List[ConnectionHealthReport]:
        """Return all connection health reports."""
        return list(self._reports.values())

    def get_reports_by_source(self, src_ip: str) -> List[ConnectionHealthReport]:
        """Return all reports where src_ip is the source."""
        return [r for r in self._reports.values() if r.src_ip == src_ip]

    def get_reports_by_destination(self, dst_ip: str) -> List[ConnectionHealthReport]:
        """Return all reports where dst_ip is the destination."""
        return [r for r in self._reports.values() if r.dst_ip == dst_ip]

    def get_unhealthy_connections(self, threshold: float = 70.0) -> List[ConnectionHealthReport]:
        """Return connections with health_score below the threshold."""
        return [r for r in self._reports.values() if r.health_score < threshold]

    def reset(self) -> None:
        """Clear all flow state and reports."""
        self._flows.clear()
        self._reports.clear()

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

    def _analyse_handshake(
        self,
        state: _FlowState,
        flags_syn: bool,
        flags_ack: bool,
        seq: Optional[int],
        timestamp: float,
        reverse_key: Tuple[str, str, int, int],
    ) -> None:
        """Track TCP handshake state (bidirectional)."""
        if flags_syn and not flags_ack:
            # SYN packet
            if not state.syn_seen:
                state.syn_seen = True
                state.syn_time = timestamp
            else:
                state.syn_retries += 1

        elif flags_syn and flags_ack:
            # SYN-ACK packet (response to our SYN)
            if state.syn_seen and not state.syn_ack_seen:
                state.syn_ack_seen = True
                state.syn_ack_time = timestamp
                if state.syn_time is not None:
                    state.handshake_time_ms = (
                        (timestamp - state.syn_time) * 1000.0
                    )
            # Also mark the reverse flow's SYN as acknowledged
            rev_state = self._flows.get(reverse_key)
            if rev_state is not None and rev_state.syn_seen and not rev_state.syn_ack_seen:
                rev_state.syn_ack_seen = True
                rev_state.syn_ack_time = timestamp
                if rev_state.syn_time is not None:
                    rev_state.handshake_time_ms = (
                        (timestamp - rev_state.syn_time) * 1000.0
                    )

        elif flags_ack and not flags_syn:
            # Pure ACK - could be the final ACK of a 3-way handshake
            if state.syn_seen and state.syn_ack_seen and not state.final_ack_seen:
                state.final_ack_seen = True
                state.ack_time = timestamp
                state.handshake_completed = True
            # Also mark reverse flow's handshake as completed if applicable
            rev_state = self._flows.get(reverse_key)
            if rev_state is not None and rev_state.syn_seen and rev_state.syn_ack_seen and not rev_state.final_ack_seen:
                rev_state.final_ack_seen = True
                rev_state.ack_time = timestamp
                rev_state.handshake_completed = True

        # Check for handshake failure (SYN sent, no SYN-ACK after timeout or retries)
        if (
            state.syn_seen
            and not state.syn_ack_seen
            and (
                timestamp - (state.syn_time or timestamp) > HANDSHAKE_TIMEOUT_S
                or state.syn_retries >= 2
            )
        ):
            state.handshake_failed = True

        # Check for incomplete handshake (SYN-ACK received but no final ACK)
        if state.syn_ack_seen and not state.final_ack_seen and state.last_seen:
            if timestamp - state.syn_ack_time > HANDSHAKE_TIMEOUT_S:
                state.handshake_incomplete = True

    def _detect_retransmission(
        self,
        state: _FlowState,
        seq: Optional[int],
        payload_len: int,
        flags_syn: bool,
        flags_fin: bool,
        timestamp: float,
        flow_key: Tuple[str, str, int, int],
    ) -> bool:
        """Detect if this segment is a retransmission."""
        if seq is None:
            return False

        # Get or initialize sequence tracking for this direction
        direction_key = flow_key  # we track per direction via flow_key
        seen = state.seen_sequences.setdefault(direction_key, [])

        seq_int = int(seq)
        end_seq = seq_int + (1 if (flags_syn or flags_fin) else max(payload_len, 0))

        # Check for exact duplicate
        for prev_seq, prev_end in seen:
            if prev_seq == seq_int and prev_end == end_seq:
                return True

        # Check for overlapping range (possible retransmission)
        for prev_seq, prev_end in seen:
            if seq_int < prev_end and end_seq > prev_seq:
                if not (prev_seq == seq_int and prev_end == end_seq):
                    return True

        # Record this sequence
        seen.append((seq_int, end_seq))
        if len(seen) > 500:
            seen.pop(0)

        return False

    def _build_report(self, state: _FlowState, reverse_state: Optional[_FlowState] = None) -> Optional[ConnectionHealthReport]:
        """Build a ConnectionHealthReport from flow state.

        Aggregates metrics from both forward and reverse directions when
        reverse_state is provided, giving a holistic view of connection health.
        """
        # Need at least a few segments to be meaningful
        if state.total_segments < 2:
            return None

        # Aggregate counters from both directions
        total_segments = state.total_segments
        data_segments = state.data_segments
        retransmission_segments = state.retransmission_segments
        duplicate_ack_count = state.duplicate_ack_count
        zero_window_count = state.zero_window_count
        window_full_count = state.window_full_count
        rst_count = state.rst_count

        if reverse_state is not None:
            total_segments += reverse_state.total_segments
            data_segments += reverse_state.data_segments
            retransmission_segments += reverse_state.retransmission_segments
            duplicate_ack_count += reverse_state.duplicate_ack_count
            zero_window_count += reverse_state.zero_window_count
            window_full_count += reverse_state.window_full_count
            rst_count += reverse_state.rst_count

        duration = (state.last_seen or 0) - (state.first_seen or 0)

        # Compute retransmission rate
        retrans_rate = (
            retransmission_segments / max(data_segments, 1)
            if data_segments > 0
            else 0.0
        )

        # Compute duplicate ACK frequency
        dup_ack_freq = (
            duplicate_ack_count / max(duration, 0.001)
            if duration > 0
            else 0.0
        )

        # RTT statistics
        rtt_samples = state.rtt_samples
        median_rtt = None
        rtt_min = None
        rtt_max = None
        rtt_avg = None
        rtt_var = None
        rtt_trend = "insufficient"

        if rtt_samples:
            sorted_rtt = sorted(rtt_samples)
            n = len(sorted_rtt)
            median_rtt = sorted_rtt[n // 2] * 1000.0  # ms
            rtt_min = min(rtt_samples) * 1000.0
            rtt_max = max(rtt_samples) * 1000.0
            rtt_avg = (sum(rtt_samples) / n) * 1000.0
            if n > 1:
                mean = sum(rtt_samples) / n
                var = sum((x - mean) ** 2 for x in rtt_samples) / n
                rtt_var = math.sqrt(var) * 1000.0  # ms

            # Trend: compare first half vs second half
            if n >= 6:
                first_half = sorted_rtt[: n // 2]
                second_half = sorted_rtt[n // 2 :]
                first_avg = sum(first_half) / len(first_half)
                second_avg = sum(second_half) / len(second_half)
                diff_pct = (second_avg - first_avg) / max(first_avg, 0.001)
                if diff_pct > 0.1:
                    rtt_trend = "degrading"
                elif diff_pct < -0.1:
                    rtt_trend = "improving"
                else:
                    rtt_trend = "stable"

        # --- Health score computation ---
        score = 100.0
        evidence: List[str] = []

        # Direct deductions for critical handshake issues
        # (applied outside the weight system since these are fundamental)
        if state.handshake_failed:
            score -= 45.0
            evidence.append("TCP handshake failed (SYN sent, no SYN-ACK received)")
        if state.handshake_incomplete:
            score -= 25.0
            evidence.append("TCP handshake incomplete (SYN-ACK received, no final ACK)")

        # Handshake timing component (10%)
        handshake_penalty = 0.0
        if state.handshake_time_ms is not None:
            hs_ms = state.handshake_time_ms
            if hs_ms > 500:
                handshake_penalty += 20.0
                evidence.append(f"Slow handshake: {hs_ms:.0f} ms SYN-to-SYN-ACK")
            elif hs_ms > 200:
                handshake_penalty += 8.0
                evidence.append(f"Elevated handshake time: {hs_ms:.0f} ms")
        if state.syn_retries > 0:
            handshake_penalty += min(20.0, state.syn_retries * 5.0)
            evidence.append(f"{state.syn_retries} SYN retransmission(s)")
        score -= handshake_penalty * self._weights["handshake"]

        # Retransmission component (25%)
        retrans_penalty = 0.0
        if retrans_rate >= RETRANSMISSION_RATE_CRITICAL:
            retrans_penalty += 55.0
            evidence.append(
                f"Critical retransmission rate: {retrans_rate*100:.1f}% of segments"
            )
        elif retrans_rate >= RETRANSMISSION_RATE_POOR:
            retrans_penalty += 30.0
            evidence.append(
                f"High retransmission rate: {retrans_rate*100:.1f}% of segments"
            )
        elif retrans_rate > 0:
            retrans_penalty += 8.0
            evidence.append(
                f"Minor retransmissions: {retrans_rate*100:.1f}% of segments"
            )
        score -= retrans_penalty * self._weights["retransmission"]

        # Duplicate ACK component (15%)
        dup_ack_penalty = 0.0
        if duplicate_ack_count > 0:
            if dup_ack_freq >= DUP_ACK_RATE_CRITICAL:
                dup_ack_penalty += 40.0
                evidence.append(
                    f"Critical duplicate ACK frequency: {dup_ack_freq:.1f}/sec"
                )
            elif dup_ack_freq >= DUP_ACK_RATE_POOR:
                dup_ack_penalty += 20.0
                evidence.append(
                    f"Elevated duplicate ACK frequency: {dup_ack_freq:.1f}/sec"
                )
            else:
                dup_ack_penalty += 8.0
                evidence.append(
                    f"{duplicate_ack_count} duplicate ACK(s) observed"
                )
        score -= dup_ack_penalty * self._weights["duplicate_ack"]

        # RTT component (20%)
        rtt_penalty = 0.0
        if median_rtt is not None:
            if median_rtt >= RTT_MEDIAN_CRITICAL_MS:
                rtt_penalty += 40.0
                evidence.append(f"Critical median RTT: {median_rtt:.0f} ms")
            elif median_rtt >= RTT_MEDIAN_POOR_MS:
                rtt_penalty += 20.0
                evidence.append(f"High median RTT: {median_rtt:.0f} ms")
        score -= rtt_penalty * self._weights["rtt"]

        # RTT variation component (10%)
        var_penalty = 0.0
        if rtt_var is not None:
            if rtt_var >= RTT_VARIATION_CRITICAL_MS:
                var_penalty += 35.0
                evidence.append(f"Critical RTT variation: {rtt_var:.0f} ms std dev")
            elif rtt_var >= RTT_VARIATION_POOR_MS:
                var_penalty += 15.0
                evidence.append(f"Elevated RTT variation: {rtt_var:.0f} ms std dev")
        score -= var_penalty * self._weights["rtt_variation"]

        # Zero-window component (10%)
        zw_penalty = 0.0
        if zero_window_count >= ZERO_WINDOW_CRITICAL:
            zw_penalty += 35.0
            evidence.append(f"Critical zero-window events: {zero_window_count}")
        elif zero_window_count >= ZERO_WINDOW_POOR:
            zw_penalty += 15.0
            evidence.append(f"Multiple zero-window events: {zero_window_count}")
        elif zero_window_count > 0:
            zw_penalty += 8.0
            evidence.append(f"{zero_window_count} zero-window event(s)")
        score -= zw_penalty * self._weights["zero_window"]

        # RST component (10%)
        rst_penalty = 0.0
        if rst_count >= RST_COUNT_CRITICAL:
            rst_penalty += 45.0
            evidence.append(f"Critical connection resets: {rst_count}")
        elif rst_count >= RST_COUNT_POOR:
            rst_penalty += 25.0
            evidence.append(f"Connection reset(s): {rst_count}")
        score -= rst_penalty * self._weights["rst"]

        # Premature termination component
        if state.premature_termination:
            score -= 20.0 * self._weights["rst"]
            evidence.append("Connection terminated prematurely (RST instead of FIN)")

        # Window-full component (included in zero_window weight, minor)
        if window_full_count > 0:
            score -= min(8.0, window_full_count * 1.5) * self._weights["zero_window"]
            evidence.append(
                f"{window_full_count} near-full window condition(s)"
            )

        # Clamp score
        score = max(0.0, min(100.0, score))

        # Grade and label
        grade, label = self._score_to_grade(score)

        # Build summary string
        summary = self._build_summary(
            score,
            label,
            retrans_rate,
            retransmission_segments,
            median_rtt,
            zero_window_count,
            rst_count,
            state.handshake_failed or (reverse_state.handshake_failed if reverse_state else False),
            state.handshake_incomplete or (reverse_state.handshake_incomplete if reverse_state else False),
            duplicate_ack_count,
        )

        report = ConnectionHealthReport(
            src_ip=state.src_ip,
            dst_ip=state.dst_ip,
            src_port=state.src_port,
            dst_port=state.dst_port,
            health_score=round(score, 1),
            health_grade=grade,
            health_label=label,
            handshake=HandshakeInfo(
                completed=state.handshake_completed or (reverse_state.handshake_completed if reverse_state else False),
                syn_time=state.syn_time,
                syn_ack_time=state.syn_ack_time,
                ack_time=state.ack_time,
                handshake_time_ms=state.handshake_time_ms or (reverse_state.handshake_time_ms if reverse_state else None),
                failed=state.handshake_failed or (reverse_state.handshake_failed if reverse_state else False),
                incomplete=state.handshake_incomplete or (reverse_state.handshake_incomplete if reverse_state else False),
                syn_retries=state.syn_retries + (reverse_state.syn_retries if reverse_state else 0),
            ),
            total_segments=total_segments,
            retransmission_count=retransmission_segments,
            retransmission_rate=round(retrans_rate, 4),
            duplicate_ack_count=duplicate_ack_count,
            duplicate_ack_frequency=round(dup_ack_freq, 2),
            zero_window_count=zero_window_count,
            window_full_count=window_full_count,
            rst_count=rst_count,
            premature_termination=state.premature_termination or (reverse_state.premature_termination if reverse_state else False),
            rtt_samples=list(rtt_samples),
            median_rtt_ms=round(median_rtt, 1) if median_rtt else None,
            rtt_min_ms=round(rtt_min, 1) if rtt_min else None,
            rtt_max_ms=round(rtt_max, 1) if rtt_max else None,
            rtt_avg_ms=round(rtt_avg, 1) if rtt_avg else None,
            rtt_variation_ms=round(rtt_var, 1) if rtt_var else None,
            rtt_trend=rtt_trend,
            duration_seconds=round(duration, 2),
            first_seen=state.first_seen,
            last_seen=state.last_seen,
            evidence=evidence,
            summary=summary,
        )
        return report

    @staticmethod
    def _score_to_grade(score: float) -> tuple[str, str]:
        """Convert numeric score to letter grade and label."""
        if score >= 90:
            return "A", "Excellent"
        elif score >= 80:
            return "B", "Good"
        elif score >= 70:
            return "C", "Fair"
        elif score >= 50:
            return "D", "Poor"
        else:
            return "F", "Critical"

    @staticmethod
    def _build_summary(
        score: float,
        label: str,
        retrans_rate: float,
        retransmission_segments: int,
        median_rtt: Optional[float],
        zero_window_count: int,
        rst_count: int,
        handshake_failed: bool,
        handshake_incomplete: bool,
        duplicate_ack_count: int,
    ) -> str:
        """Build a human-readable summary string."""
        _, grade_label = ConnectionDiagnosticEngine._score_to_grade(score)
        parts = [f"Connection health: {grade_label}."]

        # Retransmission statement
        if retransmission_segments > 0:
            pct = retrans_rate * 100
            parts.append(
                f"Retransmissions affected {pct:.0f}% of observed TCP segments"
            )

        # RTT statement
        if median_rtt is not None:
            parts.append(
                f"the connection had a median estimated RTT of {median_rtt:.0f} ms"
            )

        # Additional issues
        extra = []
        if zero_window_count > 0:
            extra.append(f"{zero_window_count} zero-window event(s)")
        if rst_count > 0:
            extra.append(f"{rst_count} connection reset(s)")
        if handshake_failed:
            extra.append("handshake failed")
        if handshake_incomplete:
            extra.append("incomplete handshake")
        if duplicate_ack_count > 0:
            extra.append(f"{duplicate_ack_count} duplicate ACK(s)")

        if extra:
            parts.append("; ".join(extra) + ".")

        return " ".join(parts)

    # ------------------------------------------------------------------ #
    # Integration with Flow model
    # ------------------------------------------------------------------ #
    def apply_to_flow(self, flow: Flow) -> None:
        """Apply diagnostic results to a wiretap Flow object.

        Updates flow-level RTT and retransmission fields from the report
        if one exists for this flow's direction.
        """
        report = self.get_report(
            flow.src_ip, flow.dst_ip,
            flow.src_port or 0, flow.dst_port or 0,
        )
        if not report:
            # Try reverse direction
            report = self.get_report(
                flow.dst_ip, flow.src_ip,
                flow.dst_port or 0, flow.src_port or 0,
            )
        if not report:
            return

        flow.retransmission_count = report.retransmission_count
        flow.out_of_order_count = report.duplicate_ack_count

        if report.median_rtt_ms is not None:
            flow.rtt = report.median_rtt_ms / 1000.0
            flow.smoothed_rtt = report.median_rtt_ms / 1000.0
            flow.rtt_min = report.rtt_min_ms / 1000.0 if report.rtt_min_ms else None
            flow.rtt_max = report.rtt_max_ms / 1000.0 if report.rtt_max_ms else None
            flow.rtt_avg = report.rtt_avg_ms / 1000.0 if report.rtt_avg_ms else None
