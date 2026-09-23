from PyQt6.QtWidgets import QWidget, QGridLayout, QLabel, QFrame
from PyQt6.QtCore import Qt, QTimer
from wiretap.models.packet import Packet
from typing import List
import time


class StatisticsWidget(QFrame):
    """Widget to display capture statistics."""

    def __init__(self, parent=None):
        super().__init__(parent)
        # Remove setFrameStyle to let stylesheet handle appearance
        self.layout = QGridLayout(self)
        self.layout.setSpacing(8)  # Add spacing between items
        self._packets: List[Packet] = []
        self._start_time = time.time()
        self._last_update_time = self._start_time
        self._init_ui()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update_display)
        self._timer.start(1000)  # Update every second

    def _init_ui(self):
        # Create labels
        self.labels = {}
        row = 0
        self.layout.addWidget(QLabel("Total Packets:"), row, 0)
        self.labels['total_packets'] = QLabel("0")
        self.layout.addWidget(self.labels['total_packets'], row, 1)
        row += 1
        self.layout.addWidget(QLabel("Total Bytes:"), row, 0)
        self.labels['total_bytes'] = QLabel("0")
        self.layout.addWidget(self.labels['total_bytes'], row, 1)
        row += 1
        self.layout.addWidget(QLabel("Packets/sec:"), row, 0)
        self.labels['pps'] = QLabel("0.00")
        self.layout.addWidget(self.labels['pps'], row, 1)
        row += 1
        self.layout.addWidget(QLabel("Bytes/sec:"), row, 0)
        self.labels['bps'] = QLabel("0.00")
        self.layout.addWidget(self.labels['bps'], row, 1)
        row += 1
        self.layout.addWidget(QLabel("Protocol Distribution:"), row, 0, 1, 2)
        row += 1
        self.protocol_label = QLabel("")
        self.protocol_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.layout.addWidget(self.protocol_label, row, 0, 1, 2)
        row += 1
        self.layout.addWidget(QLabel("Top Talkers (by packets):"), row, 0, 1, 2)
        row += 1
        self.talkers_label = QLabel("")
        self.talkers_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.layout.addWidget(self.talkers_label, row, 0, 1, 2)
        row += 1
        self.layout.addWidget(QLabel("Top Conversations:"), row, 0, 1, 2)
        row += 1
        self.conversations_label = QLabel("")
        self.conversations_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.layout.addWidget(self.conversations_label, row, 0, 1, 2)
        row += 1

    def set_packets(self, packets: List[Packet]):
        """Set the list of packets to compute statistics from."""
        self._packets = packets
        self._update_stats()

    def add_packet(self, packet: Packet):
        self._packets.append(packet)

    def _update_stats(self):
        """Compute statistics from the current packet list."""
        if not self._packets:
            return
        total_packets = len(self._packets)
        total_bytes = sum(len(p.raw_bytes) for p in self._packets)
        now = time.time()
        elapsed = now - self._start_time
        if elapsed > 0:
            pps = total_packets / elapsed
            bps = total_bytes / elapsed
        else:
            pps = 0.0
            bps = 0.0
        # Protocol distribution
        proto_counts = {}
        for p in self._packets:
            # Determine protocol from packet layers (simplified: first layer after Ethernet?)
            proto = "Unknown"
            ip_layer = p.get_layer("IPv4")
            if ip_layer:
                proto_num = ip_layer.get_field("protocol", "?")
                proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
                proto = proto_map.get(proto_num, str(proto_num))
            else:
                arp_layer = p.get_layer("ARP")
                if arp_layer:
                    proto = "ARP"
                else:
                    # Check for other layers
                    if p.get_layer("TCP"):
                        proto = "TCP"
                    elif p.get_layer("UDP"):
                        proto = "UDP"
                    elif p.get_layer("ICMP"):
                        proto = "ICMP"
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
        # Sort protocols by count
        sorted_proto = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)
        proto_text = ", ".join([f"{p}: {c}" for p, c in sorted_proto])
        # Top talkers (by source IP)
        src_counts = {}
        dst_counts = {}
        for p in self._packets:
            ip_layer = p.get_layer("IPv4")
            if ip_layer:
                src = ip_layer.get_field("src_addr", "?")
                dst = ip_layer.get_field("dst_addr", "?")
                src_counts[src] = src_counts.get(src, 0) + 1
                dst_counts[dst] = dst_counts.get(dst, 0) + 1
        # Combine src and dst for talkers
        talker_counts = {}
        for ip, count in src_counts.items():
            talker_counts[ip] = talker_counts.get(ip, 0) + count
        for ip, count in dst_counts.items():
            talker_counts[ip] = talker_counts.get(ip, 0) + count
        top_talkers = sorted(talker_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        talkers_text = ", ".join([f"{ip}: {count}" for ip, count in top_talkers])
        # Top conversations (pair of IPs)
        conv_counts = {}
        for p in self._packets:
            ip_layer = p.get_layer("IPv4")
            if ip_layer:
                src = ip_layer.get_field("src_addr", "?")
                dst = ip_layer.get_field("dst_addr", "?")
                # Ensure consistent ordering
                if src < dst:
                    key = (src, dst)
                else:
                    key = (dst, src)
                conv_counts[key] = conv_counts.get(key, 0) + 1
        top_convs = sorted(conv_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        convs_text = ", ".join([f"{a} <-> {b}: {count}" for (a, b), count in top_convs])
        # Update labels
        self.labels['total_packets'].setText(f"{total_packets:,}")
        self.labels['total_bytes'].setText(f"{total_bytes:,}")
        self.labels['pps'].setText(f"{pps:.2f}")
        self.labels['bps'].setText(f"{bps:.2f}")
        self.protocol_label.setText(proto_text)
        self.talkers_label.setText(talkers_text)
        self.conversations_label.setText(convs_text)

    def update_display(self):
        """Update the display (called by timer)."""
        self._update_stats()