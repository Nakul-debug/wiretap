"""A lightweight statistics dashboard derived from the existing packet list."""

import time
from collections import Counter
from typing import List

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QFrame, QGridLayout, QLabel, QProgressBar, QScrollArea, QVBoxLayout, QWidget

from wiretap.models.packet import Packet


def packet_protocol(packet: Packet) -> str:
    ip_layer = packet.get_layer("IPv4")
    if ip_layer:
        return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip_layer.get_field("protocol"), "Other")
    if packet.get_layer("ARP"):
        return "ARP"
    return "Other"


class StatisticsWidget(QScrollArea):
    """Scrollable overview of metrics available directly from captured packets."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packets: List[Packet] = []
        self._start_time = time.time()
        self.setWidgetResizable(True)
        root = QWidget()
        root.setObjectName("appRoot")
        self.setWidget(root)
        self.layout = QVBoxLayout(root)
        self.layout.setContentsMargins(14, 12, 14, 14)
        self.layout.setSpacing(12)
        self._init_ui()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update_display)
        self._timer.start(1000)

    def _panel(self, title: str) -> tuple[QFrame, QVBoxLayout]:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 12, 14, 14)
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        layout.addWidget(title_label)
        return panel, layout

    def _init_ui(self):
        heading = QLabel("Capture statistics")
        heading.setObjectName("sectionTitle")
        self.layout.addWidget(heading)
        self.empty = QLabel("Capture some traffic to generate statistics.")
        self.empty.setObjectName("emptyDescription")
        self.layout.addWidget(self.empty)

        summary, summary_layout = self._panel("Capture summary")
        grid = QGridLayout()
        self.summary_labels = {}
        for index, (key, label) in enumerate((("packets", "Packets"), ("bytes", "Bytes"), ("pps", "Capture rate"), ("protocols", "Protocols"))):
            name = QLabel(label.upper())
            name.setObjectName("metricLabel")
            value = QLabel("0")
            value.setObjectName("metricValue")
            grid.addWidget(name, index // 2, (index % 2) * 2)
            grid.addWidget(value, index // 2, (index % 2) * 2 + 1)
            self.summary_labels[key] = value
        summary_layout.addLayout(grid)
        self.layout.addWidget(summary)

        distribution, self.distribution_layout = self._panel("Protocol distribution")
        self.layout.addWidget(distribution)
        talkers, self.talkers_layout = self._panel("Top talkers")
        self.layout.addWidget(talkers)
        self.layout.addStretch(1)

    @staticmethod
    def _clear_rows(layout: QVBoxLayout):
        while layout.count() > 1:
            item = layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()

    def set_packets(self, packets: List[Packet]):
        self._packets = list(packets)
        self._start_time = time.time()
        self._update_stats()

    def add_packet(self, packet: Packet):
        self._packets.append(packet)

    def _update_stats(self):
        total = len(self._packets)
        self.empty.setVisible(total == 0)
        total_bytes = sum(len(packet.raw_bytes) for packet in self._packets)
        elapsed = max(time.time() - self._start_time, 0.001)
        counts = Counter(packet_protocol(packet) for packet in self._packets)
        self.summary_labels["packets"].setText(f"{total:,}")
        self.summary_labels["bytes"].setText(f"{total_bytes:,}")
        self.summary_labels["pps"].setText(f"{total / elapsed:.1f} pkt/s" if total else "0 pkt/s")
        self.summary_labels["protocols"].setText(str(len(counts)))

        self._clear_rows(self.distribution_layout)
        if counts:
            for protocol, count in counts.most_common():
                row = QWidget()
                row_layout = QGridLayout(row)
                row_layout.setContentsMargins(0, 2, 0, 2)
                label = QLabel(protocol)
                value = QLabel(f"{count:,}  ({count / total:.0%})")
                value.setObjectName("muted")
                bar = QProgressBar()
                bar.setTextVisible(False)
                bar.setRange(0, total)
                bar.setValue(count)
                row_layout.addWidget(label, 0, 0)
                row_layout.addWidget(value, 0, 1)
                row_layout.addWidget(bar, 1, 0, 1, 2)
                self.distribution_layout.addWidget(row)

        self._clear_rows(self.talkers_layout)
        endpoints = Counter()
        for packet in self._packets:
            ip = packet.get_layer("IPv4")
            if ip:
                endpoints.update((ip.get_field("src_addr", "?"), ip.get_field("dst_addr", "?")))
        if endpoints:
            for address, count in endpoints.most_common(5):
                self.talkers_layout.addWidget(QLabel(f"{address}   ·   {count:,} packets"))
        else:
            message = QLabel("No IP conversations detected yet.")
            message.setObjectName("muted")
            self.talkers_layout.addWidget(message)

    def update_display(self):
        self._update_stats()
