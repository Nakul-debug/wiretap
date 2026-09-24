from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QHeaderView, QLabel, QTreeWidget, QTreeWidgetItem, QVBoxLayout
from wiretap.models.packet import Packet
from wiretap.decoders.base import DecodedLayer


class PacketDetailsView(QFrame):
    """Collapsible protocol-layer inspector for a selected decoded packet."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("panel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 14)
        layout.setSpacing(8)

        self.title = QLabel("Packet details")
        self.title.setObjectName("sectionTitle")
        self.caption = QLabel("Select a packet to inspect its protocol layers.")
        self.caption.setObjectName("muted")
        layout.addWidget(self.title)
        layout.addWidget(self.caption)

        self.empty_title = QLabel("No packet selected")
        self.empty_title.setObjectName("emptyTitle")
        self.empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_description = QLabel("Select a packet to inspect its protocol layers.")
        self.empty_description.setObjectName("emptyDescription")
        self.empty_description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty_title)
        layout.addWidget(self.empty_description)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setIndentation(14)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.hide()
        layout.addWidget(self.tree, 1)

    @staticmethod
    def _display_value(value) -> str:
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8", errors="replace")
            except Exception:
                return value.hex()
        return str(value)

    def setPacket(self, packet: Packet):
        """Display a packet's actual decoded layers and fields."""
        self.tree.clear()
        if packet is None:
            self.title.setText("Packet details")
            self.caption.setText("Select a packet to inspect its protocol layers.")
            self.empty_title.show()
            self.empty_description.show()
            self.tree.hide()
            return

        timestamp = packet.timestamp
        if isinstance(timestamp, (int, float)):
            timestamp = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]
        self.title.setText(f"Packet details  ·  {len(packet.raw_bytes):,} bytes")
        self.caption.setText(f"Captured at {timestamp}")
        self.empty_title.hide()
        self.empty_description.hide()
        self.tree.show()

        for layer in packet.layers:
            section = QTreeWidgetItem([layer.name, ""])
            section.setFirstColumnSpanned(True)
            section.setExpanded(True)
            font = section.font(0)
            font.setBold(True)
            section.setFont(0, font)
            self.tree.addTopLevelItem(section)
            for field_name, value in layer.fields.items():
                section.addChild(QTreeWidgetItem([
                    field_name.replace("_", " ").title(), self._display_value(value)
                ]))
