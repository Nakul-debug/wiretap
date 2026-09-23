from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import QTextEdit
from wiretap.models.packet import Packet
from wiretap.decoders.base import DecodedLayer


class PacketDetailsView(QTextEdit):
    """Widget to display packet protocol layers and fields as formatted text."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        # Use a monospaced font for better alignment of values
        font = QFont("Monospace")
        font.setPointSize(9)
        self.setFont(font)

    def setPacket(self, packet: Packet):
        """Display the given packet's layers and fields."""
        self.clear()

        if not packet:
            return

        lines = []
        lines.append(f"<b>Timestamp:</b> {packet.timestamp}")
        lines.append(f"<b>Length:</b> {len(packet.raw_bytes)} bytes")
        lines.append("")  # blank line

        # Add each layer
        for layer in packet.layers:
            lines.append(f"<b>Layer: {layer.name}</b>")
            for field_name, value in layer.fields.items():
                # Format value for display
                if isinstance(value, bytes):
                    try:
                        value_str = value.decode('utf-8', errors='replace')
                    except Exception:
                        value_str = value.hex()
                else:
                    value_str = str(value)
                lines.append(f"  <b>{field_name}:</b> {value_str}")
            lines.append("")  # blank line between layers

        self.setHtml("<br>".join(lines))
        # Move cursor to top
        self.moveCursor(QTextCursor.MoveOperation.Start)