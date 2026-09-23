from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QColor, QBrush
from wiretap.models.packet import Packet
from typing import List


class PacketTableModel(QAbstractTableModel):
    """Table model for displaying packets."""

    def __init__(self, packets: List[Packet] = None):
        super().__init__()
        self._packets: List[Packet] = packets or []
        self.headers = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._packets)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.headers)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        packet = self._packets[row]
        if role == Qt.ItemDataRole.DisplayRole:
            return self._get_display_data(packet, col)
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 4, 5):  # No., Protocol, Length
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        elif role == Qt.ItemDataRole.BackgroundRole:
            # Alternate row colors for better readability
            if row % 2 == 0:
                return QColor(Qt.GlobalColor.white)
            else:
                return QColor(240, 240, 255)  # very light blue
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]
        return None

    def _get_display_data(self, packet: Packet, col: int):
        # Extract summary information from packet
        src = "?"
        dst = "?"
        proto = "?"
        info = ""
        length = len(packet.raw_bytes)

        # Try to get IPv4 layer
        ip_layer = packet.get_layer("IPv4")
        if ip_layer:
            src = ip_layer.get_field("src_addr", "?")
            dst = ip_layer.get_field("dst_addr", "?")
            proto_num = ip_layer.get_field("protocol", "?")
            proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            proto = proto_map.get(proto_num, str(proto_num))

            if proto == "TCP":
                tcp_layer = packet.get_layer("TCP")
                if tcp_layer:
                    sport = tcp_layer.get_field("src_port", "?")
                    dport = tcp_layer.get_field("dst_port", "?")
                    flags = []
                    if tcp_layer.get_field("flags_syn"): flags.append("S")
                    if tcp_layer.get_field("flags_ack"): flags.append("A")
                    if tcp_layer.get_field("flags_fin"): flags.append("F")
                    if tcp_layer.get_field("flags_rst"): flags.append("R")
                    if tcp_layer.get_field("flags_psh"): flags.append("P")
                    if tcp_layer.get_field("flags_urg"): flags.append("U")
                    info = f"{sport} > {dport} [{''.join(flags)}]"
            elif proto == "UDP":
                udp_layer = packet.get_layer("UDP")
                if udp_layer:
                    sport = udp_layer.get_field("src_port", "?")
                    dport = udp_layer.get_field("dst_port", "?")
                    info = f"{sport} > {dport}"
            elif proto == "ICMP":
                icmp_layer = packet.get_layer("ICMP")
                if icmp_layer:
                    icmp_type = icmp_layer.get_field("type", "?")
                    icmp_code = icmp_layer.get_field("code", "?")
                    info = f"type={icmp_type}, code={icmp_code}"

        # ARP layer
        arp_layer = packet.get_layer("ARP")
        if arp_layer:
            src = arp_layer.get_field("sender_hw", "?")
            dst = arp_layer.get_field("target_hw", "?")
            proto = "ARP"
            info = arp_layer.get_field("description", "")

        # DNS layer
        dns_layer = packet.get_layer("DNS")
        if dns_layer:
            info = dns_layer.get_field("query_response", "") + " " + \
                   dns_layer.get_field("opcode_str", "") + " " + \
                   dns_layer.get_field("rcode_str", "")

        # HTTP layer
        http_layer = packet.get_layer("HTTP")
        if http_layer:
            if http_layer.get_field("message_type") == "request":
                method = http_layer.get_field("method", "?")
                path = http_layer.get_field("path", "?")
                info = f"{method} {path}"
            else:
                status = http_layer.get_field("status_code", "?")
                reason = http_layer.get_field("reason_phrase", "?")
                info = f"{status} {reason}"

        # Time formatting
        time_str = packet.timestamp
        if isinstance(time_str, float):
            from datetime import datetime
            time_str = datetime.fromtimestamp(time_str).strftime("%H:%M:%S.%f")[:-3]

        # Packet number (just row index + 1)
        no = str(row + 1)

        if col == 0:  # No.
            return no
        elif col == 1:  # Time
            return time_str
        elif col == 2:  # Source
            return src
        elif col == 3:  # Destination
            return dst
        elif col == 4:  # Protocol
            return proto
        elif col == 5:  # Length
            return str(length)
        elif col == 6:  # Info
            return info
        return None

    def add_packet(self, packet: Packet):
        """Add a packet to the end of the model."""
        self.beginInsertRows(QModelIndex(), len(self._packets), len(self._packets))
        self._packets.append(packet)
        self.endInsertRows()

    def packet_at(self, row: int) -> Packet:
        """Return packet at given row."""
        if 0 <= row < len(self._packets):
            return self._packets[row]
        return None

    def clear(self):
        """Clear all packets."""
        self.beginRemoveRows(QModelIndex(), 0, len(self._packets) - 1)
        self._packets.clear()
        self.endRemoveRows()