from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from wiretap.models.flow import Flow
from typing import List, Dict


class FlowTableModel(QAbstractTableModel):
    """Table model for displaying network flows."""

    def __init__(self, flows: Dict[str, Flow] = None):
        super().__init__()
        self._flows: Dict[str, Flow] = flows or {}
        self.headers = ["Src IP:Port", "Dst IP:Port", "Protocol", "Packets", "Bytes", "Duration", "State"]
        # We'll keep a list of flow keys for ordering
        self._flow_keys: List[str] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._flow_keys)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.headers)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        flow_key = self._flow_keys[row]
        flow = self._flows[flow_key]
        if role == Qt.ItemDataRole.DisplayRole:
            return self._get_display_data(flow, col)
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (3, 4, 5):  # Packets, Bytes, Duration
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]
        return None

    def _get_display_data(self, flow: Flow, col: int):
        # Format source and destination as "ip:port"
        src_str = f"{flow.src_ip}:{flow.src_port if flow.src_port is not None else ''}"
        dst_str = f"{flow.dst_ip}:{flow.dst_port if flow.dst_port is not None else ''}"
        # If port is None, we show just ip (or ip:)
        if flow.src_port is None:
            src_str = flow.src_ip
        if flow.dst_port is None:
            dst_str = flow.dst_ip

        proto = flow.protocol if flow.protocol is not None else "?"
        packets = flow.packet_count
        bytes_ = flow.byte_count
        # Duration
        if flow.first_seen and flow.last_seen:
            duration = flow.last_seen - flow.first_seen
            duration_str = f"{duration:.2f}s"
        else:
            duration_str = "0.00s"
        # State (simplified)
        state = flow.tcp_state if flow.tcp_state is not None else flow.application_protocol or "?"

        if col == 0:  # Src IP:Port
            return src_str
        elif col == 1:  # Dst IP:Port
            return dst_str
        elif col == 2:  # Protocol
            return proto
        elif col == 3:  # Packets
            return str(packets)
        elif col == 4:  # Bytes
            return str(bytes_)
        elif col == 5:  # Duration
            return duration_str
        elif col == 6:  # State
            return state
        return None

    def update_flow(self, flow_key: str, flow: Flow):
        """Update or add a flow."""
        if flow_key not in self._flows:
            # New flow
            self._flows[flow_key] = flow
            self._flow_keys.append(flow_key)
            # Insert row at the end
            row = len(self._flow_keys) - 1
            self.beginInsertRows(QModelIndex(), row, row)
            self.endInsertRows()
        else:
            # Existing flow: we just need to notify that data changed
            # Find the row
            try:
                row = self._flow_keys.index(flow_key)
                # Emit dataChanged for the entire row
                top_left = self.index(row, 0)
                bottom_right = self.index(row, self.columnCount() - 1)
                self.dataChanged.emit(top_left, bottom_right)
            except ValueError:
                pass  # should not happen

    def remove_flow(self, flow_key: str):
        """Remove a flow."""
        if flow_key in self._flows:
            row = self._flow_keys.index(flow_key)
            self.beginRemoveRows(QModelIndex(), row, row)
            del self._flows[flow_key]
            del self._flow_keys[row]
            self.endRemoveRows()

    def clear(self):
        """Clear all flows."""
        if not self._flow_keys:
            return
        self.beginRemoveRows(QModelIndex(), 0, len(self._flow_keys) - 1)
        self._flows.clear()
        self._flow_keys.clear()
        self.endRemoveRows()

    def flow_at(self, row: int) -> Flow:
        """Return flow at given row."""
        if 0 <= row < len(self._flow_keys):
            flow_key = self._flow_keys[row]
            return self._flows[flow_key]
        return None
