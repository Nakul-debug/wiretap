from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QToolBar,
    QComboBox, QPushButton, QLineEdit, QLabel, QStatusBar,
    QTableView, QTreeView, QSplitter, QMessageBox, QSizePolicy,
    QTabWidget, QFileDialog, QStyle
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtGui import QAction, QFont, QPalette, QColor
import sys
import time
from datetime import datetime
from wiretap.gui.packet_table_model import PacketTableModel
from wiretap.gui.packet_details_view import PacketDetailsView
from wiretap.gui.flow_table_model import FlowTableModel
from wiretap.gui.statistics_widget import StatisticsWidget
from wiretap.capture.interface_manager import InterfaceManager
from wiretap.models.packet import Packet
from wiretap.models.flow import Flow
from wiretap.decoders.ethernet import EthernetDecoder
from wiretap.decoders.ipv4 import IPDecoder
from wiretap.decoders.tcp import TCPDecoder
from wiretap.decoders.udp import UDPDecoder
from wiretap.decoders.icmp import ICMPDecoder
from wiretap.decoders.dns import DNSDecoder
from wiretap.decoders.http import HTTPDecoder
from wiretap.decoders.arp import ARPDecoder


class CaptureWorker(QObject):
    """Worker object that runs packet capture in a thread and emits signals."""
    packet_received = pyqtSignal(object)  # emits Packet object
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, interface: str, bpf_filter: str = ""):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._is_running = False
        # Decoders for packet decoding (optional, can be done in GUI)
        self.decoders = [
            EthernetDecoder(),
            IPDecoder(),
            ARPDecoder(),
            TCPDecoder(),
            UDPDecoder(),
            ICMPDecoder(),
            DNSDecoder(),
            HTTPDecoder(),
        ]

    def run(self):
        """Start the packet capture loop."""
        from scapy.all import AsyncSniffer, Packet as ScapyPacket
        self._is_running = True

        def scapy_packet_handler(scapy_pkt: ScapyPacket):
            if not self._is_running:
                return
            try:
                # Convert Scapy packet to our Packet object
                raw_bytes = bytes(scapy_pkt)

                pkt = Packet(
                    raw_bytes=raw_bytes,
                    timestamp=scapy_pkt.time
                )

                # Ethernet
                ethernet_decoder = self.decoders[0]

                if ethernet_decoder.supports(raw_bytes):
                    ethernet = ethernet_decoder.decode(raw_bytes)
                    pkt.add_layer(ethernet)

                    next_protocol = ethernet.get_field("next_protocol")
                    offset = ethernet.get_field("payload_offset")

                    if offset is None:
                        offset = 14

                    payload = raw_bytes[offset:]

                    # ARP
                    if next_protocol == "ARP":
                        arp_decoder = self.decoders[2]

                        if arp_decoder.supports(payload):
                            pkt.add_layer(arp_decoder.decode(payload))

                    # IPv4
                    elif next_protocol == "IPv4":
                        ip_decoder = self.decoders[1]

                        if ip_decoder.supports(payload):
                            ip_layer = ip_decoder.decode(payload)
                            pkt.add_layer(ip_layer)

                            ip_offset = ip_layer.get_field("payload_offset")

                            if ip_offset is None:
                                ip_offset = 20

                            transport_payload = payload[ip_offset:]

                            transport_protocol = ip_layer.get_field("next_protocol")

                            # TCP
                            if transport_protocol == "TCP":
                                tcp_decoder = self.decoders[3]

                                if tcp_decoder.supports(transport_payload):
                                    tcp_layer = tcp_decoder.decode(transport_payload)
                                    pkt.add_layer(tcp_layer)

                                    tcp_offset = tcp_layer.get_field("payload_offset")

                                    if tcp_offset is None:
                                        tcp_offset = 20

                                    app_payload = transport_payload[tcp_offset:]

                                    # HTTP
                                    http_decoder = self.decoders[7]

                                    if app_payload and http_decoder.supports(app_payload):
                                        pkt.add_layer(http_decoder.decode(app_payload))

                            # UDP
                            elif transport_protocol == "UDP":
                                udp_decoder = self.decoders[4]

                                if udp_decoder.supports(transport_payload):
                                    udp_layer = udp_decoder.decode(transport_payload)
                                    pkt.add_layer(udp_layer)

                                    udp_offset = udp_layer.get_field("payload_offset")

                                    if udp_offset is None:
                                        udp_offset = 8

                                    app_payload = transport_payload[udp_offset:]

                                    # DNS
                                    dns_decoder = self.decoders[6]

                                    if app_payload and dns_decoder.supports(app_payload):
                                        pkt.add_layer(dns_decoder.decode(app_payload))

                            # ICMP
                            elif transport_protocol == "ICMP":
                                icmp_decoder = self.decoders[5]

                                if icmp_decoder.supports(transport_payload):
                                    pkt.add_layer(icmp_decoder.decode(transport_payload))

                self.packet_received.emit(pkt)
                # Optionally decode packet here or leave to GUI
                # For now, we emit raw packet; decoding can be done in GUI
                self.packet_received.emit(pkt)
            except Exception as e:
                self.error.emit(f"Error processing packet: {e}")

        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=scapy_packet_handler,
                filter=self.bpf_filter if self.bpf_filter else None,
                store=False
            )
            self.sniffer.start()
            while self._is_running:
                # Sleep briefly to allow checking _is_running
                time.sleep(0.1)
            self.sniffer.stop()
        except Exception as e:
            self.error.emit(f"Failed to start capture: {e}")
        finally:
            self.finished.emit()

    def stop(self):
        """Stop the capture."""
        self._is_running = False


class MainWindow(QMainWindow):
    """Main application window for WireTap."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("WireTap - Network Protocol Analyzer")
        self.setGeometry(100, 100, 1200, 800)

        # Packet data
        self.packets = []
        self.packet_model = PacketTableModel()
        self.current_packet: Packet = None

        # Capture worker and thread
        self.capture_thread = None
        self.capture_worker = None

        # Interface manager
        self.iface_mgr = InterfaceManager()
        # Flows dictionary for flow tracking
        self.flows = {}

        # Flow data
        self.flow_model = FlowTableModel()
        # Statistics widget
        self.statistics_widget = StatisticsWidget()
        # Flow table view
        self.flow_table_view = QTableView()
        self.flow_table_view.setModel(self.flow_model)
        # Packet table view
        self.packet_table = QTableView()
        self.packet_table.setModel(self.packet_model)
        # Packet details view
        self.packet_details = PacketDetailsView()
        # Tab widget
        self.tab_widget = QTabWidget()
        # Packet view widget (holds packet table and details)
        self.packet_view_widget = QWidget()
        self._setup_ui()
        self._setup_connections()
        self._populate_interface_combo()
        self.apply_modern_style()

    def apply_modern_style(self):
        """Apply a modern dark theme to the application."""
        # Set Fusion style for better cross-platform consistency
        from PyQt6.QtWidgets import QApplication
        QApplication.setStyle("Fusion")
        
        # Dark color palette
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        
        QApplication.instance().setPalette(dark_palette)
        
        # Apply stylesheet for additional styling
        self.setStyleSheet("""
            /* Main window and panels */
            QMainWindow {
                background-color: #353535;
            }
            
            /* Toolbar styling */
            QToolBar {
                background-color: #2b2b2b;
                border-bottom: 1px solid #444444;
                spacing: 4px;
                padding: 4px;
            }
            QToolBar QLabel {
                color: #ffffff;
                font-weight: bold;
            }
            QToolBar QComboBox, QToolBar QLineEdit {
                background-color: #404040;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 4px 8px;
                color: white;
                min-width: 100px;
            }
            QToolBar QComboBox::drop-down, QToolBar QLineEdit::clear-button {
                width: 0px; /* Hide default clear button */
            }
            QToolBar QComboBox QAbstractItemView {
                background-color: #404040;
                color: white;
                selection-background-color: #2a82da;
            }
            QToolBar QPushButton {
                background-color: #404040;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 6px 12px;
                color: white;
                font-weight: bold;
                min-width: 80px;
            }
            QToolBar QPushButton:hover {
                background-color: #4a4a4a;
                border-color: #666666;
            }
            QToolBar QPushButton:pressed {
                background-color: #3a3a3a;
            }
            QToolBar QPushButton:disabled {
                background-color: #2b2b2b;
                color: #666666;
                border-color: #444444;
            }
            QToolBar QSeparator {
                width: 1px;
                background-color: #444444;
                margin: 4px 8px;
            }
            
            /* Table views */
            QTableView {
                background-color: #2b2b2b;
                alternate-background-color: #323232;
                gridline-color: #444444;
                selection-background-color: #2a82da;
                color: white;
                border: none;
            }
            QTableView::item {
                padding: 4px;
                border-bottom: 1px solid #2b2b2b;
            }
            QTableView::item:selected {
                background-color: #2a82da;
            }
            QTableView::item:hover {
                background-color: #3a3a3a;
            }
            QHeaderView::section {
                background-color: #2b2b2b;
                color: #ffffff;
                padding: 8px 4px;
                border: 1px solid #444444;
                font-weight: bold;
                font-size: 9pt;
            }
            QHeaderView::section:horizontal {
                border-top: none;
                border-left: none;
            }
            QHeaderView::section:first {
                border-left: none;
            }
            
            /* Tab widget */
            QTabWidget::pane {
                border: 1px solid #444444;
                background-color: #2b2b2b;
                border-radius: 4px;
                top: -1px;
            }
            QTabWidget::tab-bar {
                alignment: left;
            }
            QTabBar::tab {
                background-color: #353535;
                color: #cccccc;
                border: 1px solid #444444;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 8px 16px;
                margin-right: 2px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #2b2b2b;
                color: #ffffff;
                border-bottom: 2px solid #2a82da;
            }
            QTabBar::tab:hover:!selected {
                background-color: #404040;
                color: #ffffff;
            }
            
            /* Group boxes and frames */
            QGroupBox, QFrame {
                border: 1px solid #444444;
                border-radius: 4px;
                margin-top: 8px;
                padding-top: 8px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                color: #ffffff;
            }
            
            /* Labels */
            QLabel {
                color: #ffffff;
            }
            
            /* Status bar */
            QStatusBar {
                background-color: #2b2b2b;
                border-top: 1px solid #444444;
                color: #cccccc;
                font-size: 9pt;
            }
            QStatusBar QLabel {
                padding: 2px 6px;
            }
            
            /* Menu bar (if present) */
            QMenuBar {
                background-color: #2b2b2b;
                color: white;
                border-bottom: 1px solid #444444;
            }
            QMenuBar::item {
                padding: 4px 8px;
                background-color: transparent;
            }
            QMenuBar::item:selected {
                background-color: #404040;
                border-radius: 3px;
            }
            QMenu {
                background-color: #353535;
                color: white;
                border: 1px solid #444444;
            }
            QMenu::item {
                padding: 4px 24px 4px 8px;
            }
            QMenu::item:selected {
                background-color: #2a82da;
                border-radius: 3px;
            }
            
            /* Line edits and combo boxes (outside toolbar) */
            QLineEdit, QComboBox {
                background-color: #404040;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 6px 8px;
                color: white;
                selection-background-color: #2a82da;
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #2a82da;
            }
            QComboBox QAbstractItemView {
                background-color: #404040;
                color: white;
                selection-background-color: #2a82da;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left-width: 1px;
                border-left-color: #555555;
                border-left-style: solid;
                border-top-right-radius: 3px;
                border-bottom-right-radius: 3px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 4px solid #ffffff;
                width: 0px;
                height: 0px;
            }
            
            /* Buttons (outside toolbar) */
            QPushButton {
                background-color: #404040;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 6px 12px;
                color: white;
                font-weight: bold;
                min-width: 60px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border-color: #666666;
            }
            QPushButton:pressed {
                background-color: #3a3a3a;
            }
            QPushButton:disabled {
                background-color: #2b2b2b;
                color: #666666;
                border-color: #444444;
            }
            
            /* Text edit and plain text edit */
            QTextEdit, QPlainTextEdit {
                background-color: #2b2b2b;
                color: white;
                border: 1px solid #555555;
                border-radius: 3px;
                selection-background-color: #2a82da;
            }
            
            /* Scroll bars */
            QScrollBar:vertical {
                background-color: #2b2b2b;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #555555;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #666666;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            
            QScrollBar:horizontal {
                background-color: #2b2b2b;
                height: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal {
                background-color: #555555;
                border-radius: 6px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #666666;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: none;
            }
            
            /* Splitter */
            QSplitter::handle {
                background-color: #444444;
            }
            QSplitter::handle:horizontal {
                width: 2px;
            }
            QSplitter::handle:vertical {
                height: 2px;
            }
            QSplitter::handle:hover {
                background-color: #555555;
            }
            
            /* Progress bar */
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                text-align: center;
                background-color: #2b2b2b;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #2a82da;
                border-radius: 2px;
            }
        """)

    def _setup_ui(self):
        """Create the user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Toolbar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # Interface selector
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        toolbar.addWidget(QLabel("Interface: "))
        toolbar.addWidget(self.interface_combo)

        # Filter
        toolbar.addSeparator()
        toolbar.addWidget(QLabel("Filter: "))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("e.g., tcp port 80")
        self.filter_edit.setMaximumWidth(200)
        toolbar.addWidget(self.filter_edit)

        # Start/Stop buttons
        self.start_action = QAction("Start", self)
        self.start_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        toolbar.addAction(self.start_action)
        self.stop_action = QAction("Stop", self)
        self.stop_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        self.stop_action.setEnabled(False)
        toolbar.addAction(self.stop_action)

        # Clear button
        clear_action = QAction("Clear", self)
        clear_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon))
        toolbar.addAction(clear_action)
        toolbar.addSeparator()

        # Export/Import actions
        self.export_action = QAction("Export PCAP", self)
        self.export_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        toolbar.addAction(self.export_action)
        
        self.export_csv_action = QAction("Export CSV", self)
        self.export_csv_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView))
        toolbar.addAction(self.export_csv_action)
        
        self.export_json_action = QAction("Export JSON", self)
        self.export_json_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
        toolbar.addAction(self.export_json_action)
        
        self.report_action = QAction("Generate Report", self)
        self.report_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
        toolbar.addAction(self.report_action)
        
        self.import_action = QAction("Import", self)
        self.import_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon))
        toolbar.addAction(self.import_action)
        
        self.save_db_action = QAction("Save to DB", self)
        self.save_db_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DriveFDIcon))
        toolbar.addAction(self.save_db_action)
        
        self.load_db_action = QAction("Load from DB", self)
        self.load_db_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon))
        toolbar.addAction(self.load_db_action)
        
        toolbar.addSeparator()
        
        # Packet count label
        self.packet_count_label = QLabel("Packets: 0")
        toolbar.addWidget(self.packet_count_label)

        # Tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Packet view tab
        packet_splitter = QSplitter(Qt.Orientation.Vertical)
        packet_splitter.addWidget(self.packet_table)
        packet_splitter.addWidget(self.packet_details)
        packet_splitter.setSizes([400, 300])
        self.packet_view_widget.setLayout(QVBoxLayout())
        self.packet_view_widget.layout().addWidget(packet_splitter)
        self.tab_widget.addTab(self.packet_view_widget, "Packets")

        # Flows tab
        self.tab_widget.addTab(self.flow_table_view, "Flows")

        # Statistics tab
        self.tab_widget.addTab(self.statistics_widget, "Statistics")

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _setup_connections(self):
        """Connect signals and slots."""
        self.start_action.triggered.connect(self.start_capture)
        self.stop_action.triggered.connect(self.stop_capture)
        self.interface_combo.currentIndexChanged.connect(self._on_interface_changed)
        self.filter_edit.returnPressed.connect(self._on_filter_changed)
        self.export_action.triggered.connect(self.export_packets)
        self.export_csv_action.triggered.connect(self.export_packets_csv)
        self.export_json_action.triggered.connect(self.export_packets_json)
        self.report_action.triggered.connect(self.generate_report)
        self.import_action.triggered.connect(self.import_packets)
        self.save_db_action.triggered.connect(self.save_to_database)
        self.load_db_action.triggered.connect(self.load_from_database)
        self.packet_table.selectionModel().selectionChanged.connect(self._on_packet_selected)
        self.packet_model.layoutChanged.connect(self._update_packet_count)

    def _populate_interface_combo(self):
        """Populate the interface combo box with available interfaces."""
        self.interface_combo.clear()
        interfaces = self.iface_mgr.get_interfaces()
        if not interfaces:
            QMessageBox.warning(self, "No Interfaces", "No network interfaces found.")
            return
        for iface in interfaces:
            text = f"{iface['name']} ({iface['description']}) - {iface['ip']}"
            self.interface_combo.addItem(text, iface['name'])

    def _on_interface_changed(self, index):
        """Handle interface selection change."""
        if index >= 0:
            self.selected_interface = self.interface_combo.itemData(index)
        else:
            self.selected_interface = None

    def _on_filter_changed(self):
        """Handle filter entry change (applied on Enter)."""
    def export_packets(self):
        """Export packets to a PCAP file."""
        if not self.packets:
            QMessageBox.information(self, "No Packets", "No packets to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Packets",
            "",
            "PCAP Files (*.pcap);;All Files (*)"
        )
        
        if filename:
            try:
                from scapy.utils import PcapWriter
                writer = PcapWriter(filename, sync=True)
                for packet in self.packets:
                    writer.write(packet.raw_bytes)
                writer.close()
                QMessageBox.information(self, "Export Successful", f"Exported {len(self.packets)} packets to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export packets: {str(e)}")

    def import_packets(self):
        """Import packets from a PCAP file."""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Import Packets",
            "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        
        if filename:
            try:
                from scapy.utils import PcapReader
                from wiretap.models.packet import Packet
                import time
                
                # Clear existing packets
                self.clear_packets()
                
                count = 0
                for scapy_packet in PcapReader(filename):
                    # Convert Scapy packet to our Packet format
                    raw_bytes = bytes(scapy_packet)
                    packet = Packet(raw_bytes, time.time())
                    self.packets.append(packet)
                    self.packet_model.add_packet(packet)
                    self.statistics_widget.add_packet(packet)
                    self._track_flow(packet)
                    count += 1
                
                self.packet_table.scrollToBottom()
                self._update_packet_count()
                QMessageBox.information(self, "Import Successful", f"Imported {count} packets from {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Failed to import packets: {str(e)}")

        # Filter will be applied when capture (re)starts
        pass

    def export_packets_csv(self):
        """Export packets to a CSV file."""
        if not self.packets:
            QMessageBox.information(self, "No Packets", "No packets to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Packets to CSV",
            "",
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if filename:
            try:
                from wiretap.storage.csv_exporter import export_packets_to_csv
                export_packets_to_csv(self.packets, filename)
                QMessageBox.information(self, "Export Successful", f"Exported {len(self.packets)} packets to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export packets to CSV: {str(e)}")

    def export_packets_json(self):
        """Export packets to a JSON file."""
        if not self.packets:
            QMessageBox.information(self, "No Packets", "No packets to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Packets to JSON",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                from wiretap.storage.csv_exporter import export_packets_to_json
                export_packets_to_json(self.packets, filename)
                QMessageBox.information(self, "Export Successful", f"Exported {len(self.packets)} packets to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export packets to JSON: {str(e)}")

    def save_to_database(self):
        """Save packets and flows to SQLite database."""
        if not self.packets and not self.flows:
            QMessageBox.information(self, "No Data", "No packets or flows to save.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save to Database",
            "",
            "SQLite Database (*.db);;All Files (*)"
        )
        
        if filename:
            try:
                from wiretap.storage.sqlite_store import SQLStore
                db = SQLStore(filename)
                
                # Save packets
                packet_ids = db.save_packets(self.packets)
                
                # Save flows
                flow_ids = db.save_flows(self.flows)
                
                QMessageBox.information(
                    self, 
                    "Database Save Successful", 
                    f"Saved {len(self.packets)} packets and {len(self.flows)} flows to {filename}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to save to database: {str(e)}")

    def load_from_database(self):
        """Load packets and flows from SQLite database."""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load from Database",
            "",
            "SQLite Database (*.db);;All Files (*)"
        )
        
        if filename:
            try:
                from wiretap.storage.sqlite_store import SQLStore
                db = SQLStore(filename)
                
                # Load packets
                packets = db.load_packets()
                
                # Load flows
                flows = db.load_flows()
                
                # Clear existing data
                self.clear_packets()
                self.flows.clear()
                self.flow_model.clear()
                
                # Add loaded packets
                for packet in packets:
                    self.packets.append(packet)
                    self.packet_model.add_packet(packet)
                    self.statistics_widget.add_packet(packet)
                    self._track_flow(packet)
                
                # Update flow model with loaded flows
                for flow_key, flow in flows.items():
                    self.flows[flow_key] = flow
                    self.flow_model.update_flow(flow_key, flow)
                
                self.packet_table.scrollToBottom()
                self._update_packet_count()
                
                QMessageBox.information(
                    self, 
                    "Database Load Successful", 
                    f"Loaded {len(packets)} packets and {len(flows)} flows from {filename}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to load from database: {str(e)}")

    def generate_report(self):
        """Generate an HTML report of the capture."""
        if not self.packets:
            QMessageBox.information(self, "No Packets", "No packets to generate report for.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Generate Report",
            "",
            "HTML Files (*.html);;All Files (*)"
        )
        
        if filename:
            try:
                # Generate HTML report
                html_content = self._generate_html_report()
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                QMessageBox.information(self, "Report Generated", f"Report generated successfully at {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Report Error", f"Failed to generate report: {str(e)}")

    def _generate_html_report(self):
        """Generate an HTML report of the capture."""
        # Calculate statistics
        total_packets = len(self.packets)
        total_bytes = sum(len(p.raw_bytes) for p in self.packets)
        
        # Protocol distribution
        proto_counts = {}
        for p in self.packets:
            proto = "Unknown"
            ip_layer = p.get_layer("IPv4")
            if ip_layer:
                proto_num = ip_layer.get_field("protocol", "?")
                proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
                proto = proto_map.get(proto_num, str(proto_num))
            else:
                if p.get_layer("TCP"):
                    proto = "TCP"
                elif p.get_layer("UDP"):
                    proto = "UDP"
                elif p.get_layer("ICMP"):
                    proto = "ICMP"
                elif p.get_layer("ARP"):
                    proto = "ARP"
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
        
        # Top talkers (by source IP)
        src_counts = {}
        dst_counts = {}
        for p in self.packets:
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
        
        # Top conversations (pair of IPs)
        conv_counts = {}
        for p in self.packets:
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
        
        # Flow statistics
        total_flows = len(self.flows)
        
        # Generate HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>WireTap Network Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2 {{ color: #2c3e50; }}
        .summary {{ background-color: #ecf0f1; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .section {{ margin-bottom: 30px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .stats-container {{ display: flex; flex-wrap: wrap; gap: 20px; }}
        .stat-box {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; flex: 1; min-width: 200px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #3498db; }}
        .stat-label {{ font-size: 14px; color: #7f8c8d; }}
    </style>
</head>
<body>
    <h1>WireTap Network Analysis Report</h1>
    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <h2>Capture Summary</h2>
        <div class="stats-container">
            <div class="stat-box">
                <div class="stat-value">{total_packets}</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{total_bytes:,}</div>
                <div class="stat-label">Total Bytes</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{total_flows}</div>
                <div class="stat-label">Total Flows</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Protocol Distribution</h2>
        <table>
            <tr><th>Protocol</th><th>Packet Count</th><th>Percentage</th></tr>
"""
        
        for proto, count in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            html += f"            <tr><td>{proto}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>\n"
        
        html += """        </table>
    </div>
    
    <div class="section">
        <h2>Top Talkers (by packet count)</h2>
        <table>
            <tr><th>IP Address</th><th>Packet Count</th></tr>
"""
        
        for ip, count in top_talkers:
            html += f"            <tr><td>{ip}</td><td>{count}</td></tr>\n"
        
        html += """        </table>
    </div>
    
    <div class="section">
        <h2>Top Conversations</h2>
        <table>
            <tr><th>Connection</th><th>Packet Count</th></tr>
"""
        
        for (src, dst), count in top_convs:
            html += f"            <tr><td>{src} <-> {dst}</td><td>{count}</td></tr>\n"
        
        html += """        </table>
    </div>
    
    <div class="section">
        <h2>Flow Information</h2>
        <p>Total flows detected: {total_flows}</p>
        <p>Note: For detailed flow information, please use the Flows tab in the application.</p>
    </div>
</body>
</html>
""".format(total_flows=total_flows)
        
        return html

    def start_capture(self):
        """Start packet capture."""
        iface = self.interface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "No Interface", "Please select a network interface.")
            return

        # Disable UI during capture
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.interface_combo.setEnabled(False)
        self.filter_edit.setEnabled(False)
        self.status_bar.showMessage(f"Capturing on {iface}...")

        # Create and start capture worker in a thread
        self.capture_thread = QThread()
        self.capture_worker = CaptureWorker(iface, self.filter_edit.text())
        self.capture_worker.moveToThread(self.capture_thread)
        self.capture_thread.started.connect(self.capture_worker.run)
        self.capture_worker.packet_received.connect(self._on_packet_received)
        self.capture_worker.finished.connect(self.capture_thread.quit)
        self.capture_worker.finished.connect(self.capture_worker.deleteLater)
        self.capture_thread.finished.connect(self.capture_thread.deleteLater)
        self.capture_worker.error.connect(self._on_capture_error)
        self.capture_thread.start()

    def stop_capture(self):
        """Stop packet capture."""
        if self.capture_worker:
            self.capture_worker.stop()
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.filter_edit.setEnabled(True)
        self.status_bar.showMessage("Capture stopped")

    def _on_packet_received(self, packet: Packet):
        """Handle a newly captured packet."""
        self.packets.append(packet)
        self.packet_model.add_packet(packet)
        self.statistics_widget.add_packet(packet)
        self._track_flow(packet)
        # Optionally auto-scroll to the latest packet
        self.packet_table.scrollToBottom()

    def _on_capture_error(self, error_msg: str):
        """Handle capture error."""
        QMessageBox.critical(self, "Capture Error", error_msg)
        self.stop_capture()

    def _on_packet_selected(self, selected, deselected):
        """Handle packet selection in the table."""
        indexes = selected.indexes()
        if indexes:
            row = indexes[0].row()
            packet = self.packet_model.packet_at(row)
            if packet:
                self.current_packet = packet
                self.packet_details.setPacket(packet)
        else:
            self.packet_details.setPacket(None)

    def _update_packet_count(self):
        """Update the packet count label."""
        count = len(self.packets)
        self.packet_count_label.setText(f"Packets: {count}")


    def _track_flow(self, packet: Packet):
        """Update flow statistics from a packet."""
        # Extract IPv4 layer
        ip_layer = packet.get_layer("IPv4")
        if not ip_layer:
            return
        src_ip = ip_layer.get_field("src_addr")
        dst_ip = ip_layer.get_field("dst_addr")
        proto_num = ip_layer.get_field("protocol")
        # Map protocol number to name
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto = proto_map.get(proto_num, str(proto_num))
        src_port = dst_port = None
        if proto == "TCP":
            tcp_layer = packet.get_layer("TCP")
            if tcp_layer:
                src_port = tcp_layer.get_field("src_port")
                dst_port = tcp_layer.get_field("dst_port")
        elif proto == "UDP":
            udp_layer = packet.get_layer("UDP")
            if udp_layer:
                src_port = udp_layer.get_field("src_port")
                dst_port = udp_layer.get_field("dst_port")
        # For ICMP and others, ports remain None
        flow_key = f"{src_ip}:{src_port if src_port is not None else ''}->{dst_ip}:{dst_port if dst_port is not None else ''}:{proto}"
        # Normalize key: remove trailing colons if needed
        # We'll keep as is for simplicity
        if flow_key not in self.flows:
            flow = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto
            )
            self.flows[flow_key] = flow
        else:
            flow = self.flows[flow_key]
        # Update flow with packet
        flow.update(len(packet.raw_bytes), packet.timestamp)
        # Update flow model
        self.flow_model.update_flow(flow_key, flow)



def main():
    from PyQt6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()