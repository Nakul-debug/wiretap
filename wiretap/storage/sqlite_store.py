"""SQLite storage for packets and flows."""
import sqlite3
import os
from typing import List, Dict, Any, Optional
from wiretap.models.packet import Packet
from wiretap.models.flow import Flow


class SQLStore:
    """SQLite storage for packets and flows."""
    
    def __init__(self, db_path: str = "wiretap.db"):
        """Initialize the SQLite store."""
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize the database tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create packets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                raw_bytes BLOB
            )
        ''')
        
        # Create packet layers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet_layers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER,
                layer_name TEXT,
                field_name TEXT,
                field_value TEXT,
                FOREIGN KEY (packet_id) REFERENCES packets (id)
            )
        ''')
        
        # Create flows table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_count INTEGER,
                byte_count INTEGER,
                first_seen REAL,
                last_seen REAL,
                tcp_state TEXT,
                application_protocol TEXT,
                forward_packet_count INTEGER,
                reverse_packet_count INTEGER,
                forward_byte_count INTEGER,
                reverse_byte_count INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_packet(self, packet: Packet) -> int:
        """Save a packet to the database and return its ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert packet
        cursor.execute(
            "INSERT INTO packets (timestamp, raw_bytes) VALUES (?, ?)",
            (packet.timestamp, packet.raw_bytes)
        )
        packet_id = cursor.lastrowid
        
        # Insert packet layers
        for layer in packet.layers:
            for field_name, field_value in layer.fields.items():
                cursor.execute(
                    "INSERT INTO packet_layers (packet_id, layer_name, field_name, field_value) VALUES (?, ?, ?, ?)",
                    (packet_id, layer.name, field_name, str(field_value))
                )
        
        conn.commit()
        conn.close()
        return packet_id
    
    def save_packets(self, packets: List[Packet]) -> List[int]:
        """Save multiple packets to the database and return their IDs."""
        return [self.save_packet(packet) for packet in packets]
    
    def save_flow(self, flow: Flow) -> int:
        """Save a flow to the database and return its ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO flows (
                src_ip, dst_ip, src_port, dst_port, protocol,
                packet_count, byte_count, first_seen, last_seen,
                tcp_state, application_protocol,
                forward_packet_count, reverse_packet_count,
                forward_byte_count, reverse_byte_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol,
            flow.packet_count, flow.byte_count, flow.first_seen, flow.last_seen,
            flow.tcp_state, flow.application_protocol,
            flow.forward_packet_count, flow.reverse_packet_count,
            flow.forward_byte_count, flow.reverse_byte_count
        ))
        
        flow_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return flow_id
    
    def save_flows(self, flows: Dict[str, Flow]) -> Dict[str, int]:
        """Save multiple flows to the database and return their IDs."""
        result = {}
        for flow_key, flow in flows.items():
            result[flow_key] = self.save_flow(flow)
        return result
    
    def load_packets(self) -> List[Packet]:
        """Load all packets from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all packets
        cursor.execute("SELECT id, timestamp, raw_bytes FROM packets ORDER BY id")
        packet_rows = cursor.fetchall()
        
        packets = []
        for packet_id, timestamp, raw_bytes in packet_rows:
            # Create packet
            packet = Packet(raw_bytes, timestamp)
            
            # Get layers for this packet
            cursor.execute(
                "SELECT layer_name, field_name, field_value FROM packet_layers WHERE packet_id = ?",
                (packet_id,)
            )
            layer_rows = cursor.fetchall()
            
            # Group fields by layer
            layers_dict = {}
            for layer_name, field_name, field_value in layer_rows:
                if layer_name not in layers_dict:
                    layers_dict[layer_name] = {}
                layers_dict[layer_name][field_name] = field_value
            
            # Convert to DecodedLayer objects (simplified - we'll just store the data)
            # In a full implementation, we'd need to reconstruct the actual DecodedLayer objects
            # For now, we'll just note that we have the layer data
            # This is a limitation of this simple implementation
            
            packets.append(packet)
        
        conn.close()
        return packets
    
    def load_flows(self) -> Dict[str, Flow]:
        """Load all flows from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                   packet_count, byte_count, first_seen, last_seen,
                   tcp_state, application_protocol,
                   forward_packet_count, reverse_packet_count,
                   forward_byte_count, reverse_byte_count
            FROM flows
        ''')
        flow_rows = cursor.fetchall()
        
        flows = {}
        for row in flow_rows:
            (src_ip, dst_ip, src_port, dst_port, protocol,
             packet_count, byte_count, first_seen, last_seen,
             tcp_state, application_protocol,
             forward_packet_count, reverse_packet_count,
             forward_byte_count, reverse_byte_count) = row
            
            flow_key = f"{src_ip}:{src_port if src_port is not None else ''}->{dst_ip}:{dst_port if dst_port is not None else ''}:{protocol}"
            # Normalize key: remove trailing colons if needed
            flow_key = flow_key.replace("::", ":").rstrip(":")
            
            flow = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol
            )
            flow.packet_count = packet_count
            flow.byte_count = byte_count
            flow.first_seen = first_seen
            flow.last_seen = last_seen
            flow.tcp_state = tcp_state
            flow.application_protocol = application_protocol
            flow.forward_packet_count = forward_packet_count
            flow.reverse_packet_count = reverse_packet_count
            flow.forward_byte_count = forward_byte_count
            flow.reverse_byte_count = reverse_byte_count
            
            flows[flow_key] = flow
        
        conn.close()
        return flows