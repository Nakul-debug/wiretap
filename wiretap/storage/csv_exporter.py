"""CSV exporter for packets and flows."""
import csv
import json
from datetime import datetime
from typing import List, Dict, Any
from wiretap.models.packet import Packet
from wiretap.models.flow import Flow


def export_packets_to_csv(packets: List[Packet], filename: str) -> None:
    """Export packets to a CSV file."""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write header
        writer.writerow(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        
        # Write packet data
        for i, packet in enumerate(packets, 1):
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
                time_str = datetime.fromtimestamp(time_str).strftime("%H:%M:%S.%f")[:-3]

            writer.writerow([i, time_str, src, dst, proto, length, info])


def export_packets_to_json(packets: List[Packet], filename: str) -> None:
    """Export packets to a JSON file."""
    packets_data = []
    for packet in packets:
        packet_dict = {
            "timestamp": packet.timestamp,
            "length": len(packet.raw_bytes),
            "layers": []
        }
        
        for layer in packet.layers:
            layer_dict = {
                "name": layer.name,
                "fields": layer.fields
            }
            packet_dict["layers"].append(layer_dict)
            
        packets_data.append(packet_dict)
    
    with open(filename, 'w') as jsonfile:
        json.dump(packets_data, jsonfile, indent=2)


def export_flows_to_csv(flows: Dict[str, Flow], filename: str) -> None:
    """Export flows to a CSV file."""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write header
        writer.writerow(['Src IP:Port', 'Dst IP:Port', 'Protocol', 'Packets', 'Bytes', 'Duration', 'State'])
        
        # Write flow data
        for flow_key, flow in flows.items():
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

            writer.writerow([src_str, dst_str, proto, packets, bytes_, duration_str, state])


def export_flows_to_json(flows: Dict[str, Flow], filename: str) -> None:
    """Export flows to a JSON file."""
    flows_data = {}
    for flow_key, flow in flows.items():
        flows_data[flow_key] = {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "first_seen": flow.first_seen,
            "last_seen": flow.last_seen,
            "tcp_state": flow.tcp_state,
            "application_protocol": flow.application_protocol,
            "forward_packet_count": flow.forward_packet_count,
            "reverse_packet_count": flow.reverse_packet_count,
            "forward_byte_count": flow.forward_byte_count,
            "reverse_byte_count": flow.reverse_byte_count
        }
    
    with open(filename, 'w') as jsonfile:
        json.dump(flows_data, jsonfile, indent=2)