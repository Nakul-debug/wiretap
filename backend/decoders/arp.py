"""ARP decoder."""
from .base import BaseDecoder, DecodedLayer


class ARPDecoder(BaseDecoder):
    """Decode ARP packets."""

    def supports(self, packet_bytes: bytes) -> bool:
        """ARP decoder supports packets with at least 8 bytes."""
        return len(packet_bytes) >= 8

    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode ARP packet and return a DecodedLayer."""
        if len(packet_bytes) < 8:
            layer = DecodedLayer("ARP")
            layer.add_field("error", "Packet too short for ARP header")
            return layer

        hw_type = int.from_bytes(packet_bytes[0:2], byteorder='big')
        proto_type = int.from_bytes(packet_bytes[2:4], byteorder='big')
        hw_len = packet_bytes[4]
        proto_len = packet_bytes[5]
        opcode = int.from_bytes(packet_bytes[6:8], byteorder='big')

        # Calculate offsets
        sender_hw_start = 8
        sender_proto_start = sender_hw_start + hw_len
        target_hw_start = sender_proto_start + proto_len
        target_proto_start = target_hw_start + hw_len
        total_length = target_proto_start + proto_len

        # Extract addresses (if we have enough bytes)
        sender_hw = packet_bytes[sender_hw_start:sender_proto_start] if len(packet_bytes) >= sender_proto_start else b''
        sender_proto = packet_bytes[sender_proto_start:target_hw_start] if len(packet_bytes) >= target_hw_start else b''
        target_hw = packet_bytes[target_hw_start:target_proto_start] if len(packet_bytes) >= target_proto_start else b''
        target_proto = packet_bytes[target_proto_start:total_length] if len(packet_bytes) >= total_length else b''

        layer = DecodedLayer("ARP")
        layer.add_field("hw_type", hw_type)
        layer.add_field("proto_type", f"0x{proto_type:04x}")
        layer.add_field("hw_len", hw_len)
        layer.add_field("proto_len", proto_len)
        layer.add_field("opcode", opcode)
        layer.add_field("sender_hw", self._bytes_to_hex(sender_hw))
        layer.add_field("sender_proto", self._bytes_to_hex(sender_proto))
        layer.add_field("target_hw", self._bytes_to_hex(target_hw))
        layer.add_field("target_proto", self._bytes_to_hex(target_proto))
        layer.add_field("payload_offset", total_length)

        # Map opcode to description
        opcode_desc = {
            1: "Request",
            2: "Reply",
            3: "Reverse Request",
            4: "Reverse Reply",
            5: "DRARP Request",
            6: "DRARP Reply",
            7: "DRARP Error",
            8: "InARP Request",
            9: "InARP Reply",
        }
        if opcode in opcode_desc:
            layer.add_field("description", opcode_desc[opcode])
        else:
            layer.add_field("description", f"Unknown opcode {opcode}")

        # For Ethernet/IPv4 ARP, we can make a more readable description
        if hw_type == 1 and proto_type == 0x0800 and hw_len == 6 and proto_len == 4:
            sender_mac = self._mac_to_str(sender_hw)
            sender_ip = self._ip_to_str(sender_proto)
            target_mac = self._mac_to_str(target_hw)
            target_ip = self._ip_to_str(target_proto)
            if opcode == 1:  # Request
                layer.add_field("description", f"Who has {target_ip}? Tell {sender_ip}")
                layer.add_field("sender_mac", sender_mac)
                layer.add_field("sender_ip", sender_ip)
                layer.add_field("target_ip", target_ip)
            elif opcode == 2:  # Reply
                layer.add_field("description", f"{sender_ip} is at {sender_mac}")
                layer.add_field("sender_mac", sender_mac)
                layer.add_field("sender_ip", sender_ip)
                layer.add_field("target_mac", target_mac)
                layer.add_field("target_ip", target_ip)

        return layer

    @staticmethod
    def _bytes_to_hex(b: bytes) -> str:
        """Convert bytes to hex string."""
        return b.hex()

    @staticmethod
    def _mac_to_str(mac_bytes: bytes) -> str:
        """Convert MAC address bytes to colon-separated hex string."""
        if len(mac_bytes) != 6:
            return ':'.join(f'{b:02x}' for b in mac_bytes)
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    @staticmethod
    def _ip_to_str(ip_bytes: bytes) -> str:
        """Convert IPv4 address bytes to dotted decimal string."""
        if len(ip_bytes) != 4:
            return '.'.join(str(b) for b in ip_bytes)
        return '.'.join(str(b) for b in ip_bytes)