"""IPv4 decoder."""
from .base import BaseDecoder, DecodedLayer


class IPDecoder(BaseDecoder):
    """Decode IPv4 packets."""

    def supports(self, packet_bytes: bytes) -> bool:
        """IPv4 decoder supports packets with at least 20 bytes and version 4."""
        if len(packet_bytes) < 20:
            return False
        version = packet_bytes[0] >> 4
        return version == 4

    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode IPv4 header and return a DecodedLayer."""
        if len(packet_bytes) < 20:
            layer = DecodedLayer("IPv4")
            layer.add_field("error", "Packet too short for IPv4 header")
            return layer

        # Extract fields from the first 20 bytes
        byte0 = packet_bytes[0]
        version = byte0 >> 4
        ihl = byte0 & 0x0F  # Internet Header Length in 32-bit words
        DSCP_ECN = packet_bytes[1]
        total_length = int.from_bytes(packet_bytes[2:4], byteorder='big')
        identification = int.from_bytes(packet_bytes[4:6], byteorder='big')
        flags_fragment = int.from_bytes(packet_bytes[6:8], byteorder='big')
        flags = flags_fragment >> 13
        fragment_offset = flags_fragment & 0x1FFF
        ttl = packet_bytes[8]
        proto = packet_bytes[9]
        header_checksum = int.from_bytes(packet_bytes[10:12], byteorder='big')
        src_addr = packet_bytes[12:16]
        dst_addr = packet_bytes[16:20]

        header_length = ihl * 4
        if header_length < 20:
            header_length = 20  # minimum, though shouldn't happen if ihl >=5
        if header_length > len(packet_bytes):
            header_length = len(packet_bytes)  # truncate to available length

        layer = DecodedLayer("IPv4")
        layer.add_field("version", version)
        layer.add_field("ihl", ihl)
        layer.add_field("header_length", header_length)
        layer.add_field("dscp", DSCP_ECN >> 2)
        layer.add_field("ecn", DSCP_ECN & 0x03)
        layer.add_field("total_length", total_length)
        layer.add_field("identification", identification)
        layer.add_field("flags", flags)
        layer.add_field("fragment_offset", fragment_offset)
        layer.add_field("ttl", ttl)
        layer.add_field("protocol", proto)
        layer.add_field("header_checksum", f"0x{header_checksum:04x}")
        layer.add_field("src_addr", self._ip_to_str(src_addr))
        layer.add_field("dst_addr", self._ip_to_str(dst_addr))
        layer.add_field("payload_offset", header_length)

        # Determine next protocol based on protocol number
        protocol_map = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            89: "OSPF",
        }
        next_proto = protocol_map.get(proto, f"Unknown ({proto})")
        layer.add_field("next_protocol", next_proto)

        # If there are options (header_length > 20), we could note them
        if header_length > 20:
            layer.add_field("options_present", True)
            layer.add_field("options_length", header_length - 20)
        else:
            layer.add_field("options_present", False)

        return layer

    @staticmethod
    def _ip_to_str(ip_bytes: bytes) -> str:
        """Convert IPv4 address bytes to dotted decimal string."""
        return '.'.join(str(b) for b in ip_bytes)