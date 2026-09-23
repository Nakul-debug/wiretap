"""UDP decoder."""
from .base import BaseDecoder, DecodedLayer


class UDPDecoder(BaseDecoder):
    """Decode UDP datagrams."""

    def supports(self, packet_bytes: bytes) -> bool:
        """UDP decoder supports packets with at least 8 bytes."""
        return len(packet_bytes) >= 8

    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode UDP header and return a DecodedLayer."""
        if len(packet_bytes) < 8:
            layer = DecodedLayer("UDP")
            layer.add_field("error", "Packet too short for UDP header")
            return layer

        src_port = int.from_bytes(packet_bytes[0:2], byteorder='big')
        dst_port = int.from_bytes(packet_bytes[2:4], byteorder='big')
        length = int.from_bytes(packet_bytes[4:6], byteorder='big')
        checksum = int.from_bytes(packet_bytes[6:8], byteorder='big')

        layer = DecodedLayer("UDP")
        layer.add_field("src_port", src_port)
        layer.add_field("dst_port", dst_port)
        layer.add_field("length", length)
        layer.add_field("checksum", f"0x{checksum:04x}")
        layer.add_field("payload_offset", 8)

        return layer