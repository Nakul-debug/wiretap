"""TCP decoder."""
from .base import BaseDecoder, DecodedLayer


class TCPDecoder(BaseDecoder):
    """Decode TCP segments."""

    def supports(self, packet_bytes: bytes) -> bool:
        """TCP decoder supports packets with at least 20 bytes."""
        return len(packet_bytes) >= 20

    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode TCP header and return a DecodedLayer."""
        if len(packet_bytes) < 20:
            layer = DecodedLayer("TCP")
            layer.add_field("error", "Packet too short for TCP header")
            return layer

        # Extract fields from the first 20 bytes
        src_port = int.from_bytes(packet_bytes[0:2], byteorder='big')
        dst_port = int.from_bytes(packet_bytes[2:4], byteorder='big')
        seq_num = int.from_bytes(packet_bytes[4:8], byteorder='big')
        ack_num = int.from_bytes(packet_bytes[8:12], byteorder='big')
        data_offset_reserved = packet_bytes[12]
        data_offset = (data_offset_reserved >> 4) & 0x0F  # number of 32-bit words
        reserved = data_offset_reserved & 0x0F
        flags = packet_bytes[13]
        window_size = int.from_bytes(packet_bytes[14:16], byteorder='big')
        checksum = int.from_bytes(packet_bytes[16:18], byteorder='big')
        urgent_ptr = int.from_bytes(packet_bytes[18:20], byteorder='big')

        header_length = data_offset * 4
        if header_length < 20:
            header_length = 20
        if header_length > len(packet_bytes):
            header_length = len(packet_bytes)

        layer = DecodedLayer("TCP")
        layer.add_field("src_port", src_port)
        layer.add_field("dst_port", dst_port)
        layer.add_field("seq_num", seq_num)
        layer.add_field("ack_num", ack_num)
        layer.add_field("data_offset", data_offset)
        layer.add_field("reserved", reserved)
        layer.add_field("flags_fin", bool(flags & 0x01))
        layer.add_field("flags_syn", bool(flags & 0x02))
        layer.add_field("flags_rst", bool(flags & 0x04))
        layer.add_field("flags_psh", bool(flags & 0x08))
        layer.add_field("flags_ack", bool(flags & 0x10))
        layer.add_field("flags_urg", bool(flags & 0x20))
        layer.add_field("flags_ece", bool(flags & 0x40))
        layer.add_field("flags_cwr", bool(flags & 0x80))
        layer.add_field("window_size", window_size)
        layer.add_field("checksum", f"0x{checksum:04x}")
        layer.add_field("urgent_ptr", urgent_ptr)
        layer.add_field("payload_offset", header_length)

        # If there are options (header_length > 20), we could note them
        if header_length > 20:
            layer.add_field("options_present", True)
            layer.add_field("options_length", header_length - 20)
        else:
            layer.add_field("options_present", False)

        return layer