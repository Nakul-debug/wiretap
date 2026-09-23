"""ICMP decoder."""
from .base import BaseDecoder, DecodedLayer


class ICMPDecoder(BaseDecoder):
    """Decode ICMP packets."""

    def supports(self, packet_bytes: bytes) -> bool:
        """ICMP decoder supports packets with at least 4 bytes."""
        return len(packet_bytes) >= 4

    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode ICMP header and return a DecodedLayer."""
        if len(packet_bytes) < 4:
            layer = DecodedLayer("ICMP")
            layer.add_field("error", "Packet too short for ICMP header")
            return layer

        icmp_type = packet_bytes[0]
        icmp_code = packet_bytes[1]
        checksum = int.from_bytes(packet_bytes[2:4], byteorder='big')

        layer = DecodedLayer("ICMP")
        layer.add_field("type", icmp_type)
        layer.add_field("code", icmp_code)
        layer.add_field("checksum", f"0x{checksum:04x}")
        layer.add_field("payload_offset", 4)

        # Map common type/code to description
        type_desc = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            6: "Alternate Host Address",
            8: "Echo Request",
            9: "Router Advertisement",
            10: "Router Solicitation",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp",
            14: "Timestamp Reply",
            15: "Information Request",
            16: "Information Reply",
            17: "Address Mask Request",
            18: "Address Mask Reply",
        }
        if icmp_type in type_desc:
            layer.add_field("description", type_desc[icmp_type])
        else:
            layer.add_field("description", f"Unknown Type {icmp_type}")

        # For certain types, there are additional fields we could decode
        # For example, Echo Request/Reply have identifier and sequence number
        if icmp_type in (0, 8) and len(packet_bytes) >= 8:
            identifier = int.from_bytes(packet_bytes[4:6], byteorder='big')
            sequence = int.from_bytes(packet_bytes[6:8], byteorder='big')
            layer.add_field("identifier", identifier)
            layer.add_field("sequence_number", sequence)
            if icmp_type == 0:
                layer.add_field("description", "Echo Reply")
            else:
                layer.add_field("description", "Echo Request")

        return layer