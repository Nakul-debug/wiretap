"""DNS decoder."""
from .base import BaseDecoder, DecodedLayer


class DNSDecoder(BaseDecoder):
    """Decode DNS packets."""

    def supports(self, packet_bytes: bytes) -> bool:
        """DNS decoder supports packets with at least 12 bytes."""
        return len(packet_bytes) >= 12

    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode DNS header and return a DecodedLayer."""
        if len(packet_bytes) < 12:
            layer = DecodedLayer("DNS")
            layer.add_field("error", "Packet too short for DNS header")
            return layer

        # DNS header: 12 bytes
        transaction_id = int.from_bytes(packet_bytes[0:2], byteorder='big')
        flags = int.from_bytes(packet_bytes[2:4], byteorder='big')
        qdcount = int.from_bytes(packet_bytes[4:6], byteorder='big')
        ancount = int.from_bytes(packet_bytes[6:8], byteorder='big')
        nscount = int.from_bytes(packet_bytes[8:10], byteorder='big')
        arcount = int.from_bytes(packet_bytes[10:12], byteorder='big')

        # Extract flag fields
        qr = (flags >> 15) & 0x01  # Query/Response
        opcode = (flags >> 11) & 0x0F
        aa = (flags >> 10) & 0x01  # Authoritative Answer
        tc = (flags >> 9) & 0x01   # Truncated
        rd = (flags >> 8) & 0x01   # Recursion Desired
        ra = (flags >> 7) & 0x01   # Recursion Available
        z = (flags >> 4) & 0x07    # Z (reserved)
        rcode = flags & 0x0F       # Response Code

        layer = DecodedLayer("DNS")
        layer.add_field("transaction_id", transaction_id)
        layer.add_field("qr", qr)
        layer.add_field("opcode", opcode)
        layer.add_field("aa", aa)
        layer.add_field("tc", tc)
        layer.add_field("rd", rd)
        layer.add_field("ra", ra)
        layer.add_field("z", z)
        layer.add_field("rcode", rcode)
        layer.add_field("qdcount", qdcount)
        layer.add_field("ancount", ancount)
        layer.add_field("nscount", nscount)
        layer.add_field("arcount", arcount)
        layer.add_field("payload_offset", 12)  # We'll update after parsing question section

        # Map opcode and rcode to strings
        opcode_str = {
            0: "Query",
            1: "IQuery",
            2: "Status",
            # 3-15 reserved
        }.get(opcode, f"Unknown ({opcode})")

        rcode_str = {
            0: "No Error",
            1: "Format Error",
            2: "Server Failure",
            3: "Name Error",
            4: "Not Implemented",
            5: "Refused",
            # 6-15 reserved
        }.get(rcode, f"Unknown ({rcode})")

        layer.add_field("opcode_str", opcode_str)
        layer.add_field("rcode_str", rcode_str)
        layer.add_field("query_response", "Response" if qr else "Query")

        # Parse question section if present
        offset = 12
        for i in range(qdcount):
            if offset >= len(packet_bytes):
                layer.add_field("error", f"Question section {i+1} incomplete")
                break
            # Parse domain name (simplified: no compression handling)
            domain, offset = self._parse_domain_name(packet_bytes, offset)
            if offset is None:
                layer.add_field("error", f"Failed to parse domain name in question {i+1}")
                break
            # After domain name: qtype (2 bytes), qclass (2 bytes)
            if offset + 4 > len(packet_bytes):
                layer.add_field("error", f"Question {i+1} missing type/class")
                break
            qtype = int.from_bytes(packet_bytes[offset:offset+2], byteorder='big')
            qclass = int.from_bytes(packet_bytes[offset+2:offset+4], byteorder='big')
            offset += 4
            layer.add_field(f"qdomain_{i}", domain)
            layer.add_field(f"qtype_{i}", qtype)
            layer.add_field(f"qclass_{i}", qclass)
            # Map qtype to string
            qtype_str = {
                1: "A",
                2: "NS",
                5: "CNAME",
                6: "SOA",
                12: "PTR",
                15: "MX",
                16: "TXT",
                28: "AAAA",
            }.get(qtype, f"Unknown ({qtype})")
            layer.add_field(f"qtype_str_{i}", qtype_str)

        # Update payload offset to after the question section (we ignore answer/auth/additional for now)
        layer.add_field("payload_offset", offset)

        return layer

    def _parse_domain_name(self, packet_bytes: bytes, offset: int):
        """Parse a domain name from the packet bytes starting at offset.
        Returns (domain_string, new_offset) or (None, None) on error.
        This does not handle name compression (pointers).
        """
        labels = []
        while offset < len(packet_bytes):
            length = packet_bytes[offset]
            if length == 0:
                # End of domain name
                offset += 1
                break
            # Check if this is a pointer (compression): the two highest bits set?
            # For simplicity, we assume no compression. If the length byte has the top two bits set, it's a pointer.
            if (length & 0xC0) == 0xC0:
                # Pointer: we don't handle compression for now
                # We'll just skip the pointer and break
                offset += 2
                break
            offset += 1
            if offset + length > len(packet_bytes):
                return None, None
            label = packet_bytes[offset:offset+length]
            try:
                labels.append(label.decode('utf-8'))
            except UnicodeDecodeError:
                labels.append(label.decode('latin-1'))  # fallback
            offset += length
        domain = '.'.join(labels) if labels else ''
        return domain, offset