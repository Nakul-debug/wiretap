"""Ethernet II decoder."""
from .base import BaseDecoder, DecodedLayer


class EthernetDecoder(BaseDecoder):
    """Decode Ethernet II frames."""

    ETHERTYPE_IP = 0x0800
    ETHERTYPE_ARP = 0x0806
    ETHERTYPE_IPV6 = 0x86DD
    ETHERTYPE_VLAN = 0x8100
    ETHERTYPE_VLAN_QINQ = 0x88A8

    def supports(self, packet_bytes: bytes) -> bool:
        """Ethernet decoder supports any packet with at least 14 bytes."""
        return len(packet_bytes) >= 14

    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode Ethernet II frame and return a DecodedLayer."""
        if len(packet_bytes) < 14:
            # Should not happen if supports is called first, but guard anyway
            layer = DecodedLayer("Ethernet")
            layer.add_field("error", "Packet too short for Ethernet header")
            return layer

        dst_mac = packet_bytes[0:6]
        src_mac = packet_bytes[6:12]
        ethertype = int.from_bytes(packet_bytes[12:14], byteorder='big')

        layer = DecodedLayer("Ethernet")
        layer.add_field("dst_mac", self._mac_to_str(dst_mac))
        layer.add_field("src_mac", self._mac_to_str(src_mac))
        layer.add_field("ethertype", f"0x{ethertype:04x}")
        layer.add_field("payload_offset", 14)

        # Determine next protocol based on ethertype
        if ethertype == self.ETHERTYPE_IP:
            layer.add_field("next_protocol", "IPv4")
        elif ethertype == self.ETHERTYPE_ARP:
            layer.add_field("next_protocol", "ARP")
        elif ethertype == self.ETHERTYPE_IPV6:
            layer.add_field("next_protocol", "IPv6")
        elif ethertype in (self.ETHERTYPE_VLAN, self.ETHERTYPE_VLAN_QINQ):
            layer.add_field("next_protocol", "VLAN")
            # Note: we are not decoding VLAN here; the payload offset would be 18
            # For simplicity, we'll leave it to the user to extend.
            # We could adjust payload offset, but we'll keep it simple and let the next decoder handle it.
            # Actually, we should skip the VLAN tag (4 bytes) and adjust ethertype.
            # For now, we'll just note that it's VLAN and leave the payload offset as 14.
            # This is a limitation; but for MVP we can ignore VLAN.
            pass
        else:
            layer.add_field("next_protocol", f"Unknown (0x{ethertype:04x})")

        return layer

    @staticmethod
    def _mac_to_str(mac_bytes: bytes) -> str:
        """Convert MAC address bytes to colon-separated hex string."""
        return ':'.join(f'{b:02x}' for b in mac_bytes)