"""ICMP decoder."""
from .base import BaseDecoder


class ICMPDecoder(BaseDecoder):
    def decode(self, packet_bytes: bytes):
        pass

    def supports(self, packet_bytes: bytes) -> bool:
        return False