"""ARP decoder."""
from .base import BaseDecoder


class ARPDecoder(BaseDecoder):
    def decode(self, packet_bytes: bytes):
        pass

    def supports(self, packet_bytes: bytes) -> bool:
        return False