"""UDP decoder."""
from .base import BaseDecoder


class UDPDecoder(BaseDecoder):
    def decode(self, packet_bytes: bytes):
        pass

    def supports(self, packet_bytes: bytes) -> bool:
        return False