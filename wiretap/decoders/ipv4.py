"""IPv4 decoder."""
from .base import BaseDecoder


class IPDecoder(BaseDecoder):
    def decode(self, packet_bytes: bytes):
        pass

    def supports(self, packet_bytes: bytes) -> bool:
        return False