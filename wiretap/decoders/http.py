"""HTTP decoder."""
from .base import BaseDecoder


class HTTPDecoder(BaseDecoder):
    def decode(self, packet_bytes: bytes):
        pass

    def supports(self, packet_bytes: bytes) -> bool:
        return False