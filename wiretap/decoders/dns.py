"""DNS decoder."""
from .base import BaseDecoder


class DNSDecoder(BaseDecoder):
    def decode(self, packet_bytes: bytes):
        pass

    def supports(self, packet_bytes: bytes) -> bool:
        return False