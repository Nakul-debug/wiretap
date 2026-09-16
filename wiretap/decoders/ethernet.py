"""Ethernet II decoder."""
from .base import BaseDecoder


class EthernetDecoder(BaseDecoder):
    def decode(self, packet_bytes: bytes):
        # Implementation to be added
        pass

    def supports(self, packet_bytes: bytes) -> bool:
        # Implementation to be added
        return False