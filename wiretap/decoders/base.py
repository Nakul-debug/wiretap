"""Base decoder class."""
from abc import ABC, abstractmethod


class BaseDecoder(ABC):
    @abstractmethod
    def decode(self, packet_bytes: bytes):
        pass

    @abstractmethod
    def supports(self, packet_bytes: bytes) -> bool:
        pass