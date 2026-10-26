"""Base decoder class."""
from abc import ABC, abstractmethod
from typing import Dict, Any


class DecodedLayer:
    """Base class for a decoded protocol layer."""

    def __init__(self, name: str):
        self.name = name
        self.fields: Dict[str, Any] = {}

    def add_field(self, name: str, value: Any):
        """Add a field to the layer."""
        self.fields[name] = value

    def get_field(self, name: str, default: Any = None) -> Any:
        """Get a field by name."""
        return self.fields.get(name, default)


class BaseDecoder(ABC):
    """Abstract base protocol decoder."""

    @abstractmethod
    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode packet bytes and return a DecodedLayer."""
        pass

    @abstractmethod
    def supports(self, packet_bytes: bytes) -> bool:
        """Return True if this decoder can parse the packet."""
        pass