"""Data models for packets."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from wiretap.decoders.base import DecodedLayer


@dataclass
class Packet:
    """Represents a captured network packet."""
    raw_bytes: bytes
    timestamp: float = field(default_factory=datetime.now().timestamp)
    layers: List[DecodedLayer] = field(default_factory=list)

    def add_layer(self, layer: DecodedLayer):
        """Add a decoded protocol layer to the packet."""
        self.layers.append(layer)

    def get_layer(self, name: str) -> Optional[DecodedLayer]:
        """Get the first layer with the given name."""
        for layer in self.layers:
            if layer.name == name:
                return layer
        return None