"""Capture manager for live packet capture."""
import logging
from threading import Lock
from typing import Callable, Optional
from scapy.all import AsyncSniffer, Packet as ScapyPacket

from wiretap.models.packet import Packet
from wiretap.decoders.base import DecodedLayer


logger = logging.getLogger(__name__)


class CaptureManager:
    """Manages live packet capture using Scapy."""

    def __init__(self):
        self._sniffer: Optional[AsyncSniffer] = None
        self._packet_callback: Optional[Callable[[Packet], None]] = None
        self._lock = Lock()
        self._is_running = False

    def start(self, interface: str, packet_callback: Callable[[Packet], None],
              bpf_filter: str = ""):
        """
        Start capturing packets on the given interface.

        Args:
            interface: Name of the network interface to capture on.
            packet_callback: Function to call for each captured packet.
            bpf_filter: Optional BPF filter string (e.g., "tcp port 80").
        """
        with self._lock:
            if self._is_running:
                logger.warning("Capture is already running")
                return

            self._packet_callback = packet_callback

            def scapy_packet_handler(scapy_pkt: ScapyPacket):
                """Convert Scapy packet to our Packet object and invoke callback."""
                try:
                    # Create our Packet object
                    pkt = Packet(
                        raw_bytes=bytes(scapy_pkt),
                        timestamp=scapy_pkt.time
                    )
                    if self._packet_callback:
                        self._packet_callback(pkt)
                except Exception as e:
                    logger.error(f"Error processing packet: {e}", exc_info=True)

            try:
                self._sniffer = AsyncSniffer(
                    iface=interface,
                    prn=scapy_packet_handler,
                    filter=bpf_filter if bpf_filter else None,
                    store=False  # Don't store packets in memory, we handle via callback
                )
                self._sniffer.start()
                self._is_running = True
                logger.info(f"Started capture on interface {interface}")
            except Exception as e:
                logger.error(f"Failed to start capture: {e}", exc_info=True)
                self._sniffer = None
                self._packet_callback = None
                raise

    def stop(self):
        """Stop the packet capture."""
        with self._lock:
            if not self._is_running or self._sniffer is None:
                return
            try:
                self._sniffer.stop()
                self._sniffer = None
                self._is_running = False
                logger.info("Stopped capture")
            except Exception as e:
                logger.error(f"Error stopping capture: {e}", exc_info=True)
            finally:
                self._sniffer = None
                self._is_running = False
                self._packet_callback = None

    @property
    def is_running(self) -> bool:
        """Return True if capture is currently running."""
        return self._is_running