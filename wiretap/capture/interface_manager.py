"""Interface manager for discovering network interfaces."""
from typing import List, Dict, Optional
from scapy.arch import get_if_list, get_if_addr
from scapy.error import Scapy_Exception


class InterfaceManager:
    """Manages network interface discovery and selection."""

    def __init__(self):
        self.interfaces: List[Dict[str, str]] = []
        self._refresh_interfaces()

    def _refresh_interfaces(self):
        """Refresh the list of network interfaces."""
        self.interfaces = []
        try:
            if_names = get_if_list()
            for if_name in if_names:
                try:
                    ip_addr = get_if_addr(if_name)
                except Scapy_Exception:
                    ip_addr = "0.0.0.0"  # No IP address
                # Try to get a description (not always available)
                description = if_name  # fallback
                self.interfaces.append({
                    "name": if_name,
                    "description": description,
                    "ip": ip_addr,
                })
        except Exception as e:
            # If we can't get interfaces, leave the list empty
            print(f"Warning: Could not list interfaces: {e}")

    def get_interfaces(self) -> List[Dict[str, str]]:
        """Return a list of available interfaces."""
        return self.interfaces.copy()

    def get_interface_by_name(self, name: str) -> Optional[Dict[str, str]]:
        """Return interface details by name, or None if not found."""
        for iface in self.interfaces:
            if iface["name"] == name:
                return iface
        return None

    def get_default_interface(self) -> Optional[Dict[str, str]]:
        """Attempt to determine the default interface (non-loopback with an IP)."""
        for iface in self.interfaces:
            if iface["ip"] != "0.0.0.0" and not iface["name"].startswith("lo"):
                return iface
        # Fallback to first non-loopback
        for iface in self.interfaces:
            if not iface["name"].startswith("lo"):
                return iface
        # If all else fails, return the first interface
        if self.interfaces:
            return self.interfaces[0]
        return None