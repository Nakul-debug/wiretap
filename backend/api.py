"""Local HTTP bridge between the Wiretap engine and the React application.

Run with ``python -m uvicorn wiretap.api:app --reload``.  This module keeps the
capture engine in-process; it does not send captured traffic to a remote service.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.analysis import ConnectionDiagnosticEngine, MLAnomalyDetector, RetransmissionDetector, RTTEstimator, ThreatDetector, TimePatternDetector
from backend.capture.capture_manager import CaptureManager
from backend.capture.interface_manager import InterfaceManager
from backend.decoders.arp import ARPDecoder
from backend.decoders.dns import DNSDecoder
from backend.decoders.ethernet import EthernetDecoder
from backend.decoders.icmp import ICMPDecoder
from backend.decoders.ipv4 import IPDecoder
from backend.decoders.tcp import TCPDecoder
from backend.decoders.udp import UDPDecoder
from backend.models.flow import Flow
from backend.models.packet import Packet
from backend.query.engine import QueryEngine
from backend.query.parser import QueryParser
from backend.storage.sqlite_store import SQLStore

app = FastAPI(title="Wiretap local API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])


class StartCapture(BaseModel):
    interface: str
    bpf_filter: str = ""


class NaturalLanguageQuery(BaseModel):
    query: str


class DatabasePath(BaseModel):
    path: str = "wiretap.db"


class WiretapService:
    """Coordinates capture, decoder pipeline, analyses, and in-memory data."""

    def __init__(self) -> None:
        self.capture = CaptureManager()
        self.interfaces = InterfaceManager()
        self.packets: list[Packet] = []
        self.flows: dict[str, Flow] = {}
        self.lock = Lock()
        self.started_at: float | None = None
        self.elapsed_seconds = 0.0
        self.threats = ThreatDetector()
        self.ml_detector = MLAnomalyDetector()
        self.ml_alerts: list[Any] = []
        self.rtt = RTTEstimator()
        self.retransmissions = RetransmissionDetector()
        self.time_patterns = TimePatternDetector()
        self.connection_health = ConnectionDiagnosticEngine()

    def decode(self, packet: Packet) -> None:
        """Run captured Ethernet frames through the available decoders."""
        raw = packet.raw_bytes
        ethernet = EthernetDecoder().decode(raw)
        packet.add_layer(ethernet)
        offset = ethernet.get_field("payload_offset", 14)
        kind = ethernet.get_field("next_protocol")
        payload = raw[offset:]
        if kind == "ARP":
            packet.add_layer(ARPDecoder().decode(payload)); return
        if kind != "IPv4" or not IPDecoder().supports(payload):
            return
        ip = IPDecoder().decode(payload)
        packet.add_layer(ip)
        transport = payload[ip.get_field("payload_offset", 20):]
        protocol = ip.get_field("next_protocol")
        if protocol == "TCP" and TCPDecoder().supports(transport):
            tcp = TCPDecoder().decode(transport); packet.add_layer(tcp)
            app_payload = transport[tcp.get_field("payload_offset", 20):]
            if (tcp.get_field("src_port") == 53 or tcp.get_field("dst_port") == 53) and DNSDecoder().supports(app_payload):
                packet.add_layer(DNSDecoder().decode(app_payload))
        elif protocol == "UDP" and UDPDecoder().supports(transport):
            udp = UDPDecoder().decode(transport); packet.add_layer(udp)
            app_payload = transport[udp.get_field("payload_offset", 8):]
            if (udp.get_field("src_port") == 53 or udp.get_field("dst_port") == 53) and DNSDecoder().supports(app_payload):
                packet.add_layer(DNSDecoder().decode(app_payload))
        elif protocol == "ICMP" and ICMPDecoder().supports(transport):
            packet.add_layer(ICMPDecoder().decode(transport))

    def ingest(self, packet: Packet) -> None:
        self.decode(packet)
        with self.lock:
            self.packets.append(packet)
            # Bound memory while retaining a substantial inspection window.
            if len(self.packets) > 10_000:
                self.packets.pop(0)
            self._update_flow(packet)
            self.threats.analyse(packet)
            ml_alert = self.ml_detector.analyse(packet)
            if ml_alert:
                self.ml_alerts.append(ml_alert)
            self.rtt.analyse(packet)
            self.retransmissions.analyse(packet)
            self.time_patterns.analyse(packet)
            self.connection_health.analyse(packet)

    def clear(self) -> None:
        """Clear the current session without stopping a running capture."""
        with self.lock:
            self.packets.clear(); self.flows.clear(); self.started_at = datetime.now().timestamp() if self.capture.is_running else None; self.elapsed_seconds = 0.0
            self.threats.reset(); self.ml_detector.reset(); self.ml_alerts.clear(); self.rtt.reset(); self.retransmissions.reset()
            self.time_patterns = TimePatternDetector(); self.connection_health = ConnectionDiagnosticEngine()

    def _update_flow(self, packet: Packet) -> None:
        ip = packet.get_layer("IPv4")
        if not ip:
            return
        transport = packet.get_layer("TCP") or packet.get_layer("UDP")
        src, dst = str(ip.get_field("src_addr")), str(ip.get_field("dst_addr"))
        protocol = "TCP" if packet.get_layer("TCP") else "UDP" if packet.get_layer("UDP") else ip.get_field("next_protocol")
        src_port = transport.get_field("src_port") if transport else None
        dst_port = transport.get_field("dst_port") if transport else None
        key = f"{src}:{src_port}>{dst}:{dst_port}:{protocol}"
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(src, dst, src_port, dst_port, protocol)
            self.flows[key] = flow
        flow.update(len(packet.raw_bytes), packet.timestamp)

    def packet_view(self, packet: Packet, number: int) -> dict[str, Any]:
        ip = packet.get_layer("IPv4")
        transport = packet.get_layer("TCP") or packet.get_layer("UDP")
        protocol = "ARP" if packet.get_layer("ARP") else "ICMP" if packet.get_layer("ICMP") else "TCP" if packet.get_layer("TCP") else "UDP" if packet.get_layer("UDP") else "IPv4" if ip else "ETHERNET"
        source = ip.get_field("src_addr", "—") if ip else packet.get_layer("Ethernet").get_field("src_mac", "—")
        destination = ip.get_field("dst_addr", "—") if ip else packet.get_layer("Ethernet").get_field("dst_mac", "—")
        ports = f"{transport.get_field('src_port')} → {transport.get_field('dst_port')}" if transport else ""
        return {"id": number, "timestamp": packet.timestamp, "time": datetime.fromtimestamp(packet.timestamp, timezone.utc).strftime("%H:%M:%S.%f")[:-3], "source": source, "destination": destination, "protocol": protocol, "length": len(packet.raw_bytes), "info": ports, "layers": [{"name": layer.name, "fields": layer.fields} for layer in packet.layers], "hex": packet.raw_bytes[:96].hex(" ")}


service = WiretapService()


@app.get("/api/interfaces")
def get_interfaces() -> dict[str, Any]:
    return {"interfaces": service.interfaces.get_interfaces(), "default": service.interfaces.get_default_interface()}


@app.get("/api/status")
def get_status() -> dict[str, Any]:
    with service.lock:
        elapsed = service.elapsed_seconds
        if service.capture.is_running and service.started_at:
            elapsed += datetime.now().timestamp() - service.started_at
        total_bytes = sum(len(packet.raw_bytes) for packet in service.packets)
        return {"capturing": service.capture.is_running, "packet_count": len(service.packets), "flow_count": len(service.flows), "alert_count": len(service.threats.get_alerts()) + len(service.ml_alerts), "duration": elapsed, "bytes": total_bytes}


@app.post("/api/capture/start")
def start_capture(body: StartCapture) -> dict[str, Any]:
    if not service.interfaces.get_interface_by_name(body.interface):
        raise HTTPException(400, "Unknown network interface")
    try:
        service.capture.start(body.interface, service.ingest, body.bpf_filter)
        service.started_at = datetime.now().timestamp()
        return get_status()
    except Exception as exc:
        raise HTTPException(500, f"Could not start capture: {exc}") from exc


@app.post("/api/capture/stop")
def stop_capture() -> dict[str, Any]:
    if service.capture.is_running and service.started_at:
        service.elapsed_seconds += datetime.now().timestamp() - service.started_at
        service.started_at = None
    service.capture.stop()
    return get_status()


@app.post("/api/capture/clear")
def clear_capture() -> dict[str, Any]:
    service.clear()
    return get_status()


@app.get("/api/packets")
def get_packets(limit: int = 200, offset: int = 0) -> dict[str, Any]:
    with service.lock:
        reverse_indexed = list(enumerate(service.packets, 1))[-max(1, min(limit, 500)):]
        return {"packets": [service.packet_view(packet, number) for number, packet in reverse_indexed[offset:]], "total": len(service.packets)}


@app.get("/api/packets/{number}")
def get_packet(number: int) -> dict[str, Any]:
    with service.lock:
        if number < 1 or number > len(service.packets): raise HTTPException(404, "Packet not found")
        return service.packet_view(service.packets[number - 1], number)


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    with service.lock:
        counts = Counter((packet.get_layer("TCP") and "TCP") or (packet.get_layer("UDP") and "UDP") or (packet.get_layer("ARP") and "ARP") or (packet.get_layer("ICMP") and "ICMP") or "OTHER" for packet in service.packets)
        return {
            "protocols": counts,
            "flows": [flow.__dict__ for flow in service.flows.values()],
            "alerts": [alert.__dict__ for alert in [*service.threats.get_alerts(), *service.ml_alerts]],
            "health_reports": [report.to_dict() for report in service.connection_health.get_all_reports()],
            "retransmission_events": [event.__dict__ for event in service.retransmissions.get_all_events()],
            "rtt_samples": [sample.__dict__ for sample in service.rtt.get_all_samples()],
        }


@app.post("/api/query")
def query(body: NaturalLanguageQuery) -> dict[str, Any]:
    parser = QueryParser(); parsed = parser.parse(body.query)
    with service.lock:
        engine = QueryEngine(service.packets, service.flows, [*service.threats.get_alerts(), *service.ml_alerts])
        engine.set_time_detector(service.time_patterns); engine.set_connection_diagnostic(service.connection_health)
        result = engine.execute(parsed)
        indexed = {id(packet): index for index, packet in enumerate(service.packets, 1)}
        return {"description": engine.describe_filter(parsed), "confidence": parsed.confidence, "packets": [service.packet_view(packet, indexed[id(packet)]) for packet in result["packets"]], "flows": [flow.__dict__ for flow in result["flows"]], "alerts": [alert.__dict__ for alert in result["alerts"]], "suggestions": parsed.suggestions}


@app.post("/api/storage/save")
def save_database(body: DatabasePath) -> dict[str, int]:
    with service.lock:
        store = SQLStore(body.path); store.save_packets(service.packets); store.save_flows(service.flows)
        return {"packets": len(service.packets), "flows": len(service.flows)}


@app.post("/api/storage/load")
def load_database(body: DatabasePath) -> dict[str, int]:
    with service.lock:
        store = SQLStore(body.path); service.packets = store.load_packets(); service.flows = store.load_flows()
        return {"packets": len(service.packets), "flows": len(service.flows)}
