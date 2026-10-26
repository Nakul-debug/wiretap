# Wiretap

Wiretap is an educational network-protocol analyzer with a Python capture and
analysis engine plus a local Vite + React web interface. Captured traffic stays
on the machine: the frontend communicates with a local API at
`127.0.0.1:8000`.

## Features

- Live network-interface capture with optional BPF filters
- Decoding for Ethernet, ARP, IPv4, TCP, UDP, ICMP, and DNS traffic
- Packet stream and decoded frame inspector
- Flow tracking with packet, byte, and duration metrics
- TCP RTT estimation, retransmission/duplicate-ACK detection, and connection-health reports
- Rule-based, time-pattern, and ML-assisted threat detection
- Natural-language traffic queries, such as `Find DNS requests that received no response`
- SQLite session save and load
- Responsive dark, monochrome React workspace with dedicated views for Capture, Flows, Statistics, Threats, and Query

## Requirements

- Python 3.10+
- Node.js 20+
- A capture backend and elevated privileges for live capture
  - Windows: install [Npcap](https://npcap.com/) and run the API terminal as Administrator
  - Linux: run with the appropriate `sudo`/capture capability

## Run locally

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Then start the API and frontend in separate terminals.

```bash
# Terminal 1 — from the repository root
python -m backend
```

```bash
# Terminal 2
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite (normally `http://localhost:5173`). Select an
interface, optionally enter a BPF filter such as `tcp port 443`, then choose
**Start Capture**.

## Frontend commands

```bash
cd frontend
npm run dev       # Development server
npm run build     # Type-check and production build
npm run preview   # Serve the production build locally
```

## Notes

- Capture may fail without administrator/root privileges or an installed packet-capture backend.
- HTTPS payloads are encrypted; Wiretap can inspect transport metadata but not decrypted application contents.
- The anomaly detectors are educational heuristics, not a production intrusion-detection system.
- **Clear Session** removes the in-memory packets, flows, alerts, and analysis state without requiring a restart.
