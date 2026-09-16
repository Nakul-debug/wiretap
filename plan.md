# NetScope — Network Protocol Analyzer
## Step-by-Step Development Plan

## 1. Project Overview

**NetScope** is a lightweight, educational desktop network protocol analyzer that captures, decodes, and analyzes network packets in real time. It provides detailed inspection of Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, and HTTP traffic while presenting protocol information in a structured and beginner-friendly manner.

The project is designed to serve two purposes:

1. **Educational platform** — help students and beginners understand how network protocols are structured and how they interact.
2. **Practical monitoring tool** — provide basic network troubleshooting, flow analysis, TCP stream reconstruction, RTT estimation, and traffic statistics.

---

## 2. Technology Stack

### 2.1 Core Language

| Component | Technology | Purpose |
|-----------|------------|---------|
| Programming Language | Python 3.10 or later | Main application and protocol processing |
| Type Hints | `typing` module | Improve code readability and maintainability |
| Data Classes | `dataclasses` | Represent packets, flows, and decoded fields |

### 2.2 Networking Libraries

| Library | Purpose |
|---------|---------|
| **Scapy** | Packet capture, crafting, parsing, and manipulation |
| **libpcap / WinPcap / Npcap** | Low-level packet capture backend (installed with Scapy where required) |
| Python `socket` module | Low-level socket understanding and optional raw socket experiments |
| `ipaddress` (standard library) | IP address parsing, validation, and network operations |

> **Note:** PyShark is optional and can be added later for comparison or advanced PCAP analysis. It is not required for the initial implementation.

### 2.3 Graphical User Interface

| Component | Technology | Purpose |
|-----------|------------|---------|
| GUI Framework | PyQt6 | Desktop interface, packet tables, detail panels, and dialogs |
| Qt Designer (optional) | Visual layout design | Drag-and-drop creation of `.ui` files |
| Qt Charts (optional) | Traffic graphs and protocol distribution charts | Part of the PyQt6 ecosystem |

### 2.4 Data Processing and Visualization

| Library | Purpose |
|---------|---------|
| NumPy | Efficient numerical calculations |
| Pandas | Flow-level statistics, aggregation, and tabular data handling |
| Matplotlib | Static traffic graphs and protocol usage charts |
| PyQtGraph (optional) | High-performance live traffic graphs |

### 2.5 Storage (Optional)

## 2.6 Team Organization

- **Person A** – Overall project lead, architecture, high‑level design.
- **Person B** – Core capture & decoder team: Scapy, packet models, analysis engines.
- **Person C** – UI & experience: PyQt6 GUI, filters, dashboards, documentation, packaging.

| Component | Purpose |
|-----------|---------|
| SQLite | Persist packet captures, analysis history, and saved reports |
| CSV export | Lightweight export of packet and flow statistics |

### 2.6 Development and Testing Tools

| Tool | Purpose |
|------|---------|
| Git | Version control |
| GitHub / GitLab | Remote repository and collaboration |
| `venv` or `virtualenv` | Isolated Python environment |
| `pip` | Dependency installation |
| `pytest` | Unit and integration tests |
| `pytest-qt` (optional) | GUI component tests |
| `black` | Code formatting |
| `ruff` or `flake8` | Linting and static checks |
| `mypy` (optional) | Static type checking |
| Scapy test traffic generators | Generate controlled packets for validation |

---

## 3. Software and System Prerequisites

### 3.1 General Requirements

- Python 3.10 or later (Python 3.11/3.12 recommended).
- A supported operating system: Windows, macOS, or Linux.
- Administrator or root privileges for live packet capture.
- A network interface capable of promiscuous mode (optional but useful).
- Git installed for version control.

### 3.2 Platform-Specific Capture Requirements

| Platform | Requirement |
|----------|-------------|
| **Windows** | Install Npcap with WinPcap API compatibility. Run the application as Administrator. |
| **macOS** | Grant terminal/IDE accessibility or network monitoring permissions. Capture may require elevated privileges. |
| **Linux** | Install `libpcap` development packages and grant capture permissions (for example, `setcap cap_net_raw,cap_net_admin=eip` on the Python executable, or use `sudo`). |

### 3.3 Recommended Python Packages

```text
scapy>=2.5.0
PyQt6>=6.5.0
numpy>=1.24.0
pandas>=2.0.0
matplotlib>=3.7.0
pytest>=7.4.0
pytest-qt>=4.2.0
black>=23.0.0
ruff>=0.1.0
```

Optional:

```text
pyqtgraph>=0.13.0
pyshark>=0.6.0
```

---

## 4. Recommended Project Structure

Create the repository with the following layout:

```text
wiretap/
├── README.md
├── plan.md
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── LICENSE
├── docs/
│   ├── architecture.md
│   ├── protocol-reference.md
│   └── user-guide.md
├── wiretap/
│   ├── __init__.py
│   ├── __main__.py
│   ├── main.py
│   │
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── capture_manager.py
│   │   ├── interface_manager.py
│   │   └── packet_source.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── packet.py
│   │   ├── flow.py
│   │   ├── statistics.py
│   │   └── analysis_result.py
│   │
│   ├── decoders/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── ethernet.py
│   │   ├── arp.py
│   │   ├── ipv4.py
│   │   ├── ipv6.py
│   │   ├── icmp.py
│   │   ├── tcp.py
│   │   ├── udp.py
│   │   ├── dns.py
│   │   └── http.py
│   │
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── flow_analyzer.py
│   │   ├── rtt_estimator.py
│   │   ├── stream_reconstructor.py
│   │   ├── retransmission_detector.py
│   │   └── statistics_generator.py
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── sqlite_store.py
│   │   └── csv_exporter.py
│   │
│   ├── gui/
│   │   ├── __init__.py
│   │   ├── main_window.py
│   │   ├── widgets/
│   │   │   ├── packet_table.py
│   │   │   ├── packet_details.py
│   │   │   ├── interface_selector.py
│   │   │   ├── filter_bar.py
│   │   │   ├── flow_table.py
│   │   │   └── statistics_dashboard.py
│   │   └── dialogs/
│   │       ├── about_dialog.py
│   │       └── settings_dialog.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── protocol_helpers.py
│       ├── formatting.py
│       └── logging_config.py
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── capture/
│   ├── decoders/
│   ├── analysis/
│   ├── storage/
│   └── gui/
│
├── examples/
│   ├── sample_captures/
│   └── demo_scripts/
│
└── scripts/
    ├── generate_sample_traffic.py
    └── benchmark_decoders.py
```

---

## 5. Development Phases

The project should be built incrementally. Each phase should produce a working milestone before moving to the next one.

---

# Phase 0 — Planning and Environment Setup

## 5.1 Define the Minimum Viable Product (MVP)

Before writing code, finalize the MVP scope:

- Capture packets from a selected interface.
- Display a live packet list.
- Decode Ethernet, IPv4/IPv6, TCP/UDP, and ICMP.
- Show a hierarchical packet-detail view.
- Apply protocol and text filters.
- Provide basic flow and protocol statistics.

Features such as PCAP import/export, SQLite persistence, HTTP reconstruction, and advanced charts can follow in later phases.

## 5.2 Create the Repository

1. Create a new Git repository named `wiretap`.
2. Add a descriptive `README.md`.
3. Add this `plan.md`.
4. Add a `.gitignore` covering:
   - Python bytecode (`__pycache__/`, `*.pyc`).
   - Virtual environments (`.venv/`, `venv/`).
   - IDE settings (`.idea/`, `.vscode/` if not shared).
   - Generated reports, logs, and captures.
   - macOS metadata (`.DS_Store`).
5. Add a `LICENSE` (choose an appropriate open-source license).

## 5.3 Set Up the Python Environment

```bash
cd wiretap
python3 -m venv .venv
source .venv/bin/activate       # macOS/Linux
# .venv\Scripts\activate        # Windows
python -m pip install --upgrade pip
```

Create `requirements.txt` and install dependencies:

```bash
pip install -r requirements.txt
```

## 5.4 Configure Development Tools

1. Configure `black` or another formatter.
2. Configure `ruff` or `flake8` for linting.
3. Configure `pytest` with sensible defaults.
4. Add a `pyproject.toml` for project metadata and tool configuration.
5. Create an initial GitHub/GitLab repository and push the first commit.

## 5.5 Verify Capture Permissions

Before implementing capture logic, confirm that the machine can capture packets:

```bash
python -c "import scapy.all as scapy; print(scapy.conf.ifaces)"
```

If capture fails, install the platform-specific capture backend and grant the necessary privileges.

---

# Phase 1 — Core Models and Packet Capture

## 5.6 Implement the Data Models

Create reusable data classes that represent:

- A raw captured packet.
- A decoded packet with protocol layers.
- Protocol fields and their human-readable values.
- A network flow (source, destination, protocol, ports).
- TCP stream state.
- Analysis results (RTT, retransmissions, byte counts).
- Summary statistics.

Recommended design principles:

- Keep models independent of Scapy and the GUI.
- Use immutable data classes where practical.
- Store both raw bytes and decoded values for debugging.
- Define a common interface for protocol decoders.

## 5.7 Implement Interface Discovery

Create an `InterfaceManager` that:

1. Lists available network interfaces.
2. Shows interface names, descriptions, IP addresses, and status.
3. Allows the user to select one interface.
4. Handles interfaces that appear or disappear while the application is running.
5. Gracefully handles permission errors.

## 5.8 Implement the Packet Capture Manager

Create a `CaptureManager` that:

1. Starts and stops Scapy sniffing on the selected interface.
2. Runs capture in a background thread or worker so the GUI never freezes.
3. Emits captured packets to subscribers through signals or a thread-safe queue.
4. Applies an optional BPF capture filter.
5. Records packet timestamps and capture statistics.
6. Handles errors and cleanup safely.
7. Supports both live capture and offline PCAP input (PCAP can be added in Phase 1b or Phase 3).

## 5.9 Add Capture Unit Tests

Test:

- Interface enumeration with mocked interfaces.
- Capture start/stop behavior.
- Packet emission and callback handling.
- Invalid interface names.
- Permission-related error handling.
- Filter syntax validation.

## 5.10 Phase 1 Milestone

By the end of this phase, a command-line or minimal GUI prototype should be able to list interfaces, start a capture, and print basic packet summaries without crashing.

---

# Phase 2 — Protocol Decoding Pipeline

## 5.11 Define the Decoder Contract

Create a common base class or protocol for decoders:

- `decode(packet) -> DecodedLayer`
- `supports(packet) -> bool`
- `display_name`
- `fields`

Each decoder should be independently testable and should never raise uncaught exceptions. Malformed packets must produce a clear "decode incomplete" or "invalid" state.

## 5.12 Implement Ethernet II Decoder

Extract:

- Destination MAC address.
- Source MAC address.
- EtherType.
- VLAN tags, if present.
- Payload length.

Handle common EtherTypes:

- `0x0800` — IPv4.
- `0x0806` — ARP.
- `0x86DD` — IPv6.
- `0x8100` / `0x88A8` — VLAN-tagged frames.

## 5.13 Implement ARP Decoder

Extract:

- Hardware type.
- Protocol type.
- Hardware address length.
- Protocol address length.
- Operation (request/reply).
- Sender MAC/IP.
- Target MAC/IP.

Display a friendly description such as "Who has 192.168.1.1? Tell 192.168.1.10".

## 5.14 Implement IPv4 Decoder

Extract:

- Version and header length.
- DSCP/ECN.
- Total length.
- Identification.
- Flags and fragment offset.
- TTL.
- Protocol.
- Header checksum.
- Source and destination addresses.
- Options, if present.

Validate:

- Minimum header length.
- Total length against captured payload length.
- Fragment handling.
- Header checksum optionally.

## 5.15 Implement IPv6 Decoder

Extract:

- Version.
- Traffic class and flow label.
- Payload length.
- Next header.
- Hop limit.
- Source and destination addresses.

Support common extension headers where practical:

- Hop-by-Hop Options.
- Routing.
- Fragment.
- Destination Options.
- AH and ESP (ESP payload should be treated as opaque).

## 5.16 Implement ICMP Decoder

Extract:

- Type and code.
- Checksum.
- Identifier and sequence number for echo messages.
- Common message names (Echo Request, Echo Reply, Destination Unreachable, Time Exceeded, etc.).
- Embedded payload summary when available.

## 5.17 Implement TCP Decoder

Extract:

- Source and destination ports.
- Sequence number.
- Acknowledgment number.
- Data offset.
- Reserved bits.
- Flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR).
- Window size.
- Checksum.
- Urgent pointer.
- TCP options (MSS, window scaling, SACK permitted, timestamps, etc.).

Handle malformed headers and truncated packets safely.

## 5.18 Implement UDP Decoder

Extract:

- Source and destination ports.
- Length.
- Checksum.
- Payload size.

Validate length and checksum fields where possible.

## 5.19 Implement DNS Decoder

Decode both queries and responses:

- Transaction ID.
- Flags.
- Question count.
- Answer, authority, and additional counts.
- Query name, type, and class.
- Response records:
  - A / AAAA.
  - CNAME.
  - MX.
  - NS.
  - TXT.
  - PTR.
  - SOA.
- Compression pointers and malformed names.
- Truncated responses.

## 5.20 Implement HTTP Decoder

Perform best-effort decoding of HTTP over TCP:

- Request line: method, URI, version.
- Response line: version, status code, reason phrase.
- Headers.
- Content length.
- Chunked transfer decoding (optional).
- Common methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH.
- Common response status categories.

Important: HTTP may be split across multiple TCP segments and may be encrypted (HTTPS). The first implementation should decode only complete, unencrypted HTTP messages and mark partial/encrypted traffic clearly.

## 5.21 Build the Layered Decoding Pipeline

Implement a dispatcher that:

1. Receives a raw packet.
2. Detects the link-layer type.
3. Walks Ethernet → ARP/IP → TCP/UDP/ICMP → DNS/HTTP.
4. Produces a tree of decoded layers.
5. Records errors without stopping the entire pipeline.
6. Preserves offsets and byte ranges for each layer.

## 5.22 Add Decoder Unit Tests

For every decoder, create tests using:

- Hand-crafted byte strings.
- Scapy-generated packets.
- Valid packets.
- Truncated packets.
- Invalid lengths.
- Unknown protocol numbers.
- IPv4 and IPv6 variants.
- DNS compression and multiple records.
- TCP segmentation edge cases.

## 5.23 Phase 2 Milestone

A packet should be accepted as raw bytes and produce a complete, hierarchical protocol tree with all expected fields and a readable summary line.

---

# Phase 3 — Traffic Analysis

## 5.24 Implement Flow Identification

Define a flow key using:

- Source IP and destination IP.
- Source and destination ports.
- Transport protocol.
- Direction (or separate bidirectional flow buckets).

Maintain:

- Packet count.
- Byte count.
- First-seen and last-seen timestamps.
- TCP state transitions.
- Application protocol guesses.
- Per-direction statistics.

## 5.25 Implement the Flow Analyzer

Provide:

- Active flow tracking.
- Flow creation, update, and expiration.
- Bidirectional flow grouping.
- Top talkers and top communicating host pairs.
- Protocol distribution.
- Per-flow packet and byte totals.
- Idle timeout cleanup.

## 5.26 Implement RTT Estimation

Estimate RTT using TCP sequence and acknowledgment numbers:

1. Record the timestamp when a data-bearing segment is sent.
2. Match a later ACK that acknowledges the sequence range.
3. Calculate `RTT = ACK_time - segment_time`.
4. Maintain per-flow samples.
5. Report minimum, maximum, average, and smoothed RTT.

Handle:

- Retransmissions.
- Out-of-order segments.
- ACK-only traffic.
- Sequence number wraparound (basic handling initially).
- Multiple outstanding segments.

## 5.27 Implement Retransmission Detection

Detect likely retransmissions using:

- Duplicate sequence numbers.
- Overlapping sequence ranges.
- Duplicate ACKs.
- Fast retransmission patterns.

Classify:

- True retransmission.
- Possible retransmission.
- Out-of-order delivery.

Maintain per-flow retransmission counts and rates.

## 5.28 Implement TCP Stream Reconstruction

Group TCP packets by connection and direction:

1. Identify the connection using the 4-tuple.
2. Order segments by sequence number.
3. Remove duplicate bytes.
4. Handle retransmissions and overlaps.
5. Reassemble payload in sequence order.
6. Preserve direction labels (client → server and server → client).
7. Display reconstructed data as text or hex.

For the MVP, implement a robust basic version that works for ordered traffic and document limitations for complex cases.

## 5.29 Implement Statistics Generation

Generate:

- Total packets and bytes.
- Packets per second / bytes per second.
- Protocol distribution (count and percentage).
- Top source and destination hosts.
- Top conversations.
- TCP flag distribution.
- DNS query counts.
- HTTP request/response counts.
- Retransmission rate.
- RTT summary.
- Bandwidth utilization over time.

## 5.30 Add Analysis Unit Tests

Test with synthetic packet sequences covering:

- New, active, and expired flows.
- RTT calculation with matching ACKs.
- Duplicate and overlapping TCP segments.
- Retransmission and out-of-order cases.
- Stream reconstruction with gaps and duplicates.
- Statistics aggregation and percentage calculations.

## 5.31 Phase 3 Milestone

The analyzer should process a capture and produce flow tables, RTT estimates, retransmission indicators, reconstructed TCP streams, and aggregate statistics.

---

# Phase 4 — Desktop Graphical User Interface

## 5.32 Design the Main Window Layout

Create a usable layout with:

1. **Toolbar**
   - Interface selector.
   - Start/stop capture buttons.
   - Clear button.
   - Filter input.
   - Save/export actions.
   - Settings and help actions.

2. **Packet List**
   - Number.
   - Time.
   - Source.
   - Destination.
   - Protocol.
   - Length.
   - Info/summary.

3. **Packet Details**
   - Expandable protocol tree.
   - Field name and value columns.
   - Raw hex view.
   - Copy field/copy packet actions.

4. **Statistics Dashboard**
   - Capture counters.
   - Protocol distribution.
   - Top hosts and conversations.
   - RTT and retransmission summaries.

5. **Flow Table**
   - Source/destination.
   - Ports.
   - Protocol.
   - Packets/bytes.
   - Duration.
   - State.

6. **TCP Stream Viewer**
   - Direction selector.
   - Reconstructed text/hex view.
   - Search and copy actions.

## 5.33 Implement Qt Thread Safety

- Run capture and analysis in worker threads.
- Communicate with the GUI only through Qt signals or a thread-safe queue.
- Never modify Qt widgets from a worker thread.
- Provide back-pressure so a very high packet rate does not exhaust memory.
- Add pause/resume behavior if useful.

## 5.34 Implement the Packet Table

Features:

- Efficient row insertion and updates.
- Sorting by columns.
- Selection synchronization with packet details.
- Color coding by protocol.
- Time formatting options.
- Virtualization or batching for high packet rates.

## 5.35 Implement the Packet Details Tree

Features:

- Expand/collapse protocol layers.
- Display field names and values.
- Show warnings for malformed packets.
- Highlight the selected field in the hex view (optional advanced feature).
- Copy individual fields and entire packet summaries.

## 5.36 Implement Filters and Search

Support:

- Protocol filter (Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP).
- Source/destination host filter.
- Port filter.
- Free-text search across packet summaries and fields.
- Clear/reset filter action.
- Invalid filter feedback.

For the MVP, filtering can be applied in memory after decoding. A BPF capture filter may be added later for efficiency.

## 5.37 Implement the Statistics Dashboard

Display:

- Live counters.
- Protocol distribution bar or pie chart.
- Top communicating hosts.
- Top conversations.
- Packets/bytes per second.
- RTT and retransmission indicators.

Use Matplotlib, Qt Charts, or PyQtGraph. Keep updates throttled (for example, once per second) to avoid excessive CPU usage.

## 5.38 Implement the Flow Table and TCP Stream Viewer

- Show active and recently expired flows.
- Allow selecting a flow to inspect its packets.
- Allow selecting a TCP conversation to view reconstructed streams.
- Provide text and hexadecimal display modes.
- Provide copy-to-clipboard actions.

## 5.39 Implement Settings and Preferences

Persist user preferences such as:

- Last-used interface.
- Default capture filter.
- Time display format.
- Theme/appearance (optional).
- Statistics refresh interval.
- Maximum retained packets in memory.
- Export directory.

Use Qt `QSettings` or a small JSON configuration file.

## 5.40 Add GUI Tests

Test:

- Main window construction.
- Start/stop capture state transitions.
- Packet table updates.
- Filter behavior.
- Selection synchronization.
- Worker-thread signal delivery.
- Graceful shutdown.

## 5.41 Phase 4 Milestone

The desktop application should provide a responsive, end-to-end experience: select an interface, capture packets, inspect them, filter them, and view analysis results.

---

# Phase 5 — Storage, Export, and Offline Analysis

## 5.42 Add PCAP Import

Allow users to open `.pcap` and, if supported, `.pcapng` files:

1. Read packets sequentially.
2. Feed them through the same decoder and analysis pipeline used for live capture.
3. Display a progress indicator for large files.
4. Support pause, resume, and cancellation.

## 5.43 Add PCAP Export

Allow exporting:

- All captured packets.
- Filtered packets.
- Selected packets.
- A single flow or conversation.

## 5.44 Add SQLite Persistence (Optional)

Design a schema for:

- Packet metadata.
- Decoded protocol fields.
- Flows.
- Analysis results.
- Capture sessions.

Keep the database optional so the core analyzer remains lightweight.

## 5.45 Add CSV/JSON Export

Export:

- Packet summaries.
- Flow tables.
- Statistics reports.
- Reconstructed TCP streams.

## 5.46 Add Report Generation (Optional)

Generate a concise HTML or Markdown report containing:

- Capture summary.
- Protocol distribution.
- Top hosts and conversations.
- RTT and retransmission findings.
- Notable DNS/HTTP activity.

## 5.47 Phase 5 Milestone

Users should be able to analyze saved captures offline and export their findings in common formats.

---

# Phase 6 — Performance, Reliability, and Hardening

## 5.48 Profile the Capture and Analysis Pipeline

Measure:

- Packets processed per second.
- Decode time per protocol.
- Memory growth during long captures.
- GUI update overhead.
- Queue depth under load.

## 5.49 Optimize Hot Paths

Potential optimizations:

- Batch GUI updates.
- Use efficient data structures for flow lookup.
- Avoid unnecessary packet copying.
- Cache decoded summaries.
- Throttle statistics recalculation.
- Limit retained packet history or spill to disk.
- Use NumPy/Pandas only where they provide a clear benefit.

## 5.50 Improve Error Handling

Ensure the application handles:

- Interface removal.
- Permission loss.
- Malformed packets.
- Very large packets.
- Unsupported protocols.
- Disk-full conditions during export.
- Unexpected worker-thread termination.

## 5.51 Add Logging and Diagnostics

Implement:

- Structured application logs.
- Capture and decoder error counters.
- A diagnostics window or log viewer.
- Optional verbose debugging mode.

## 5.52 Add Resource Limits

Provide configurable limits for:

- Maximum packets retained in memory.
- Maximum flow table size.
- Maximum stream reconstruction size.
- Capture duration or size (optional).

## 5.53 Phase 6 Milestone

NetScope should remain responsive and stable during extended captures and high traffic rates, with clear feedback when resource limits are reached.

---

# Phase 7 — Documentation, Packaging, and Release

## 5.54 Write User Documentation

Create `docs/user-guide.md` covering:

- Installation.
- Capture permissions by platform.
- Interface selection.
- Starting and stopping a capture.
- Reading packet details.
- Filters and search.
- Flow analysis.
- TCP stream reconstruction.
- RTT and retransmission interpretation.
- PCAP import/export.
- Troubleshooting common problems.

## 5.55 Write Developer Documentation

Create `docs/architecture.md` and `docs/protocol-reference.md` covering:

- Module responsibilities.
- Data flow from capture to GUI.
- Decoder interfaces.
- Model definitions.
- Thread-safety rules.
- How to add a new protocol decoder.
- Testing strategy.
- Performance considerations.

## 5.56 Add Example Traffic

Provide safe sample captures or generation scripts for:

- ARP request/reply.
- IPv4 TCP and UDP.
- IPv6.
- ICMP echo.
- DNS query/response.
- HTTP request/response.
- Retransmission and RTT examples.

Never distribute real user traffic or sensitive network data.

## 5.57 Package the Application

Choose one or more distribution methods:

- `pip install wiretap` for developers.
- Platform-specific executable bundles using PyInstaller or Briefcase.
- Optional Homebrew, Winget, or Linux package later.

Include:

- Scapy and GUI dependencies.
- Capture backend instructions.
- Platform-specific privilege notes.
- A command-line entry point (`wiretap`) in addition to the GUI.

## 5.58 Prepare the Release Checklist

Before each release:

- Run the full test suite.
- Run linting and formatting checks.
- Build the package.
- Test on Windows, macOS, and Linux where possible.
- Verify capture permissions instructions.
- Verify PCAP import/export.
- Update the changelog and version number.
- Create a release note with known limitations.

---

## 6. Suggested Implementation Order

For the fastest path to a working prototype, follow this order:

1. **Repository and environment setup.**
2. **Core models and decoder interface.**
3. **Ethernet, IPv4, IPv6, TCP, UDP, and ICMP decoders.**
4. **Scapy-based capture manager and interface listing.**
5. **Minimal command-line packet dumper.**
6. **Layered decoding pipeline.**
7. **Basic PyQt6 main window and packet table.**
8. **Packet details tree and hex view.**
9. **Flow analyzer and protocol statistics.**
10. **Filters and search.**
11. **TCP stream reconstruction.**
12. **RTT estimation and retransmission detection.**
13. **DNS and HTTP decoders.**
14. **Statistics dashboard and charts.**
15. **PCAP import/export.**
16. **SQLite/CSV/JSON persistence.**
17. **Performance optimization and long-capture hardening.**
18. **Documentation, packaging, and release.**

---

## 7. Testing Strategy

### 7.1 Unit Tests

Write focused tests for:

- Every protocol decoder.
- Model serialization and formatting.
- Flow creation and expiration.
- RTT matching.
- Retransmission classification.
- TCP stream assembly.
- Statistics calculations.
- Filter parsing.
- Storage operations.

### 7.2 Integration Tests

Test complete pipelines:

- Raw bytes → decoded packet tree.
- Capture event → model → analysis → GUI update.
- PCAP file → flow table and statistics.
- TCP segment sequence → reconstructed stream.

### 7.3 Synthetic Traffic Tests

Use Scapy to generate deterministic packets and test expected output without requiring special hardware.

### 7.4 Manual Tests

Perform real-world tests on:

- Loopback traffic.
- ARP on a local network.
- DNS queries.
- HTTP traffic to a controlled local server.
- IPv6 if available.
- High-rate traffic for performance checks.

### 7.5 GUI Tests

Use `pytest-qt` where practical, but prioritize manual GUI testing for layout, responsiveness, and user experience.

---

## 8. Security, Privacy, and Ethical Considerations

Because NetScope captures network traffic, the project must be designed responsibly:

1. **Capture only with permission.** Clearly document that users must have authorization to monitor a network.
2. **Avoid storing payloads by default.** Treat packet contents as sensitive.
3. **Provide a privacy notice.** Explain what is captured and where it is stored.
4. **Redact sensitive fields in reports.** Consider masking credentials, tokens, and personal data.
5. **Do not decode or expose encrypted content.** HTTPS payloads should remain opaque.
6. **Use least privilege.** Run capture with only the permissions required by the operating system.
7. **Secure saved captures.** Warn users that PCAP files can contain sensitive information.
8. **Do not perform active scanning or injection by default.** The initial project should be passive and educational.

---

## 9. Known Limitations and Future Enhancements

### 9.1 Initial Limitations

- HTTP decoding is best-effort and does not handle all transfer encodings.
- HTTPS payloads cannot be decrypted.
- TCP reconstruction may be imperfect when segments are heavily reordered or contain large gaps.
- RTT estimation is approximate and depends on observable TCP sequence/ACK behavior.
- Live capture requires platform-specific privileges.
- Very high packet rates may require batching, sampling, or disk-backed storage.

### 9.2 Possible Future Enhancements

- TLS fingerprinting without decryption.
- Advanced BPF filter builder.
- Real-time alerting for anomalies.
- GeoIP and ASN enrichment (optional, privacy-sensitive).
- Machine-learning-based traffic classification.
- Multi-interface simultaneous capture.
- Remote capture agent.
- Plugin architecture for custom decoders.
- Dark mode and accessibility improvements.
- Web-based dashboard mode.
- Comparison of captures and baseline profiles.

---

## 10. Definition of Done

The project is considered complete for its initial release when all of the following are true:

- [ ] The application installs cleanly in a fresh virtual environment.
- [ ] Interfaces can be listed and selected.
- [ ] Live capture starts and stops safely.
- [ ] Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, and HTTP are decoded.
- [ ] Packet details are displayed hierarchically.
- [ ] Filters and search work correctly.
- [ ] Flows, RTT estimates, retransmissions, and statistics are generated.
- [ ] TCP streams can be reconstructed for normal traffic.
- [ ] PCAP import and export are available.
- [ ] The GUI remains responsive during capture.
- [ ] Unit and integration tests pass.
- [ ] Documentation explains installation, usage, limitations, and privacy.
- [ ] The application has been manually tested on at least one supported platform.
- [ ] A release package or reproducible installation procedure is provided.

---

## 11. Summary

NetScope should be built as a modular Python application with a clear separation between capture, decoding, analysis, storage, and presentation. Start with a small, reliable MVP: capture packets, decode the most common protocols, and display them clearly. Then add flow analysis, TCP reconstruction, RTT/retransmission metrics, and visualization. Finally, harden the application, add offline analysis and export features, document the system thoroughly, and package it for end users.

The most important engineering rule throughout the project is to keep the packet-processing pipeline deterministic and testable: every raw packet should produce the same decoded result regardless of whether it came from a live interface or a saved PCAP file.
