import { useEffect, useMemo, useState, type ReactNode } from "react";

type Packet = {
  id: number;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  layers: { name: string; fields: Record<string, unknown> }[];
  hex: string;
};
type Status = {
  capturing: boolean;
  packet_count: number;
  flow_count: number;
  alert_count: number;
  duration: number;
  bytes: number;
};
type Flow = {
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  packet_count: number;
  byte_count: number;
  first_seen: number;
  last_seen: number;
  tcp_state?: string;
};
type Alert = {
  source_ip: string;
  threat_type: string;
  severity: string;
  confidence: number;
  description: string;
  timestamp: number;
};
type Stats = {
  protocols: Record<string, number>;
  flows: Flow[];
  alerts: Alert[];
  health_reports: Health[];
  retransmission_events: Event[];
  rtt_samples: { rtt: number }[];
};
type Health = {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  health_score: number;
  health_grade: string;
  health_label: string;
  summary: string;
  median_rtt_ms: number | null;
  retransmission_count: number;
  rst_count: number;
};
type Event = {
  classification: string;
  src_ip: string;
  dst_ip: string;
  description: string;
};
type Interface = { name: string; description: string; ip: string };
type Tab = "capture" | "flows" | "statistics" | "threats" | "query";
const zero: Status = {
  capturing: false,
  packet_count: 0,
  flow_count: 0,
  alert_count: 0,
  duration: 0,
  bytes: 0,
};
const tabs: [Tab, string][] = [
  ["capture", "LIVE CAPTURE"],
  ["flows", "FLOWS"],
  ["statistics", "STATISTICS"],
  ["threats", "THREATS"],
  ["query", "QUERY"],
];
async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok)
    throw new Error(
      (await response.json().catch(() => null))?.detail ||
        `Request failed (${response.status})`,
    );
  return response.json();
}
const duration = (seconds: number) =>
  new Date(seconds * 1000).toISOString().slice(11, 19);
const size = (bytes: number) =>
  bytes > 1e6
    ? `${(bytes / 1e6).toFixed(2)} MB`
    : `${(bytes / 1e3).toFixed(1)} KB`;

export default function App() {
  const [tab, setTab] = useState<Tab>("capture"),
    [status, setStatus] = useState<Status>(zero),
    [stats, setStats] = useState<Stats>({
      protocols: {},
      flows: [],
      alerts: [],
      health_reports: [],
      retransmission_events: [],
      rtt_samples: [],
    }),
    [interfaces, setInterfaces] = useState<Interface[]>([]),
    [iface, setIface] = useState(""),
    [bpf, setBpf] = useState(""),
    [packets, setPackets] = useState<Packet[]>([]),
    [selected, setSelected] = useState<Packet | null>(null),
    [notice, setNotice] = useState("CONNECTING TO LOCAL ENGINE"),
    [query, setQuery] = useState(""),
    [queryResult, setQueryResult] = useState<{
      description: string;
      confidence: number;
      packets: Packet[];
      flows: Flow[];
      alerts: Alert[];
      suggestions: string[];
    } | null>(null);
  const refresh = async () => {
    try {
      const [s, p, x] = await Promise.all([
        api<Status>("/status"),
        api<{ packets: Packet[] }>("/packets?limit=300"),
        api<Stats>("/stats"),
      ]);
      setStatus(s);
      setPackets(p.packets);
      setStats(x);
      setSelected(
        (old) =>
          p.packets.find((p) => p.id === old?.id) || p.packets.at(-1) || null,
      );
      setNotice("LOCAL ENGINE READY");
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "ENGINE UNAVAILABLE");
    }
  };
  useEffect(() => {
    api<{ interfaces: Interface[]; default: Interface | null }>("/interfaces")
      .then((x) => {
        setInterfaces(x.interfaces);
        setIface(x.default?.name || x.interfaces[0]?.name || "");
      })
      .catch(() => setNotice("ENGINE UNAVAILABLE"));
    refresh();
    const id = setInterval(refresh, 1500);
    return () => clearInterval(id);
  }, []);
  const filtered = useMemo(
    () =>
      packets.filter((p) =>
        Object.values(p).join(" ").toLowerCase().includes(bpf.toLowerCase()),
      ),
    [packets, bpf],
  );
  const command = async (action: "toggle" | "clear") => {
    try {
      if (action === "clear") {
        await api("/capture/clear", { method: "POST" });
        setBpf("");
        setSelected(null);
        setQueryResult(null);
        setNotice("SESSION CLEARED");
      } else if (status.capturing)
        await api("/capture/stop", { method: "POST" });
      else
        await api("/capture/start", {
          method: "POST",
          body: JSON.stringify({ interface: iface, bpf_filter: bpf }),
        });
      await refresh();
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Request failed");
    }
  };
  const runQuery = async () => {
    if (!query.trim()) return;
    try {
      const result = await api<typeof queryResult>("/query", {
        method: "POST",
        body: JSON.stringify({ query }),
      });
      setQueryResult(result);
      setTab("query");
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Query failed");
    }
  };
  const save = async (mode: "save" | "load") => {
    const path = window.prompt(`SQLite database path to ${mode}`, "wiretap.db");
    if (!path) return;
    try {
      await api(`/storage/${mode}`, {
        method: "POST",
        body: JSON.stringify({ path }),
      });
      await refresh();
      setNotice(`DATABASE ${mode.toUpperCase()} COMPLETE`);
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "Storage request failed");
    }
  };
  return (
    <main className="app-shell">
      <header className="masthead">
        <a className="wordmark" href="/">
          WIRETAP<span>®</span>
        </a>
        <p className="edition">NETWORK OBSERVATORY / LOCAL</p>
        <div className="capture-state">
          <i className={status.capturing ? "live" : ""} />
          {status.capturing ? "CAPTURING" : notice}
        </div>
      </header>
      <nav>
        {tabs.map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={tab === id ? "active" : ""}
          >
            {label}
          </button>
        ))}
      </nav>
      <section className="command-bar">
        <label>
          INTERFACE{" "}
          <select value={iface} onChange={(e) => setIface(e.target.value)}>
            {interfaces.map((x) => (
              <option key={x.name} value={x.name}>
                {x.description} / {x.ip}
              </option>
            ))}
          </select>
        </label>
        <label className="filter">
          BPF / DISPLAY FILTER{" "}
          <input
            value={bpf}
            onChange={(e) => setBpf(e.target.value)}
            placeholder="tcp port 443"
          />
        </label>
        <button className="square-button" onClick={() => command("clear")}>
          CLEAR SESSION
        </button>
        <button
          className="capture-button"
          disabled={!iface}
          onClick={() => command("toggle")}
        >
          {status.capturing ? "STOP CAPTURE" : "START CAPTURE"} <b>↗</b>
        </button>
      </section>
      <section className="metrics">
        <Metric
          label="PACKETS"
          value={status.packet_count.toLocaleString()}
          note="IN MEMORY"
        />
        <Metric label="BYTES" value={size(status.bytes)} note="CAPTURED" />
        <Metric
          label="ACTIVE FLOWS"
          value={status.flow_count.toString()}
          note="ANALYSED"
        />
        <Metric
          label="DURATION"
          value={duration(status.duration)}
          note={`${status.alert_count} ALERTS`}
        />
      </section>
      {tab === "capture" && (
        <Capture
          packets={filtered}
          total={status.packet_count}
          selected={selected}
          select={setSelected}
        />
      )}{" "}
      {tab === "flows" && (
        <Flows flows={stats.flows} health={stats.health_reports} />
      )}{" "}
      {tab === "statistics" && <Statistics stats={stats} />}{" "}
      {tab === "threats" && <Threats alerts={stats.alerts} />}{" "}
      {tab === "query" && (
        <Query
          query={query}
          setQuery={setQuery}
          run={runQuery}
          result={queryResult}
        />
      )}
      <footer>
        <span>WIRETAP / LOCAL SESSION</span>
        <span>{notice}</span>
        <span>
          <button onClick={() => save("save")}>SAVE DB</button> /{" "}
          <button onClick={() => save("load")}>LOAD DB</button>
        </span>
      </footer>
    </main>
  );
}
function Capture({
  packets,
  total,
  selected,
  select,
}: {
  packets: Packet[];
  total: number;
  selected: Packet | null;
  select: (p: Packet) => void;
}) {
  return (
    <section className="workspace">
      <div className="packet-panel panel">
        <Title
          name="PACKET STREAM"
          note={`${packets.length} SHOWN / ${total} TOTAL`}
        />
        <PacketTable packets={packets} selected={selected} select={select} />
      </div>
      <aside className="inspector panel">
        <Title
          name="FRAME INSPECTOR"
          note={selected ? `#${selected.id}` : "—"}
        />
        {selected ? (
          <>
            <div className="protocol-path">
              {selected.layers.map((x) => (
                <span key={x.name}>{x.name}</span>
              ))}
            </div>
            <dl>
              {selected.layers.flatMap((layer) =>
                Object.entries(layer.fields).map(([key, value]) => (
                  <Detail
                    key={`${layer.name}-${key}`}
                    label={key.replaceAll("_", " ")}
                    value={String(value)}
                  />
                )),
              )}
            </dl>
            <div className="hex-title">PAYLOAD / HEXADECIMAL</div>
            <pre>{selected.hex.match(/.{1,32}/g)?.join("\n")}</pre>
          </>
        ) : (
          <Empty text="Select a captured packet to inspect decoded protocol layers." />
        )}
      </aside>
    </section>
  );
}
function Flows({ flows, health }: { flows: Flow[]; health: Health[] }) {
  return (
    <Panel title="ACTIVE FLOWS" note={`${flows.length} FLOWS`}>
      <table>
        <thead>
          <tr>
            <th>SOURCE</th>
            <th>DESTINATION</th>
            <th>PROTO</th>
            <th>PACKETS</th>
            <th>BYTES</th>
            <th>DURATION</th>
            <th>HEALTH</th>
          </tr>
        </thead>
        <tbody>
          {flows.map((f, i) => {
            const h = health.find(
              (x) =>
                x.src_ip === f.src_ip &&
                x.dst_ip === f.dst_ip &&
                x.src_port === f.src_port &&
                x.dst_port === f.dst_port,
            );
            return (
              <tr key={i}>
                <td>
                  {f.src_ip}:{f.src_port ?? "—"}
                </td>
                <td>
                  {f.dst_ip}:{f.dst_port ?? "—"}
                </td>
                <td>{f.protocol}</td>
                <td>{f.packet_count}</td>
                <td>{size(f.byte_count)}</td>
                <td>{duration(f.last_seen - f.first_seen)}</td>
                <td>
                  {h ? `${h.health_grade} / ${h.health_score.toFixed(0)}` : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {!flows.length && <Empty text="No IP flows have been observed yet." />}
    </Panel>
  );
}
function Statistics({ stats }: { stats: Stats }) {
  const total = Object.values(stats.protocols).reduce((a, b) => a + b, 0);
  return (
    <section className="dashboard">
      <Panel title="PROTOCOL DISTRIBUTION" note={`${total} PACKETS`}>
        {Object.entries(stats.protocols).map(([name, count]) => (
          <div className="bar" key={name}>
            <span>{name}</span>
            <i>
              <b style={{ width: `${total ? (count / total) * 100 : 0}%` }} />
            </i>
            <em>{count}</em>
          </div>
        ))}
        {!total && <Empty text="Capture traffic to generate statistics." />}
      </Panel>
      <Panel
        title="CONNECTION HEALTH"
        note={`${stats.health_reports.length} TCP REPORTS`}
      >
        <table>
          <thead>
            <tr>
              <th>FLOW</th>
              <th>SCORE</th>
              <th>RTT</th>
              <th>RETRANS.</th>
              <th>RESETS</th>
            </tr>
          </thead>
          <tbody>
            {stats.health_reports.map((h, i) => (
              <tr key={i}>
                <td>
                  {h.src_ip}:{h.src_port} → {h.dst_ip}:{h.dst_port}
                </td>
                <td>
                  {h.health_grade} / {h.health_label}
                </td>
                <td>{h.median_rtt_ms?.toFixed(1) ?? "—"} ms</td>
                <td>{h.retransmission_count}</td>
                <td>{h.rst_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      <Panel
        title="TCP ANOMALIES"
        note={`${stats.retransmission_events.length} EVENTS`}
      >
        <ul className="events">
          {stats.retransmission_events.map((event, i) => (
            <li key={i}>
              <b>{event.classification}</b> {event.description}
            </li>
          ))}
        </ul>
        {!stats.retransmission_events.length && (
          <Empty text="No retransmission or duplicate-ACK events." />
        )}
      </Panel>
    </section>
  );
}
function Threats({ alerts }: { alerts: Alert[] }) {
  const counts = alerts.reduce<Record<string, number>>((out, x) => {
    out[x.severity] = (out[x.severity] || 0) + 1;
    return out;
  }, {});
  return (
    <Panel
      title="THREAT DETECTION"
      note={`${alerts.length} UNIQUE-SOURCE ALERTS`}
    >
      <div className="severity">
        {["critical", "high", "medium", "low"].map((x) => (
          <span key={x}>
            {x.toUpperCase()} <b>{counts[x] || 0}</b>
          </span>
        ))}
      </div>
      <table>
        <thead>
          <tr>
            <th>TIME</th>
            <th>SOURCE</th>
            <th>TYPE</th>
            <th>SEVERITY</th>
            <th>CONFIDENCE</th>
            <th>DESCRIPTION</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={i}>
              <td>{new Date(a.timestamp * 1000).toLocaleTimeString()}</td>
              <td>{a.source_ip}</td>
              <td>{a.threat_type}</td>
              <td>{a.severity}</td>
              <td>{(a.confidence * 100).toFixed(0)}%</td>
              <td>{a.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!alerts.length && (
        <Empty text="Rule-based, ML, and time-pattern detectors are monitoring captured traffic." />
      )}
    </Panel>
  );
}
function Query({
  query,
  setQuery,
  run,
  result,
}: {
  query: string;
  setQuery: (x: string) => void;
  run: () => void;
  result: {
    description: string;
    confidence: number;
    packets: Packet[];
    flows: Flow[];
    alerts: Alert[];
    suggestions: string[];
  } | null;
}) {
  return (
    <section className="query-page">
      <Panel title="NATURAL LANGUAGE QUERY" note="QUERY ENGINE">
        <div className="query-control">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            placeholder="e.g. Show TCP retransmissions involving 10.0.0.1"
          />
          <button className="capture-button" onClick={run}>
            RUN QUERY ↗
          </button>
        </div>
        <p className="examples">
          Try: DNS requests with no response · connections above 500 ms ·
          unhealthy connections from 10.0.0.1
        </p>
      </Panel>
      {result && (
        <>
          <Panel
            title="GENERATED FILTER"
            note={`${(result.confidence * 100).toFixed(0)}% CONFIDENCE`}
          >
            <p className="description">{result.description}</p>
            {result.suggestions.map((x) => (
              <p className="suggestion" key={x}>
                {x}
              </p>
            ))}
          </Panel>
          <Panel
            title="MATCHING PACKETS"
            note={`${result.packets.length} RESULTS`}
          >
            <PacketTable
              packets={result.packets}
              selected={null}
              select={() => {}}
            />
          </Panel>
          <Flows flows={result.flows} health={[]} />
          <Threats alerts={result.alerts} />
        </>
      )}
    </section>
  );
}
function PacketTable({
  packets,
  selected,
  select,
}: {
  packets: Packet[];
  selected: Packet | null;
  select: (p: Packet) => void;
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {[
              "NO.",
              "TIME",
              "SOURCE",
              "DESTINATION",
              "PROTO",
              "LENGTH",
              "INFO",
            ].map((x) => (
              <th key={x}>{x}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {packets.map((p) => (
            <tr
              key={p.id}
              className={selected?.id === p.id ? "selected" : ""}
              onClick={() => select(p)}
            >
              <td>{String(p.id).padStart(6, "0")}</td>
              <td>{p.time}</td>
              <td>{p.source}</td>
              <td>{p.destination}</td>
              <td>{p.protocol}</td>
              <td>{p.length}</td>
              <td>{p.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!packets.length && <Empty text="No packets match this view." />}
    </div>
  );
}
function Panel({
  title,
  note,
  children,
}: {
  title: string;
  note: string;
  children: ReactNode;
}) {
  return (
    <section className="wide-panel panel">
      <Title name={title} note={note} />
      {children}
    </section>
  );
}
function Title({ name, note }: { name: string; note: string }) {
  return (
    <div className="panel-title">
      <span>{name}</span>
      <em>{note}</em>
    </div>
  );
}
function Metric({
  label,
  value,
  note,
}: {
  label: string;
  value: string;
  note: string;
}) {
  return (
    <div className="metric">
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{note}</span>
    </div>
  );
}
function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}
function Empty({ text }: { text: string }) {
  return <div className="empty-inspector">{text}</div>;
}
