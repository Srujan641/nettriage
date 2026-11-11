import { useMemo, useRef, useState } from "react";
import type { Capture, Insight, Packet } from "../api";

const ROW_LIMIT = 1500;
const ALARM = new Set(["rst", "tls-alert", "dns-error"]);

function rowClass(p: Packet, selected: Set<number>): string {
  const classes = [];
  if (selected.has(p.no)) classes.push("is-selected");
  if (p.tags.some((t) => ALARM.has(t))) classes.push("is-alarm");
  else if (p.tags.length) classes.push("is-flagged");
  return classes.join(" ");
}

/** Wireshark-style packet list with the analyser's findings above it. */
export function PacketTable({ capture }: { capture: Capture }) {
  const [proto, setProto] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState<Insight | null>(null);
  const tableRef = useRef<HTMLDivElement>(null);
  const hasDirection = capture.packets.some((p) => p.dir);
  const selected = useMemo(() => new Set(picked?.packets ?? []), [picked]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return capture.packets.filter(
      (p) =>
        (proto === "all" || p.proto === proto) &&
        (!q || p.info.toLowerCase().includes(q) || p.src.includes(q) || p.dst.includes(q) || String(p.no) === q),
    );
  }, [capture, proto, query]);

  function show(insight: Insight) {
    setPicked(insight);
    setProto("all");
    setQuery("");
    requestAnimationFrame(() => {
      const row = tableRef.current?.querySelector<HTMLElement>(`[data-no="${insight.packets[0]}"]`);
      row?.scrollIntoView({ block: "center" });
    });
  }

  const problems = capture.insights.filter((i) => i.severity === "problem");
  const context = capture.insights.filter((i) => i.severity !== "problem");

  return (
    <div className="capture">
      <section className="insights">
        <h3>What the capture shows</h3>
        <p className="capture__meta">
          {capture.file} holds {capture.packet_count} packets over {capture.duration_s.toFixed(2)} seconds.
        </p>
        {capture.insights.length === 0 && <p className="insights__none">Nothing abnormal: no resets, alerts, DNS errors, retransmissions or dropped probes.</p>}
        <ul>
          {[...problems, ...context].map((i, n) => (
            <li key={n} className={`insight insight--${i.severity} ${picked === i ? "is-picked" : ""}`}>
              <span className={`tag tag--${i.severity === "problem" ? "critical" : "info"}`}>{i.severity === "problem" ? "Fault" : "Context"}</span>
              <div>
                <p>{i.text}</p>
                <div className="insight__actions">
                  {i.packets.length > 0 && (
                    <button type="button" className="link" onClick={() => show(i)}>
                      {i.packets.length > 1 ? `Show ${i.packets.length} packets` : `Show packet ${i.packets[0]}`}
                    </button>
                  )}
                  <span className="insight__filter">
                    Wireshark filter <code>{i.filter}</code>
                  </span>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <div className="toolbar">
        <div className="cells" role="group" aria-label="Protocol">
          {["all", ...Object.keys(capture.protocols)].map((p) => (
            <button key={p} type="button" className={`cell ${proto === p ? "is-on" : ""}`} aria-pressed={proto === p} onClick={() => setProto(p)}>
              {p === "all" ? "All" : p} <span className="num">{p === "all" ? capture.packet_count : capture.protocols[p]}</span>
            </button>
          ))}
        </div>
        <label className="field field--inline">
          <span className="visually-hidden">Filter packets</span>
          <input
            type="search"
            name="packet-filter"
            autoComplete="off"
            placeholder="Filter by address, text or number"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
      </div>

      <div className="table-scroll" ref={tableRef}>
        <table className="table table--packets">
          <thead>
            <tr>
              <th className="num">No.</th>
              <th className="num">Time</th>
              {hasDirection && <th>Dir</th>}
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th className="num">Length</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, ROW_LIMIT).map((p) => (
              <tr key={p.no} data-no={p.no} className={rowClass(p, selected)}>
                <td className="num">{p.no}</td>
                <td className="num">{p.time.toFixed(4)}</td>
                {hasDirection && <td>{p.dir}</td>}
                <td>{p.src}</td>
                <td>{p.dst}</td>
                <td>{p.proto}</td>
                <td className="num">{p.length}</td>
                <td className="info">{p.info}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={hasDirection ? 8 : 7} className="table__empty">
                  No packets match this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {(rows.length > ROW_LIMIT || capture.truncated) && (
        <p className="hint">Showing the first {Math.min(rows.length, ROW_LIMIT)} packets. Narrow the filter, or open the file in Wireshark for the rest.</p>
      )}
    </div>
  );
}
