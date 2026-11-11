import { type FormEvent, useEffect, useRef, useState } from "react";
import { type Health, type Options, type Report, streamDiagnosis } from "../api";
import { Board, type BoardRow, Findings, Verdict } from "../components/ReportView";

const DEFAULT_CHECKS = [
  ["dns", "DNS lookup"],
  ["ping", "Ping (ICMP echo)"],
  ["traceroute", "Traceroute"],
  ["mtr", "MTR (per-hop loss and latency)"],
  ["mtu", "Path MTU (DF-bit ping sweep)"],
  ["ports", "TCP port check"],
  ["tls", "TLS handshake and certificate"],
  ["http", "HTTP response"],
];

const EXAMPLES = [
  { target: "example.com", note: "a healthy site" },
  { target: "expired.badssl.com", note: "expired certificate" },
  { target: "wrong.host.badssl.com", note: "certificate for another name" },
  { target: "tls-v1-0.badssl.com:1010", note: "TLS 1.0 only" },
  { target: "example.com:81", note: "firewalled port" },
];

type Phase = "idle" | "running" | "done" | "error";

export function Diagnose({ health }: { health: Health | null }) {
  const [target, setTarget] = useState("");
  const [options, setOptions] = useState<Options>({ ports: "", resolver: "", tlsMax: "" });
  const [phase, setPhase] = useState<Phase>("idle");
  const [rows, setRows] = useState<BoardRow[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const cancel = useRef<(() => void) | null>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => () => cancel.current?.(), []);

  function run(value: string) {
    const wanted = value.trim();
    if (!wanted) {
      setError("Enter a hostname or URL to diagnose.");
      setPhase("error");
      input.current?.focus();
      return;
    }
    cancel.current?.();
    setTarget(wanted);
    setReport(null);
    setError("");
    setPhase("running");
    setRows(DEFAULT_CHECKS.map(([id, title]) => ({ id, title, state: "waiting" })));
    cancel.current = streamDiagnosis(wanted, options, (event) => {
      if (event.type === "start") {
        setRows(event.checks.map((c) => ({ ...c, state: "waiting" })));
      } else if (event.type === "check_started") {
        setRows((prev) => prev.map((r) => (r.id === event.id ? { ...r, state: "running" } : r)));
      } else if (event.type === "check_finished") {
        setRows((prev) => prev.map((r) => (r.id === event.check.id ? { ...r, state: event.check.status, check: event.check } : r)));
      } else if (event.type === "report") {
        setReport(event.report);
        setPhase("done");
      } else {
        setError(event.message);
        setPhase("error");
        setRows([]);
      }
    });
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    run(target);
  }

  const done = rows.filter((r) => r.check).length;
  const missing = health ? Object.entries(health.tools).filter(([, ok]) => !ok).map(([t]) => t) : [];

  return (
    <div className="stack">
      <form className="runbar" onSubmit={onSubmit} noValidate>
        <label className="field field--grow">
          <span className="field__label">Hostname or URL</span>
          <input
            ref={input}
            type="text"
            name="target"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="example.com or https://host:8443/health"
            value={target}
            aria-invalid={phase === "error" && !target.trim() ? true : undefined}
            onChange={(e) => setTarget(e.target.value)}
          />
        </label>
        <button type="submit" className="btn btn--primary" aria-busy={phase === "running"}>
          {phase === "running" ? "Running" : "Run diagnosis"}
        </button>
        <details className="options">
          <summary>Options</summary>
          <div className="options__grid">
            <label className="field">
              <span className="field__label">Extra TCP ports</span>
              <input type="text" name="ports" inputMode="numeric" autoComplete="off" placeholder="22,80,443" value={options.ports} onChange={(e) => setOptions({ ...options, ports: e.target.value })} />
            </label>
            <label className="field">
              <span className="field__label">DNS server to query</span>
              <input type="text" name="resolver" inputMode="decimal" autoComplete="off" placeholder="system resolver" value={options.resolver} onChange={(e) => setOptions({ ...options, resolver: e.target.value })} />
            </label>
            <label className="field">
              <span className="field__label">Client TLS ceiling</span>
              <select name="tls_max" value={options.tlsMax} onChange={(e) => setOptions({ ...options, tlsMax: e.target.value })}>
                <option value="">Modern client (TLS 1.3)</option>
                <option value="1.2">Older client (TLS 1.2)</option>
                <option value="1.1">Legacy client (TLS 1.1)</option>
              </select>
            </label>
          </div>
        </details>
      </form>

      {phase === "error" && (
        <div className="notice notice--error" role="alert">
          <strong>The diagnosis did not run.</strong>
          <span>{error}</span>
        </div>
      )}

      {phase === "idle" && (
        <section className="idle">
          <div className="idle__lead">
            <h1>Find the layer that breaks.</h1>
            <p className="lead">Eight checks walk up the stack, from DNS to HTTP. The report names the first one that fails and why.</p>
          </div>
          <div className="idle__examples">
            <h2>Try a target</h2>
            <ul className="examples">
              {EXAMPLES.map((ex) => (
                <li key={ex.target}>
                  <button type="button" className="example" onClick={() => run(ex.target)}>
                    <span className="example__target">{ex.target}</span>
                    <span className="example__note">{ex.note}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
          <Board rows={DEFAULT_CHECKS.map(([id, title]) => ({ id, title, state: "waiting" }))} />
          {missing.length > 0 && (
            <p className="hint">
              Not installed on this machine: {missing.join(", ")}. NetTriage falls back to built-in probes for mtr and nmap; tcpdump is only needed to record captures.
            </p>
          )}
        </section>
      )}

      {phase === "running" && (
        <>
          <section className="verdict verdict--running" aria-live="polite">
            <div className="verdict__status">
              <span className="verdict__word">Running</span>
              <dl className="verdict__meta">
                <div>
                  <dt>Target</dt>
                  <dd>{target}</dd>
                </div>
                <div>
                  <dt>Checks done</dt>
                  <dd>
                    {done} of {rows.length}
                  </dd>
                </div>
              </dl>
            </div>
            <h1 className="verdict__headline">Probing {target}. The verdict appears when the last check lands.</h1>
          </section>
          <Board rows={rows} />
        </>
      )}

      {phase === "done" && report && (
        <>
          <Verdict report={report} />
          <Findings findings={report.findings} />
          <Board rows={rows} />
          <div className="actions">
            <p className="hint">Select a row to see the commands that were run and their raw output.</p>
            <a className="btn" href={`/api/reports/${report.id}/markdown`} download={`nettriage-${report.target.host}.md`}>
              Download Markdown
            </a>
          </div>
        </>
      )}
    </div>
  );
}
