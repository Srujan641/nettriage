import { useState } from "react";
import { type Check, type Finding, type Report, type Status, VERDICT, formatMs } from "../api";

const STATE_WORD: Record<Status | "waiting" | "running", string> = {
  ok: "Pass",
  warn: "Warn",
  fail: "Fail",
  skip: "Skipped",
  waiting: "Queued",
  running: "Running",
};

export function StateMark({ state }: { state: Status | "waiting" | "running" }) {
  return (
    <span className={`state state--${state}`}>
      <span className="state__sq" aria-hidden="true" />
      {STATE_WORD[state]}
    </span>
  );
}

/** The verdict plate: one sentence that names the root cause. */
export function Verdict({ report }: { report: Report }) {
  return (
    <section className={`verdict verdict--${report.overall}`} aria-live="polite">
      <div className="verdict__status">
        <span className="verdict__word">{VERDICT[report.overall]}</span>
        <dl className="verdict__meta">
          <div>
            <dt>Target</dt>
            <dd>{report.target.url}</dd>
          </div>
          <div>
            <dt>Address</dt>
            <dd>{report.resolved_ip ?? "unresolved"}</dd>
          </div>
          <div>
            <dt>Took</dt>
            <dd>{formatMs(report.duration_ms)}</dd>
          </div>
        </dl>
      </div>
      <h1 className="verdict__headline">{report.headline}</h1>
    </section>
  );
}

const SEVERITY_WORD = { critical: "Critical", warning: "Warning", info: "Note" } as const;

export function Findings({ findings }: { findings: Finding[] }) {
  if (!findings.length) return null;
  return (
    <section className="panel">
      <h2>Findings</h2>
      <ul className="findings">
        {findings.map((f) => (
          <li key={f.code + f.message} className={`finding finding--${f.severity}`}>
            <div className="finding__head">
              <span className={`tag tag--${f.severity}`}>{SEVERITY_WORD[f.severity]}</span>
              <code>{f.code}</code>
              <span className="finding__layer">{f.layer} layer</span>
            </div>
            <p className="finding__msg">{f.message}</p>
            {(f.evidence || f.remedy) && (
              <dl className="finding__more">
                {f.evidence && (
                  <div>
                    <dt>Evidence</dt>
                    <dd>{f.evidence}</dd>
                  </div>
                )}
                {f.remedy && (
                  <div>
                    <dt>Next step</dt>
                    <dd>{f.remedy}</dd>
                  </div>
                )}
              </dl>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Short row names and what each check does, shown before it has a result. */
const CHECKS: Record<string, { name: string; does: string }> = {
  dns: { name: "DNS lookup", does: "dig for A and AAAA records; public resolvers are asked too if yours fails" },
  ping: { name: "Ping", does: "five ICMP echoes for loss, latency and jitter" },
  traceroute: { name: "Traceroute", does: "the route to the host, hop by hop" },
  mtr: { name: "MTR", does: "five probes per hop to find where loss or latency starts" },
  mtu: { name: "Path MTU", does: "pings with Don't-Fragment set to find the largest packet that gets through" },
  ports: { name: "TCP ports", does: "open, closed (reset) or filtered (silence) for each port" },
  tls: { name: "TLS and certificate", does: "openssl s_client handshake, certificate dates and names, versions accepted" },
  http: { name: "HTTP response", does: "curl to the resolved address: status, redirects and timing" },
};

export interface BoardRow {
  id: string;
  title: string;
  state: Status | "waiting" | "running";
  check?: Check;
}

/** The diagnostic board: one row per check, filled in as results land. */
export function Board({ rows }: { rows: BoardRow[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <section className="board" aria-label="Diagnostic checks">
      <div className="board__head" aria-hidden="true">
        <span>Check</span>
        <span>Result</span>
        <span className="num">Time</span>
        <span>State</span>
      </div>
      <ol className="board__rows">
        {rows.map((row, i) => {
          const expanded = open === row.id && !!row.check;
          const canOpen = !!row.check && (row.check.commands.length > 0 || hasDetails(row.check));
          return (
            <li key={row.id} className={`board__row board__row--${row.state}`}>
              <button
                type="button"
                className="board__line"
                aria-expanded={canOpen ? expanded : undefined}
                disabled={!canOpen}
                onClick={() => setOpen(expanded ? null : row.id)}
              >
                <span className="board__name">
                  <span className="board__idx num">{String(i + 1).padStart(2, "0")}</span>
                  {CHECKS[row.id]?.name ?? row.title}
                </span>
                <span className="board__summary">{row.check?.summary ?? (row.state === "running" ? "Probing now" : (CHECKS[row.id]?.does ?? ""))}</span>
                <span className="board__time num">{row.check && row.state !== "skip" ? formatMs(row.check.duration_ms) : ""}</span>
                <StateMark state={row.state} />
              </button>
              {expanded && row.check && <CheckDetail check={row.check} />}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function hasDetails(check: Check): boolean {
  const d = check.details;
  return Boolean(d.hops?.length || d.ports?.length || d.certificate || d.timing_ms || d.a?.length);
}

function CheckDetail({ check }: { check: Check }) {
  return (
    <div className="detail">
      <Structured check={check} />
      {check.commands.map((cmd, i) => (
        <figure className="evidence" key={i}>
          <figcaption>
            <code>$ {cmd.command}</code>
            <span className="num">
              {cmd.timed_out ? "timed out" : `exit ${cmd.exit_code}`}, {formatMs(cmd.duration_ms)}
            </span>
          </figcaption>
          <pre tabIndex={0}>{trimCerts(cmd.output) || "(no output)"}</pre>
        </figure>
      ))}
    </div>
  );
}

/** Certificates in s_client output are base64 walls; fold them so the evidence stays readable. */
function trimCerts(output: string): string {
  return output.replace(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g, "-----BEGIN CERTIFICATE----- [folded] -----END CERTIFICATE-----");
}

function Structured({ check }: { check: Check }) {
  const d = check.details;
  if ((check.id === "mtr" || check.id === "traceroute") && d.hops?.length) {
    const mtr = check.id === "mtr";
    return (
      <table className="table">
        <thead>
          <tr>
            <th className="num">Hop</th>
            <th>Address</th>
            {mtr && <th className="num">Loss</th>}
            {mtr && <th className="num">Sent</th>}
            {mtr && <th className="num">Best</th>}
            <th className="num">{mtr ? "Average" : "Round trip"}</th>
            {mtr && <th className="num">Worst</th>}
          </tr>
        </thead>
        <tbody>
          {d.hops.map((h: any) => (
            <tr key={h.ttl} className={mtr && h.ip && h.loss_pct >= 20 ? "is-flagged" : undefined}>
              <td className="num">{h.ttl}</td>
              <td>{h.ip ?? "no reply"}</td>
              {mtr && <td className="num">{h.loss_pct.toFixed(0)}%</td>}
              {mtr && <td className="num">{h.sent}</td>}
              {mtr && <td className="num">{fmt(h.best_ms)}</td>}
              <td className="num">{fmt(mtr ? h.avg_ms : h.rtt_ms)}</td>
              {mtr && <td className="num">{fmt(h.worst_ms)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  if (check.id === "ports" && d.ports?.length) {
    return (
      <table className="table">
        <thead>
          <tr>
            <th className="num">Port</th>
            <th>Service</th>
            <th>State</th>
            <th className="num">Connect</th>
            <th>What happened</th>
          </tr>
        </thead>
        <tbody>
          {d.ports.map((p: any) => (
            <tr key={p.port} className={p.state !== "open" && p.port === d.primary?.port ? "is-flagged" : undefined}>
              <td className="num">{p.port}</td>
              <td>{p.service || "unknown"}</td>
              <td>{p.state}</td>
              <td className="num">{fmt(p.connect_ms)}</td>
              <td>{p.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  if (check.id === "tls") {
    const c = d.certificate;
    return (
      <div className="facts-grid">
        {d.versions && (
          <dl className="facts">
            <div>
              <dt>Negotiated</dt>
              <dd>{d.protocol ? `${d.protocol}, ${d.cipher}` : "no session"}</dd>
            </div>
            {Object.entries(d.versions as Record<string, boolean | null>).map(([v, ok]) => (
              <div key={v}>
                <dt>{v}</dt>
                <dd>{ok === true ? "accepted" : ok === false ? "refused" : "not testable from this client"}</dd>
              </div>
            ))}
          </dl>
        )}
        {c && (
          <dl className="facts">
            <div>
              <dt>Subject</dt>
              <dd>{c.common_name ?? c.subject}</dd>
            </div>
            <div>
              <dt>Issuer</dt>
              <dd>{c.issuer_name ?? c.issuer}</dd>
            </div>
            <div>
              <dt>Valid from</dt>
              <dd>{c.not_before?.slice(0, 10)}</dd>
            </div>
            <div>
              <dt>Valid until</dt>
              <dd>
                {c.not_after?.slice(0, 10)} ({c.days_left < 0 ? `expired ${-c.days_left} days ago` : `${c.days_left} days left`})
              </dd>
            </div>
            <div>
              <dt>Names</dt>
              <dd>{(c.san ?? []).slice(0, 6).join(", ") || "none"}</dd>
            </div>
            <div>
              <dt>Key</dt>
              <dd>
                {c.key_bits} bit, {c.signature_algorithm}
              </dd>
            </div>
            <div>
              <dt>Chain check</dt>
              <dd>{d.verify_text ?? "not run"}</dd>
            </div>
          </dl>
        )}
      </div>
    );
  }
  if (check.id === "http" && d.timing_ms) {
    const t = d.timing_ms;
    return (
      <dl className="facts">
        <div>
          <dt>Status</dt>
          <dd>{d.status_code ? `${d.status_code} ${d.reason ?? ""}` : "no response"}</dd>
        </div>
        <div>
          <dt>Server</dt>
          <dd>{d.server ?? "not disclosed"}</dd>
        </div>
        <div>
          <dt>TCP connect</dt>
          <dd>{fmt(t.connect)}</dd>
        </div>
        {t.tls ? (
          <div>
            <dt>TLS done</dt>
            <dd>{fmt(t.tls)}</dd>
          </div>
        ) : null}
        <div>
          <dt>First byte</dt>
          <dd>{fmt(t.first_byte)}</dd>
        </div>
        <div>
          <dt>Total</dt>
          <dd>{fmt(t.total)}</dd>
        </div>
        <div>
          <dt>Body</dt>
          <dd>{d.bytes} bytes</dd>
        </div>
        {d.redirects?.length ? (
          <div>
            <dt>Redirects</dt>
            <dd>{d.redirects.map((r: any) => `${r.status} to ${r.location}`).join(", then ")}</dd>
          </div>
        ) : null}
      </dl>
    );
  }
  if (check.id === "dns" && (d.a?.length || d.aaaa?.length)) {
    return (
      <dl className="facts">
        <div>
          <dt>Resolver</dt>
          <dd>{d.resolver ?? "none"}</dd>
        </div>
        <div>
          <dt>A records</dt>
          <dd>{d.a?.join(", ") || "none"}</dd>
        </div>
        <div>
          <dt>AAAA records</dt>
          <dd>{d.aaaa?.join(", ") || "none"}</dd>
        </div>
        {d.cname?.length ? (
          <div>
            <dt>CNAME chain</dt>
            <dd>{d.cname.join(", then ")}</dd>
          </div>
        ) : null}
        {d.ttl != null && (
          <div>
            <dt>TTL</dt>
            <dd>{d.ttl} s</dd>
          </div>
        )}
      </dl>
    );
  }
  return null;
}

function fmt(v: number | null | undefined): string {
  return v == null ? "none" : `${v < 10 ? v.toFixed(1) : v.toFixed(0)} ms`;
}

/** A finished report: verdict, findings, then the board with evidence behind each row. */
export function ReportView({ report }: { report: Report }) {
  const rows: BoardRow[] = report.checks.map((c) => ({ id: c.id, title: c.title, state: c.status, check: c }));
  return (
    <>
      <Verdict report={report} />
      <Findings findings={report.findings} />
      <Board rows={rows} />
      <p className="hint">Select a row to see the commands that were run and their raw output.</p>
    </>
  );
}
