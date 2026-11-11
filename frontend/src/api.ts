// Types and calls for the NetTriage API (backend/nettriage/api.py).

export type Status = "ok" | "warn" | "fail" | "skip";

export interface Command {
  command: string;
  exit_code: number | null;
  output: string;
  duration_ms: number;
  timed_out: boolean;
}

export interface Check {
  id: string;
  title: string;
  status: Status;
  summary: string;
  details: Record<string, any>;
  commands: Command[];
  duration_ms: number;
}

export interface Finding {
  severity: "critical" | "warning" | "info";
  code: string;
  layer: string;
  message: string;
  evidence: string;
  remedy: string;
}

export interface Report {
  id: string;
  target: { raw: string; host: string; scheme: string; port: number; path: string; url: string };
  started_at: string;
  duration_ms: number;
  resolved_ip: string | null;
  overall: Status;
  headline: string;
  findings: Finding[];
  checks: Check[];
  environment: { version?: string; platform?: string; tools?: Record<string, boolean> };
}

export interface ReportSummary {
  id: string;
  target: string;
  started_at: string;
  duration_ms: number;
  overall: Status;
  headline: string;
  resolved_ip: string | null;
}

export interface Health {
  status: string;
  version: string;
  platform: string;
  tools: Record<string, boolean>;
  checks: { id: string; title: string }[];
}

export interface Packet {
  no: number;
  time: number;
  src: string;
  dst: string;
  proto: string;
  length: number;
  info: string;
  tags: string[];
  dir: string;
}

export interface Insight {
  severity: "problem" | "info";
  kind: string;
  text: string;
  packets: number[];
  filter: string;
}

export interface Capture {
  file: string;
  packet_count: number;
  truncated: boolean;
  duration_s: number;
  protocols: Record<string, number>;
  insights: Insight[];
  packets: Packet[];
}

export interface Scenario {
  id: string;
  title: string;
  layer: string;
  target: string;
  symptom: string;
  fault: string;
  command: string;
  expect: string;
  captures: { name: string; label: string }[];
  has_report: boolean;
  writeup?: string;
  report?: Report | null;
}

export interface Options {
  ports: string;
  resolver: string;
  tlsMax: string;
}

export type StreamEvent =
  | { type: "start"; id: string; target: string; checks: { id: string; title: string }[] }
  | { type: "check_started"; id: string }
  | { type: "check_finished"; check: Check }
  | { type: "report"; report: Report }
  | { type: "error"; message: string };

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(url, init);
  } catch {
    throw new Error("The NetTriage API is not reachable. Start it with: nettriage serve");
  }
  if (!resp.ok) {
    let detail = `${resp.status} ${resp.statusText}`;
    try {
      const body = await resp.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      /* keep the status text */
    }
    throw new Error(resp.status === 502 || resp.status === 504 ? "The NetTriage API is not reachable. Start it with: nettriage serve" : detail);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  health: () => getJson<Health>("/api/health"),
  reports: () => getJson<ReportSummary[]>("/api/reports"),
  report: (id: string) => getJson<Report>(`/api/reports/${id}`),
  deleteReport: (id: string) => getJson<{ deleted: string }>(`/api/reports/${id}`, { method: "DELETE" }),
  scenarios: () => getJson<Scenario[]>("/api/scenarios"),
  scenario: (id: string) => getJson<Scenario>(`/api/scenarios/${id}`),
  scenarioCapture: (id: string, name: string) => getJson<Capture>(`/api/scenarios/${id}/captures/${name}`),
  analyze: (file: File) =>
    getJson<Capture>("/api/pcap/analyze", {
      method: "POST",
      body: file,
      headers: { "Content-Type": "application/octet-stream", "X-Filename": file.name.replace(/[^\w.-]/g, "_") },
    }),
};

/** Run a diagnosis and receive each check as it finishes. Returns a function that cancels the stream. */
export function streamDiagnosis(target: string, options: Options, onEvent: (e: StreamEvent) => void): () => void {
  const params = new URLSearchParams({ target });
  if (options.ports.trim()) params.set("ports", options.ports.replace(/\s+/g, ""));
  if (options.resolver.trim()) params.set("resolver", options.resolver.trim());
  if (options.tlsMax) params.set("tls_max", options.tlsMax);
  const controller = new AbortController();

  (async () => {
    try {
      const resp = await fetch(`/api/diagnose/stream?${params}`, { signal: controller.signal });
      if (!resp.ok || !resp.body) {
        let message = resp.status >= 500 ? "The NetTriage API is not reachable. Start it with: nettriage serve" : `Request failed (${resp.status})`;
        try {
          const body = await resp.json();
          if (typeof body.detail === "string") message = body.detail;
        } catch {
          /* keep the default */
        }
        onEvent({ type: "error", message });
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let finished = false;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let cut: number;
        while ((cut = buffer.indexOf("\n\n")) >= 0) {
          const chunk = buffer.slice(0, cut);
          buffer = buffer.slice(cut + 2);
          if (chunk.startsWith("data: ")) {
            const event = JSON.parse(chunk.slice(6)) as StreamEvent;
            if (event.type === "report" || event.type === "error") finished = true;
            onEvent(event);
          }
        }
      }
      if (!finished) onEvent({ type: "error", message: "The connection to the API closed before the report arrived." });
    } catch (err) {
      if (!controller.signal.aborted) {
        onEvent({ type: "error", message: "The NetTriage API is not reachable. Start it with: nettriage serve" });
      }
    }
  })();
  return () => controller.abort();
}

export const VERDICT: Record<Status, string> = { ok: "Healthy", warn: "Degraded", fail: "Broken", skip: "Skipped" };

export function formatMs(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`;
}

export function formatWhen(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
