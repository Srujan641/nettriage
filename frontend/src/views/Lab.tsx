import { marked } from "marked";
import { useEffect, useMemo, useState } from "react";
import { type Capture, type Scenario, api } from "../api";
import { PacketTable } from "../components/PacketTable";
import { ReportView } from "../components/ReportView";
import { go } from "../router";

const TABS = [
  { key: "writeup", label: "Write-up" },
  { key: "packets", label: "Packets" },
  { key: "report", label: "Tool report" },
];

export function Lab({ id, tab, capture }: { id?: string; tab?: string; capture?: string }) {
  const [list, setList] = useState<Scenario[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .scenarios()
      .then((s) => {
        setList(s);
        if (!id && s.length) go("lab", s[0].id);
      })
      .catch((e: Error) => setError(e.message));
  }, [id]);

  if (error) return <Notice text={error} />;
  if (!list) return <Skeleton lines={6} label="Loading scenarios" />;
  if (!list.length)
    return (
      <div className="empty">
        <h1>No lab scenarios found</h1>
        <p>The scenario definitions live in labs/scenarios. Check that the API was started from this project.</p>
      </div>
    );

  return (
    <div className="lab">
      <nav className="lab__list" aria-label="Scenarios">
        <h1>Lab scenarios</h1>
        <p className="lab__intro">Faults built on purpose in a Docker lab, diagnosed by the tool and captured for Wireshark.</p>
        <ul>
          {list.map((s) => (
            <li key={s.id}>
              <a href={`#/lab/${s.id}`} aria-current={s.id === id ? "true" : undefined}>
                <span className="lab__layer">{s.layer}</span>
                <span className="lab__title">{s.title}</span>
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <div className="lab__body">{id && <ScenarioView key={id} id={id} tab={tab ?? "writeup"} capture={capture} />}</div>
    </div>
  );
}

function ScenarioView({ id, tab, capture }: { id: string; tab: string; capture?: string }) {
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.scenario(id).then(setScenario).catch((e: Error) => setError(e.message));
  }, [id]);

  const html = useMemo(() => (scenario?.writeup ? (marked.parse(scenario.writeup, { async: false }) as string) : ""), [scenario]);

  if (error) return <Notice text={error} />;
  if (!scenario) return <Skeleton lines={8} label="Loading scenario" />;
  const recorded = scenario.captures.length > 0;
  const active = capture && scenario.captures.some((c) => c.name === capture) ? capture : scenario.captures[0]?.name;

  return (
    <article className="scenario">
      <header className="scenario__head">
        <h2>{scenario.title}</h2>
        <dl className="facts">
          <div>
            <dt>Symptom</dt>
            <dd>{scenario.symptom}</dd>
          </div>
          <div>
            <dt>Planted fault</dt>
            <dd>{scenario.fault}</dd>
          </div>
          <div>
            <dt>Command</dt>
            <dd>
              <code>{scenario.command}</code>
            </dd>
          </div>
        </dl>
      </header>

      <div className="cells cells--tabs" role="tablist" aria-label="Scenario material">
        {TABS.map((t) => (
          <button key={t.key} type="button" role="tab" aria-selected={tab === t.key} className={`cell ${tab === t.key ? "is-on" : ""}`} onClick={() => go("lab", id, t.key)}>
            {t.label}
          </button>
        ))}
      </div>

      {!recorded && tab !== "writeup" && (
        <div className="empty">
          <h3>Not recorded yet</h3>
          <p>
            Run the lab to record the report and captures for this scenario: <code>./labs/run.sh {id}</code>
          </p>
        </div>
      )}

      {tab === "writeup" &&
        (html ? (
          <div className="prose" dangerouslySetInnerHTML={{ __html: html }} />
        ) : (
          <div className="empty">
            <h3>No write-up for this scenario</h3>
            <p>Write-ups live in docs/scenarios/{id}.md.</p>
          </div>
        ))}

      {tab === "packets" && recorded && active && (
        <>
          <div className="toolbar">
            <div className="cells" role="group" aria-label="Capture point">
              {scenario.captures.map((c) => (
                <button key={c.name} type="button" className={`cell ${active === c.name ? "is-on" : ""}`} aria-pressed={active === c.name} onClick={() => go("lab", id, "packets", c.name)}>
                  {c.label}
                </button>
              ))}
            </div>
            <a className="btn btn--small" href={`/api/scenarios/${id}/captures/${active}?download=true`}>
              Download .pcap
            </a>
          </div>
          <LabCapture key={active} id={id} name={active} />
        </>
      )}

      {tab === "report" && recorded && (scenario.report ? <ReportView report={scenario.report} /> : <Notice text="This scenario has captures but no saved report." />)}
    </article>
  );
}

function LabCapture({ id, name }: { id: string; name: string }) {
  const [data, setData] = useState<Capture | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api.scenarioCapture(id, name).then(setData).catch((e: Error) => setError(e.message));
  }, [id, name]);
  if (error) return <Notice text={error} />;
  if (!data) return <Skeleton lines={10} label="Decoding capture" />;
  return <PacketTable capture={data} />;
}

export function Notice({ text }: { text: string }) {
  return (
    <div className="notice notice--error" role="alert">
      <strong>That did not load.</strong>
      <span>{text}</span>
    </div>
  );
}

export function Skeleton({ lines, label }: { lines: number; label: string }) {
  return (
    <div className="skeleton" role="status" aria-label={label}>
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className="skeleton__line" />
      ))}
    </div>
  );
}
