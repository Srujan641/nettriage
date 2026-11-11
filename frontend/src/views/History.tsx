import { useEffect, useState } from "react";
import { type Report, type ReportSummary, api, formatMs, formatWhen } from "../api";
import { ReportView, StateMark } from "../components/ReportView";
import { Notice, Skeleton } from "./Lab";

export function History() {
  const [items, setItems] = useState<ReportSummary[] | null>(null);
  const [error, setError] = useState("");
  const [confirming, setConfirming] = useState<string | null>(null);

  const load = () => api.reports().then(setItems).catch((e: Error) => setError(e.message));
  useEffect(() => {
    load();
  }, []);

  async function remove(id: string) {
    await api.deleteReport(id).catch(() => undefined);
    setConfirming(null);
    load();
  }

  return (
    <div className="stack">
      <header className="pagehead">
        <h1>History</h1>
        <p className="lead">Every diagnosis run from this dashboard, newest first.</p>
      </header>
      {error && <Notice text={error} />}
      {!items && !error && <Skeleton lines={6} label="Loading history" />}
      {items && items.length === 0 && (
        <div className="empty">
          <h2>No reports yet</h2>
          <p>Reports are saved here each time a diagnosis finishes.</p>
          <a className="btn btn--primary" href="#/">
            Run a diagnosis
          </a>
        </div>
      )}
      {items && items.length > 0 && (
        <div className="table-scroll">
          <table className="table table--history">
            <thead>
              <tr>
                <th>State</th>
                <th>Target</th>
                <th>Verdict</th>
                <th>Run at</th>
                <th className="num">Took</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td>
                    <StateMark state={r.overall} />
                  </td>
                  <td>
                    <a href={`#/report/${r.id}`}>{r.target}</a>
                  </td>
                  <td className="info">{r.headline}</td>
                  <td>{formatWhen(r.started_at)}</td>
                  <td className="num">{formatMs(r.duration_ms)}</td>
                  <td className="table__actions">
                    {confirming === r.id ? (
                      <>
                        <button type="button" className="link link--danger" onClick={() => remove(r.id)}>
                          Confirm delete
                        </button>
                        <button type="button" className="link" onClick={() => setConfirming(null)}>
                          Keep
                        </button>
                      </>
                    ) : (
                      <button type="button" className="link" onClick={() => setConfirming(r.id)}>
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function SavedReport({ id }: { id: string }) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api.report(id).then(setReport).catch((e: Error) => setError(e.message));
  }, [id]);
  if (error) return <Notice text={error} />;
  if (!report) return <Skeleton lines={8} label="Loading report" />;
  return (
    <div className="stack">
      <p className="crumb">
        <a href="#/history">History</a> / {report.target.host}, {formatWhen(report.started_at)}
      </p>
      <ReportView report={report} />
    </div>
  );
}
