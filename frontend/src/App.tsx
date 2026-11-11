import { useEffect, useState } from "react";
import { type Health, api } from "./api";
import { useRoute } from "./router";
import { Captures } from "./views/Captures";
import { Diagnose } from "./views/Diagnose";
import { History, SavedReport } from "./views/History";
import { Lab } from "./views/Lab";

const NAV = [
  { key: "", label: "Diagnose" },
  { key: "lab", label: "Lab scenarios" },
  { key: "captures", label: "Capture analyser" },
  { key: "history", label: "History" },
];

export function App() {
  const route = useRoute();
  const view = route[0] ?? "";
  const current = view === "report" ? "history" : view;
  const [health, setHealth] = useState<Health | null | "down">(null);

  useEffect(() => {
    let alive = true;
    const check = () =>
      api
        .health()
        .then((h) => alive && setHealth(h))
        .catch(() => alive && setHealth("down"));
    check();
    const timer = window.setInterval(check, 15000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <div className="container topbar__in">
          <a className="wordmark" href="#/" aria-label="NetTriage home">
            NetTriage
          </a>
          <nav aria-label="Main">
            <ul className="topbar__nav">
              {NAV.map((n) => (
                <li key={n.key}>
                  <a href={`#/${n.key}`} aria-current={current === n.key ? "page" : undefined}>
                    {n.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <p className={`apistate apistate--${health === "down" ? "down" : health ? "up" : "wait"}`} role="status">
            <span className="state__sq" aria-hidden="true" />
            {health === "down" ? "API offline" : health ? `API ${health.version}` : "Connecting"}
          </p>
        </div>
      </header>

      <main id="main" className="container main">
        {health === "down" && (
          <div className="notice notice--error" role="alert">
            <strong>The NetTriage API is not running.</strong>
            <span>
              Start it in a terminal, then this page reconnects on its own: <code>cd backend && ./.venv/bin/nettriage serve</code>
            </span>
          </div>
        )}
        {view === "" && <Diagnose health={health && health !== "down" ? health : null} />}
        {view === "lab" && <Lab id={route[1]} tab={route[2]} capture={route[3]} />}
        {view === "captures" && <Captures />}
        {view === "history" && <History />}
        {view === "report" && route[1] && <SavedReport id={route[1]} />}
        {!["", "lab", "captures", "history", "report"].includes(view) && (
          <div className="empty">
            <h1>No such page</h1>
            <p>
              <a href="#/">Back to Diagnose</a>
            </p>
          </div>
        )}
      </main>
    </>
  );
}
