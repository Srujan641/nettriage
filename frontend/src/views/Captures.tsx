import { type DragEvent, useRef, useState } from "react";
import { type Capture, api } from "../api";
import { PacketTable } from "../components/PacketTable";
import { Notice, Skeleton } from "./Lab";

export function Captures() {
  const [capture, setCapture] = useState<Capture | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [over, setOver] = useState(false);
  const picker = useRef<HTMLInputElement>(null);

  async function load(file: File | undefined) {
    if (!file) return;
    setBusy(true);
    setError("");
    setCapture(null);
    try {
      setCapture(await api.analyze(file));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setOver(false);
    load(e.dataTransfer.files[0]);
  }

  return (
    <div className="stack">
      <header className="pagehead">
        <h1>Capture analyser</h1>
        <p className="lead">Decode a tcpdump or Wireshark capture and get the packets that explain the failure.</p>
      </header>

      <div className={`drop ${over ? "is-over" : ""}`} onDragOver={(e) => (e.preventDefault(), setOver(true))} onDragLeave={() => setOver(false)} onDrop={onDrop}>
        <p>
          <strong>Drop a .pcap or .pcapng file here</strong>
        </p>
        <p className="drop__hint">Up to 25 MB. The file is decoded by the local API and is not stored.</p>
        <button type="button" className="btn btn--primary" onClick={() => picker.current?.click()} disabled={busy}>
          Choose a file
        </button>
        <input ref={picker} type="file" name="capture" accept=".pcap,.pcapng,.cap" className="visually-hidden" tabIndex={-1} onChange={(e) => (load(e.target.files?.[0]), (e.target.value = ""))} />
      </div>

      {busy && <Skeleton lines={8} label="Decoding capture" />}
      {error && <Notice text={error} />}
      {capture && <PacketTable capture={capture} />}
      {!capture && !busy && !error && (
        <p className="hint">
          No capture to hand? Record one with <code>sudo nettriage example.com --pcap out.pcap</code>, or open a lab scenario and look at its packets.
        </p>
      )}
    </div>
  );
}
