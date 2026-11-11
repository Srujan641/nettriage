# Architecture

## The idea

Network faults are diagnosed by walking up the stack: does the name resolve, does the host answer, is the port open, does TLS complete, does the application reply? NetTriage automates that walk and then does the part that usually stays in an engineer's head: it reasons across the results and names the first layer that breaks, in a sentence.

```
                 ┌────────────── frontend/ (React) ──────────────┐
                 │ Diagnose · Lab scenarios · Captures · History │
                 └───────────────────────┬───────────────────────┘
                                         │ HTTP + server-sent events
┌──────────── CLI ────────────┐   ┌──────┴──────── api.py ────────┐
│ nettriage example.com       │   │ FastAPI on 127.0.0.1:8000     │
└──────────────┬──────────────┘   └──────────────┬────────────────┘
               └──────────────┬──────────────────┘
                       engine.py  (orchestration, events)
                              │
     ┌────────┬───────────────┼───────────────┬─────────┬────────┐
   dns.py  network.py      ports.py         tls.py    http.py   capture.py
    dig    ping, traceroute  connect()   openssl s_client  curl   tcpdump
           mtr, DF sweep     + nmap      + version probes
                              │
                       diagnosis.py  (cross-layer rules -> headline + findings)
                              │
                 render.py (terminal, Markdown)      pcap.py (capture decoder)
```

## Components

| Path | Responsibility |
|---|---|
| `backend/nettriage/checks/` | One module per layer. Each check runs real tools, parses their output and returns a `CheckResult`: a status, a one-line summary, structured details, and every command it ran with the raw output as evidence. Checks only measure; they do not decide what the problem is. |
| `backend/nettriage/engine.py` | Runs DNS first, then the network checks (ping, traceroute, MTR, path MTU) in parallel with the service chain (TCP, then TLS, then HTTP). Emits an event as each check finishes. Skips checks that cannot be meaningful, such as TLS when the port is closed. |
| `backend/nettriage/diagnosis.py` | The rules engine. Pure logic over check results, so it is unit-tested without a network. Produces the headline and the findings, each with evidence and a next step. |
| `backend/nettriage/pcap.py` | A dependency-free reader for pcap and pcapng. Decodes IPv4, TCP, UDP, ICMP, DNS, TLS handshake and alert records, and HTTP first lines. Then finds the packets that explain a failure. |
| `backend/nettriage/api.py` | Local REST API. Streams a diagnosis as server-sent events, stores reports as JSON, serves lab scenarios and decodes uploaded captures. |
| `frontend/` | React and TypeScript dashboard built with Vite. |
| `labs/` | Docker Compose lab: one healthy service and four broken ones, plus the runner that records each scenario. |

## Design decisions

**The engine has no third-party dependencies.** The CLI runs on any machine with Python 3.10 and the standard network tools. FastAPI is an optional extra for the dashboard.

**Real tools first, built-in fallbacks second.** The brief names `dig`, `ping`, `traceroute`, `mtr`, `nmap` and `openssl s_client`, and those are what run. Where a tool is often missing or needs root, there is a fallback: a TCP `connect()` scan stands in for `nmap`, and a built-in ICMP prober stands in for `mtr`. The prober sends one echo per TTL per cycle and times each reply. On macOS it uses datagram ICMP sockets, which need no root.

**Every later check is pinned to the address DNS returned.** `curl --resolve` and `openssl s_client -connect <ip> -servername <host>` guarantee that all layers test the same server, and let a custom resolver (such as the lab's) drive the whole chain.

**The TLS check behaves like a current browser.** It offers TLS 1.2 and 1.3. Whether the server still accepts older versions is measured separately, one connection per version, and reported as its own finding.

**First broken layer wins.** If the port is closed, the report says so and does not also complain that TLS and HTTP failed. Supporting checks are used to explain a failure, not to add noise: a host that ignores ping but accepts TCP gets a note, not a warning.

**One root cause, not a list of symptoms.** The MTU rule is the example. A stalled HTTP response and a path-MTU measurement with no ICMP error are two facts; the diagnosis joins them into one finding and suppresses the generic "HTTP stalled" one.

**The capture analyser separates faults from context.** NetTriage's own probes produce resets and TLS alerts on a healthy server. The analyser labels those as context, so the baseline capture reports zero faults and a real fault stands out.

## Security

The API launches network probes on request, so it is treated as a local tool.

- It binds to `127.0.0.1` and warns if started on any other address. CORS allows only localhost origins.
- Targets are validated once, in `parse_target`, before anything runs: scheme allow-list, strict hostname grammar, no whitespace or control characters. Hostnames end up in the argv of external tools, so a value that could be read as an option is rejected.
- External tools are always run with an argument list, never through a shell.
- Report and scenario identifiers are matched against a strict pattern before they touch the filesystem.
- At most three diagnoses run at once, and uploads are capped at 25 MB.
- Lab certificates and keys are generated at start-up into a Docker volume. No key material is committed.

Only test hosts you own or are authorised to test.

## Testing

`backend/tests/` holds 90 tests:

| File | What it covers |
|---|---|
| `test_util.py`, `test_parsers.py` | Target validation, and parsing of ping, mtr and certificate-name output from both macOS and Linux |
| `test_diagnosis.py` | The rules engine, including the exact sentence from the brief |
| `test_pcap.py` | The decoder against synthetic packets, and against the recorded lab captures: each planted fault must be found, and the baseline must report none |
| `test_api.py` | Endpoints, input rejection and path-traversal attempts |
| `test_cli.py`, `test_network_checks.py` | The command line, renderers, and the ping, traceroute, MTR, path-MTU and port checks run against loopback |
| `test_live.py` | End-to-end runs against the internet (badssl.com), marked `network` |

## Known limits

- IPv4 only. IPv6 addresses are reported by the DNS check but not tested.
- The capture decoder reads the start of each TCP segment. It does not reassemble streams, so a TLS record split across packets is decoded only from its first packet.
- The path-MTU check needs the target to answer ping.
- Recording a capture needs root, or BPF access on macOS. The lab avoids this by capturing inside containers.
