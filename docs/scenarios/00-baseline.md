# Baseline: a healthy service

Packet numbers refer to the included `labs/captures/00-baseline/client.pcap`. Re-running the lab records a new capture with different numbering.

## Why this run exists

A capture of a broken service only means something next to a capture of a working one. This is the control: `healthy.lab` serves a certificate signed by the lab CA over TLS 1.3 and answers HTTP 200.

## What the tool reported

> Everything checks out: DNS resolves fine, TCP 443 is open, the TLS handshake succeeds (TLSv1.3) and the server answers HTTP 200.

All eight checks pass. The path MTU is the full 1500 bytes, and there is one hop.

## What a clean capture looks like

| Step | What to look for | Wireshark filter |
|---|---|---|
| DNS | Each query has a response within a millisecond, rcode `NOERROR` | `dns` |
| TCP | SYN, SYN/ACK, ACK: the three-way handshake completes | `tcp.flags.syn == 1` |
| TLS | Client Hello, then Server Hello, then encrypted records | `tls.handshake` |
| HTTP | Carried inside TLS, so it shows as Application Data | `tls.app_data` |
| Ping | Every echo request has a reply | `icmp` |

## Probe traffic you will see in every capture

NetTriage records its own traffic, so some packets come from its probes and are not symptoms. They appear here on a healthy server:

- **A connection that opens and closes with no data.** The TCP port check. The server answers the empty connection with a `decode_error` alert, because it expected a Client Hello.
- **A SYN, SYN/ACK, RST with a small window (1024).** The `nmap` half-open scan.
- **Client Hellos offering only TLS 1.0, then only TLS 1.1, each refused with `protocol_version`.** The version probes. A healthy server is supposed to refuse these.
- **RSTs at the end of short connections.** The probes close abruptly once they have their answer.

The analyser labels all of these "Context" and reports zero faults for this capture.
