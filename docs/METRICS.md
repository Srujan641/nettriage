# Measured results

Produced by `scripts/benchmark.py` on 2026-11-11. Every figure below was observed in that run; re-run the script to reproduce it.

## Root-cause accuracy

Each case is a target whose fault is known in advance. A fault case passes only if the tool's top finding is the expected one. A healthy case passes only if the tool raises no critical finding.

| Measure | Result |
|---|---|
| Correct root cause on fault runs | **22 of 23** |
| False alarms on healthy runs | **0 of 7** |
| Distinct targets | 18 (12 different fault types across DNS, TCP, TLS, HTTP and path MTU) |
| Time for a full 8-check diagnosis | median 13.2 s, 90th percentile 18.3 s |

| Where | Layer | Target | Planted or known fault | Expected | Reported | Result | Time |
|---|---|---|---|---|---|---|---|
| internet (run 1) | control | `https://github.com` | healthy site | `(healthy)` | `(healthy)` | pass | 18.3 s |
| internet (run 1) | control | `https://www.cloudflare.com` | healthy site | `(healthy)` | `(healthy)` | pass | 9.2 s |
| internet (run 1) | control | `https://1.1.1.1` | healthy, IP literal | `(healthy)` | `(healthy)` | pass | 8.2 s |
| internet (run 1) | dns | `https://nettriage-no-such-name-zz91.com` | name does not exist | `DNS_NXDOMAIN` | `DNS_NXDOMAIN` | pass | 6.1 s |
| internet (run 1) | tcp | `http://localhost:9` | nothing listening (RST) | `TCP_PORT_CLOSED` | `TCP_PORT_CLOSED` | pass | 1.2 s |
| internet (run 1) | tcp | `https://example.com:81` | firewalled port (silence) | `TCP_PORT_FILTERED` | `TCP_PORT_FILTERED` | pass | 8.2 s |
| internet (run 1) | tls | `https://expired.badssl.com` | expired certificate | `TLS_CERT_EXPIRED` | `TCP_PORT_FILTERED` | **FAIL** | 15.2 s |
| internet (run 1) | tls | `https://wrong.host.badssl.com` | certificate for another name | `TLS_HOSTNAME_MISMATCH` | `TLS_HOSTNAME_MISMATCH` | pass | 15.2 s |
| internet (run 1) | tls | `https://self-signed.badssl.com` | self-signed certificate | `TLS_SELF_SIGNED` | `TLS_SELF_SIGNED` | pass | 23.9 s |
| internet (run 1) | tls | `https://untrusted-root.badssl.com` | unknown root CA | `TLS_UNTRUSTED_CHAIN` | `TLS_UNTRUSTED_CHAIN` | pass | 18.3 s |
| internet (run 1) | tls | `https://tls-v1-0.badssl.com:1010` | TLS 1.0-only server | `TLS_VERSION_MISMATCH` | `TLS_VERSION_MISMATCH` | pass | 15.2 s |
| internet (run 1) | http | `https://httpbin.org/status/503` | application returns 503 | `HTTP_5XX` | `HTTP_5XX` | pass | 14.0 s |
| internet (run 2) | control | `https://github.com` | healthy site | `(healthy)` | `(healthy)` | pass | 18.3 s |
| internet (run 2) | control | `https://www.cloudflare.com` | healthy site | `(healthy)` | `(healthy)` | pass | 8.2 s |
| internet (run 2) | control | `https://1.1.1.1` | healthy, IP literal | `(healthy)` | `(healthy)` | pass | 8.2 s |
| internet (run 2) | dns | `https://nettriage-no-such-name-zz91.com` | name does not exist | `DNS_NXDOMAIN` | `DNS_NXDOMAIN` | pass | 6.1 s |
| internet (run 2) | tcp | `http://localhost:9` | nothing listening (RST) | `TCP_PORT_CLOSED` | `TCP_PORT_CLOSED` | pass | 1.2 s |
| internet (run 2) | tcp | `https://example.com:81` | firewalled port (silence) | `TCP_PORT_FILTERED` | `TCP_PORT_FILTERED` | pass | 8.2 s |
| internet (run 2) | tls | `https://expired.badssl.com` | expired certificate | `TLS_CERT_EXPIRED` | `TLS_CERT_EXPIRED` | pass | 15.2 s |
| internet (run 2) | tls | `https://wrong.host.badssl.com` | certificate for another name | `TLS_HOSTNAME_MISMATCH` | `TLS_HOSTNAME_MISMATCH` | pass | 22.5 s |
| internet (run 2) | tls | `https://self-signed.badssl.com` | self-signed certificate | `TLS_SELF_SIGNED` | `TLS_SELF_SIGNED` | pass | 20.9 s |
| internet (run 2) | tls | `https://untrusted-root.badssl.com` | unknown root CA | `TLS_UNTRUSTED_CHAIN` | `TLS_UNTRUSTED_CHAIN` | pass | 15.1 s |
| internet (run 2) | tls | `https://tls-v1-0.badssl.com:1010` | TLS 1.0-only server | `TLS_VERSION_MISMATCH` | `TLS_VERSION_MISMATCH` | pass | 15.1 s |
| internet (run 2) | http | `https://httpbin.org/status/503` | application returns 503 | `HTTP_5XX` | `HTTP_5XX` | pass | 16.3 s |
| lab (run 1) | control | `https://healthy.lab` | healthy lab server | `(healthy)` | `(healthy)` | pass | 10.7 s |
| lab (run 1) | dns | `https://app.silent.lab` | resolver never answers | `DNS_TIMEOUT` | `DNS_TIMEOUT` | pass | 12.4 s |
| lab (run 1) | dns | `https://ghost.lab` | name does not exist | `DNS_NXDOMAIN` | `DNS_NXDOMAIN` | pass | 0.4 s |
| lab (run 1) | tcp | `http://reset.lab:8080/` | RST after the request | `HTTP_RESET` | `HTTP_RESET` | pass | 10.6 s |
| lab (run 1) | tls | `https://legacy-tls.lab` | TLS 1.0-only server | `TLS_VERSION_MISMATCH` | `TLS_VERSION_MISMATCH` | pass | 10.7 s |
| lab (run 1) | network | `http://bigfile.lab/` | path-MTU black hole | `MTU_BLACKHOLE` | `MTU_BLACKHOLE` | pass | 15.4 s |

## Packet-capture analyser

Run over the 7 recorded lab captures (670 packets). A capture passes when every expected fault type is flagged, and the baseline capture passes only if nothing is flagged.

| Measure | Result |
|---|---|
| Captures analysed correctly | **7 of 7** |
| Decode speed (pure Python, single thread) | about 156,557 packets per second |

| Capture | Packets | Must flag | Flagged | Result |
|---|---|---|---|---|
| `00-baseline/client.pcap` | 145 | none | none | pass |
| `01-dns-failure/client.pcap` | 4 | dns | dns | pass |
| `01-dns-failure/nxdomain.pcap` | 4 | dns | dns | pass |
| `02-tcp-reset/client.pcap` | 77 | tcp | tcp | pass |
| `03-tls-version-mismatch/client.pcap` | 123 | tls | tls | pass |
| `04-mtu-blackhole/client.pcap` | 122 | mtu, tcp | mtu, tcp | pass |
| `04-mtu-blackhole/r2.pcap` | 195 | mtu, tcp | mtu, tcp | pass |

## What these numbers do not show

- The cases are a small, hand-picked set of textbook faults. Passing them shows the tool recognises those faults, not that it is right on every network.
- The internet cases depend on third-party test hosts (badssl.com, httpbin.org) and can fail when those hosts misbehave.
- Lab captures are small. The decode speed is a relative figure for this machine, not a capacity claim.
