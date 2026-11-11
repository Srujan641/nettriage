# MTU and fragmentation: a path-MTU black hole

Packet numbers refer to the captures included in `labs/captures/04-mtu-blackhole/`. Re-running the lab renumbers them.

## The fault

```
client ── lab_net (1500) ── r1 ══ wan_net (MTU 1000) ══ r2 ── far_net (1500) ── bigfile
10.77.0.10                                                                     10.78.0.20
```

The link between the two routers carries packets of at most 1000 bytes. That alone is fine: a router that cannot forward a packet with Don't-Fragment set replies with ICMP type 3 code 4, "fragmentation needed", and the sender shrinks its packets. This is path-MTU discovery.

The fault is that both routers drop those ICMP messages, as an over-zealous "block all ICMP" firewall rule would. The sender never learns that its packets are too big.

## Symptom

This is the failure that passes every basic check:

- Ping works.
- The port is open.
- The request is accepted and the response headers arrive.
- Then the download hangs until the client gives up.

Small packets fit through the narrow link. Only full-size ones vanish.

## What the tool reported

> DNS resolves fine, TCP 80 is open, but the HTTP response stalls because of a path-MTU black hole: only packets up to 1000 bytes cross the path, larger ones are dropped, and the ICMP 'fragmentation needed' message that should tell the sender to shrink them never arrives.

Finding `MTU_BLACKHOLE`. Two checks combine to reach it. The HTTP check saw headers and then a 15-second stall. The path-MTU check found that a ping of 1000 bytes with Don't-Fragment set is answered and one of 1001 bytes disappears, with no ICMP error.

## What Wireshark shows on the client (`client.pcap`)

**The stall:**

| No. | Time | Packet |
|---|---|---|
| 57 to 59 | 0.112 s | TCP handshake. Both sides advertise `MSS=1460` |
| 60 | 0.112 s | `GET / HTTP/1.1` |
| 62 | 0.113 s | `HTTP/1.0 200 OK`: the headers, 144 bytes, small enough to pass |
| 63 | 0.113 s | Client ACKs the headers (`Ack=145`) |
| | | **15 seconds in which no data arrives** |
| 121 | 15.115 s | Client gives up and sends FIN, still at `Ack=145` |
| 122 | 15.157 s | Server's ACK carries `Seq=16073` |

Packet 122 gives it away: the server's sequence number is 16073, so it has sent about 16 kB. The client has acknowledged 145 bytes. Nearly 16 kB left the server and never arrived.

**The measurement.** The tool's Don't-Fragment ping sweep is in the same capture:

| No. | IP length | Reply? |
|---|---|---|
| 53 | 1500 | none |
| 82 | 792 | yes (83) |
| 84 | 1146 | none |
| 118 | **1000** | yes (119) |
| 120 | **1001** | none |

No ICMP error comes back for the lost pings. Filter: `icmp.type == 8 && ip.flags.df == 1 && !icmp.resp_in`. On a healthy path the filter `icmp.type == 3 && icmp.code == 4` would show the router's replies. Here it shows nothing.

## What Wireshark shows on router r2 (`r2.pcap`)

The client capture shows that packets are missing. The capture on the router next to the server shows where they die. It was taken on all interfaces, so every forwarded packet appears twice: once coming in, once going out.

| No. | Packet | Seen |
|---|---|---|
| 105, 106 | `HTTP/1.0 200 OK`, 196 bytes | in and out: forwarded |
| 109, 110 | Response body, `Len=7240` each | **in only** |
| 111 | Response body, 1500 bytes | **in only** |
| 131, 150, 163, 190, 191 | `[TCP Retransmission]` of the same 1500-byte segment | **in only** |

The retransmissions arrive at 0.69 s, 1.51 s, 3.18 s, 6.44 s and 13.10 s. The gap doubles each time: TCP's exponential backoff. The server keeps resending a packet of exactly the size the path cannot carry.

(The 7240-byte frames are five 1448-byte segments that the capturing host's receive offload merged. On the wire they were 1500-byte packets.)

Filter for the dropped traffic: `ip.len > 1000 && ip.flags.df == 1`. Filter for the retries: `tcp.analysis.retransmission`.

## Why the TCP handshake did not prevent this

Each end advertises an MSS from its own interface MTU: 1500 minus 40 bytes of headers gives 1460. Neither end knows about the 1000-byte link in the middle. Learning about it is the job of the ICMP message that is being dropped.

## Fix

1. **The real fix:** stop filtering ICMP type 3 code 4. Path-MTU discovery depends on it.
2. **If you do not control that firewall:** clamp the MSS on the router so endpoints never send packets that large: `iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`
3. **On a single affected host:** lower its interface MTU, or enable `net.ipv4.tcp_mtu_probing=1` so TCP finds the limit without ICMP.

## Where this happens in production

VPN and IPsec tunnels, GRE, PPPoE and cloud overlay networks all reduce the usable MTU. Pair any of them with a firewall that blocks ICMP and you get exactly this failure: SSH logs in and then freezes on the first large output, and HTTPS hangs during the TLS handshake because the certificate does not fit in one small packet.
