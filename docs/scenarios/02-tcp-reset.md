# TCP reset: connection killed after the request

Packet numbers refer to the included `labs/captures/02-tcp-reset/client.pcap`. Re-running the lab renumbers them.

## The fault

The server at `reset.lab:8080` accepts the TCP connection, reads the HTTP request, then closes the socket with `SO_LINGER` set to zero. That makes the kernel send a RST instead of the normal FIN. A backend process that crashes mid-request looks the same on the wire, and so does an inline IPS or WAF that kills a connection it dislikes.

## Symptom

`curl: (56) Recv failure: Connection reset by peer`. The port is open, so "is the service up?" checks pass.

## What the tool reported

> DNS resolves fine, TCP 8080 is open, but the HTTP request fails because the connection was reset by the peer after the request was sent.

Finding `HTTP_RESET`. Ping, traceroute, MTR and path MTU are all clean, which rules out the network path.

## What Wireshark shows

The HTTP attempt is six packets:

| No. | Direction | Packet | Meaning |
|---|---|---|---|
| 54 | client to server | `[SYN]` | Client asks to connect |
| 55 | server to client | `[SYN, ACK]` | Server accepts: the port is open |
| 56 | client to server | `[ACK]` | Handshake complete |
| 57 | client to server | `GET / HTTP/1.1` | The request, 80 bytes |
| 58 | server to client | `[ACK] Ack=81` | The server's TCP stack received the request |
| 59 | server to client | **`[RST, ACK]`** | The server aborts the connection |

What matters is the order. Packet 58 proves the request arrived, so the network delivered it. Packet 59 comes from the server's address in the same 100 microseconds, with no response data in between: the server sent zero payload bytes on this connection.

Filter: `tcp.flags.reset == 1 && ip.src == 10.77.0.30`

## Three resets that mean different things

| Pattern | Meaning |
|---|---|
| SYN answered directly by RST | Port closed: nothing is listening, or a firewall rejects with tcp-reset |
| Handshake, request, then RST and no reply (this case) | The application or a security device killed the connection on purpose |
| RST after a complete exchange | An abrupt close. Often harmless: scanners and some clients do it |

Packets 49 to 51 in this capture show the third kind: the `nmap` half-open scan sends SYN, gets SYN/ACK, and resets. The analyser files it under "Context".

## Who sent the RST?

A reset carries the source address of the server even when a middlebox forged it. To find the real sender, capture on both ends and compare:

- RST leaves the server's own interface: the server sent it. Check application logs for a crash.
- RST arrives at the client but never left the server: a device in the path injected it. The IP TTL of the RST usually differs from the server's other packets, which exposes the forger (`ip.ttl` column in Wireshark).

## Fix

Here: fix the server so it answers instead of aborting. In production: read the application and proxy logs at the timestamp of the RST, then check IPS and WAF logs for a block on that connection.
