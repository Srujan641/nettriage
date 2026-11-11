# TLS version mismatch: a TLS 1.0-only server

Packet numbers refer to the included `labs/captures/03-tls-version-mismatch/client.pcap`. Re-running the lab renumbers them.

## The fault

`legacy-tls.lab` is pinned to TLS 1.0, like an appliance or an old Java service that was never upgraded. Modern clients offer TLS 1.2 and 1.3 only, since TLS 1.0 and 1.1 were retired by RFC 8996. Client and server have no version in common.

## Symptom

Browsers show `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`. `curl` reports `tlsv1 alert protocol version`. TCP 443 is open and the certificate is valid, so port checks and certificate monitors stay green.

## What the tool reported

> DNS resolves fine, TCP 443 is open, but the TLS handshake fails because client and server share no TLS version: this client offers TLSv1.2 and TLSv1.3, the server only accepts TLSv1.0.

Finding `TLS_VERSION_MISMATCH`. The HTTP check is skipped, because HTTPS needs a TLS session.

## What Wireshark shows

The failing handshake:

| No. | Direction | Packet |
|---|---|---|
| 56 to 58 | both | TCP three-way handshake completes |
| 59 | client to server | **Client Hello**, SNI `legacy-tls.lab`, `supported_versions`: TLS 1.3, TLS 1.2 |
| 60 | server to client | `[ACK]`: the hello arrived |
| 61 | server to client | **Alert (fatal): protocol_version** |
| 62 to 65 | both | Orderly close |

There is no Server Hello. The server read the client's version list, found nothing it speaks, and said so in a 7-byte alert. In Wireshark, expand packet 59 to `Extension: supported_versions` to see the list, and packet 61 to `Alert Message > Description: Protocol Version (70)`.

Filters: `tls.handshake.type == 1` for Client Hellos, `tls.alert_message.desc == 70` for the alert.

## How the tool knows the server speaks TLS 1.0

After the failure, NetTriage opens one connection per TLS version and offers only that version:

| Packets | Client offers | Server's answer | Result |
|---|---|---|---|
| 69 to 77 | TLS 1.0 only | Server Hello selecting TLS 1.0, full handshake | **Accepted** |
| 81 to 86 | TLS 1.1 only | Server Hello selecting TLS 1.0 (a downgrade) | Client refuses |
| 90 to 95 | TLS 1.2 only | Server Hello selecting TLS 1.0 | Client refuses |
| 99 onward | TLS 1.3 only | Alert: protocol_version | Refused |

So the server's range is exactly TLS 1.0. For 1.1 and 1.2 it tries to negotiate down and the client sends the `protocol_version` alert itself (packets 85 and 94).

## Telling TLS handshake failures apart

| After the Client Hello | Meaning |
|---|---|
| Alert `protocol_version` | No TLS version in common (this case) |
| Alert `handshake_failure` | A version in common, but no shared cipher suite |
| Server Hello and Certificate, then a client alert `bad_certificate`, `certificate_expired` or `unknown_ca` | The client rejects the certificate |
| TCP RST | Something refuses the connection outright, often SNI filtering |
| Nothing | The hello or the reply is being dropped. Check the path MTU |

## Fix

Enable TLS 1.2 and 1.3 on the server (`ssl_protocols TLSv1.2 TLSv1.3;` in nginx, `SSLProtocol -all +TLSv1.2 +TLSv1.3` in Apache). If the server cannot be upgraded, put a TLS-terminating proxy in front of it. Re-enabling TLS 1.0 on clients is not a fix.
