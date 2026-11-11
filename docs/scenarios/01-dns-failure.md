# DNS failure: the resolver goes silent

Packet numbers refer to the captures included in `labs/captures/01-dns-failure/`. Re-running the lab renumbers them.

## The fault

The lab DNS server (`10.77.0.53`) receives queries for `*.silent.lab` and never replies. This reproduces a resolver that has crashed, or a firewall that drops UDP port 53. The web server behind the name is irrelevant: the client never learns its address.

## Symptom

Users report "the site is down". Browsers show a name-resolution error after a long pause.

## What the tool reported

> DNS fails: 10.77.0.53 does not answer DNS queries.

Finding `DNS_TIMEOUT`. Every later check is skipped, because there is no IP address to test. The tool does not guess past the first broken layer.

## What Wireshark shows (`client.pcap`)

The whole capture is four packets:

| No. | Time | Packet |
|---|---|---|
| 1 | 0.00 s | Query `A app.silent.lab` to 10.77.0.53 |
| 2 | 3.01 s | The same query again (same transaction ID `0xabb2`) |
| 3 | 6.03 s | Query `AAAA app.silent.lab` |
| 4 | 9.04 s | The same AAAA query again |

Three things identify a dead resolver:

1. **No responses at all.** Filter `dns.flags.response == 1` returns nothing.
2. **Retries reuse the transaction ID** three seconds apart. That gap is the resolver timeout (`dig +time=3`).
3. **No ICMP "port unreachable" comes back.** A host that is up with no DNS service would send one. Silence means the packets are dropped, or the server is down.

Filter for unanswered queries: `dns && !dns.response_in`

## Contrast: NXDOMAIN (`nxdomain.pcap`)

The second capture queries `ghost.lab`, which the server answers as non-existent:

| No. | Time | Packet |
|---|---|---|
| 1 | 0.0000 s | Query `A ghost.lab` |
| 2 | 0.0002 s | Response, rcode **NXDOMAIN** |

Here the resolver is healthy and fast. The name is the problem. The tool reports `DNS_NXDOMAIN` instead. Filter: `dns.flags.rcode == 3`

## Telling DNS failures apart

| In the capture | Meaning | Where to look |
|---|---|---|
| Queries, no responses | Resolver down or UDP 53 filtered | The resolver host, and firewalls in between |
| Response with NXDOMAIN | The name does not exist | The zone's records, or a typo |
| Response with SERVFAIL | Resolver could not get an answer upstream | Delegation and DNSSEC (`dig +trace`, `dig +cd`) |
| Response with REFUSED | Resolver will not serve this client | Its ACLs |

## Fix

Restore the resolver, or allow UDP and TCP 53 to it. To confirm it is the resolver and not the name, query another one: `dig @1.1.1.1 name`. On a real network NetTriage does this comparison automatically.
