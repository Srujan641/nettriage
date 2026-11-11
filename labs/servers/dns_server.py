"""Lab DNS server (UDP 53) with three behaviours:

  known names          -> A record
  *.silent.lab         -> no reply at all (resolver outage)
  broken-zone.lab      -> SERVFAIL
  anything else        -> NXDOMAIN
"""
import socket
import struct

ZONE = {
    "healthy.lab": "10.77.0.20",
    "reset.lab": "10.77.0.30",
    "legacy-tls.lab": "10.77.0.40",
    "bigfile.lab": "10.78.0.20",
}


def parse_question(data):
    labels, pos = [], 12
    while data[pos]:
        labels.append(data[pos + 1 : pos + 1 + data[pos]].decode())
        pos += 1 + data[pos]
    qtype = struct.unpack("!H", data[pos + 1 : pos + 3])[0]
    return ".".join(labels).lower(), qtype, data[12 : pos + 5]


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    print("lab DNS listening on :53", flush=True)
    while True:
        data, peer = sock.recvfrom(1500)
        try:
            name, qtype, question = parse_question(data)
        except (IndexError, struct.error, UnicodeDecodeError):
            continue
        if name.endswith("silent.lab"):
            print(f"{peer[0]} {name} -> (dropped)", flush=True)
            continue
        txid = data[:2]
        answer, rcode = b"", 0
        if name == "broken-zone.lab":
            rcode = 2
        elif name not in ZONE:
            rcode = 3
        elif qtype == 1:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ZONE[name])
        flags = 0x8580 | rcode  # response, authoritative, recursion desired+available
        header = txid + struct.pack("!HHHHH", flags, 1, 1 if answer else 0, 0, 0)
        sock.sendto(header + question + answer, peer)
        print(f"{peer[0]} {name} type {qtype} -> rcode {rcode}", flush=True)


main()
