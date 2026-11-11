"""The TCP-reset fault: accept the connection, read the request, then abort with RST.

SO_LINGER with a zero timeout makes close() send RST instead of the normal FIN,
which is exactly what a crashing backend or an inline security device produces.
"""
import socket
import struct

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 8080))
srv.listen(16)
print("reset server listening on :8080", flush=True)
while True:
    conn, peer = srv.accept()
    conn.settimeout(2)
    try:
        data = conn.recv(4096)
    except OSError:
        data = b""
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()
    print(f"{peer[0]} sent {len(data)} bytes -> RST", flush=True)
