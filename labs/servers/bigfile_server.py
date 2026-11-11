"""Plain HTTP server whose response (200 kB) needs full-size packets.

Nothing is wrong with this server. The fault is on the path: see router.sh.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = (b"NetTriage lab payload. " * 64 + b"\n") * 136  # ~200 kB


class Handler(BaseHTTPRequestHandler):
    server_version = "nettriage-lab"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} {fmt % args}", flush=True)


print("bigfile server listening on :80", flush=True)
ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
