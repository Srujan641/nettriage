"""HTTPS (443) + HTTP (80) server for the lab.

  web_server.py healthy.lab            modern TLS 1.2/1.3 - the control case
  web_server.py legacy-tls.lab --legacy   TLS 1.0 ONLY - the version-mismatch fault
"""
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = sys.argv[1]
LEGACY = "--legacy" in sys.argv


class Handler(BaseHTTPRequestHandler):
    server_version = "nettriage-lab"

    def do_GET(self):
        body = f"<h1>{NAME}</h1><p>lab server is up</p>\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} {fmt % args}", flush=True)


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"/certs/{NAME}.crt", f"/certs/{NAME}.key")
    if LEGACY:
        ctx.set_ciphers("ALL:@SECLEVEL=0")  # TLS 1.0 needs SHA-1 signatures
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class TLSServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):  # failed handshakes are expected here
        print(f"{client_address[0]} connection error: {sys.exc_info()[1]}", flush=True)


https = TLSServer(("0.0.0.0", 443), Handler)
https.socket = tls_context().wrap_socket(https.socket, server_side=True, do_handshake_on_connect=False)


def finish_handshake(self):
    self.request.do_handshake()
    BaseHTTPRequestHandler.setup(self)


Handler.setup = lambda self: finish_handshake(self) if isinstance(self.request, ssl.SSLSocket) else BaseHTTPRequestHandler.setup(self)
threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever, daemon=True).start()
print(f"{NAME}: HTTPS on :443 ({'TLS 1.0 only' if LEGACY else 'TLS 1.2+'}), HTTP on :80", flush=True)
https.serve_forever()
