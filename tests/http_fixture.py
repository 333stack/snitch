# Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
"""Run the transport suite using an ephemeral loopback HTTP server."""
import itertools
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    counter = itertools.count()
    searches = 0

    def log_message(self, *_):
        pass

    def do_CONNECT(self):
        self.send_response(403)
        self.send_header("Retry-After", "60")
        self.end_headers()

    def do_GET(self):
        path = self.path.partition("?")[0]
        status, headers, body = 200, {}, str(next(self.counter)).encode()
        if path == "/redirect":
            status, headers = 302, {"Location": "/count"}
        elif path == "/search":
            type(self).searches += 1
            status, headers = 429, {"Retry-After": "60"}
        elif path == "/search-attempts":
            body = str(self.searches).encode()
        elif path == "/user-agent":
            body = self.headers.get("User-Agent", "").encode()
        elif path == "/html-only":
            if self.headers.get("Accept") != "text/html":
                status, body = 406, b"Not Acceptable"
            else:
                headers, body = {"Content-Type": "text/html"}, b"<title>Fixture profile</title>"
        elif path == "/limited":
            status, headers = 429, {"Retry-After": "60"}
        elif path == "/oversized":
            body = b"x" * ((8 << 20) + 1)
        elif path == "/slow":
            time.sleep(5)
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


try:
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
except PermissionError as error:
    print(f"Loopback fixture unavailable: {error}", file=sys.stderr)
    sys.exit(77)

with fixture as server, socket.socket() as offline_proxy:
    offline_proxy.bind(("127.0.0.1", 0))  # Reserve the port without accepting connections.
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        subprocess.run([sys.argv[1], f"http://127.0.0.1:{server.server_port}",
                        f"http://127.0.0.1:{offline_proxy.getsockname()[1]}"],
                       check=True, timeout=20)
    finally:
        server.shutdown()
