#!/usr/bin/env python3
"""HTTP/1.1 with keep-alive for the outside network (see outside.sh): every request is
answered with the address it was sent to, on the same connection.

    http-server.py <port>
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):  # noqa: N802 (the name http.server calls)
        body = f"{self.connection.getsockname()[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


ThreadingHTTPServer.daemon_threads = True
ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
