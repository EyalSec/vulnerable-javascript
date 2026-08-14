#!/usr/bin/env python3
"""Serve this app locally, for offline runs and for development.

Standard library only, no dependencies.

    ./serve.py                # http://127.0.0.1:8000/
    ./serve.py 9000           # a different port
    ./serve.py 9000 0.0.0.0   # bind wider (do not do this on a shared network)

Serve it over HTTP rather than opening index.html from disk. A file:// page has
no fragment to deep link with, and document.cookie, document.referrer and both
web storages are empty on it, which silently disables more than half of the
catalogue.
"""
import http.server
import socketserver
import sys
import os

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=os.path.dirname(os.path.abspath(__file__)), **kw)

    def end_headers(self):
        # No caching, so an edit shows up on reload rather than three reloads later.
        self.send_header("Cache-Control", "no-store")
        # The app is deliberately vulnerable; make sure nothing indexes it even
        # when someone binds it wider than they meant to.
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((HOST, PORT), Handler) as httpd:
        print("Northwind Retail Analytics (deliberately vulnerable)")
        print("  http://%s:%d/" % (HOST, PORT))
        print("  http://%s:%d/catalog.html   <- the vulnerability catalogue" % (HOST, PORT))
        print("Ctrl-C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
