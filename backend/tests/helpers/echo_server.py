"""
echo_server.py — Minimal plain-HTTP echo server for integration tests.

Binds to 127.0.0.1 on a caller-supplied port and responds to every request
with a fixed JSON body.  Runs in a daemon thread so it is automatically
cleaned up when the test process exits.

Usage::

    server = EchoServer(port=18080)
    server.start()
    # ... run tests ...
    server.stop()
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


# Number of connections accepted in the OS listen backlog before dropping.
# Not security-sensitive here; we just want a small stable number.
_BACKLOG = 5


class _EchoHandler(BaseHTTPRequestHandler):
    """Responds to any request with 200 OK + a small JSON body."""

    def do_GET(self) -> None:
        self._respond()

    def do_HEAD(self) -> None:
        self._respond(body=False)

    def do_POST(self) -> None:
        self._respond()

    def _respond(self, body: bool = True) -> None:
        payload = json.dumps({"echo": "ok", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if body:
            self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:  # suppress noisy output
        pass


class EchoServer:
    """
    Plain HTTP echo server running on 127.0.0.1:<port>.

    This is test scaffolding only.  The ``_blackhole`` variant accepts
    connections and immediately closes them to test fail-closed behavior.
    """

    def __init__(self, port: int, blackhole: bool = False) -> None:
        self.port = port
        self._blackhole = blackhole
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._blackhole:
            self._server = _BlackHoleServer(("127.0.0.1", self.port), _BlackHoleHandler)
        else:
            self._server = HTTPServer(("127.0.0.1", self.port), _EchoHandler)
        self._server.socket.setsockopt(
            __import__("socket").SOL_SOCKET,
            __import__("socket").SO_REUSEADDR,
            1,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=3)


# ---------------------------------------------------------------------------
# Black-hole variant: accepts TCP but immediately closes the connection.
# Used to confirm fail-closed: if the addon blocks the request, the black
# hole should never receive a connection.
# ---------------------------------------------------------------------------

class _BlackHoleServer(HTTPServer):
    """Counts accepted connections so tests can assert the number is zero."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connection_count: int = 0

    def get_request(self):
        result = super().get_request()
        self.connection_count += 1
        return result


class _BlackHoleHandler(BaseHTTPRequestHandler):
    def handle(self) -> None:
        # Immediately close — we just want to count the connection attempt.
        self.connection.close()

    def log_message(self, fmt: str, *args) -> None:
        pass


class BlackHoleServer(EchoServer):
    """
    A TCP server that accepts connections and immediately closes them.
    Exposes ``connection_count`` so tests can assert no connection was opened.
    """

    def __init__(self, port: int) -> None:
        super().__init__(port, blackhole=True)

    @property
    def connection_count(self) -> int:
        if isinstance(self._server, _BlackHoleServer):
            return self._server.connection_count
        return 0
