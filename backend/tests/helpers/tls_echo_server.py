"""
tls_echo_server.py — TLS/HTTPS echo server for integration tests.

Wraps a plain HTTPServer with an ssl.SSLContext so that integration tests can
make real HTTPS connections through the mitmproxy-under-test and verify:

1. The TLS handshake succeeds using the self-signed server certificate.
2. The SNI supplied by the client (the proxy, acting as a TLS relay) matches
   the expected hostname — confirming that IP-pinning in server_connect()
   does not corrupt the SNI value sent upstream.

Usage::

    certs = generate_test_certs(tmp_dir)
    server = TLSEchoServer(
        port=18443,
        cert_path=certs["server_cert_path"],
        key_path=certs["server_key_path"],
    )
    server.start()
    last_sni = server.last_sni   # inspect after a connection
    server.stop()
"""
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class _TLSEchoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        payload = json.dumps({"tls_echo": "ok", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:
        pass


class _SNICapturingHTTPSServer(HTTPServer):
    """HTTPServer subclass that records the SNI from the most recent TLS handshake."""

    def __init__(self, server_address, handler_class, ssl_context: ssl.SSLContext) -> None:
        super().__init__(server_address, handler_class)
        self._ssl_context = ssl_context
        self.last_sni: str | None = None

        def _sni_callback(sock, server_name, initial_ctx):
            self.last_sni = server_name
            return None

        self._ssl_context.sni_callback = _sni_callback

    def get_request(self):
        """
        Wraps the raw socket in TLS, capturing server_hostname (SNI).
        """
        raw_sock, addr = self.socket.accept()
        tls_sock = self._ssl_context.wrap_socket(raw_sock, server_side=True)
        return tls_sock, addr


class TLSEchoServer:
    """
    HTTPS echo server on 127.0.0.1:<port>.

    ``last_sni`` is updated on each connection.  Tests should check it after
    issuing a request to confirm that the proxy forwarded the correct hostname
    in the TLS ClientHello.
    """

    def __init__(self, port: int, cert_path: Path, key_path: Path) -> None:
        self.port = port
        self._cert_path = Path(cert_path)
        self._key_path = Path(key_path)
        self._server: _SNICapturingHTTPSServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(self._cert_path), keyfile=str(self._key_path))

        self._server = _SNICapturingHTTPSServer(
            ("127.0.0.1", self.port),
            _TLSEchoHandler,
            ssl_context=ctx,
        )
        import socket as _socket
        self._server.socket.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)

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

    @property
    def last_sni(self) -> str | None:
        if self._server:
            return self._server.last_sni
        return None
