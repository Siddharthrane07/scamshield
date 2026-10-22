"""
canary_listener.py — Independent TCP and UDP leak-detection listeners.

These listeners verify that unproxied, direct network connections do not occur:
- CanaryListener: Binds a local TCP port. If Chromium or any subresource bypasses
  the proxy and makes a direct connection, the canary accepts the connection
  and increments connection_count, triggering an immediate test failure.
- UDPSinkServer: Binds a local UDP port. Used in QUIC (BR-10) and WebRTC (BR-07)
  tests to confirm that direct UDP datagrams are not sent out-of-band.
"""
import socket
import threading


class CanaryListener:
    """
    Direct TCP Canary Server.
    Counts accepted raw TCP connections.
    """

    def __init__(self, port: int, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port = port
        self.connection_count = 0
        self._lock = threading.Lock()
        self._server_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(10)
        self._server_sock.settimeout(0.5)
        self._running = True

        def _serve():
            while self._running:
                try:
                    conn, _ = self._server_sock.accept()
                    with self._lock:
                        self.connection_count += 1
                    try:
                        conn.close()
                    except OSError:
                        pass
                except (socket.timeout, OSError):
                    continue

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)

    def reset(self) -> None:
        with self._lock:
            self.connection_count = 0


class UDPSinkServer:
    """
    Direct UDP Canary Server.
    Counts received UDP datagrams.
    """

    def __init__(self, port: int, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port = port
        self.packet_count = 0
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(0.5)
        self._running = True

        def _listen():
            while self._running:
                try:
                    data, _ = self._sock.recvfrom(65535)
                    if data:
                        with self._lock:
                            self.packet_count += 1
                except (socket.timeout, OSError):
                    continue

        self._thread = threading.Thread(target=_listen, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)

    def reset(self) -> None:
        with self._lock:
            self.packet_count = 0
