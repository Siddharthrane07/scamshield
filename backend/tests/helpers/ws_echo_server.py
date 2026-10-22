"""
ws_echo_server.py — Local WebSocket echo server for Track C browser tests.

Uses modern websockets.asyncio.server.serve to handle:
- Plain WebSockets: ws://
- Secure WebSockets: wss:// (with ssl.SSLContext)
"""
import asyncio
import ssl
import threading
from pathlib import Path
from typing import Optional
from websockets.asyncio.server import serve, Server


class WebSocketEchoServer:
    """
    WebSocket echo server running on 127.0.0.1:<port>.
    Supports both plain ws:// and secure wss:// (when cert_path & key_path are supplied).
    """

    def __init__(
        self,
        port: int,
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None,
        host: str = "127.0.0.1",
    ) -> None:
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.last_sni: Optional[str] = None
        self.last_path: Optional[str] = None
        self.connection_count = 0

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server: Optional[Server] = None
        self._thread: Optional[threading.Thread] = None
        self._ready_event = threading.Event()

    async def _handler(self, websocket):
        self.connection_count += 1
        self.last_path = getattr(websocket.request, "path", "/ws")
        async for message in websocket:
            if message == "ping":
                await websocket.send("pong")
            else:
                await websocket.send(f"echo:{message}")

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.cert_path or not self.key_path:
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))

        def _sni_callback(sock, server_name, initial_ctx):
            self.last_sni = server_name
            return None

        ctx.sni_callback = _sni_callback
        return ctx

    def _run_server(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        ssl_ctx = self._build_ssl_context()

        async def _main():
            self._server = await serve(
                self._handler,
                self.host,
                self.port,
                ssl=ssl_ctx,
            )
            self._ready_event.set()
            await self._server.serve_forever()

        try:
            self._loop.run_until_complete(_main())
        except (asyncio.CancelledError, Exception):
            pass

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()
        self._ready_event.wait(timeout=5.0)

    def stop(self) -> None:
        if self._server and self._loop and self._loop.is_running():
            async def _shutdown():
                self._server.close()
                await self._server.wait_closed()
            try:
                future = asyncio.run_coroutine_threadsafe(_shutdown(), self._loop)
                future.result(timeout=2.0)
            except Exception:
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=2.0)
