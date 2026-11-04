"""Self-contained HTTP catcher for the unrestricted-file / parsing suite.

It plays two roles on one port:

  1. Hosts a hostile document (SVG/XML/HTML...) at  /f/<token>.<ext>
  2. Listens for the second-order callback the document triggers when a parser
     resolves its external entity/href:  /c/<token>

The backend fetching /f/<token> only proves it fetched a URL (that is SSRF,
already covered). The finding we care about is a hit on /c/<token>: that only
happens if the server fetched our non-image file AND parsed it, resolving the
embedded reference. That callback is the oracle — no inference.

Reachability note: the target backend must be able to reach this server, so
`public_base` is whatever URL the backend can hit (a VPS, an ngrok/cloudflared
tunnel, or a LAN address). Bind host/port are where the server actually listens.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _State:
    def __init__(self) -> None:
        self.files: dict[str, tuple[str, bytes]] = {}   # token -> (content_type, body)
        self.fetched: set[str] = set()                  # tokens whose /f was fetched
        self.parsed: set[str] = set()                   # tokens whose /c was hit (PROOF)
        self.lock = threading.Lock()


def _make_handler(state: _State):
    class Handler(BaseHTTPRequestHandler):
        def _ok(self, body: bytes, ctype: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path.startswith("/f/"):
                token = path[3:].split(".", 1)[0]
                with state.lock:
                    state.fetched.add(token)
                    entry = state.files.get(token)
                if entry:
                    self._ok(entry[1], entry[0])
                else:
                    self._ok(b"not found", "text/plain")
            elif path.startswith("/c/"):
                token = path[3:].split("/", 1)[0]
                with state.lock:
                    state.parsed.add(token)           # <-- the confirmation
                self._ok(b"1", "text/plain")
            else:
                self._ok(b"ok", "text/plain")

        def log_message(self, *a):  # quiet
            return

    return Handler


class Catcher:
    """Threaded HTTP server; register a payload, then poll whether it parsed."""

    def __init__(self, bind_host: str, bind_port: int, public_base: str) -> None:
        self.public_base = public_base.rstrip("/")
        self._state = _State()
        self._srv = ThreadingHTTPServer((bind_host, bind_port), _make_handler(self._state))
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def start(self) -> "Catcher":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def __enter__(self) -> "Catcher":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def callback_url(self, token: str) -> str:
        """The URL a payload embeds; a hit on it confirms parsing."""
        return f"{self.public_base}/c/{token}"

    def register(self, token: str, content_type: str, body: str, ext: str) -> str:
        """Host `body` at /f/<token>.<ext>; return the URL to put in the sink."""
        with self._state.lock:
            self._state.files[token] = (content_type, body.encode("utf-8"))
        return f"{self.public_base}/f/{token}.{ext}"

    def was_fetched(self, token: str) -> bool:
        with self._state.lock:
            return token in self._state.fetched

    def was_parsed(self, token: str) -> bool:
        with self._state.lock:
            return token in self._state.parsed
