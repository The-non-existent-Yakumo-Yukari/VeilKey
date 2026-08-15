"""
DeniableCipher Web UI — local launcher.

Runs a tiny HTTP server on 127.0.0.1 with a per-run random token in the URL,
serves the self-contained web app (app.html / app.js / crypto.js), and opens
the default browser.

SECURITY MODEL
  * All cryptography runs in the browser (WebCrypto).  This server is an inert
    static host: it never sees keys or plaintext, so it imports no crypto
    library at all.
  * Bound to 127.0.0.1 only.  Every request must carry the per-run token in the
    URL path (compared in constant time), so a malicious web page or local
    process cannot reach the server without knowing the token (Jupyter-style
    protection).
  * Responses are no-store / nosniff and served under a strict CSP.

Exits when the page calls POST /<token>/api/shutdown, or on Ctrl+C.
"""

from __future__ import annotations

import errno
import json
import os
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

APP_NAME = "DeniableCipher"
WEB_FILES = ("app.html", "app.js", "crypto.js")

# Content types (always set, never guess)
MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}

# CSP: scripts must be same-origin files (no inline script); inline styles are
# allowed so the single-file design can use a <style> block.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'"
)


def resource_path(name: str) -> Path:
    """Locate a bundled web file — PyInstaller _MEIPASS when frozen, else next to this file."""
    base = getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)
    return Path(base) / name


class _Handler(BaseHTTPRequestHandler):
    server_version = "DeniableCipher/1.0"

    # Silence the default log line (one line per request pollutes the console).
    def log_message(self, *args):  # noqa: D401
        pass

    # ---- helpers ----

    @property
    def _parts(self) -> tuple[bool, str, Path]:
        """Return (authorized, relative_path, file_path) for this request.

        The token lives in the first path segment: /<token>/app.js, etc.
        Anything else is rejected (404).
        """
        parsed = urlparse(self.path)
        segs = [s for s in parsed.path.split("/") if s]
        if len(segs) < 1:
            return False, "", Path()
        tok = segs[0]
        if not secrets.compare_digest(tok, self.server.token):  # type: ignore[attr-defined]
            return False, "", Path()
        rel = "/".join(segs[1:]) or "app.html"
        return True, rel, resource_path(rel)

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(body)

    def _deny(self, status: int = 404) -> None:
        self._send(status, b"not found", "text/plain; charset=utf-8")

    # ---- verbs ----

    def do_GET(self):
        auth, rel, path = self._parts
        if not auth or rel not in WEB_FILES or not path.is_file():
            self._deny()
            return
        try:
            data = path.read_bytes()
        except OSError:
            self._deny(500)
            return
        self._send(200, data, MIME.get(path.suffix, "application/octet-stream"))

    def do_POST(self):
        auth, rel, _ = self._parts
        if not auth or rel != "api/shutdown":
            self._deny()
            return
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        self._send(200, json.dumps({"ok": True, "bye": True}).encode("utf-8"),
                   "application/json; charset=utf-8")
        # Stop the server after the response is flushed.
        threading.Thread(target=self.server.shutdown, daemon=True).start()  # type: ignore[attr-defined]


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, token: str):
        self.token = token
        super().__init__(addr, _Handler)


def _log(*msg: object) -> None:
    try:
        print(*msg)
    except OSError:
        pass  # stdout closed (e.g. --noconsole launcher)


def _main() -> int:
    # Optional test hooks (default behavior is unchanged):
    #   DC_TOKEN  — use a fixed token instead of a random one
    #   DC_PORT   — bind a fixed port instead of an ephemeral one
    #   DC_NO_OPEN— skip webbrowser.open (automation shouldn't pop browsers)
    token = os.environ.get("DC_TOKEN") or secrets.token_urlsafe(18)
    port = int(os.environ.get("DC_PORT", 0)) if os.environ.get("DC_PORT") else 0
    try:
        server = _Server(("127.0.0.1", port), token)
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            _log("ERROR: port in use (should not happen with an ephemeral port)")
        else:
            _log("ERROR: could not start server:", e)
        return 1

    host, port = server.server_address[0], server.server_address[1]
    url = f"http://{host}:{port}/{token}/"

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    _log("")
    _log("  " + APP_NAME + " Web UI")
    _log("  " + "-" * (len(APP_NAME) + 7))
    _log("  URL   " + url)
    _log("  Cryptography runs in your browser. Keys and plaintext never reach")
    _log("  this local server. Close the page or press Ctrl+C to exit.")
    _log("")

    if not os.environ.get("DC_NO_OPEN"):
        try:
            webbrowser.open(url)
        except Exception as e:  # noqa: BLE001
            _log("  WARNING: could not open a browser automatically:", e)
            _log("  Open this URL manually:", url)

    try:
        t.join()
    except KeyboardInterrupt:
        _log("  Shutting down...")
    finally:
        server.server_close()
    return 0


def _run() -> None:
    try:
        sys.exit(_main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        # In a --noconsole build there is no terminal; write a traceback to a
        # log file next to the executable so failures are not silent.
        try:
            here = Path(sys.argv[0]).resolve().parent
            with open(here / "deniable_error.log", "a", encoding="utf-8") as fh:
                fh.write("---- DeniableCipher error ----\n")
                import traceback
                traceback.print_exc(file=fh)
        except Exception:  # noqa: BLE001
            pass
        sys.exit(1)


if __name__ == "__main__":
    _run()
