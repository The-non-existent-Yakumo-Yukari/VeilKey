"""
Server smoke tests for webui/app.py (the local launcher).

Verifies the security posture: token-gated paths, strict response headers,
no path traversal, and the graceful shutdown endpoint.
"""

from __future__ import annotations

import http.client
import json
import os
import secrets
import sys
import threading
from pathlib import Path

import pytest

WEBUI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WEBUI))

import app as appmod  # noqa: E402


def _get(host, port, path):
    conn = http.client.HTTPConnection(host, port)
    conn.request("GET", path)
    resp = conn.getresponse()
    return conn, resp


def _start_server():
    server = appmod._Server(("127.0.0.1", 0), secrets.token_urlsafe(18))
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, t


@pytest.fixture()
def server():
    s, t = _start_server()
    yield s
    s.shutdown()
    s.server_close()
    t.join(timeout=5)


def test_pages_served_with_token_and_headers(server):
    host, port = server.server_address
    token = server.token

    # correct token → app.html
    conn, resp = _get(host, port, f"/{token}/")
    body = resp.read()
    assert resp.status == 200
    assert resp.getheader("Content-Type", "").startswith("text/html")
    assert resp.getheader("Cache-Control") == "no-store"
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    csp = resp.getheader("Content-Security-Policy", "")
    assert "default-src 'self'" in csp and "script-src 'self'" in csp
    assert b"DeniableCipher" in body
    conn.close()

    # assets
    for rel, ctype in [("app.js", "text/javascript"), ("crypto.js", "text/javascript")]:
        conn, resp = _get(host, port, f"/{token}/{rel}")
        assert resp.status == 200, rel
        assert resp.getheader("Content-Type", "").startswith(ctype)
        assert resp.read()
        conn.close()


def test_token_gating(server):
    host, port = server.server_address

    # no token
    conn, resp = _get(host, port, "/")
    assert resp.status == 404
    conn.close()

    # wrong token
    conn, resp = _get(host, port, "/wrongtoken/")
    assert resp.status == 404
    conn.close()


def test_no_path_traversal(server):
    host, port = server.server_address
    token = server.token

    for path in [f"/{token}/../app.py", f"/{token}/..%2fapp.py", f"/{token}/app.py"]:
        conn, resp = _get(host, port, path)
        assert resp.status == 404, path
        resp.read()
        conn.close()


def test_unknown_paths_404(server):
    host, port = server.server_address
    token = server.token
    conn, resp = _get(host, port, f"/{token}/nope.css")
    assert resp.status == 404
    resp.read()
    conn.close()


def test_shutdown_endpoint(server):
    host, port = server.server_address
    token = server.token
    conn = http.client.HTTPConnection(host, port)
    conn.request("POST", f"/{token}/api/shutdown", body=b"{}")
    resp = conn.getresponse()
    body = json.loads(resp.read())
    assert resp.status == 200
    assert body["ok"] is True
    conn.close()
    # handler spawns a thread that calls server.shutdown(); wait for serve_forever
    import time
    deadline = time.time() + 5
    while time.time() < deadline and server.__dict__.get("__shutdown_request") is not True:
        time.sleep(0.05)
    # no assertion on exit: serve_forever returns after shutdown() completes


def test_post_without_token_rejected(server):
    host, port = server.server_address
    conn = http.client.HTTPConnection(host, port)
    conn.request("POST", "/api/shutdown", body=b"{}")
    resp = conn.getresponse()
    assert resp.status == 404
    resp.read()
    conn.close()


def test_main_lifecycle_via_subprocess():
    """Run app.py as a real subprocess with the DC_* test hooks (fixed
    token+port, no browser), fetch the page, then shut down and assert a
    clean exit code.  Exercises the actual _main() entry path."""
    import socket
    import subprocess
    import time

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    token = "testtoken123456"

    env = {**os.environ, "DC_TOKEN": token, "DC_PORT": str(port), "DC_NO_OPEN": "1"}
    proc = subprocess.Popen([sys.executable, str(WEBUI / "app.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        # wait for the server to come up (banner prints before serve_forever)
        served = False
        for _ in range(100):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                conn.request("GET", f"/{token}/")
                resp = conn.getresponse()
                body = resp.read()
                assert resp.status == 200
                assert b"DeniableCipher" in body
                conn.close()
                served = True
                break
            except OSError:
                time.sleep(0.05)
        assert served, "server never accepted connections"

        # token gate active through the real entry path
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/nope/")
        resp = conn.getresponse()
        assert resp.status == 404
        resp.read()
        conn.close()

        # graceful shutdown → process exits 0
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("POST", f"/{token}/api/shutdown", body=b"{}")
        resp = conn.getresponse()
        body = json.loads(resp.read())
        assert resp.status == 200 and body["ok"] is True
        conn.close()
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
