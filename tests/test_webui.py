"""The local web server: the host guard and the response headers.

WHY THIS FILE EXISTS

`webui.py` binds to 127.0.0.1, and it is easy to read that as "only this
machine can reach it". It is not quite that. A page on the open web cannot
READ a loopback response across origins, but an attacker who resolves their
own domain to 127.0.0.1 is same origin as far as the browser is concerned,
and from there `/api/key` and `/api/decrypt` answer normally. That is DNS
rebinding, and the bind address does nothing about it.

What does give it away is the `Host` header, which still carries the name the
browser was aimed at. `host_allowed()` is the whole defence, so it is tested
here name by name rather than trusted.

The server had no tests at all before this. These cover the guard; the
encrypt and decrypt round trip through HTTP is covered at the end.
"""

from __future__ import annotations

import http.client
import json
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import webui  # noqa: E402

PORT = 8731


# ───────────────────────────── the guard ─────────────────────────────

@pytest.mark.parametrize("header", [
    "127.0.0.1",
    f"127.0.0.1:{PORT}",
    "localhost",
    f"localhost:{PORT}",
    f"LOCALHOST:{PORT}",              # the header is not case sensitive
    "[::1]",
    f"[::1]:{PORT}",
])
def test_the_names_that_mean_this_machine_pass(header):
    assert webui.host_allowed(header, PORT)


@pytest.mark.parametrize("header", [
    "evil.example.com",
    f"evil.example.com:{PORT}",
    # The shape of a real rebinding host: a name that resolves to 127.0.0.1
    # while reading as something else. The address it resolves to is not the
    # question, the name is.
    f"127.0.0.1.nip.io:{PORT}",
    "localhost.evil.example.com",
    "127.0.0.1.evil.example.com",
    "notlocalhost",
    "192.168.1.10",                   # this machine on the LAN, still not loopback
    "[::ffff:127.0.0.1]",             # loopback written so the check cannot read it
    "",
    None,
])
def test_every_other_name_is_refused(header):
    assert not webui.host_allowed(header, PORT)


def test_a_different_port_is_refused():
    """A guard that ignored the port would accept another local server's name."""
    assert webui.host_allowed(f"127.0.0.1:{PORT}", PORT)
    assert not webui.host_allowed("127.0.0.1:9999", PORT)


def test_a_malformed_bracket_host_does_not_get_through():
    assert not webui.host_allowed("[::1", PORT)
    assert not webui.host_allowed("[::1]x", PORT)


# ──────────────────────── against a live server ──────────────────────

@pytest.fixture(scope="module")
def server():
    """A real server on a port the OS picks, so a busy 8731 cannot fail this."""
    httpd = webui.Server((webui.HOST, 0), webui.Handler)
    port = httpd.server_address[1]
    webui.Handler.port = port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        webui.Handler.port = PORT


def request(port, path, host=None, method="GET", body=None):
    connection = http.client.HTTPConnection(webui.HOST, port, timeout=10)
    headers = {"Host": host if host is not None else f"127.0.0.1:{port}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    status, received = response.status, dict(response.getheaders())
    connection.close()
    return status, received, payload


def test_a_foreign_host_is_refused_on_both_methods(server):
    """GET and POST both, because guarding one of them guards nothing."""
    status, _, _ = request(server, "/api/key", host="evil.example.com")
    assert status == 403
    status, _, _ = request(server, "/api/encrypt", host="evil.example.com",
                           method="POST",
                           body=json.dumps({"key": "00" * 32, "text": "x"}))
    assert status == 403


@pytest.mark.parametrize("header,expected", [
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
])
def test_the_headers_are_on_every_response(server, header, expected):
    for path in ("/", "/api/state", "/does-not-exist"):
        _, received, _ = request(server, path)
        assert received.get(header) == expected, path


def test_the_policy_allows_nothing_off_this_machine(server):
    _, received, _ = request(server, "/")
    policy = received.get("Content-Security-Policy", "")
    assert "default-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    # A policy naming an outside host would mean the page pulls code from
    # somewhere, which is the thing being ruled out.
    assert "http://" not in policy and "https://" not in policy


def test_the_directory_cannot_be_escaped(server):
    for path in ("/../webui.py", "/../../../etc/passwd", "/..%2fwebui.py"):
        status, _, _ = request(server, path)
        assert status == 404, path


def test_an_unexpected_error_does_not_describe_itself(server):
    """A 500 body must not carry paths or fragments of the input."""
    status, _, payload = request(
        server, "/api/decrypt", method="POST",
        body=json.dumps({"key": "00" * 32, "blob": "zz"}))
    text = payload.decode("utf-8")
    assert status in (400, 500)
    assert "Traceback" not in text
    assert str(ROOT) not in text


def test_encrypt_and_decrypt_still_round_trip(server):
    """The guard must not have cost the server its actual job."""
    key = "ab" * 32
    status, _, payload = request(
        server, "/api/encrypt", method="POST",
        body=json.dumps({"key": key, "text": "hello world"}))
    assert status == 200
    out = json.loads(payload)
    assert out["ok"] and out["bytes"] == webui.CIPHERTEXT_BYTES

    status, _, payload = request(
        server, "/api/decrypt", method="POST",
        body=json.dumps({"key": key, "blob": out["blob"]}))
    assert status == 200
    back = json.loads(payload)
    assert back["ok"] and back["text"] == "hello world"
