"""Local web interface server.

    python webui.py

Encryption runs in this process, not in the browser. The interface calls the
crypto engine rather than imitating it: a second implementation in JavaScript
would mean two wire formats that could silently drift apart.

No dependencies, standard library only.
"""

from __future__ import annotations

import io
import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from crypto import (  # noqa: E402
                    CIPHERTEXT_BYTES,
                    CryptoError,
                    Engine,
                    load_corpus,
                    text_capacity,
)
from crypto.primitives import NONCE_BYTES, SELECTOR_BYTES, TAG_BYTES  # noqa: E402
from crypto.wire import PAYLOAD_FIXED_BYTES  # noqa: E402

from render import latex_unicode  # noqa: E402

ROOT = Path(__file__).resolve().parent / "webui"
CORPUS = load_corpus()
CAPACITY = text_capacity(CORPUS)
TEXT_ENTRY = CORPUS.by_slug("ham-metin")

CONTENT_TYPE = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
}


def split_blob(blob: bytes) -> dict:
    """Split a ciphertext into its regions, for the wire view in the interface."""
    p0 = NONCE_BYTES
    p1 = p0 + SELECTOR_BYTES
    p2 = len(blob) - TAG_BYTES
    return {
        "nonce": blob[:p0].hex(),
        "selector": blob[p0:p1].hex(),
        "payloadPrefix": blob[p1:p1 + 24].hex(),
        "tag": blob[p2:].hex(),
        "bounds": {
            "nonce": [0, p0],
            "selector": [p0, p1],
            "payload": [p1, p2],
            "tag": [p2, len(blob)],
        },
    }


SAMPLE_SLUGS = [
    "ec-weierstrass-short",
    "euler-totient",
    "lwe",
    "sunger-yapisi",
    "hmac",
    "ecdh-ortak-sir",
]


def sample_formulas() -> list[dict]:
    """The corpus formulas shown in the bottom strip.

    Read from the corpus rather than hard coded, so the screen follows the entries.
    """
    output = []
    for slug in SAMPLE_SLUGS:
        try:
            e = CORPUS.by_slug(slug)
        except CryptoError:
            continue
        output.append({
            "id": f"0x{e.id:04X}",
            "name": e.name,
            # The LaTeX source stays in the corpus; readable Unicode goes to the screen.
            "formula": latex_unicode(e.doc.get("latex", "")),
            "summary": (e.doc.get("summary") or "").split(".")[0].strip(),
        })
    return output


def constants() -> dict:
    used = TEXT_ENTRY.payload_bits
    return {
        "samples": sample_formulas(),
        "capacity": CAPACITY,
        "totalBytes": CIPHERTEXT_BYTES,
        "nonceBytes": NONCE_BYTES,
        "selectorBytes": SELECTOR_BYTES,
        "tagBytes": TAG_BYTES,
        "payloadBytes": PAYLOAD_FIXED_BYTES,
        "payloadBits": used,
        "paddingBits": PAYLOAD_FIXED_BYTES * 8 - used,
        "entryId": f"0x{TEXT_ENTRY.id:04X}",
        "entryName": TEXT_ENTRY.name,
        "formula": latex_unicode(TEXT_ENTRY.doc.get("latex", "")),
        "corpus": len(CORPUS.active),
    }


HOST = "127.0.0.1"

# Everything the page needs it serves itself, so the policy can say `self` and
# nothing else. No CDN, no inline script, no external font.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
       "img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def host_allowed(header: str | None, port: int) -> bool:
    """Whether a Host header belongs to this loopback server.

    This is the defence against DNS rebinding, and without it binding to
    127.0.0.1 is less protection than it looks. A page on the open web cannot
    read a loopback response across origins, but an attacker who points their
    own domain at 127.0.0.1 is same-origin as far as the browser is concerned,
    and then `/api/key` and `/api/decrypt` are theirs to call and read. The
    browser still sends the attacker's name in `Host`, so that is the field
    that gives it away. Only the names that really mean this machine pass.
    """
    if not header:
        return False
    name = header.strip()
    if name.startswith("["):                      # [::1]:8731
        closing = name.find("]")
        if closing < 0:
            return False
        hostname, rest = name[1:closing], name[closing + 1:]
        if rest and not rest.startswith(":"):
            return False
        tail = rest[1:]
    else:
        hostname, _, tail = name.partition(":")
    if tail and tail != str(port):
        return False
    return hostname.lower() in {"localhost", "127.0.0.1", "::1"}


class Handler(BaseHTTPRequestHandler):
    server_version = "crypto/1.0"
    port = 8731

    def log_message(self, *args):  # quiet
        pass

    # -- helpers --────────────────────────────────────────────

    def _send(self, code: int, body: bytes, tip: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", tip)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # `nosniff` matters most on the 404 path, where a wrong guess at the
        # type would let the browser decide for itself what it is looking at.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _guard(self) -> bool:
        """Refuse anything that did not address this machine by name."""
        if host_allowed(self.headers.get("Host"), self.port):
            return True
        self._send(403, b"forbidden: this server answers on loopback only",
                   "text/plain; charset=utf-8")
        return False

    def _json(self, data: dict, code: int = 200) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 1 << 20:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _engine(self, key_hex: str) -> Engine:
        try:
            key = bytes.fromhex(key_hex.strip())
        except ValueError:
            raise CryptoError("the key is not valid hex") from None
        if len(key) < 16:
            raise CryptoError(f"the key must be at least 16 bytes, got {len(key)}")
        return Engine(CORPUS, key)

    # -- routing --────────────────────────────────────────────

    def do_GET(self) -> None:
        if not self._guard():
            return
        path = self.path.split("?")[0]

        if path == "/api/state":
            return self._json(constants())

        if path == "/api/key":
            return self._json({"key": os.urandom(32).hex()})

        file = ROOT / ("index.html" if path == "/" else path.lstrip("/"))
        try:
            file = file.resolve()
            file.relative_to(ROOT.resolve())     # block escaping the directory
            body = file.read_bytes()
        except (OSError, ValueError):
            return self._send(404, b"not found", "text/plain; charset=utf-8")

        self._send(200, body, CONTENT_TYPE.get(file.suffix, "application/octet-stream"))

    def do_POST(self) -> None:
        if not self._guard():
            return
        path = self.path.split("?")[0]
        request = self._body()

        try:
            engine = self._engine(request.get("key", ""))

            if path == "/api/encrypt":
                text = request.get("text", "")
                blob = engine.encrypt_text(text)
                return self._json({
                    "ok": True,
                    "blob": blob.hex(),
                    "bytes": len(blob),
                    "inBytes": len(text.encode("utf-8")),
                    "chars": len(text),
                    "regions": split_blob(blob),
                })

            if path == "/api/decrypt":
                blob = bytes.fromhex(request.get("blob", "").strip())
                text = engine.decrypt_text(blob)
                return self._json({
                    "ok": True,
                    "text": text,
                    "bytes": len(blob),
                    "outBytes": len(text.encode("utf-8")),
                    "regions": split_blob(blob),
                })

        except CryptoError as e:
            return self._json({"ok": False, "error": str(e)}, 400)
        except ValueError:
            return self._json({"ok": False, "error": "the ciphertext is not valid hex"}, 400)
        except Exception:  # unexpected
            # The text of an unexpected exception carries file paths and
            # sometimes fragments of the input. It goes to the operator's
            # terminal, not into the response body.
            traceback.print_exc()
            return self._json({"ok": False, "error": "internal error"}, 500)

        self._json({"ok": False, "error": "unknown endpoint"}, 404)


class Server(ThreadingHTTPServer):
    """Do not bind silently a second time if the port is already in use.

    On Windows SO_REUSEADDR lets a second process bind the same port. The
    result is that you think you restarted while requests still reach the old
    process, and your code change looks like it did nothing. A clear error is
    better.
    """
    allow_reuse_address = False


def main(port: int = 8731) -> None:
    # UTF-8 for the console banner below. This used to run at import time,
    # which meant importing the module reached in and replaced the caller's
    # stdout. Nothing above this function prints, so it belongs here, and
    # now the module can be imported by a test.
    # line_buffering, so the banner and any later line appear as they happen.
    # Block buffering would hold them until the buffer filled, which for a
    # server that prints a few lines and then waits means never.
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  line_buffering=True)

    if not ROOT.is_dir():
        print(f"interface directory missing: {ROOT}")
        raise SystemExit(1)

    print(f"  corpus   : {len(CORPUS.active)} active entries")
    print(f"  capacity : {CAPACITY} bytes UTF-8")
    print(f"  output   : {CIPHERTEXT_BYTES} bytes (fixed)")
    print(f"\n  http://{HOST}:{port}\n")
    # The guard compares against this, so a non default port has to reach it.
    Handler.port = port
    try:
        server = Server((HOST, port), Handler)
    except OSError:
        print(f"  ERROR: port {port} is in use. Stop the running server or")
        print(f"  give another port:  python webui.py {port + 1}")
        raise SystemExit(1)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8731)
