"""КРИПТО, the desktop application.

    python app.py

No server, no browser. The Tkinter window calls the engine DIRECTLY:
the crypto.Engine class runs in the same process with no HTTP layer between.

The background is generated: a dome grid, collision traces, a recursive tree,
a perspective floor. None of it is an image file.
"""

from __future__ import annotations

import math
import os
import random
import tkinter as tk
from tkinter import font as tkfont

from render import latex_unicode
from crypto import (
    CIPHERTEXT_BYTES,
    DecodeError,
    CryptoError,
    Engine,
    Session,
    ReplayError,
    load_corpus,
    text_capacity,
)
from crypto.primitives import NONCE_BYTES, SELECTOR_BYTES, TAG_BYTES

# ── colour palette ──────────────────────────────────────────────────────

BLACK = "#070305"
BACKGROUND = "#0d0409"
MAROON = "#2c0c17"
RED = "#d92b2b"
RED_BRIGHT = "#ff4a48"
BLIND = "#ff6a3d"
BLUE = "#5d8fb9"
BLUE_DIM = "#28425c"
TEXT = "#f0dade"
TEXT_MID = "#b9939b"
TEXT_DIM = "#7d5c65"

SAMPLE_SLUGS = [
    "ec-weierstrass-short", "euler-totient", "lwe",
    "sunger-yapisi", "hmac", "ecdh-ortak-sir",
]


def shuffle(a: str, b: str, t: float) -> str:
    """A linear blend between two hex colours."""
    t = max(0.0, min(1.0, t))
    ar, net, ab = int(a[1:3], 16), int(a[3:5], 16), int(a[5:7], 16)
    br, bg, bb = int(b[1:3], 16), int(b[3:5], 16), int(b[5:7], 16)
    return "#%02x%02x%02x" % (
        int(ar + (br - ar) * t), int(net + (bg - net) * t), int(ab + (bb - ab) * t),
    )


# ═══════════════════════════════════════════════════════════════════════
#  ARKA PLAN
# ═══════════════════════════════════════════════════════════════════════

class Backdrop:
    """Draws the generated landscape onto the canvas."""

    def __init__(self, canvas: tk.Canvas) -> None:
        self.k = canvas
        self.lit: list[int] = []
        self.phase = 0.0

    def draw(self, W: int, H: int) -> None:
        k = self.k
        k.delete("backdrop")
        if W < 50 or H < 50:
            return

        horizon = int(H * 0.66)
        centre = W // 2
        rng = random.Random(20260812)

        # sky: a banded gradient
        band = 6
        for y in range(0, horizon, band):
            t = y / max(1, horizon)
            colour = shuffle("#0a0409", "#3d1018", t ** 1.6)
            k.create_rectangle(0, y, W, y + band, fill=colour, outline="", tags="backdrop")

        k.create_rectangle(0, horizon, W, H, fill="#05060a", outline="", tags="backdrop")

        # dome: longitude and latitude arcs
        rx, ry = W * 0.78, H * 0.95
        for j in range(-8, 9):
            t = j / 8
            colour = shuffle("#0a0409", "#4e6b86", 0.55 - abs(t) * 0.32)
            w = abs(rx * t) + 1
            k.create_arc(centre - w, horizon - ry, centre + w, horizon + ry,
                         start=0, extent=180, style=tk.ARC, outline=colour, tags="backdrop")
        for i in range(1, 10):
            t = i / 9
            colour = shuffle("#0a0409", "#4e6b86", 0.42 * (1 - t * 0.5))
            k.create_arc(centre - rx * t, horizon - ry * t, centre + rx * t, horizon + ry * t,
                         start=0, extent=180, style=tk.ARC, outline=colour, tags="backdrop")

        # sacred geometry: a bundle of circles on a hexagonal lattice
        r = min(W, H) * 0.09
        oy = horizon - H * 0.40
        for a in range(-3, 4):
            for b in range(-3, 4):
                x = centre + (a + b * 0.5) * r * 1.732
                y = oy + b * r * 1.5
                if math.hypot(x - centre, y - oy) > r * 4.6:
                    continue
                k.create_oval(x - r, y - r, x + r, y + r,
                              outline="#2a1016", tags="backdrop")

        # collision traces
        self.lit.clear()
        ox, oy = centre, horizon - H * 0.42
        span = min(W, H)
        for _ in range(90):
            a0 = rng.uniform(0, math.tau)
            x = ox + math.cos(a0) * rng.uniform(0, span * 0.05)
            y = oy + math.sin(a0) * rng.uniform(0, span * 0.05)
            ang = a0 + rng.uniform(-0.5, 0.5)
            length = rng.uniform(span * 0.10, span * 0.95)
            arc = rng.uniform(-0.030, 0.030)
            count = 34
            step = length / count

            point = [x, y]
            for _ in range(count):
                ang += arc
                x += math.cos(ang) * step
                y += math.sin(ang) * step
                point += [x, y]

            if rng.random() < 0.22:            # an Archimedean spiral at the tip
                sr, sa = 1.5, ang
                dir = 1 if rng.random() < 0.5 else -1
                for _ in range(46):
                    sa += 0.34 * dir
                    sr += 0.55
                    point += [x + math.cos(sa) * sr, y + math.sin(sa) * sr]

            bright = rng.random() < 0.18
            colour = shuffle(MAROON, RED_BRIGHT, rng.uniform(0.75, 1.0) if bright
                             else rng.uniform(0.14, 0.5))
            cid = k.create_line(*point, fill=colour, width=2 if bright else 1,
                                smooth=True, tags="backdrop")
            if bright:
                self.lit.append(cid)

        # horizon koru
        for i in range(26):
            t = i / 26
            k.create_rectangle(0, horizon - i * 3 - 3, W, horizon - i * 3,
                               fill=shuffle("#3d1018", "#1a0810", t),
                               outline="", tags="backdrop")
        k.create_line(0, horizon, W, horizon, fill=BLIND, tags="backdrop")

        self._silhouette(W, H, horizon, centre, rng)
        self._background(W, H, horizon, centre)

    def _silhouette(self, W, H, horizon, centre, rng) -> None:
        k = self.k
        # mountains
        point = [0, H, 0, horizon - H * 0.02]
        x = 0
        while x < W:
            w = rng.uniform(W * 0.06, W * 0.17)
            point += [x + w * 0.5, horizon - rng.uniform(H * 0.02, H * 0.10),
                      x + w, horizon - rng.uniform(0, H * 0.02)]
            x += w
        point += [W, H]
        k.create_polygon(*point, fill="#000000", outline="", tags="backdrop")

        # the recursive tree
        def branch(x, y, ang, length, depth):
            if depth == 0 or length < 2:
                return
            x2 = x + math.cos(ang) * length
            y2 = y + math.sin(ang) * length
            k.create_line(x, y, x2, y2, fill="#000000",
                          width=max(1, int(depth * 0.8)), tags="backdrop")
            branch(x2, y2, ang - rng.uniform(0.24, 0.46), length * 0.76, depth - 1)
            branch(x2, y2, ang + rng.uniform(0.24, 0.46), length * 0.76, depth - 1)
            if rng.random() < 0.25:
                branch(x2, y2, ang + rng.uniform(-0.2, 0.2), length * 0.58, depth - 1)

        branch(centre, horizon + H * 0.02, -math.pi / 2, H * 0.075, 8)

    def _background(self, W, H, horizon, centre) -> None:
        k = self.k
        for i in range(30):
            z = i + 0.35
            y = horizon + (H - horizon) * (1 - 1 / (1 + z * 0.30))
            if y > H:
                break
            near = (y - horizon) / max(1, H - horizon)
            k.create_line(0, y, W, y,
                          fill=shuffle("#05060a", BLUE, 0.12 + near * 0.55),
                          tags="backdrop")
        for i in range(-22, 23):
            k.create_line(centre, horizon, centre + i * W * 0.10, H,
                          fill=shuffle("#05060a", BLUE, 0.42 - abs(i) * 0.012),
                          tags="backdrop")

    def jitter(self) -> None:
        """Slowly oscillates the colour of the bright traces."""
        self.phase += 0.07
        t = 0.72 + 0.28 * math.sin(self.phase)
        colour = shuffle(MAROON, RED_BRIGHT, t)
        for cid in self.lit:
            try:
                self.k.itemconfigure(cid, fill=colour)
            except tk.TclError:
                pass


# ═══════════════════════════════════════════════════════════════════════
#  YARDIMCI WIDGET'LAR
# ═══════════════════════════════════════════════════════════════════════


# The engine's error messages are already in English, so they are shown as
# they come. This used to be a translation seam back when `crypto/` spoke
# Turkish; keeping the function keeps the call sites stable and gives one
# place to shape a message if that is ever needed again.


def error_text(e: Exception) -> str:
    """The engine's message, shown as it is."""
    return str(e)


def button(parent_widget, text, command, *, primary=True, gen=None):
    b = tk.Button(
        parent_widget, text=text, command=command, cursor="hand2",
        bg=MAROON if primary else BACKGROUND,
        fg="#ffffff" if primary else BLUE,
        activebackground=RED if primary else BLUE_DIM,
        activeforeground="#ffffff",
        relief=tk.FLAT, bd=0,
        highlightthickness=1,
        highlightbackground=RED if primary else BLUE_DIM,
        highlightcolor=RED,
        font=("Consolas", 9, "bold"),
        padx=10, pady=6,
    )
    if gen:
        b.configure(width=gen)
    return b


def text_box(parent_widget, line, *, read_only=False):
    t = tk.Text(
        parent_widget, height=line, wrap=tk.CHAR,
        bg="#0a0308", fg=RED_BRIGHT if read_only else TEXT,
        insertbackground=RED, selectbackground=RED, selectforeground="#fff",
        relief=tk.FLAT, bd=0,
        highlightthickness=1, highlightbackground=BLUE_DIM, highlightcolor=RED,
        font=("Consolas", 9), padx=8, pady=6,
    )
    return t


def label(parent_widget, text, *, colour=TEXT_DIM, size=8, bold=False):
    return tk.Label(parent_widget, text=text, bg=BACKGROUND, fg=colour,
                    font=("Consolas", size, "bold" if bold else "normal"),
                    anchor="w")


# ═══════════════════════════════════════════════════════════════════════
#  UYGULAMA
# ═══════════════════════════════════════════════════════════════════════

class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.corpus = load_corpus()
        self.capacity = text_capacity(self.corpus)
        self.engine: Engine | None = None
        self.session: Session | None = None
        self._key_raw: bytes = b""

        root.title("КРИПТО - formula codebook")
        root.configure(bg=BLACK)
        root.geometry("1200x840")
        root.minsize(940, 720)

        self.canvas = tk.Canvas(root, bg=BLACK, highlightthickness=0)
        self.canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.backdrop = Backdrop(self.canvas)

        self._setup()
        self.root.bind("<Configure>", self._on_resize)
        self._last_size = (0, 0)
        self.root.after(60, lambda: self._redraw(force=True))
        self._jitter()

        self.generate_key()

    # -- layout ------------------------------------------------------

    def _setup(self) -> None:
        k = self.root

        # header
        tk.Label(k, text="КРИПТО", bg=BLACK, fg="#ffffff",
                 font=("Consolas", 26, "bold")).place(relx=0.032, rely=0.022)
        tk.Label(k, text="формула · formula codebook v1", bg=BLACK, fg=TEXT_DIM,
                 font=("Consolas", 8)).place(relx=0.032, rely=0.072)

        self.equation = tk.Label(
            k, text="𝒞 = ν ‖ σ ‖ π ‖ τ      σ = ι ⊕ Ψκ(ν)      π = (ℓ ‖ m ‖ 0*) ⊕ Ωκ(ν)",
            bg=BLACK, fg=TEXT_MID, font=("Consolas", 10))
        self.equation.place(relx=0.968, rely=0.040, anchor="e")

        # the key strip
        ser = tk.Frame(k, bg=BACKGROUND, highlightthickness=1,
                       highlightbackground=BLUE_DIM)
        ser.place(relx=0.032, rely=0.108, relwidth=0.936, height=46)

        label(ser, "KEY κ", colour=TEXT_MID, size=9, bold=True).pack(
            side=tk.LEFT, padx=(12, 10))

        self.key = tk.Entry(
            ser, bg="#0a0308", fg=BLUE, insertbackground=RED,
            relief=tk.FLAT, bd=0, highlightthickness=1,
            highlightbackground=BLUE_DIM, highlightcolor=RED,
            font=("Consolas", 9))
        self.key.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10), pady=9)
        self.key.bind("<KeyRelease>", lambda e: self.check_key())

        self.key_badge = label(ser, "—", colour=TEXT_DIM, size=8)
        self.key_badge.configure(bg=BACKGROUND, width=7)
        self.key_badge.pack(side=tk.RIGHT, padx=(0, 12))
        button(ser, "GENERATE", self.generate_key, primary=False).pack(
            side=tk.RIGHT, padx=(0, 10), pady=8)

        # panolar
        self.decoy_on = tk.BooleanVar(value=True)
        self.session_open = tk.BooleanVar(value=True)

        self.clipboard_encrypt = self._clipboard(
            "ENCRYPT", "ШИФРОВАТЬ", "m ↦ 𝒞", 0.032,
            "PLAINTEXT m", "CIPHERTEXT 𝒞", "ENCRYPT", self.encrypt,
            extra=self._options)
        self.clipboard_decrypt = self._clipboard(
            "DECRYPT", "РАСШИФРОВАТЬ", "𝒞 ↦ m", 0.516,
            "CIPHERTEXT 𝒞", "DECRYPTED m", "DECRYPT", self.decrypt)

        (self.in_plain, self.out_cipher, self.measure_left) = self.clipboard_encrypt
        (self.in_cipher, self.out_decrypted, self.measure_right) = self.clipboard_decrypt

        self.in_plain.bind("<KeyRelease>", lambda e: self.measure())
        self.in_cipher.bind("<KeyRelease>", lambda e: self.measure())

        # the bottom strip
        alt = tk.Frame(k, bg=BACKGROUND, highlightthickness=1,
                       highlightbackground=BLUE_DIM)
        alt.place(relx=0.032, rely=0.795, relwidth=0.936, relheight=0.155)

        top = tk.Frame(alt, bg=BACKGROUND)
        top.pack(fill=tk.X, padx=12, pady=(8, 4))
        label(top, "WIRE FORMATI", colour=TEXT_DIM, size=8, bold=True).pack(side=tk.LEFT)
        self.total_labels = label(top, f"{CIPHERTEXT_BYTES} B", colour=RED_BRIGHT, size=8)
        self.total_labels.pack(side=tk.RIGHT)

        self.wire = tk.Canvas(alt, bg=BACKGROUND, highlightthickness=0, height=40)
        self.wire.pack(fill=tk.X, padx=12)

        self.state = label(alt, "ready", colour=TEXT_DIM, size=8)
        self.state.pack(fill=tk.X, padx=12, pady=(6, 8))

        # help buttons
        helper = tk.Frame(k, bg=BLACK)
        helper.place(relx=0.968, rely=0.962, anchor="e")
        button(helper, "SYMBOL GLOSSARY", self.open_glossary, primary=False).pack(side=tk.LEFT, padx=4)
        button(helper, "CORPUS", self.open_corpus, primary=False).pack(side=tk.LEFT, padx=4)

    def _options(self, p: tk.Frame) -> None:
        """Mode switches under the encryption panel."""
        for text, variable, command in (
            ("DECOY CHAIN  ·  random formula mix in every ciphertext",
             self.decoy_on, None),
            ("SESSION  ·  sequence number + replay protection (ADR-014)",
             self.session_open, self.session_changed),
        ):
            box = tk.Checkbutton(
                p, text=text, variable=variable, command=command,
                bg=BACKGROUND, fg=BLUE, selectcolor=MAROON,
                activebackground=BACKGROUND, activeforeground=RED_BRIGHT,
                font=("Consolas", 8), anchor="w",
                relief=tk.FLAT, bd=0, highlightthickness=0, cursor="hand2")
            box.pack(fill=tk.X, padx=14, pady=(8, 0))

    def _clipboard(self, title, cyrillic, op, relx, enter, exit, button_text, command,
                   *, extra=None):
        p = tk.Frame(self.root, bg=BACKGROUND, highlightthickness=1, highlightbackground=RED)
        p.place(relx=relx, rely=0.175, relwidth=0.452, relheight=0.605)

        top = tk.Frame(p, bg=BACKGROUND)
        top.pack(fill=tk.X, padx=14, pady=(12, 8))
        tk.Label(top, text=title, bg=BACKGROUND, fg="#ffffff",
                 font=("Consolas", 13, "bold")).pack(side=tk.LEFT)
        tk.Label(top, text=cyrillic, bg=BACKGROUND, fg=BLUE_DIM,
                 font=("Consolas", 7)).pack(side=tk.LEFT, padx=(8, 0))
        tk.Label(top, text=op, bg=BACKGROUND, fg=BLUE,
                 font=("Consolas", 9)).pack(side=tk.RIGHT)

        tk.Frame(p, bg=MAROON, height=1).pack(fill=tk.X, padx=14)

        label(p, enter, size=8).pack(fill=tk.X, padx=14, pady=(10, 3))
        input = text_box(p, 6)
        input.pack(fill=tk.BOTH, expand=True, padx=14)

        measure = label(p, "", colour=TEXT_DIM, size=8)
        measure.pack(fill=tk.X, padx=14, pady=(4, 6))

        button(p, button_text, command).pack(fill=tk.X, padx=14)

        if extra:
            extra(p)

        label(p, exit, size=8).pack(fill=tk.X, padx=14, pady=(10, 3))
        output = text_box(p, 5, read_only=True)
        output.pack(fill=tk.BOTH, expand=True, padx=14)

        eyl = tk.Frame(p, bg=BACKGROUND)
        eyl.pack(fill=tk.X, padx=14, pady=10)
        button(eyl, "KOPYALA", lambda: self.copy(output), primary=False).pack(side=tk.LEFT)
        if button_text == "ENCRYPT":
            button(eyl, "SEND TO DECRYPT >", self.transfer, primary=False).pack(
                side=tk.LEFT, padx=6)

        return input, output, measure

    # -- drawing -----------------------------------------------------

    def _on_resize(self, event) -> None:
        if event.widget is self.root:
            self._redraw()

    def _redraw(self, force=False) -> None:
        W, H = self.root.winfo_width(), self.root.winfo_height()
        if not force and (abs(W - self._last_size[0]) < 12 and
                          abs(H - self._last_size[1]) < 12):
            return
        self._last_size = (W, H)
        self.backdrop.draw(W, H)
        self.wire_ciz()

    def _jitter(self) -> None:
        self.backdrop.jitter()
        self.root.after(110, self._jitter)

    def wire_ciz(self, regions=None) -> None:
        w = self.wire
        w.delete("all")
        W = max(1, w.winfo_width())
        h = 40

        fields = [
            ("ν", "nonce", NONCE_BYTES, 0.12, BLUE),
            ("σ", "selector", SELECTOR_BYTES, 0.10, BLIND),
            ("π", "payload + padding", CIPHERTEXT_BYTES - NONCE_BYTES
             - SELECTOR_BYTES - TAG_BYTES, 0.64, RED_BRIGHT),
            ("τ", "tag", TAG_BYTES, 0.14, BLUE),
        ]
        x = 0
        for symbol, name, byte, ratio, colour in fields:
            gen = W * ratio
            w.create_rectangle(x, 0, x + gen, h, fill="#12060c", outline=BLUE_DIM)
            w.create_text(x + gen / 2, 11, text=symbol, fill=colour,
                          font=("Consolas", 11, "bold"))
            w.create_text(x + gen / 2, 25, text=f"{name}  {byte} B", fill=TEXT_DIM,
                          font=("Consolas", 7))
            x += gen

    # -- operations --------------------------------------------------

    def notify(self, message: str, error=False) -> None:
        self.state.configure(text=message, fg=RED_BRIGHT if error else TEXT_DIM)

    def generate_key(self) -> None:
        self.key.delete(0, tk.END)
        self.key.insert(0, os.urandom(32).hex())
        self.check_key()
        self.notify("new key generated")

    def check_key(self) -> bool:
        raw = self.key.get().strip()
        try:
            b = bytes.fromhex(raw)
        except ValueError:
            b = b""
        valid = len(b) >= 16
        self.key_badge.configure(
            text=f"{len(b)} B" if b else "—",
            fg=BLUE if valid else (RED_BRIGHT if raw else TEXT_DIM))

        # If the key changed the session has to reset too: sequence numbers
        # hang on the key, and carrying an old window into a new key is meaningless.
        if b != self._key_raw:
            self._key_raw = b
            self.engine = Engine(self.corpus, b) if valid else None
            self.session = Session(self.engine) if valid else None
        return valid

    def session_changed(self) -> None:
        """Toggling session mode resets the counter and the replay window."""
        if self.engine is not None:
            self.session = Session(self.engine)
        self.notify("session mode " + ("on · sequence starts at 1"
                                       if self.session_open.get() else
                                       "off · messages have no replay protection"))

    def measure(self) -> None:
        text = self.in_plain.get("1.0", "end-1c")
        n = len(text.encode("utf-8"))
        overflow = n > self.capacity
        self.measure_left.configure(
            text=f"{len(text)} chars   ·   {n} / {self.capacity} bytes",
            fg=RED_BRIGHT if overflow else TEXT_DIM)

        raw = "".join(self.in_cipher.get("1.0", "end-1c").split())
        m = len(raw) // 2
        self.measure_right.configure(
            text=f"{m} bytes   ·   expected {CIPHERTEXT_BYTES}",
            fg=TEXT_DIM if m in (0, CIPHERTEXT_BYTES) else RED_BRIGHT)

    def _write(self, box: tk.Text, text: str) -> None:
        box.delete("1.0", tk.END)
        box.insert("1.0", text)

    def encrypt(self) -> None:
        if not self.check_key():
            self.notify("invalid key: at least 16 bytes of hex", error=True)
            return
        text = self.in_plain.get("1.0", "end-1c")
        if not text:
            self.notify("plaintext is empty", error=True)
            return
        decoy = self.decoy_on.get()
        # In session mode encryption goes through Session and each call produces
        # the next sequence number. With it off the engine is called directly and
        # the sequence stays 0, so that message cannot go through replay protection.
        source = self.session if self.session_open.get() else self.engine
        try:
            blob = (source.encrypt_hidden(text) if decoy
                    else source.encrypt_text(text))
        except CryptoError as e:
            self._write(self.out_cipher, "")
            self.notify(error_text(e), error=True)
            return

        self._write(self.out_cipher, blob.hex())
        self.measure()
        n = NONCE_BYTES

        order = self.engine.read_frame(blob).seq
        stamp = f"#{order}" if order else "unsequenced"

        if decoy:
            records = self.engine.decode_chain(blob, check=False)
            names = [e.slug for e, _ in records if e.slug != "ham-metin"]
            self.last_chain = records
            self.notify(f"encrypted · {len(blob)} B · {stamp} · {len(records)} records "
                        f"({len(names)} decoys) · ν {blob[:6].hex()}…")
        else:
            self.notify(f"encrypted · {len(blob)} B · {stamp} · single record · "
                        f"ν {blob[:6].hex()}… "
                        f"σ {blob[n:n + SELECTOR_BYTES].hex()} "
                        f"τ {blob[-TAG_BYTES:][:6].hex()}…")

    def decrypt(self) -> None:
        if not self.check_key():
            self.notify("invalid key: at least 16 bytes of hex", error=True)
            return
        raw = "".join(self.in_cipher.get("1.0", "end-1c").split())
        if not raw:
            self.notify("ciphertext is empty", error=True)
            return
        try:
            blob = bytes.fromhex(raw)
        except ValueError:
            self.notify("ciphertext is not valid hex", error=True)
            return
        # In session mode the replay check comes FIRST: a packet arriving a
        # second time is refused without the payload being decrypted (ADR-014).
        stamp = ""
        if self.session_open.get():
            try:
                c = self.session.verify(blob)
            except ReplayError as e:
                self._write(self.out_decrypted, "")
                self.notify(f"REPLAY REJECTED · {str(e).split('.')[0]}", error=True)
                return
            except CryptoError as e:
                self._write(self.out_decrypted, "")
                self.notify(error_text(e), error=True)
                return
            stamp = f" · #{c.seq}"

        # The mode is not asked of the user: the decoy chain is tried first, then
        # plain text. Since the tag is verified on both paths it is safe.
        record_count = None
        try:
            try:
                text = self.engine.decrypt_hidden(blob)
                record_count = len(self.engine.decode_chain(blob, check=False))
            except DecodeError:
                text = self.engine.decrypt_text(blob)
        except CryptoError as e:
            self._write(self.out_decrypted, "")
            self.notify(error_text(e), error=True)
            return

        self._write(self.out_decrypted, text)
        mode = f"chain of {record_count} records" if record_count else "single record"
        self.notify(f"decrypted · {mode}{stamp} · {len(text)} chars · "
                    f"{len(text.encode('utf-8'))} bytes")

    def transfer(self) -> None:
        self._write(self.in_cipher, self.out_cipher.get("1.0", "end-1c"))
        self.measure()
        self.notify("ciphertext sent to the decrypt field")

    def copy(self, box: tk.Text) -> None:
        data = box.get("1.0", "end-1c")
        if not data:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(data)
        self.notify("copied to clipboard")

    # -- help windows ------------------------------------------------

    def _window(self, title: str, gen=780, load=620) -> tuple[tk.Toplevel, tk.Frame]:
        p = tk.Toplevel(self.root)
        p.title(title)
        p.configure(bg=BLACK)
        p.geometry(f"{gen}x{load}")
        p.transient(self.root)

        canvas = tk.Canvas(p, bg=BLACK, highlightthickness=0)
        scroll = tk.Scrollbar(p, orient=tk.VERTICAL, command=canvas.yview,
                              bg=BACKGROUND, troughcolor=BLACK, bd=0,
                              activebackground=RED, relief=tk.FLAT)
        ic = tk.Frame(canvas, bg=BLACK)
        ic.bind("<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=ic, anchor="nw", width=gen - 22)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-e.delta // 120, "units"))
        return p, ic

    def open_glossary(self) -> None:
        _, ic = self._window("SYMBOL GLOSSARY · словарь")

        groups = [
            ("PARTS OF THE CIPHERTEXT", [
                ("𝒞", "ciphertext", "The four parts below, laid end to end. Always 1339 bytes."),
                ("ν", "nonce", "16 random bytes, regenerated for every encryption. This is why encrypting the same text twice gives different output. It travels in the clear and is not secret."),
                ("σ", "selector", "2 bytes saying which corpus entry was used. Masked with the key, so it looks random from outside."),
                ("π", "payload", "Frame header, message and padding. Encrypted, 1289 bytes."),
                ("τ", "tag", "Integrity seal, 32 bytes. Flip one bit and verification fails."),
            ]),
            ("INPUTS", [
                ("κ", "key", "What you type in the field above. All security rests on it."),
                ("m", "message", "The plaintext you want to encrypt."),
                ("ℓ", "length", "Real byte count of the message. Carried so the decoder knows where padding starts."),
                ("ι", "identity", "Number of the corpus entry. 0x0701 for raw text."),
                ("0*", "padding", "Zeros appended to the message so every output has the same size."),
            ]),
            ("OPERATIONS", [
                ("‖", "concatenation", "Join two parts.  ab ‖ cd = abcd"),
                ("⊕", "XOR", "Bitwise addition. Apply it twice with the same value and you are back where you started, so encryption and decryption are the same operation."),
                ("Ψκ Ωκ", "keystream", "Byte sequences derived from the key and the nonce, indistinguishable from random. They act as masks."),
                ("H", "entropy", "A measure of unpredictability, in bits."),
                ("Σ", "sum", "Add up the bit widths of all parameters."),
            ]),
        ]

        for title, lines in groups:
            tk.Label(ic, text=title, bg=BLACK, fg=RED_BRIGHT,
                     font=("Consolas", 9, "bold"), anchor="w").pack(
                fill=tk.X, padx=18, pady=(16, 8))
            for symbol, name, description in lines:
                line = tk.Frame(ic, bg=BLACK)
                line.pack(fill=tk.X, padx=18, pady=3)
                tk.Label(line, text=symbol, bg=BLACK, fg=RED_BRIGHT,
                         font=("Consolas", 14, "bold"), width=5, anchor="n").pack(
                    side=tk.LEFT, anchor="n")
                body = tk.Frame(line, bg=BLACK)
                body.pack(side=tk.LEFT, fill=tk.X, expand=True)
                tk.Label(body, text=name, bg=BLACK, fg="#ffffff",
                         font=("Consolas", 9, "bold"), anchor="w").pack(fill=tk.X)
                tk.Label(body, text=description, bg=BLACK, fg=TEXT_MID,
                         font=("Consolas", 8), anchor="w", justify=tk.LEFT,
                         wraplength=600).pack(fill=tk.X)

        tk.Label(ic, text="WHAT THE THREE EQUATIONS SAY", bg=BLACK, fg=RED_BRIGHT,
                 font=("Consolas", 9, "bold"), anchor="w").pack(
            fill=tk.X, padx=18, pady=(20, 8))

        for form, description in [
            ("𝒞 = ν ‖ σ ‖ π ‖ τ",
             "The ciphertext is four parts laid end to end."),
            ("σ = ι ⊕ Ψκ(ν)",
             "The formula identity is not written in the clear. It is XORed with a mask "
             "derived from the key, so it looks different every time."),
            ("π = (ℓ ‖ m ‖ 0*) ⊕ Ωκ(ν)",
             "Length, message and padding are joined and XORed with the keystream. The "
             "length is encrypted too, so the message size is not visible from outside."),
        ]:
            tk.Label(ic, text=form, bg=BLACK, fg=RED_BRIGHT,
                     font=("Consolas", 12), anchor="w").pack(fill=tk.X, padx=18, pady=(8, 2))
            tk.Label(ic, text=description, bg=BLACK, fg=TEXT_MID,
                     font=("Consolas", 8), anchor="w", justify=tk.LEFT,
                     wraplength=680).pack(fill=tk.X, padx=18, pady=(0, 6))

        tk.Frame(ic, bg=BLACK, height=20).pack()

    def open_corpus(self) -> None:
        _, ic = self._window("CORPUS · из корпуса", gen=820, load=640)

        tk.Label(ic, text="FORMULAS IN THE CATALOG", bg=BLACK, fg=RED_BRIGHT,
                 font=("Consolas", 9, "bold"), anchor="w").pack(
            fill=tk.X, padx=18, pady=(16, 4))
        tk.Label(ic, text="These are not part of the wire format. They are examples of the "
                 "content the system can carry.",
                 bg=BLACK, fg=TEXT_DIM, font=("Consolas", 8), anchor="w",
                 justify=tk.LEFT, wraplength=740).pack(fill=tk.X, padx=18, pady=(0, 10))

        for e in self.corpus.active:
            card = tk.Frame(ic, bg="#0c0409", highlightthickness=1,
                            highlightbackground="#1d2c3a")
            card.pack(fill=tk.X, padx=18, pady=3)

            top = tk.Frame(card, bg="#0c0409")
            top.pack(fill=tk.X, padx=12, pady=(8, 2))
            tk.Label(top, text=f"0x{e.id:04X}", bg="#0c0409", fg=TEXT_DIM,
                     font=("Consolas", 8)).pack(side=tk.LEFT)
            tk.Label(top, text=e.name, bg="#0c0409", fg="#ffffff",
                     font=("Consolas", 9, "bold")).pack(side=tk.LEFT, padx=(10, 0))

            formula = latex_unicode(e.doc.get("latex", ""))
            tk.Label(card, text=formula, bg="#0c0409", fg=RED_BRIGHT,
                     font=("Consolas", 10), anchor="w", justify=tk.LEFT,
                     wraplength=740).pack(fill=tk.X, padx=12, pady=(2, 2))

            digest = (e.doc.get("summary") or "").split(".")[0].strip()
            tk.Label(card, text=digest, bg="#0c0409", fg=TEXT_DIM,
                     font=("Consolas", 8), anchor="w", justify=tk.LEFT,
                     wraplength=740).pack(fill=tk.X, padx=12, pady=(0, 8))

        tk.Frame(ic, bg=BLACK, height=20).pack()


def main() -> None:
    root = tk.Tk()
    try:
        tkfont.nametofont("TkDefaultFont").configure(family="Consolas", size=9)
    except tk.TclError:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
