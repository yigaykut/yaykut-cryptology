"""An end to end test of the desktop application.

The window is really created, the buttons are called and the result is read
from the boxes. It needs a display and is skipped where there is none.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

tk = pytest.importorskip("tkinter")

# The root is created ONCE and lives until the tests finish.
# On Windows creating and destroying Tk() in a loop breaks Tcl: the next
# Tk() call fails with "couldn't read file init.tcl". So the probe window is
# not destroyed either, it is used directly as the real root.
try:
    _ROOT = tk.Tk()
except tk.TclError:
    pytest.skip("no display", allow_module_level=True)

import app as U  # noqa: E402


@pytest.fixture(scope="module")
def app():
    _ROOT.geometry("1200x840")
    u = U.App(_ROOT)
    _ROOT.update()
    yield u
    _ROOT.destroy()


@pytest.fixture(autouse=True)
def clean(app):
    """Before every test: empty the boxes, refresh the key, close sub windows."""
    for box in (app.in_plain, app.out_cipher,
                app.in_cipher, app.out_decrypted):
        box.delete("1.0", tk.END)
    app.generate_key()
    app.measure()
    yield
    for child in app.root.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.destroy()


def test_window_is_created(app):
    assert app.corpus is not None
    assert app.capacity > 0


def test_at_startup_key_is_generated(app):
    raw = app.key.get()
    assert len(bytes.fromhex(raw)) == 32
    assert app.engine is not None


def test_invalid_key_engine_lowers(app):
    app.key.delete(0, tk.END)
    app.key.insert(0, "zzzz")
    assert app.check_key() is False
    assert app.engine is None


def test_short_key_is_refused(app):
    app.key.delete(0, tk.END)
    app.key.insert(0, "00" * 8)          # 8 bytes, the limit is 16
    assert app.check_key() is False


@pytest.mark.parametrize("message", [
    "café, naïve, üñî",
    "Modern cryptography: y^2 = x^3 + ax + b",
    "punctuation ,.;:!? and symbols",
    "A" * 500,
], ids=["non-ascii", "with-formula", "punctuation", "long"])
def test_encrypt_decode_round(app, message):
    app.in_plain.insert("1.0", message)
    app.encrypt()
    cipher = app.out_cipher.get("1.0", "end-1c")
    assert len(cipher) // 2 == U.CIPHERTEXT_BYTES

    app.transfer()
    app.decrypt()
    assert app.out_decrypted.get("1.0", "end-1c") == message


def test_empty_text_warning_gives(app):
    app.encrypt()
    assert "empty" in app.state.cget("text")
    assert app.out_cipher.get("1.0", "end-1c") == ""


def test_capacity_overflow_is_refused(app):
    app.in_plain.insert("1.0", "A" * (app.capacity + 10))
    app.encrypt()
    assert "too long" in app.state.cget("text")


def test_wrong_with_the_key_cannot_be_decoded(app):
    app.in_plain.insert("1.0", "secret")
    app.encrypt()
    app.transfer()

    app.key.delete(0, tk.END)
    app.key.insert(0, "11" * 32)
    app.check_key()
    app.decrypt()

    assert app.out_decrypted.get("1.0", "end-1c") == ""
    assert "did not verify" in app.state.cget("text")


def test_broken_hex_is_refused(app):
    app.in_cipher.insert("1.0", "this is not hex")
    app.decrypt()
    assert "hex" in app.state.cget("text")


def test_same_text_different_cipher_produces(app):
    outputs = set()
    for _ in range(5):
        app.in_plain.delete("1.0", tk.END)
        app.in_plain.insert("1.0", "the same message")
        app.encrypt()
        outputs.add(app.out_cipher.get("1.0", "end-1c"))
    assert len(outputs) == 5


def test_measure_indicator_is_updated(app):
    app.in_plain.insert("1.0", "abcde")
    app.measure()
    assert "5 chars" in app.measure_left.cget("text")


def test_help_windows_opens(app):
    before = sum(isinstance(c, tk.Toplevel) for c in app.root.winfo_children())
    app.open_glossary()
    app.open_corpus()
    app.root.update()
    after = sum(isinstance(c, tk.Toplevel) for c in app.root.winfo_children())
    assert after == before + 2


def test_decoy_chain_default_open(app):
    assert app.decoy_on.get() is True


@pytest.mark.parametrize("decoy", [True, False], ids=["with-decoy", "plain"])
def test_two_in_mode_also_round_drops(app, decoy):
    app.decoy_on.set(decoy)
    app.in_plain.insert("1.0", "a mode test")
    app.encrypt()
    app.transfer()
    app.decrypt()
    assert app.out_decrypted.get("1.0", "end-1c") == "a mode test"


def test_decoding_mode_own_sees(app):
    """Both kinds of ciphertext have to open without the user choosing a mode."""
    app.decoy_on.set(True)
    app.in_plain.insert("1.0", "chained")
    app.encrypt()
    chained = app.out_cipher.get("1.0", "end-1c")

    app.in_plain.delete("1.0", tk.END)
    app.in_plain.insert("1.0", "plain")
    app.decoy_on.set(False)
    app.encrypt()
    flat = app.out_cipher.get("1.0", "end-1c")

    for text, blob in (("chained", chained), ("plain", flat)):
        app.in_cipher.delete("1.0", tk.END)
        app.in_cipher.insert("1.0", blob)
        app.decrypt()
        assert app.out_decrypted.get("1.0", "end-1c") == text


def test_with_decoys_in_mode_record_count_is_reported(app):
    app.decoy_on.set(True)
    app.in_plain.insert("1.0", "status")
    app.encrypt()
    assert "records" in app.state.cget("text")


def test_two_mode_same_length_output_gives(app):
    lengths = set()
    for decoy in (True, False):
        app.decoy_on.set(decoy)
        app.in_plain.delete("1.0", tk.END)
        app.in_plain.insert("1.0", "length")
        app.encrypt()
        lengths.add(len(app.out_cipher.get("1.0", "end-1c")) // 2)
    assert lengths == {U.CIPHERTEXT_BYTES}


def test_back_plan_drawing_does_not_crash(app):
    """Drawing must not error while the window is being resized."""
    app.backdrop.draw(900, 700)
    app.backdrop.draw(1600, 1000)
    app.backdrop.jitter()
    assert app.backdrop.lit


# ────────────────────────── session kipi ──────────────────────────

def test_session_default_open(app):
    assert app.session_open.get() is True
    assert app.session is not None


@pytest.mark.parametrize("decoy", [True, False])
def test_session_in_mode_replay_is_refused(app, decoy):
    """The application's most important new guarantee (ADR-014)."""
    app.decoy_on.set(decoy)
    app.session_open.set(True)
    app.session_changed()

    app.in_plain.insert("1.0", "fire at will")
    app.encrypt()
    app.transfer()

    app.decrypt()
    assert app.out_decrypted.get("1.0", "end-1c") == "fire at will"

    app.decrypt()
    assert "REPLAY" in app.state.cget("text")
    assert app.out_decrypted.get("1.0", "end-1c") == ""


def test_session_when_off_replay_valid(app):
    """With the session off the engine is stateless, so the same packet decodes twice."""
    app.session_open.set(False)
    app.session_changed()

    app.in_plain.insert("1.0", "unprotected")
    app.encrypt()
    assert "unsequenced" in app.state.cget("text")
    app.transfer()

    for _ in range(2):
        app.decrypt()
        assert app.out_decrypted.get("1.0", "end-1c") == "unprotected"


def test_order_number_rises_and_is_reported(app):
    app.session_open.set(True)
    app.session_changed()
    for expected in (1, 2, 3):
        app.in_plain.delete("1.0", tk.END)
        app.in_plain.insert("1.0", f"message {expected}")
        app.encrypt()
        assert f"#{expected}" in app.state.cget("text")


def test_key_when_it_changes_session_is_zeroed(app):
    """Sequence numbers hang on the key; when the key changes the counter returns to 1."""
    app.session_open.set(True)
    app.session_changed()
    app.in_plain.insert("1.0", "first key")
    app.encrypt()
    assert "#1" in app.state.cget("text")

    app.generate_key()          # new key
    app.encrypt()
    assert "#1" in app.state.cget("text")


def test_session_mode_of_the_output_length_does_not_change(app):
    """The sequence number is inside the payload, so the envelope size has to stay fixed."""
    lengths = set()
    for plain in (True, False):
        app.session_open.set(plain)
        app.session_changed()
        app.in_plain.delete("1.0", tk.END)
        app.in_plain.insert("1.0", "the same text")
        app.encrypt()
        lengths.add(len(app.out_cipher.get("1.0", "end-1c")) // 2)
    assert lengths == {U.CIPHERTEXT_BYTES}
