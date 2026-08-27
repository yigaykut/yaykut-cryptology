"""The wire format: encoding and decoding.

    ┌──────────┬────────────┬──────────────────┬──────────┐
    │  nonce   │  selector  │     payload      │   tag    │
    │ 16 bytes │  2 bytes   │ 1289 bytes FIXED │ 32 bytes │
    └──────────┴────────────┴──────────────────┴──────────┘
                             always 1339 bytes in total

selector = formula_id XOR HKDF(key, nonce, "selector")
payload  = (frame ‖ body ‖ padding) XOR HKDF(key, nonce, "payload")
tag      = HMAC(HKDF(key, nonce, "mac"), nonce ‖ selector ‖ payload)

The first 9 bytes of the payload are the frame header, version plus sequence
number, see frame.py. The remaining 1280 bytes are the body. The envelope
layout and the "every ciphertext is the same length" guarantee are unchanged;
the fixed size just went from 1330 to 1339.

A fresh nonce on every encryption means the same formula encrypted twice with
the same key gives completely different output. To anyone without the key the
identity is indistinguishable from a uniform 16 bit value, which is why having
tidy sequential corpus ids leaks nothing.

Fixed padding: the payload is padded to the same size for every formula. In v1
the length varied and the distinguisher could recognise 28 of 34 formulas from
the envelope size alone, at 82.6 percent accuracy. Now every ciphertext is
identical in length down to the bit, so length carries zero information.

The padding is zero bytes, encrypted with the keystream, so the padding region
is also indistinguishable from random. It is inside the MAC coverage.

PAYLOAD_FIXED_BYTES is not computed from the corpus; it is a constant of the
wire format. If it were computed, adding a larger formula to the corpus would
make every old ciphertext undecodable.
"""

from __future__ import annotations

from typing import Any

from . import constraints as constr
from . import frame as frame_module
from . import primitives
from .bitio import BitReader, BitWriter
from .corpus import RESERVED_ID, POINT_PREFIX_BITS, Corpus, Entry, param_bits
from .errors import DecodeError, EncodingError, VerificationError
from .frame import FRAME_BYTES, UNSEQUENCED, Frame
from .prekey import Prekey, is_independent, selector_mask
from .primitives import NONCE_BYTES, SELECTOR_BYTES, TAG_BYTES

OVERHEAD_BYTES = NONCE_BYTES + SELECTOR_BYTES + TAG_BYTES
MAX_FORMULA_ID = (1 << (SELECTOR_BYTES * 8)) - 1

# The body constant, the space reserved for formula data. Adding a formula
# larger than this changes the wire format: the constant grows and old
# ciphertexts stop decoding. Such a change requires a new format version.
#
# The largest entry in the corpus, 0x0207 ElGamal, is exactly 1280 bytes and
# fills this constant completely. When the frame header was added this constant
# was NOT reduced; the payload grew by 9 bytes instead, so no corpus entry had
# to change. The envelope paid for the header, not the body.
BODY_FIXED_BYTES = 1280

# Total size of the encrypted region: frame plus body plus padding.
PAYLOAD_FIXED_BYTES = FRAME_BYTES + BODY_FIXED_BYTES

# The invariant total length of every ciphertext.
CIPHERTEXT_BYTES = OVERHEAD_BYTES + PAYLOAD_FIXED_BYTES

INT_TYPES = {"prime", "field_element", "scalar", "uint"}

# Chain mode: carrying several formulas in one ciphertext.
#
# A normal ciphertext carries one formula. In chain mode the selector carries
# the reserved id and the payload becomes a record list:
#
#     [record count: 8 bits]
#     [id1: 16 bits][parameters of formula 1]
#     [id2: 16 bits][parameters of formula 2]
#     ...
#     [zero padding]
#
# The list is inside the payload, so it is encrypted with the keystream and
# covered by the MAC. An outside observer sees neither the record count nor
# which formulas are present, and the output is still a fixed 1339 bytes.
CHAIN_ID = RESERVED_ID
CHAIN_COUNTER_BITS = 8
MAX_RECORDS = (1 << CHAIN_COUNTER_BITS) - 1


def ciphertext_length(entry: Entry | None = None) -> int:
    """Total ciphertext length, a constant independent of the formula.

    The entry parameter is accepted only to make call sites readable; the
    result never depends on it. That is the entire point of fixed padding.
    """
    return CIPHERTEXT_BYTES


def _write_param(w: BitWriter, p: dict, value: Any) -> None:
    name, ptype = p["name"], p["type"]
    bits = param_bits(p)
    if bits is None:
        raise EncodingError(f"{name!r}: bit width could not be computed")

    if ptype in INT_TYPES:
        if not isinstance(value, int) or isinstance(value, bool):
            raise EncodingError(
                f"{name!r}: expected an integer, got {type(value).__name__}")
        w.write_int(value, bits)

    elif ptype == "bytes":
        if not isinstance(value, (bytes, bytearray)):
            raise EncodingError(
                f"{name!r}: expected bytes, got {type(value).__name__}")
        w.write_bytes(bytes(value), bits)

    elif ptype == "enum":
        values = p["values"]
        if value not in values:
            raise EncodingError(
                f"{name!r}: {value!r} is not among the allowed values: {values}")
        w.write_int(values.index(value), bits)

    elif ptype == "point":
        # Compressed SEC1: one prefix byte holding the parity of y, then x.
        try:
            x, y_parity = value
        except (TypeError, ValueError):
            raise EncodingError(
                f"{name!r}: expected an (x, y_parity) pair") from None
        if y_parity not in (0, 1):
            raise EncodingError(
                f"{name!r}: y parity must be 0 or 1, got {y_parity!r}")
        w.write_int(0x02 | y_parity, POINT_PREFIX_BITS)
        w.write_int(x, bits - POINT_PREFIX_BITS)

    else:
        raise EncodingError(f"{name!r}: unknown type {ptype!r}")


def _read_param(r: BitReader, p: dict) -> Any:
    ptype = p["type"]
    bits = param_bits(p)

    if ptype in INT_TYPES:
        return r.read_int(bits)
    if ptype == "bytes":
        return r.read_bytes(bits)
    if ptype == "enum":
        idx = r.read_int(bits)
        values = p["values"]
        if idx >= len(values):
            raise DecodeError(
                f"{p['name']!r}: enum index out of range: {idx} >= {len(values)}")
        return values[idx]
    if ptype == "point":
        prefix = r.read_int(POINT_PREFIX_BITS)
        if prefix not in (0x02, 0x03):
            raise DecodeError(
                f"{p['name']!r}: invalid point prefix 0x{prefix:02X}")
        x = r.read_int(bits - POINT_PREFIX_BITS)
        return (x, prefix & 1)
    raise DecodeError(f"{p['name']!r}: unknown type {ptype!r}")


def _write_params(w: BitWriter, entry: Entry, values: dict[str, Any]) -> None:
    for p in entry.public_params:
        name = p["name"]
        if name not in values:
            raise EncodingError(f"{entry}: required parameter missing: {name!r}")
        _write_param(w, p, values[name])


def _read_params(r: BitReader, entry: Entry) -> dict[str, Any]:
    return {p["name"]: _read_param(r, p) for p in entry.public_params}


def serialize(entry: Entry, values: dict[str, Any]) -> bytes:
    """Turn the public parameters into a bit string, in wire order."""
    w = BitWriter()
    _write_params(w, entry, values)
    return w.to_bytes()


def deserialize(entry: Entry, data: bytes) -> dict[str, Any]:
    """Turn a bit string back into public parameters."""
    return _read_params(BitReader(data), entry)


def encode(
    entry: Entry,
    values: dict[str, Any],
    key: bytes,
    *,
    nonce: bytes | None = None,
    check: bool = True,
    seq: int = UNSEQUENCED,
    prekey: Prekey | None = None,
) -> bytes:
    """Turn a formula id and its parameters into ciphertext.

    The values dict must contain every public parameter. Secret and derived
    parameters are optional; if given, constraints referring to them are
    checked too, and if not, those constraints are skipped.

    `nonce` is only passed in for tests and reproducibility. It must never be
    supplied by hand in production: using the same nonce twice repeats the
    keystream and breaks the cipher.

    `seq` is the replay protection sequence number and requires state. This
    function is stateless, so the number comes from `Session`. Called directly
    it stays 0 and the message cannot go through replay protection.
    """
    if not 0 < entry.id <= MAX_FORMULA_ID:
        raise EncodingError(f"formula id out of range: 0x{entry.id:04X}")
    if entry.status == "retired":
        raise EncodingError(f"{entry}: cannot encrypt with a retired entry")

    if entry.payload_bytes > BODY_FIXED_BYTES:
        raise EncodingError(
            f"{entry}: payload is {entry.payload_bytes} bytes, the body "
            f"constant is {BODY_FIXED_BYTES} ({PAYLOAD_FIXED_BYTES} minus "
            f"{FRAME_BYTES} of frame). Growing the constant changes the wire "
            f"format and makes old ciphertexts undecodable.")

    if check:
        constr.check_all(entry.constraints, values, skip_unknown=True)

    # Fixed padding: frame plus body, completed with zeros. The padding is
    # encrypted with the keystream too, so it is indistinguishable, and it is
    # inside the MAC coverage.
    payload_pt = frame_module.wrap(seq, serialize(entry, values))
    payload_pt = payload_pt.ljust(PAYLOAD_FIXED_BYTES, b"\x00")
    nonce = nonce if nonce is not None else primitives.new_nonce()
    if len(nonce) != NONCE_BYTES:
        raise EncodingError(
            f"nonce must be {NONCE_BYTES} bytes, got {len(nonce)}")

    sel_mask, payload_ks, mac_key = primitives.subkeys(
        key, nonce, len(payload_pt))
    # With a pre-key the selector mask comes from P rather than K, so an
    # attacker holding K reads the content but cannot tell which formula it
    # was. Without one the old mask is used unchanged, so old ciphertexts keep
    # decoding.
    sel_mask = selector_mask(prekey, key, nonce, SELECTOR_BYTES, sel_mask)

    selector = primitives.xor(
        entry.id.to_bytes(SELECTOR_BYTES, "big"), sel_mask)
    payload_ct = primitives.xor(payload_pt, payload_ks)

    head = nonce + selector + payload_ct
    return head + primitives.tag(mac_key, head)


def _split(blob: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Split a ciphertext into its four fields. Validates nothing."""
    if len(blob) != CIPHERTEXT_BYTES:
        raise DecodeError(
            f"wrong ciphertext length: {len(blob)} bytes, expected "
            f"{CIPHERTEXT_BYTES}")
    return (
        blob[:NONCE_BYTES],
        blob[NONCE_BYTES:NONCE_BYTES + SELECTOR_BYTES],
        blob[NONCE_BYTES + SELECTOR_BYTES:-TAG_BYTES],
        blob[-TAG_BYTES:],
    )


def _open(blob: bytes, key: bytes,
          prekey: Prekey | None = None) -> tuple[int, Frame, bytes]:
    """Verify the tag, decrypt the payload, split off the frame.

    Returns (formula_id, frame, body). Not a single byte is interpreted before
    the tag verifies: parsing tampered data opens an attack surface, which is
    why the order here is what it is.
    """
    nonce, selector, payload_ct, tag = _split(blob)
    sel_mask, payload_ks, mac_key = primitives.subkeys(
        key, nonce, len(payload_ct))
    sel_mask = selector_mask(prekey, key, nonce, SELECTOR_BYTES, sel_mask)

    if not primitives.verify_tag(mac_key, blob[:-TAG_BYTES], tag):
        raise VerificationError(
            "tag did not verify: the data was tampered with, or the key is wrong")

    formula_id = int.from_bytes(primitives.xor(selector, sel_mask), "big")
    frame, body = frame_module.unwrap(primitives.xor(payload_ct, payload_ks))
    return formula_id, frame, body


def read_frame(blob: bytes, key: bytes) -> Frame:
    """Read only the frame header, without decrypting the whole payload.

    The tag is verified first. Then only the first 9 bytes of keystream are
    derived, which costs a single HMAC block because HKDF-Expand is sequential.

    That makes the replay window check cheap: a replayed message is rejected
    without producing 1280 bytes of keystream, so an attacker cannot burn CPU
    with a flood of replays.
    """
    nonce, _selector, payload_ct, tag = _split(blob)

    prk = primitives.hkdf_extract(salt=nonce, ikm=key)
    mac_key = primitives.hkdf_expand(
        prk, primitives.INFO_MAC, primitives.HASH_LEN)
    if not primitives.verify_tag(mac_key, blob[:-TAG_BYTES], tag):
        raise VerificationError(
            "tag did not verify: the data was tampered with, or the key is wrong")

    head_ks = primitives.hkdf_expand(
        prk, primitives.INFO_PAYLOAD, FRAME_BYTES)
    return frame_module.read_header(
        primitives.xor(payload_ct[:FRAME_BYTES], head_ks))


def decode(
    corpus: Corpus,
    blob: bytes,
    key: bytes,
    *,
    check: bool = True,
    prekey: Prekey | None = None,
) -> tuple[Entry, dict[str, Any]]:
    """Turn a ciphertext back into a formula entry and its parameters.

    The tag is verified before any data is interpreted. If verification fails
    nothing is parsed, because parsing tampered data opens an attack surface.

    Only public parameters come back; secret and derived ones were never
    written into the ciphertext.

    There is no replay protection here. This function is stateless, so passing
    the same ciphertext twice decodes it twice. Use `Session` for replay
    checking.
    """
    formula_id, _frame, body = _open(blob, key, prekey)

    if formula_id == CHAIN_ID:
        raise DecodeError(
            "this ciphertext is a chain and carries several formulas. "
            "Use decode_chain() or Engine.decode_chain().")
    entry = corpus.get(formula_id)

    if entry.payload_bytes > BODY_FIXED_BYTES:
        raise DecodeError(
            f"{entry}: payload is {entry.payload_bytes} bytes, the body "
            f"constant is {BODY_FIXED_BYTES}; the corpus does not match the "
            f"wire format")

    # deserialize reads only as many bits as the entry's schema requires; the
    # remaining padding bits are never read.
    values = deserialize(entry, body)

    if check:
        # skip_unknown is required: secret parameters are not written into the
        # ciphertext, so constraints referring to them cannot be checked here.
        constr.check_all(entry.constraints, values, skip_unknown=True)

    return entry, values


# ─────────────────────────── CHAIN MODE ───────────────────────────

def chain_capacity(entries: list[Entry]) -> tuple[int, int]:
    """Bit cost of a record list and whether it fits.

    Returns (bits_needed, bits_available).
    """
    needed = CHAIN_COUNTER_BITS + sum(
        SELECTOR_BYTES * 8 + e.payload_bits for e in entries)
    return needed, BODY_FIXED_BYTES * 8


def encode_chain(
    corpus: Corpus,
    records: list[tuple[int | str, dict[str, Any]]],
    key: bytes,
    *,
    nonce: bytes | None = None,
    check: bool = True,
    padding_rng=None,
    seq: int = UNSEQUENCED,
    prekey: Prekey | None = None,
) -> bytes:
    """Carry several formulas in one ciphertext.

    `records` is [(formula_id_or_slug, values), ...] in order.

    The output is still a fixed 1339 bytes, so how many records it carries is
    not visible from outside.

    With `padding_rng`, the space left over after the records is filled with
    random bytes instead of zeros. In a scenario where the keystream is
    compromised, a zero region would give away where the records end.
    """
    if not records:
        raise EncodingError("a chain must contain at least one record")
    if len(records) > MAX_RECORDS:
        raise EncodingError(
            f"a chain carries at most {MAX_RECORDS} records, got {len(records)}")

    resolved: list[tuple[Entry, dict[str, Any]]] = []
    for ref, values in records:
        e = corpus.by_slug(ref) if isinstance(ref, str) else corpus.get(ref)
        if e.status == "retired":
            raise EncodingError(f"{e}: a retired entry cannot go in a chain")
        resolved.append((e, values))

    needed, available = chain_capacity([e for e, _ in resolved])
    if needed > available:
        raise EncodingError(
            f"chain does not fit: {needed} bits needed, {available} available "
            f"({len(resolved)} records). Use fewer or smaller formulas.")

    w = BitWriter()
    w.write_int(len(resolved), CHAIN_COUNTER_BITS)
    for e, values in resolved:
        if check:
            constr.check_all(e.constraints, values, skip_unknown=True)
        w.write_int(e.id, SELECTOR_BYTES * 8)
        _write_params(w, e, values)

    body = frame_module.wrap(seq, w.to_bytes())
    missing = PAYLOAD_FIXED_BYTES - len(body)
    if padding_rng is None:
        padding = bytes(missing)
    else:
        padding = bytes(padding_rng.getrandbits(8) for _ in range(missing))
    payload_pt = body + padding

    nonce = nonce if nonce is not None else primitives.new_nonce()
    if len(nonce) != NONCE_BYTES:
        raise EncodingError(
            f"nonce must be {NONCE_BYTES} bytes, got {len(nonce)}")

    sel_mask, payload_ks, mac_key = primitives.subkeys(
        key, nonce, len(payload_pt))
    sel_mask = selector_mask(prekey, key, nonce, SELECTOR_BYTES, sel_mask)
    selector = primitives.xor(
        CHAIN_ID.to_bytes(SELECTOR_BYTES, "big"), sel_mask)
    payload_ct = primitives.xor(payload_pt, payload_ks)

    head = nonce + selector + payload_ct
    return head + primitives.tag(mac_key, head)


def decode_chain(
    corpus: Corpus,
    blob: bytes,
    key: bytes,
    *,
    check: bool = True,
    prekey: Prekey | None = None,
) -> list[tuple[Entry, dict[str, Any]]]:
    """Turn a chain ciphertext into a list of records."""
    ident, _frame, body = _open(blob, key, prekey)
    if ident != CHAIN_ID:
        raise DecodeError(
            f"this ciphertext is not a chain, it carries one formula "
            f"(0x{ident:04X}). Use decode().")

    r = BitReader(body)
    count = r.read_int(CHAIN_COUNTER_BITS)
    if count == 0:
        raise DecodeError("the chain looks empty, the data is corrupt")

    out: list[tuple[Entry, dict[str, Any]]] = []
    for i in range(count):
        fid = r.read_int(SELECTOR_BYTES * 8)
        try:
            e = corpus.get(fid)
        except Exception:
            raise DecodeError(
                f"record {i + 1} of the chain points at an id that is not in "
                f"the corpus: 0x{fid:04X}") from None
        values = _read_params(r, e)
        if check:
            constr.check_all(e.constraints, values, skip_unknown=True)
        out.append((e, values))
    return out


def is_chain(corpus: Corpus, blob: bytes, key: bytes) -> bool:
    """Whether a ciphertext is in chain mode. Decides only after verifying."""
    try:
        decode_chain(corpus, blob, key, check=False)
        return True
    except VerificationError:
        raise
    except DecodeError:
        return False


class Engine:
    """A convenience wrapper holding a corpus and a key together.

    It is stateless and must stay that way. It issues no sequence numbers and
    remembers no messages; passing the same ciphertext twice decodes it twice.
    Replay protection needs state and lives in `session.Session`, a thin layer
    around the engine holding the counter and the sliding window.
    """

    def __init__(self, corpus: Corpus, key: bytes, *,
                 prekey: Prekey | None = None) -> None:
        if len(key) < 16:
            raise ValueError("the key must be at least 16 bytes")
        if prekey is not None and not is_independent(prekey, key):
            # A cheap but real tripwire. With P == K, key separation buys
            # nothing. Deriving P from K is the same mistake, but this check
            # cannot catch that one.
            raise ValueError(
                "the pre-key cannot equal the master key; all of key "
                "separation rests on that independence")
        self.corpus = corpus
        self._key = key
        self._prekey = prekey

    @property
    def prekey(self) -> Prekey | None:
        return self._prekey

    def network_fingerprint(self) -> str | None:
        """The network's identity, the pre-key fingerprint. Leaks no secret."""
        return self._prekey.fingerprint() if self._prekey else None

    def fingerprint(self) -> str:
        """The key's short identity. Leaks no key material."""
        from .keys import fingerprint
        return fingerprint(self._key)

    def read_frame(self, blob: bytes) -> Frame:
        """Read a ciphertext's frame without fully decrypting the payload."""
        return read_frame(blob, self._key)

    def encrypt(self, formula: int | str, values: dict[str, Any],
                **kw) -> bytes:
        entry = (self.corpus.by_slug(formula) if isinstance(formula, str)
                 else self.corpus.get(formula))
        kw.setdefault("prekey", self._prekey)
        return encode(entry, values, self._key, **kw)

    def decode(self, blob: bytes, **kw) -> tuple[Entry, dict[str, Any]]:
        kw.setdefault("prekey", self._prekey)
        return decode(self.corpus, blob, self._key, **kw)

    def encrypt_chain(self, records, **kw) -> bytes:
        """Carry several formulas in one ciphertext."""
        kw.setdefault("prekey", self._prekey)
        return encode_chain(self.corpus, records, self._key, **kw)

    def decode_chain(self, blob: bytes,
                     **kw) -> list[tuple[Entry, dict[str, Any]]]:
        kw.setdefault("prekey", self._prekey)
        return decode_chain(self.corpus, blob, self._key, **kw)

    def encrypt_hidden(self, text: str, **kw) -> bytes:
        """Encrypt text hidden among randomly chosen decoy formulas."""
        from .message import encrypt_hidden
        return encrypt_hidden(self.corpus, text, self._key, **kw)

    def decrypt_hidden(self, blob: bytes) -> str:
        from .message import decrypt_hidden
        return decrypt_hidden(self.corpus, blob, self._key)

    # The text helpers live in message.py, which depends on wire.py, so they
    # are imported at call time to avoid a circular import.

    def encrypt_text(self, text: str, **kw) -> bytes:
        """Encrypt free text. The output is always a fixed length."""
        from .message import encrypt_text
        return encrypt_text(self.corpus, text, self._key, **kw)

    def decrypt_text(self, blob: bytes) -> str:
        """Decode a ciphertext back to text."""
        from .message import decrypt_text
        return decrypt_text(self.corpus, blob, self._key)
