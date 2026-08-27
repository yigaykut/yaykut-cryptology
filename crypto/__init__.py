"""crypto: a formula codebook cipher engine.

Layer 1, the deterministic core. Machine learning stays outside this path;
the only source of unpredictability is the nonce.

Quick start:

    from crypto import load_corpus, Engine, sample
    import os

    corpus = load_corpus()
    engine = Engine(corpus, os.urandom(32))

    entry = corpus.by_slug("sezar-sifresi")
    values = sample(entry)

    blob = engine.encrypt(entry.id, values)
    back, decoded = engine.decode(blob)
"""

from .corpus import Corpus, Entry, load_corpus, param_bits
from .curve import (
    private_key,
    public_key,
    public_key_buffer,
    shared_secret,
    shared_secret_buffer,
    x25519,
)
from .errors import (
    ConstraintViolation,
    CorpusError,
    CryptoError,
    DecodeError,
    EncodingError,
    KeyManagementError,
    ReplayError,
    SamplingError,
    VerificationError,
    VersionError,
)
from .frame import FRAME_BYTES, MAX_SEQ, UNSEQUENCED, VERSION, Frame
from .handshake import (
    HANDSHAKE_SLUG,
    INITIATOR,
    RESPONDER,
    Handshake,
    Identity,
    SecureChannel,
    SessionKeys,
)
from .handshake import pack as handshake_pack
from .handshake import unpack as handshake_unpack
from .keys import (
    KeyChain,
    device_key,
    epoch_key,
    fingerprint,
    master_key,
    wipe,
)
from .memory import SecureBuffer
from .message import (
    TEXT_SLUG,
    decrypt_hidden,
    decrypt_text,
    encrypt_hidden,
    encrypt_text,
    text_capacity,
)
from .primitives import NONCE_BYTES, SELECTOR_BYTES, TAG_BYTES, new_nonce
from .sampler import (
    hard_constraints,
    random_values,
    sample,
    sample_or_free,
)
from .session import ReplayWindow, Session
from .wire import (
    BODY_FIXED_BYTES,
    CHAIN_ID,
    CIPHERTEXT_BYTES,
    MAX_RECORDS,
    OVERHEAD_BYTES,
    PAYLOAD_FIXED_BYTES,
    Engine,
    chain_capacity,
    ciphertext_length,
    decode,
    decode_chain,
    deserialize,
    encode,
    encode_chain,
    is_chain,
    read_frame,
    serialize,
)

__all__ = [
    "Corpus", "Entry", "load_corpus", "param_bits",
    "Engine", "encode", "decode", "serialize", "deserialize",
    "sample", "sample_or_free", "random_values", "hard_constraints",
    "new_nonce", "NONCE_BYTES", "SELECTOR_BYTES", "TAG_BYTES",
    "OVERHEAD_BYTES", "PAYLOAD_FIXED_BYTES", "BODY_FIXED_BYTES",
    "CIPHERTEXT_BYTES", "ciphertext_length",
    "encode_chain", "decode_chain", "chain_capacity", "is_chain",
    "CHAIN_ID", "MAX_RECORDS",
    "encrypt_text", "decrypt_text", "text_capacity", "TEXT_SLUG",
    "encrypt_hidden", "decrypt_hidden",
    # frame and replay protection
    "Frame", "read_frame", "VERSION", "FRAME_BYTES", "UNSEQUENCED", "MAX_SEQ",
    "Session", "ReplayWindow",
    # key management
    "master_key", "device_key", "epoch_key", "KeyChain",
    "fingerprint", "wipe",
    # X25519 and handshake
    "x25519", "private_key", "public_key",
    "public_key_buffer", "shared_secret", "shared_secret_buffer",
    "Identity", "Handshake", "SessionKeys", "SecureChannel",
    "SecureBuffer",
    "handshake_pack", "handshake_unpack",
    "INITIATOR", "RESPONDER", "HANDSHAKE_SLUG",
    "CryptoError", "CorpusError", "ConstraintViolation", "EncodingError",
    "DecodeError", "VerificationError", "SamplingError",
    "VersionError", "ReplayError", "KeyManagementError",
]
