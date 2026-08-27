"""Exception types raised by the engine."""


class CryptoError(Exception):
    """Base class for every engine error."""


class CorpusError(CryptoError):
    """A corpus entry could not be loaded, or is inconsistent."""


class ConstraintViolation(CryptoError):
    """A validity constraint was not satisfied."""

    def __init__(self, expr: str, reason: str):
        self.expr = expr
        self.reason = reason
        super().__init__(f"{reason}  (constraint: {expr})")


class EncodingError(CryptoError):
    """A value does not match the schema and could not be encoded."""


class DecodeError(CryptoError):
    """Ciphertext could not be decoded: corrupt, tampered, or wrong key."""


class VerificationError(DecodeError):
    """MAC verification failed. Data was tampered with, or the key is wrong."""


class VersionError(DecodeError):
    """The ciphertext format version does not match the engine's."""


class ReplayError(DecodeError):
    """Sequence number was already seen, or fell outside the window.

    Raised even though the tag is valid. The message really did come from
    someone holding the key, but it was either recorded and replayed, or
    delayed so long we can no longer tell. Both are rejected.
    """


class KeyManagementError(CryptoError):
    """Key derivation or key management failure."""


class SamplingError(CryptoError):
    """Could not generate random values satisfying the constraints."""
