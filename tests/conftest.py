"""Test paketinin ortak kurulumu.

COVERT MODE AUTHORISATION

`NetworkMode.COVERT` was put behind a password (ADR-029). The password is not
stored in the repo in plaintext, only its salted and iterated digest, so the
tests take it from an ENVIRONMENT VARIABLE:

    CRYPTO_NETWORK_PASSWORD=...  python -m pytest tests/ -q

If it is unset, the tests exercising covert mode are **SKIPPED**. Skipped is
NOT passed, and pytest counts it separately; `skip` was chosen deliberately
over `xfail` so it does not show up as quietly green.

Authorisation is opened once at the start of the session: verification is
100,000 rounds of HMAC (about 0.5 s) and repeating it per test would be pointless cost.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.network import AUTH_ENV, authorise  # noqa: E402

# Once at the start of the session. The result has to be readable at module
# level so `pytest.mark.skipif` can decide at collection time.
SECRET_GRANT = authorise()

secret_grant_needed = pytest.mark.skipif(
    not SECRET_GRANT,
    reason=(f"{AUTH_ENV} is unset or wrong, so covert open network tests "
            f"are SKIPPED. Skipped is not passed."),
)
