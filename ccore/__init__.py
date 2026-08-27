"""The C core: source, build script and verification twin.

This package IS NOT IMPORTED IN PRODUCTION. `crypto/` loads only the compiled
library, through `crypto/fastpath.py`; the Python files here are build and
verification tools.
"""
