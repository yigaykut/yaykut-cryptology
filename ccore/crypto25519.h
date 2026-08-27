/* crypto25519: a constant time C implementation of X25519.
 *
 * The Python layer (crypto/curve.py) is algorithmically constant time but not
 * physically so: Python's arbitrary width integers run for different lengths
 * of time depending on operand SIZE. This file closes that gap. All the field
 * arithmetic runs on fixed width 64 bit integers, with no data dependent
 * branching and no data dependent memory access.
 *
 * THE INTERFACE CONTRACT
 *   Python loads this library through ctypes. If it is missing or fails its
 *   own self test, Python falls back to the pure implementation and nothing
 *   breaks. So this is not an ACCELERATOR, it is a HARDENER.
 */
#ifndef CRYPTO25519_H
#define CRYPTO25519_H

#ifdef _WIN32
#  define CRYPTO_EXPORT __declspec(dllexport)
#else
#  define CRYPTO_EXPORT __attribute__((visibility("default")))
#endif

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The interface version. The Python loader reads it and refuses the library on
 * a mismatch. If an old .dll is left lying around we want a fallback to the
 * pure implementation rather than silently wrong behaviour. */
#define CRYPTO25519_VERSION 2

CRYPTO_EXPORT int crypto25519_version(void);

/* X25519 (RFC 7748 §5): out = secret * u.
 *
 * secret 32 bytes, clamping happens INSIDE (the caller passes the raw key)
 * u      32 bytes, the top bit is ignored
 * out    32 byte
 *
 * Returns: always 0. Rejecting a zero result is done on the Python side
 * (RFC 7748 §6.1); there is no policy here, only arithmetic.
 */
CRYPTO_EXPORT int crypto25519(unsigned char out[32],
                            const unsigned char secret[32],
                            const unsigned char u[32]);

/* ─────────────────────── secure memory (ADR-020) ───────────────────────
 * In Python `bytes` is immutable: once a key goes in there it cannot be
 * erased, and where the garbage collector left copies is unknown. On the C
 * side that can be closed: the allocated block is locked (never written to
 * swap) and really zeroed before it is released.
 */

/* Zeroing that cannot be optimised away. A plain `memset` CAN BE DROPPED by
 * the compiler on the grounds that "this memory is about to be freed", and
 * there dead code elimination turns into a vulnerability. This implementation
 * goes through a volatile function pointer and cannot be dropped. */
CRYPTO_EXPORT void crypto_wipe(void *p, size_t n);

/* Allocates a zeroed and, where possible, LOCKED block.
 * If `locked` is not NULL, 1 or 0 is written to it. The lock does not
 * succeed in every environment (the working set limit on Windows,
 * RLIMIT_MEMLOCK on Linux) and the failure must not stay SILENT. */
CRYPTO_EXPORT void *crypto_buffer_open(size_t n, int *locked);

/* Wipes, unlocks, frees. In that order. */
CRYPTO_EXPORT void crypto_buffer_close(void *p, size_t n);

/* Cryptographic randomness straight into the buffer. 0 means success.
 * Why here: Python's `os.urandom` puts the result into a `bytes` object and
 * that object CANNOT BE WIPED. If the key is never to be `bytes`, the
 * generation has to happen on the C side too.
 * Source: `rand_s` (RtlGenRandom) on Windows, `/dev/urandom` elsewhere.
 * It links no extra library. */
CRYPTO_EXPORT int crypto_random(void *p, size_t n);

/* Tests that the wipe really works. 0 means passed. */
CRYPTO_EXPORT int crypto_memory_selftest(void);

/* Self test: the RFC 7748 test vectors.
 * 0 means passed, non zero says which check it stopped at.
 * The Python loader calls this BEFORE using the library. */
CRYPTO_EXPORT int crypto25519_selftest(void);

#ifdef __cplusplus
}
#endif
#endif /* CRYPTO25519_H */
