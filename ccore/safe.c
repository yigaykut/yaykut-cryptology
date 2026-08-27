/* safe.c — locked and genuinely wipeable memory for key material.
 *
 * ────────────────────────── THE GAP THIS CLOSES ──────────────────────────
 * ADR-018's list of things that could not be fixed carried this item:
 *
 *   "Keys cannot be wiped from memory. `bytes` is immutable and the garbage
 *    collector keeps copies in unexpected places."
 *
 * That was Python's limit, not cryptography's. On the C side three things can
 * be done at once, and this code does exactly those three:
 *
 *   1. THE ZEROING CANNOT BE DROPPED. If a plain `memset(p, 0, n)` is
 *      immediately followed by `free(p)`, the compiler may treat it as DEAD
 *      CODE and delete it, and usually does. This is one of the rare places
 *      where a standard optimisation turns directly into a vulnerability
 *      (CWE-14). The fix: reach `memset` through a VOLATILE function
 *      pointer, which the compiler cannot assume about, so it stays.
 *
 *   2. IT IS NEVER WRITTEN TO SWAP. An unlocked page is written to disk when
 *      the operating system is short on memory. Even if the key is wiped
 *      from memory then, the copy on disk stays after the process dies.
 *      `VirtualLock` (Windows) and `mlock` (POSIX) prevent that.
 *
 *   3. A FAILED LOCK DOES NOT STAY SILENT. The lock does not hold in every
 *      environment: the process working set limit on Windows, a low
 *      RLIMIT_MEMLOCK on Linux, and the call fails. Reporting "locked"
 *      without locking is worse than not locking, so the caller sees the result.
 *
 * ────────────────────────── KAPATILMAYAN ──────────────────────────
 * This file does not GUARANTEE that a key never enters a Python `bytes`
 * object; it only makes that POSSIBLE. If the caller says `to_bytes()` and
 * takes a copy, that copy still cannot be wiped. The responsibility is in
 * `crypto/memory.py` and it is written there explicitly.
 *
 * A kernel memory dump (core dump or crash dump) can also still contain
 * locked pages. Turning that off is a separate process level setting
 * (`PR_SET_DUMPABLE`, `SetErrorMode`) and is out of this project's scope.
 */

#ifdef _WIN32
#  define _CRT_RAND_S      /* rand_s: must come BEFORE stdlib.h */
#else
/* Strict -std=c99 hides the POSIX declarations, making mmap, mlock and
 * MAP_ANONYMOUS invisible. Feature test macros have to come BEFORE the
 * headers. */
#  define _POSIX_C_SOURCE 200809L
#  define _DEFAULT_SOURCE
#  define _BSD_SOURCE
#endif

#include "crypto25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/mman.h>
/* On some BSDs the name is MAP_ANON. */
#  if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#    define MAP_ANONYMOUS MAP_ANON
#  endif
#endif

/* A one line defence. The `volatile` qualifier is on the POINTER, not on the
 * function it points at: the compiler has to assume this pointer's value can
 * change at any moment, so it can neither inline nor drop the call. */
static void *(*volatile crypto_memset_v)(void *, int, size_t) = memset;

void crypto_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0)
        crypto_memset_v(p, 0, n);
}

/* WHY NOT malloc, AND WHY EVERY BUFFER GETS ITS OWN PAGE
 *
 * The first implementation used `malloc` plus `VirtualLock` and had a SILENT
 * weakness: if two small buffers land on the same 4 KB page, closing one
 * unlocks that page while the other is still alive. The lock is lost, nobody
 * says anything, and the "locked" claim becomes a lie.
 *
 * Because page granularity decides the reliability of a locking primitive,
 * the allocation happens at page granularity too: `VirtualAlloc` or `mmap`.
 * The cost is at least one page (4 KB) per buffer, which looks wasteful for
 * a 32 byte key, but keys are counted in TENS and the wasted pages have no
 * practical cost. libsodium's `sodium_malloc` does the same thing for the
 * same reason.
 */
void *crypto_buffer_open(size_t n, int *locked)
{
    void *p;

    if (locked != NULL)
        *locked = 0;
    if (n == 0)
        return NULL;

#ifdef _WIN32
    p = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p == NULL)
        return NULL;
    /* VirtualAlloc gives a zeroed page, and we zero it explicitly anyway, so
     * the assumption does not break silently if the allocator changes. */
    crypto_memset_v(p, 0, n);
    if (locked != NULL)
        *locked = VirtualLock(p, n) ? 1 : 0;
#else
    p = mmap(NULL, n, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    crypto_memset_v(p, 0, n);
    if (locked != NULL)
        *locked = (mlock(p, n) == 0) ? 1 : 0;
#endif
    return p;
}

void crypto_buffer_close(void *p, size_t n)
{
    if (p == NULL)
        return;

    /* The order matters: wipe first, then unlock, then release.
     * The other way round, the wipe would write to memory that is no longer ours. */
    crypto_wipe(p, n);
#ifdef _WIN32
    VirtualUnlock(p, n);
    VirtualFree(p, 0, MEM_RELEASE);
#else
    munlock(p, n);
    munmap(p, n);
#endif
}

/* ──────────────────── randomness ────────────────────
 * If a key is never to enter a Python `bytes` object, the generation has to
 * happen here too. No extra library is LINKED, deliberately: a dependency
 * such as `-lbcrypt` would take the X25519 core down with it whenever it
 * failed to link. Both paths used are inside the C runtime itself.
 */
int crypto_random(void *p, size_t n)
{
    unsigned char *b = (unsigned char *)p;

    if (p == NULL || n == 0)
        return 1;

#ifdef _WIN32
    {
        /* rand_s is Microsoft's documented secure generator (RtlGenRandom).
         * It has nothing to do with `rand`/`srand`: it is not seeded and not predictable. */
        size_t i = 0;
        while (i < n) {
            unsigned int v;
            size_t k;
            if (rand_s(&v) != 0) {
                crypto_wipe(p, n);
                return 2;
            }
            for (k = 0; k < sizeof v && i < n; k++, i++)
                b[i] = (unsigned char)((v >> (8 * k)) & 0xFF);
        }
        return 0;
    }
#else
    {
        FILE *f = fopen("/dev/urandom", "rb");
        size_t okunan;
        if (f == NULL)
            return 3;
        okunan = fread(b, 1, n, f);
        fclose(f);
        if (okunan != n) {
            crypto_wipe(p, n);
            return 4;
        }
        return 0;
    }
#endif
}

/* ──────────────────── the self test ────────────────────
 * The Python loader calls this before using the library. If wiping does not
 * work, the library should not be used at all rather than quietly claim it wiped.
 */
int crypto_memory_selftest(void)
{
    const size_t n = 256;
    unsigned char *p;
    int locked = 0;
    size_t i;

    p = (unsigned char *)crypto_buffer_open(n, &locked);
    if (p == NULL)
        return 1;

    /* 1. Is a new buffer zeroed? */
    for (i = 0; i < n; i++) {
        if (p[i] != 0) {
            crypto_buffer_close(p, n);
            return 2;
        }
    }

    /* 2. Fill it, wipe it, is it really zero? */
    for (i = 0; i < n; i++)
        p[i] = (unsigned char)(0xA5 ^ (i & 0xFF));
    crypto_wipe(p, n);
    for (i = 0; i < n; i++) {
        if (p[i] != 0) {
            crypto_buffer_close(p, n);
            return 3;
        }
    }

    /* 3. Does the randomness work? A generator returning all zeros (the
     *    source being closed, for instance) is silently catastrophic. */
    if (crypto_random(p, n) != 0) {
        crypto_buffer_close(p, n);
        return 4;
    }
    {
        int hepsi_sifir = 1;
        for (i = 0; i < n; i++) {
            if (p[i] != 0) { hepsi_sifir = 0; break; }
        }
        if (hepsi_sifir) {
            crypto_buffer_close(p, n);
            return 5;   /* all 256 bytes zero: 2^-2048, the generator is broken */
        }
    }

    crypto_buffer_close(p, n);
    /* The lock may not have held, and that is NOT AN ERROR, it is an
     * environment limit. The caller learns the state through `crypto_buffer_open`. */
    return 0;
}
