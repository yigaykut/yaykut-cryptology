/* crypto25519.c — X25519, constant time.
 *
 * ─────────────────────────── REPRESENTATION ───────────────────────────
 * The field is GF(2^255 - 19). An element is held in 12 limbs of 22 bits
 * held as:   x = Σ h[i] · 2^(22i),  i = 0..11,  h[i] ∈ [0, 2^22)
 *
 * WHY 12 x 22 AND NOT REF10'S 10 x 25.5
 * Known implementations (ref10) use 10 limbs in base 2^25.5 and unroll the
 * multiplication by hand. That is fast but hard to verify line by line. The
 * goal here is not speed but VERIFIABILITY: a plain double loop schoolbook
 * multiplication, one uniform base, an overflow margin you can work out on paper.
 *
 *   12 · 22 = 264 bit  ->  2^264 = 2^255 · 2^9 = 19 · 512 = 9728  (mod p)
 *
 * So every term in the upper half is multiplied by 9728 and folded down.
 * Overflow margin: limbs < 2^22 -> product < 2^44 -> folded term < 2^57.3.
 * The busiest accumulator acc[0]: 11 folded plus 1 plain term < 2^60.7 < 2^63.
 * So int64 does not overflow, with about 4 bits of headroom. That bound is
 * asserted on every test in ccore/twin.py, the Python twin of this file.
 *
 * ────────────────────── CONSTANT TIME BEHAVIOUR ──────────────────────
 *  . No data dependent BRANCHING. The only conditional operation is cswap,
 *    and that goes through a mask.
 *  . No data dependent MEMORY ACCESS. The index is always a loop counter.
 *  . The ladder always turns 255 steps (clamping sets bit 254 to 1).
 *  . Inversion uses the Fermat exponent: a fixed length square and multiply
 *    chain. The extended Euclidean algorithm is faster but its loop count
 *    depends on the input, which does not fit constant time.
 */

#include "crypto25519.h"
#include <string.h>
#include <stdint.h>

#define LIMBS 12          /* number of limbs */
#define BASE 22         /* limb width in bits */
#define MASK 0x3FFFFFL  /* 2^22 - 1 */
#define FOLD 9728L      /* 2^264 mod p */

typedef int64_t fe[LIMBS];

/* p = 2^255 - 19, in base 22. Check:
 *   toplam_{i=0..10} (2^22-1)·2^(22i) = 2^242 - 1
 *   p = (2^242 - 1) - 18 + 8191·2^242 = 8192·2^242 - 19 = 2^255 - 19  ok */
static const int64_t P22[LIMBS] = {
    4194285L, 4194303L, 4194303L, 4194303L, 4194303L, 4194303L,
    4194303L, 4194303L, 4194303L, 4194303L, 4194303L, 8191L
};

/* 1024*p, to remove borrowing from subtraction entirely.
 * For h[i] = f[i] + Q[i] - g[i] to stay POSITIVE we needed a multiple of p
 * whose every limb exceeds 2^22. p itself does not qualify because its top
 * limb is 8191, but 1024 times it does (8191*1024 = 8387584).
 * Never letting the sign go negative simplifies the carry loop a great deal. */
static const int64_t Q1024[LIMBS] = {
    4294947840L, 4294966272L, 4294966272L, 4294966272L, 4294966272L,
    4294966272L, 4294966272L, 4294966272L, 4294966272L, 4294966272L,
    4294966272L, 8387584L
};

/* ───────────────────────── basic operations ───────────────────────── */

/* Carry propagation. Input limbs can be arbitrarily large (about 2^61 after
 * a multiplication); on the way out they are all in [0, 2^22).
 *
 * Why three passes are enough:
 *   pass 1: about 2^61 -> the overflow above is about 2^39, folded at the
 *   pass 2: about 2^52 -> about 2^30 -> about 2^8 -> 1
 *   pass 3: settles the remaining single unit of overflow
 * twin.py asserts this on every test. */
static void fe_carry(fe h)
{
    int round, i;
    int64_t c;
    for (round = 0; round < 3; round++) {
        for (i = 0; i < LIMBS - 1; i++) {
            c = h[i] >> BASE;
            h[i] -= c << BASE;
            h[i + 1] += c;
        }
        c = h[LIMBS - 1] >> BASE;
        h[LIMBS - 1] -= c << BASE;
        h[0] += c * FOLD;
    }
}

static void fe_add(fe h, const fe f, const fe g)
{
    int i;
    for (i = 0; i < LIMBS; i++) h[i] = f[i] + g[i];
    fe_carry(h);
}

static void fe_sub(fe h, const fe f, const fe g)
{
    int i;
    for (i = 0; i < LIMBS; i++) h[i] = f[i] + Q1024[i] - g[i];
    fe_carry(h);
}

/* Schoolbook multiplication plus folding. The branching depends only on the
 * loop COUNTER, not on data, so the compiler can unroll it entirely. */
static void fe_mul(fe h, const fe f, const fe g)
{
    int64_t acc[LIMBS];
    int i, j;

    for (i = 0; i < LIMBS; i++) acc[i] = 0;

    for (i = 0; i < LIMBS; i++) {
        for (j = 0; j < LIMBS - i; j++)      /* i+j < 12: plain */
            acc[i + j] += f[i] * g[j];
        for (j = LIMBS - i; j < LIMBS; j++)   /* i+j >= 12: folded */
            acc[i + j - LIMBS] += FOLD * (f[i] * g[j]);
    }

    for (i = 0; i < LIMBS; i++) h[i] = acc[i];
    fe_carry(h);
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

/* Multiplication by a24 = (486662 - 2) / 4 = 121665, the ladder's only curve constant. */
static void fe_carp121665(fe h, const fe f)
{
    int i;
    for (i = 0; i < LIMBS; i++) h[i] = f[i] * 121665L;
    fe_carry(h);
}

/* Conditional swap; b is 0 or 1. -1 is a mask of all ones and -0 is zero, so
 * the condition comes out of arithmetic rather than branching. Limbs are
 * always in [0,2^22) after a carry, which makes the XOR safe. */
static void fe_cswap(fe f, fe g, int64_t b)
{
    int64_t mask = -b;
    int i;
    for (i = 0; i < LIMBS; i++) {
        int64_t x = mask & (f[i] ^ g[i]);
        f[i] ^= x;
        g[i] ^= x;
    }
}

static void fe_copy(fe h, const fe f)
{
    int i;
    for (i = 0; i < LIMBS; i++) h[i] = f[i];
}

static void fe_zero(fe h) { int i; for (i = 0; i < LIMBS; i++) h[i] = 0; }
static void fe_one(fe h)   { fe_zero(h); h[0] = 1; }

/* ───────────────────── seri hâle getirme ───────────────────── */

static void fe_frombytes(fe h, const unsigned char s[32])
{
    unsigned char t[36];
    int i;

    memcpy(t, s, 32);
    t[31] &= 0x7F;              /* RFC 7748: the top bit of u is ignored */
    memset(t + 32, 0, 4);

    for (i = 0; i < LIMBS; i++) {
        int bit = BASE * i;
        int byte = bit >> 3;
        int shift = bit & 7;
        uint64_t v = (uint64_t)t[byte]
                   | ((uint64_t)t[byte + 1] << 8)
                   | ((uint64_t)t[byte + 2] << 16)
                   | ((uint64_t)t[byte + 3] << 24);
        h[i] = (int64_t)((v >> shift) & (uint64_t)MASK);
    }
}

/* Full reduction: brings the value into [0, 2^255). */
static void fe_reduce(fe h)
{
    int64_t q;
    int tekrar;

    fe_carry(h);
    /* 2^255 = 19 (mod p). The top limb carries bits 242 to 263, so bit 255
     * and above is h[11] >> 13. Folding twice is enough: after the first
     * fold the value can exceed 2^255 at most once more. */
    for (tekrar = 0; tekrar < 2; tekrar++) {
        q = h[LIMBS - 1] >> 13;
        h[LIMBS - 1] -= q << 13;
        h[0] += 19 * q;
        fe_carry(h);
    }
}

static void fe_tobytes(unsigned char s[32], const fe f)
{
    fe h;
    int64_t t[LIMBS], borrow, mask;
    unsigned char buf[36];
    int i;

    fe_copy(h, f);
    fe_reduce(h);              /* now h < 2^255 */

    /* Since h < 2^255 and p = 2^255 - 19, one conditional subtraction is enough. */
    borrow = 0;
    for (i = 0; i < LIMBS; i++) {
        int64_t d = h[i] - P22[i] - borrow;
        borrow = (d >> BASE) & 1;      /* if d is negative an arithmetic shift gives -1 */
        t[i] = d + (borrow << BASE);
    }
    mask = -borrow;                    /* borrow=1 -> h < p -> h is kept */
    for (i = 0; i < LIMBS; i++)
        h[i] = (h[i] & mask) | (t[i] & ~mask);

    memset(buf, 0, sizeof buf);
    for (i = 0; i < LIMBS; i++) {
        int bit = BASE * i;
        int byte = bit >> 3;
        int shift = bit & 7;
        uint64_t v = ((uint64_t)h[i]) << shift;
        buf[byte]     |= (unsigned char)(v & 0xFF);
        buf[byte + 1] |= (unsigned char)((v >> 8) & 0xFF);
        buf[byte + 2] |= (unsigned char)((v >> 16) & 0xFF);
        buf[byte + 3] |= (unsigned char)((v >> 24) & 0xFF);
    }
    memcpy(s, buf, 32);
}

/* ───────────────────────── inversion ─────────────────────────
 * z^(p-2) = z^(-1), by Fermat's little theorem. p-2 = 2^255 - 21.
 * Zincirin sonu:  2^255 - 2^5 + 11 = 2^255 - 21  ok
 */
static void fe_invert(fe out, const fe z)
{
    fe t0, t1, t2, t3;
    int i;

    fe_sq(t0, z);                                  /* z^2         */
    fe_sq(t1, t0); fe_sq(t1, t1);                /* z^8         */
    fe_mul(t1, z, t1);                              /* z^9         */
    fe_mul(t0, t0, t1);                             /* z^11        */
    fe_sq(t2, t0);                                 /* z^22        */
    fe_mul(t1, t1, t2);                             /* z^(2^5-1)   */

    fe_sq(t2, t1); for (i = 1; i < 5; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);                             /* z^(2^10-1)  */

    fe_sq(t2, t1); for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);                             /* z^(2^20-1)  */

    fe_sq(t3, t2); for (i = 1; i < 20; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);                             /* z^(2^40-1)  */

    fe_sq(t2, t2); for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);                             /* z^(2^50-1)  */

    fe_sq(t2, t1); for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);                             /* z^(2^100-1) */

    fe_sq(t3, t2); for (i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);                             /* z^(2^200-1) */

    fe_sq(t2, t2); for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);                             /* z^(2^250-1) */

    fe_sq(t1, t1); for (i = 1; i < 5; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);                            /* z^(2^255-21) */
}

/* ─────────────────────── Montgomery merdiveni ───────────────────────
 * A direct translation of the RFC 7748 section 5 pseudocode. Only the u
 * coordinate is computed and v never appears. Addition and doubling use the
 * same formula sequence, so there is no special case or data dependent branch.
 */
static void ladder(fe out, const unsigned char k[32], const fe u)
{
    fe x1, x2, z2, x3, z3;
    fe a, aa, b, bb, e, c, d, da, cb, tmp;
    int64_t takas = 0;
    int t;

    fe_copy(x1, u);
    fe_one(x2);      fe_zero(z2);
    fe_copy(x3, u); fe_one(z3);

    for (t = 254; t >= 0; t--) {
        int64_t kt = (int64_t)((k[t >> 3] >> (t & 7)) & 1);
        takas ^= kt;
        fe_cswap(x2, x3, takas);
        fe_cswap(z2, z3, takas);
        takas = kt;

        fe_add(a, x2, z2);
        fe_sq(aa, a);
        fe_sub(b, x2, z2);
        fe_sq(bb, b);
        fe_sub(e, aa, bb);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);

        fe_add(tmp, da, cb);
        fe_sq(x3, tmp);
        fe_sub(tmp, da, cb);
        fe_sq(tmp, tmp);
        fe_mul(z3, x1, tmp);

        fe_mul(x2, aa, bb);
        fe_carp121665(tmp, e);
        fe_add(tmp, aa, tmp);
        fe_mul(z2, e, tmp);
    }

    fe_cswap(x2, x3, takas);
    fe_cswap(z2, z3, takas);

    fe_invert(tmp, z2);
    fe_mul(out, x2, tmp);
}

/* ───────────────────────── public interface ───────────────────────── */

int crypto25519_version(void) { return CRYPTO25519_VERSION; }

int crypto25519(unsigned char out[32],
                const unsigned char secret[32],
                const unsigned char u[32])
{
    unsigned char k[32];
    fe fu, result;

    memcpy(k, secret, 32);
    /* RFC 7748 decodeScalar25519, the clamping */
    k[0]  &= 248;   /* the scalar is a multiple of 8: the cofactor is neutralised */
    k[31] &= 127;   /* bit 255 is zero */
    k[31] |= 64;    /* bit 254 is one: the ladder always has the same significant length */

    fe_frombytes(fu, u);
    ladder(result, k, fu);
    fe_tobytes(out, result);

    memset(k, 0, sizeof k);
    return 0;
}

/* ──────────────────── the self test ────────────────────
 * The RFC 7748 section 5.2 and 6.1 vectors. The Python loader calls this
 * BEFORE using the library: a miscompiled .dll should not be used at all
 * rather than silently produce wrong keys.
 */

static int equal32(const unsigned char *a, const unsigned char *b)
{
    int i, fark = 0;
    for (i = 0; i < 32; i++) fark |= a[i] ^ b[i];
    return fark == 0;
}

int crypto25519_selftest(void)
{
    /* We assume arithmetic shift is signed (fe_carry, fe_tobytes). The C
     * standard leaves that to the implementation; in practice every compiler
     * shifts arithmetically, but the assumption is not left untested. */
    {
        int64_t eksi = -1;
        if ((eksi >> 22) != -1) return 1;
    }

    /* RFC 7748 section 5.2, first vector */
    {
        static const unsigned char k[32] = {
            0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d,0x3b,0x16,0x15,0x4b,
            0x82,0x46,0x5e,0xdd,0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18,
            0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4 };
        static const unsigned char u[32] = {
            0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,
            0x24,0xb1,0x5f,0x7c,0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,
            0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c };
        static const unsigned char b[32] = {
            0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90,0x8e,0x94,0xea,0x4d,
            0xf2,0x8d,0x08,0x4f,0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7,
            0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52 };
        unsigned char out[32];
        crypto25519(out, k, u);
        if (!equal32(out, b)) return 2;
    }

    /* RFC 7748 section 5.2, second vector */
    {
        static const unsigned char k[32] = {
            0x4b,0x66,0xe9,0xd4,0xd1,0xb4,0x67,0x3c,0x5a,0xd2,0x26,0x91,
            0x95,0x7d,0x6a,0xf5,0xc1,0x1b,0x64,0x21,0xe0,0xea,0x01,0xd4,
            0x2c,0xa4,0x16,0x9e,0x79,0x18,0xba,0x0d };
        static const unsigned char u[32] = {
            0xe5,0x21,0x0f,0x12,0x78,0x68,0x11,0xd3,0xf4,0xb7,0x95,0x9d,
            0x05,0x38,0xae,0x2c,0x31,0xdb,0xe7,0x10,0x6f,0xc0,0x3c,0x3e,
            0xfc,0x4c,0xd5,0x49,0xc7,0x15,0xa4,0x93 };
        static const unsigned char b[32] = {
            0x95,0xcb,0xde,0x94,0x76,0xe8,0x90,0x7d,0x7a,0xad,0xe4,0x5c,
            0xb4,0xb8,0x73,0xf8,0x8b,0x59,0x5a,0x68,0x79,0x9f,0xa1,0x52,
            0xe6,0xf8,0xf7,0x64,0x7a,0xac,0x79,0x57 };
        unsigned char out[32];
        crypto25519(out, k, u);
        if (!equal32(out, b)) return 3;
    }

    /* RFC 7748 section 6.1, Diffie-Hellman: both sides must find the same secret */
    {
        static const unsigned char a_gizli[32] = {
            0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,
            0x51,0xb2,0x66,0x45,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
            0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a };
        static const unsigned char b_gizli[32] = {
            0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,
            0x83,0x80,0x0e,0xe6,0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
            0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb };
        static const unsigned char a_acik[32] = {
            0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,
            0xb4,0x3e,0xf7,0x5a,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
            0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a };
        static const unsigned char b_acik[32] = {
            0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,
            0xec,0xe4,0x35,0x37,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
            0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f };
        static const unsigned char ortak[32] = {
            0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,
            0x80,0x35,0x0f,0x25,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,
            0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42 };
        static const unsigned char taban[32] = { 9 };
        unsigned char out[32];

        crypto25519(out, a_gizli, taban);
        if (!equal32(out, a_acik)) return 4;
        crypto25519(out, b_gizli, taban);
        if (!equal32(out, b_acik)) return 5;
        crypto25519(out, a_gizli, b_acik);
        if (!equal32(out, ortak)) return 6;
        crypto25519(out, b_gizli, a_acik);
        if (!equal32(out, ortak)) return 7;
    }

    return 0;
}
