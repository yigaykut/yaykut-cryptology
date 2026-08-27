/* TIMING THE C CORE, measured from INSIDE C.
 *
 * WHY THIS FILE EXISTS
 *
 * `sidechannel.py` measures the engine from Python, and `docs/audit.md` §5
 * wrote down that this has a limit:
 *
 *     "The C core's timing advantage | Could not be measured | The
 *      measurement is taken from Python and interpreter noise buries the
 *      signal. Proof needs an rdtsc measurement from inside C."
 *
 * A call from Python costs hundreds of nanoseconds, so even if the ladder
 * had a scalar dependent branch it would stay under that noise. Here
 * `__rdtsc()` counts PROCESSOR CYCLES with no interpreter in the way.
 *
 * WHAT IS MEASURED
 *
 * `crypto25519()` is called with two scalar classes:
 *
 *   class A: low Hamming weight (almost all bits 0)
 *   class B: high Hamming weight (almost all bits 1)
 *
 * If the Montgomery ladder is constant time, the two must spend the SAME
 * number of cycles. The ladder does the same work for every bit and the
 * choice goes through masking in `cswap`. An implementation branching on the
 * bit value would separate here obviously.
 *
 * TWO CONTROLS, is the measurement meaningful
 *
 *   POSITIVE  A deliberately data dependent function (looping popcount times).
 *             If it is not caught, the rig is blind and the real result
 *             CANNOT BE READ.
 *   NULL      The same class twice. It gives the noise floor; the real
 *             measurement only means something clearly above that floor.
 *
 * LIMITS, the honest list
 *
 *   * `rdtsc` is affected by frequency scaling and core migration. Samples
 *     are taken A/B/A/B in turn, so a slow drift loads onto both classes
 *     the same way and largely cancels in the t-test.
 *   * What is measured is CYCLE COUNT. Cache access patterns, branch
 *     prediction and memory timing are separate channels and this program
 *     does not see them.
 *   * "No leak found" does not mean "no leak".
 *
 * Build and run: `python -m ccore.c_timing`
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#include "crypto25519.h"

static int SAMPLES = 2000;
static int WARMUP = 200;

/* ─────────────────── the accumulator ─────────────────── */

typedef struct { double n, mean, m2; } Accum;

static void accum_add(Accum *b, double x)
{
    /* Welford: a stable variance in one pass. The naive "sum of squares"
     * method loses significant digits on large values such as cycle counts. */
    b->n += 1.0;
    double d = x - b->mean;
    b->mean += d / b->n;
    b->m2 += d * (x - b->mean);
}

static double variance(const Accum *b)
{
    return b->n > 1.0 ? b->m2 / (b->n - 1.0) : 0.0;
}

/* Welch t: the two samples' variances are not assumed equal. */
static double welch_t(const Accum *a, const Accum *b)
{
    double va = variance(a) / a->n, vb = variance(b) / b->n;
    double denom = sqrt(va + vb);
    return denom > 0.0 ? (a->mean - b->mean) / denom : 0.0;
}

/* ─────────────────── the work being measured ─────────────────── */

static unsigned char out[32];
static const unsigned char base[32] = { 9 };

static void call_x25519(const unsigned char *scalar)
{
    crypto25519(out, scalar, base);
}

/* THE POSITIVE CONTROL: deliberately data dependent. It loops once per set
 * bit in the scalar, so its duration depends on DATA. The rig MUST see it. */
static volatile unsigned long long trap_sum;

static void data_dependent(const unsigned char *scalar)
{
    /* THE DATA DEPENDENCE IS IN THE TRIP COUNT, NOT INSIDE A BRANCH.
     *
     * The first two versions both failed and the second one is instructive:
     *
     *   for (...) if ((scalar[i] >> b) & 1) t += ...;
     *
     * gcc -O2 turned that `if` into a CONDITIONAL MOVE (cmov). The result:
     * a function written specifically to be data dependent compiled to
     * constant time. The measurement gave A 110451 / B 110229 cycles, when
     * A's popcount is 1 and B's is 256. The rig was not blind, there was NO
     * DIFFERENCE TO MEASURE.
     *
     * That is ADR-022's compile audit confirmed from the other direction:
     * the compiler does not preserve the branch structure of the source.
     * The good news is that constant time code is preserved that way, the
     * bad news is that "there is a branch in the source" proves nothing.
     *
     * The fix: tie the loop's TRIP COUNT to the data. The compiler cannot
     * turn that into constant time, because it does not know at compile
     * time how many turns it will take. The accumulator is `volatile`, so
     * it cannot be reduced to a closed form either. */
    unsigned weight = 0;
    for (int i = 0; i < 32; i++)
        for (int b = 0; b < 8; b++)
            weight += (unsigned)((scalar[i] >> b) & 1);

    unsigned long long t = trap_sum;
    unsigned long long rounds = (unsigned long long)weight * 400ull;
    for (unsigned long long i = 0; i < rounds; i++)
        t = t * 6364136223846793005ull + i;   /* no closed form */
    trap_sum = t;
}

/* ─────────────────── the measurement ─────────────────── */

static void measure(const char *name,
                    void (*work)(const unsigned char *),
                    const unsigned char *a, const unsigned char *b,
                    double *t_out, double *diff_out)
{
    Accum ba = {0, 0, 0}, bb = {0, 0, 0};

    for (int i = 0; i < WARMUP; i++) { work(a); work(b); }

    for (int i = 0; i < SAMPLES; i++) {
        /* A and B are measured BACK TO BACK: frequency drift loads onto
         * both the same way and cancels in the difference. Measuring all of
         * A and then all of B would mistake the drift for a signal.
         *
         * THE ORDER ALTERNATES ON EVERY ITERATION and that is NOT
         * decoration. In the first version A was always measured first, so
         * the per iteration overhead (rdtsc serialisation, loop setup)
         * always landed on A. On X25519 at 1.8M cycles that stays
         * irrelevant, but on small functions it buries the signal: the
         * POSITIVE CONTROL failed at |t| = 1.03 and, worse, the sign of the
         * difference came out BACKWARDS (A 9030 / B 3720, when A does less
         * work). So the rig was not blind, it was BIASED. Alternating the
         * order cancels the bias on average. */
        Accum *first = (i & 1) ? &bb : &ba;
        Accum *second = (i & 1) ? &ba : &bb;
        const unsigned char *p_first = (i & 1) ? b : a;
        const unsigned char *p_second = (i & 1) ? a : b;

        unsigned long long t0 = __rdtsc();
        work(p_first);
        unsigned long long t1 = __rdtsc();
        work(p_second);
        unsigned long long t2 = __rdtsc();
        accum_add(first, (double)(t1 - t0));
        accum_add(second, (double)(t2 - t1));
    }

    double t = welch_t(&ba, &bb);
    double diff = ba.mean - bb.mean;
    printf("  %-46s |t| = %8.2f   %+10.1f cycles   (A %.0f / B %.0f)\n",
           name, fabs(t), diff, ba.mean, bb.mean);
    if (t_out) *t_out = fabs(t);
    if (diff_out) *diff_out = diff;
}

int main(int argc, char **argv)
{
    if (argc > 1) SAMPLES = atoi(argv[1]);
    if (argc > 2) WARMUP = atoi(argv[2]);

    unsigned char low[32], high[32], low2[32];

    memset(low, 0x00, 32);  low[0]  = 0x08;
    memset(high, 0xFF, 32);
    memcpy(low2, low, 32);

    if (crypto25519_selftest() != 0) {
        printf("  THE CORE FAILED ITS OWN SELF TEST, no measurement was taken.\n");
        return 2;
    }

    printf("\n  THE C CORE, cycle measurement with rdtsc (%d samples)\n\n", SAMPLES);

    double pos_t, null_t, real_t, real_diff;

    printf("  CONTROLS\n");
    measure("POSITIVE: a deliberately data dependent function", data_dependent,
            low, high, &pos_t, NULL);
    measure("NULL: the same scalar twice", call_x25519,
            low, low2, &null_t, NULL);

    printf("\n  MEASUREMENT\n");
    measure("X25519: low vs high Hamming weight", call_x25519,
            low, high, &real_t, &real_diff);

    printf("\n");
    int failed = 0;

    if (pos_t < 10.0) {
        printf("  X THE POSITIVE CONTROL WAS NOT CAUGHT (|t| = %.2f).\n", pos_t);
        printf("    The rig is blind; the real measurement CANNOT BE READ.\n");
        failed = 1;
    } else {
        printf("  + the rig can see: the data dependent function gives |t| = %.2f\n", pos_t);
    }

    printf("  + noise floor |t| = %.2f\n", null_t);

    /* The threshold is not ABSOLUTE, it is relative to the same run's own
     * floor. `sidechannel.py` learned that lesson on 2026-08-18: on a loaded
     * machine a fixed threshold false alarms, because the floor rises too. */
    double threshold = null_t * 3.0 > 10.0 ? null_t * 3.0 : 10.0;
    if (real_t > threshold) {
        printf("  X X25519 SHOWS SCALAR DEPENDENT TIMING\n");
        printf("    |t| = %.2f, threshold %.2f, difference %.1f cycles.\n",
               real_t, threshold, real_diff);
        failed = 1;
    } else {
        printf("  + X25519 shows NO scalar dependent timing\n");
        printf("    |t| = %.2f, threshold %.2f (3x the floor, or 10).\n",
               real_t, threshold);
    }

    printf("  LIMIT: what is measured is CYCLE COUNT. Cache patterns,\n");
    printf("  branch prediction and memory timing are separate channels and this\n");
    printf("  program does not see them. 'Not found' is not 'absent'.\n");
    return failed;
}
