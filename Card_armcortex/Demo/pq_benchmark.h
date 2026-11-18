#ifndef PQ_EMV_BENCHMARK_H
#define PQ_EMV_BENCHMARK_H

/*
 * Share the exact DWT/SysTick implementation used by the PAKE experiment.
 * The PAKE_EMV_* build switches intentionally select that shared engine.
 * PQ negotiation uses CA; the common packet's first phase slot uses C1.
 * B2 and 50 retain their original slots. PIN verification (20) is reported
 * separately; diagnostics and key proofs are excluded from both totals.
 */
#include "../../Card_pakebdh/Demo/pake_benchmark.h"

#if PAKE_EMV_BENCHMARK
static uint64_t pq_benchmark_pin_cycles;
static uint32_t pq_benchmark_pin_count;

static void pq_benchmark_clear_pin(void)
{
    pq_benchmark_pin_cycles = 0u;
    pq_benchmark_pin_count = 0u;
}

static void pq_benchmark_reset(void)
{
    pq_benchmark_clear_pin();
    pake_benchmark_reset();
}

static void pq_benchmark_record(uint8_t ins, uint32_t start, uint32_t end)
{
    if (pake_benchmark_counters.flags != PAKE_BENCHMARK_READY &&
        pake_benchmark_counters.flags != PAKE_BENCHMARK_SYSTICK_READY) {
        pq_benchmark_clear_pin();
        return;
    }
    if (ins == 0x20u) {
        pq_benchmark_pin_cycles += (uint32_t)(end - start);
        ++pq_benchmark_pin_count;
        return;
    }
    if (ins == 0xCAu) ins = 0xC1u;
    else if (ins != 0xB2u && ins != 0x50u) return;
    pake_benchmark_record(ins, start, end);
}

/*
 * F7 P1=4: separate PIN processing, using the same timer and reset as PEB1.
 * Payload: PQP1, flags u32, clock Hz u32, completed PIN APDUs u32, cycles u64.
 * Numeric fields are big-endian. Serialize cached state without any MMIO.
 * Failed PIN attempts are counted; the host excludes unsuccessful sessions.
 */
static unsigned short pq_benchmark_pin_snapshot(unsigned char *out)
{
    if (pake_benchmark_counters.flags != PAKE_BENCHMARK_READY &&
        pake_benchmark_counters.flags != PAKE_BENCHMARK_SYSTICK_READY) {
        pq_benchmark_clear_pin();
    }
    out[0] = 'P'; out[1] = 'Q'; out[2] = 'P'; out[3] = '1';
    pake_benchmark_put_u32(out + 4, pake_benchmark_counters.flags);
    pake_benchmark_put_u32(out + 8, SystemCoreClock);
    pake_benchmark_put_u32(out + 12, pq_benchmark_pin_count);
    pake_benchmark_put_u64(out + 16, pq_benchmark_pin_cycles);
    return 24;
}
#endif

#endif
