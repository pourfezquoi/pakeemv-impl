#ifndef PAKE_EMV_BENCHMARK_H
#define PAKE_EMV_BENCHMARK_H

/*
 * Optional measurement support for the existing PAKE-EMV implementation.
 * Enable PAKE_EMV_BENCHMARK=1 in the firmware build used for experiments.
 *
 * DWT is preferred. The explicitly enabled fallback extends the existing
 * core-clock SysTick with overflow IRQs; legacy F6 remains separate.
 * Each measured APDU handler MUST complete in less than 2^32 CPU cycles.
 * The host benchmark enforces a stricter bound on the full APDU round trip,
 * including communication, and rejects a run that could contain a full wrap.
 * Per-handler modulo-32 deltas are accumulated in 64-bit phase totals.
 *
 * Measurement boundary: after the complete T=1 request and its LRC have
 * been received/validated, through APDU dispatch and response construction,
 * ending before the first blocking response send. No receive/send wait is
 * included. Diagnostic F7 commands are never included in phase totals.
 */
#ifndef PAKE_EMV_BENCHMARK
#define PAKE_EMV_BENCHMARK 0
#endif
#ifndef PAKE_EMV_SYSTICK_BENCHMARK
#define PAKE_EMV_SYSTICK_BENCHMARK 0
#endif

#if PAKE_EMV_BENCHMARK

#include <stdint.h>

#define PAKE_BENCHMARK_INS             0xF7u
#define PAKE_BENCHMARK_PACKET_BYTES    40u
#define PAKE_BENCHMARK_DIAGNOSTIC_BYTES 40u
#define PAKE_BENCHMARK_READY           1u
#define PAKE_BENCHMARK_SYSTICK_READY   3u

#define PAKE_BENCHMARK_DIAG_NOT_RESET          0u
#define PAKE_BENCHMARK_DIAG_READY              1u
#define PAKE_BENCHMARK_DIAG_UNKNOWN_CLOCK      2u
#define PAKE_BENCHMARK_DIAG_TRACE_NOT_ENABLED  3u
#define PAKE_BENCHMARK_DIAG_NO_CYCLE_COUNTER   4u
#define PAKE_BENCHMARK_DIAG_COUNTER_NOT_ENABLED 5u
#define PAKE_BENCHMARK_DIAG_COUNTER_STOPPED    6u

#define PAKE_BENCHMARK_DEMCR           0xE000EDFCu
#define PAKE_BENCHMARK_DWT_CTRL        0xE0001000u
#define PAKE_BENCHMARK_DWT_CYCCNT      0xE0001004u
#define PAKE_BENCHMARK_TRCENA          (1u << 24)
#define PAKE_BENCHMARK_NOCYCCNT        (1u << 25)
#define PAKE_BENCHMARK_CYCCNTENA       1u

/* Overrides are used only by the host test; firmware defaults to MMIO. */
#ifndef PAKE_BENCHMARK_READ_REG
#define PAKE_BENCHMARK_READ_REG(address) \
    (*(volatile uint32_t *)(uintptr_t)(address))
#endif
#ifndef PAKE_BENCHMARK_WRITE_REG
#define PAKE_BENCHMARK_WRITE_REG(address, value) \
    (*(volatile uint32_t *)(uintptr_t)(address) = (uint32_t)(value))
#endif

extern uint32_t SystemCoreClock;

typedef struct {
    uint32_t flags;
    uint32_t command_count;
    uint64_t pake_cycles;
    uint64_t certificate_cycles;
    uint64_t establish_key_cycles;
} PakeBenchmarkCounters;

static PakeBenchmarkCounters pake_benchmark_counters;

typedef struct {
    uint32_t reason;
    uint32_t clock_hz;
    uint32_t demcr_before;
    uint32_t demcr_after;
    uint32_t ctrl_before;
    uint32_t ctrl_after;
    uint32_t first_cycle;
    uint32_t second_cycle;
    uint32_t ready_flags;
} PakeBenchmarkDiagnostics;

static PakeBenchmarkDiagnostics pake_benchmark_diagnostics;

#if PAKE_EMV_SYSTICK_BENCHMARK
static void pake_benchmark_drop_measurements(void)
{
    pake_benchmark_counters = (PakeBenchmarkCounters){0};
}

#include "pake_systick_benchmark.h"
#endif

static void pake_benchmark_reset_dwt(void)
{
    volatile uint32_t probe;

    pake_benchmark_counters.flags = 0u;
    pake_benchmark_counters.command_count = 0u;
    pake_benchmark_counters.pake_cycles = 0u;
    pake_benchmark_counters.certificate_cycles = 0u;
    pake_benchmark_counters.establish_key_cycles = 0u;
    pake_benchmark_diagnostics = (PakeBenchmarkDiagnostics){0};
    pake_benchmark_diagnostics.clock_hz = SystemCoreClock;

    if (pake_benchmark_diagnostics.clock_hz == 0u) {
        pake_benchmark_diagnostics.reason = PAKE_BENCHMARK_DIAG_UNKNOWN_CLOCK;
        return;
    }
    pake_benchmark_diagnostics.demcr_before =
        PAKE_BENCHMARK_READ_REG(PAKE_BENCHMARK_DEMCR);
    PAKE_BENCHMARK_WRITE_REG(PAKE_BENCHMARK_DEMCR,
        pake_benchmark_diagnostics.demcr_before |
        PAKE_BENCHMARK_TRCENA);
    pake_benchmark_diagnostics.demcr_after =
        PAKE_BENCHMARK_READ_REG(PAKE_BENCHMARK_DEMCR);
    if ((pake_benchmark_diagnostics.demcr_after & PAKE_BENCHMARK_TRCENA) == 0u) {
        pake_benchmark_diagnostics.reason = PAKE_BENCHMARK_DIAG_TRACE_NOT_ENABLED;
        return;
    }
    /* CTRL is sampled after trace enable, before changing CYCCNTENA. */
    pake_benchmark_diagnostics.ctrl_before =
        PAKE_BENCHMARK_READ_REG(PAKE_BENCHMARK_DWT_CTRL);
    if ((pake_benchmark_diagnostics.ctrl_before & PAKE_BENCHMARK_NOCYCCNT) != 0u) {
        pake_benchmark_diagnostics.reason = PAKE_BENCHMARK_DIAG_NO_CYCLE_COUNTER;
        return;
    }
    PAKE_BENCHMARK_WRITE_REG(PAKE_BENCHMARK_DWT_CTRL,
        pake_benchmark_diagnostics.ctrl_before |
        PAKE_BENCHMARK_CYCCNTENA);
    pake_benchmark_diagnostics.ctrl_after =
        PAKE_BENCHMARK_READ_REG(PAKE_BENCHMARK_DWT_CTRL);
    if ((pake_benchmark_diagnostics.ctrl_after & PAKE_BENCHMARK_CYCCNTENA) == 0u) {
        pake_benchmark_diagnostics.reason = PAKE_BENCHMARK_DIAG_COUNTER_NOT_ENABLED;
        return;
    }

    /* Do not reset the hardware counter: only our session totals are reset. */
    pake_benchmark_diagnostics.first_cycle =
        PAKE_BENCHMARK_READ_REG(PAKE_BENCHMARK_DWT_CYCCNT);
    for (probe = 0u; probe < 32u; ++probe) {
        /* Volatile loop ensures real instructions occur between reads. */
    }
    pake_benchmark_diagnostics.second_cycle =
        PAKE_BENCHMARK_READ_REG(PAKE_BENCHMARK_DWT_CYCCNT);
    if (pake_benchmark_diagnostics.second_cycle != pake_benchmark_diagnostics.first_cycle) {
        pake_benchmark_counters.flags = PAKE_BENCHMARK_READY;
        pake_benchmark_diagnostics.ready_flags = PAKE_BENCHMARK_READY;
        pake_benchmark_diagnostics.reason = PAKE_BENCHMARK_DIAG_READY;
    } else {
        pake_benchmark_diagnostics.reason = PAKE_BENCHMARK_DIAG_COUNTER_STOPPED;
    }
}

static void pake_benchmark_reset(void)
{
#if PAKE_EMV_SYSTICK_BENCHMARK
    pake_systick_stop();
    pake_systick_wraps = 0u;
    pake_systick_diagnostics = (PakeSystickDiagnostics){0};
#endif
    pake_benchmark_reset_dwt();
#if PAKE_EMV_SYSTICK_BENCHMARK
    if (pake_benchmark_counters.flags != PAKE_BENCHMARK_READY) {
        pake_systick_start();
    }
#endif
}

static uint32_t pake_benchmark_now(void)
{
#if PAKE_EMV_SYSTICK_BENCHMARK
    if (pake_benchmark_counters.flags == PAKE_BENCHMARK_SYSTICK_READY) {
        return pake_systick_now();
    }
#endif
    if (pake_benchmark_counters.flags != PAKE_BENCHMARK_READY) return 0u;
    return PAKE_BENCHMARK_READ_REG(PAKE_BENCHMARK_DWT_CYCCNT);
}

static void pake_benchmark_record(uint8_t ins, uint32_t start, uint32_t end)
{
    uint64_t *phase;
    if (pake_benchmark_counters.flags != PAKE_BENCHMARK_READY
#if PAKE_EMV_SYSTICK_BENCHMARK
        && pake_benchmark_counters.flags != PAKE_BENCHMARK_SYSTICK_READY
#endif
        ) return;
    switch (ins) {
        case 0xC1u: phase = &pake_benchmark_counters.pake_cycles; break;
        case 0xB2u: phase = &pake_benchmark_counters.certificate_cycles; break;
        case 0x50u: phase = &pake_benchmark_counters.establish_key_cycles; break;
        default: return;
    }
    *phase += (uint32_t)(end - start);
    ++pake_benchmark_counters.command_count;
}

static void pake_benchmark_put_u32(unsigned char *dst, uint32_t value)
{
    dst[0] = (unsigned char)(value >> 24);
    dst[1] = (unsigned char)(value >> 16);
    dst[2] = (unsigned char)(value >> 8);
    dst[3] = (unsigned char)value;
}

static void pake_benchmark_put_u64(unsigned char *dst, uint64_t value)
{
    pake_benchmark_put_u32(dst, (uint32_t)(value >> 32));
    pake_benchmark_put_u32(dst + 4, (uint32_t)value);
}

/*
 * F7 P1=0 resets/enables then returns a snapshot; P1=1 only reads.
 * Both use P2=0 and a five-byte APDU. Firmware appends SW=9000.
 * The ready flag is zero if the counter is absent, stopped, or clock unknown.
 *
 *   0..3   ASCII "PEB1"
 *   4..7   flags (DWT ready = 1; SysTick IRQ ready = 3; unavailable = 0)
 *   8..11  SystemCoreClock in Hz
 *  12..15  measured core APDU command count
 *  16..23  C1/PAKE handler cycles
 *  24..31  B2/certificate handler cycles
 *  32..39  50/establish-key handler cycles
 *
 * All numeric fields are unsigned big-endian. This is a versioned packet,
 * not a TLV; keep legacy F6 and its format unchanged.
 */
static unsigned short pake_benchmark_snapshot(unsigned char *out)
{
    out[0] = 'P'; out[1] = 'E'; out[2] = 'B'; out[3] = '1';
    pake_benchmark_put_u32(out + 4, pake_benchmark_counters.flags);
    pake_benchmark_put_u32(out + 8, SystemCoreClock);
    pake_benchmark_put_u32(out + 12, pake_benchmark_counters.command_count);
    pake_benchmark_put_u64(out + 16, pake_benchmark_counters.pake_cycles);
    pake_benchmark_put_u64(out + 24, pake_benchmark_counters.certificate_cycles);
    pake_benchmark_put_u64(out + 32, pake_benchmark_counters.establish_key_cycles);
    return PAKE_BENCHMARK_PACKET_BYTES;
}

/*
 * F7 P1=2 returns the cached result of the most recent reset, without MMIO.
 * No reset has reason 0; ready has reason 1; failures have reasons 2..6 above.
 * Fields not reached by an early-return path remain zero.
 *
 *   0..3   ASCII "PED1"
 *   4..7   initialization reason
 *   8..11  clock frequency at reset, in Hz
 *  12..15  DEMCR before trace enable
 *  16..19  DEMCR readback after trace enable
 *  20..23  DWT CTRL after trace enable, before CYCCNT enable
 *  24..27  DWT CTRL readback after CYCCNT enable
 *  28..31  first CYCCNT probe
 *  32..35  second CYCCNT probe
 *  36..39  ready flags from reset (same meaning as PEB1)
 *
 * All fields are unsigned big-endian. Firmware appends SW=9000.
 */
static unsigned short pake_benchmark_diagnostic_snapshot(unsigned char *out)
{
    out[0] = 'P'; out[1] = 'E'; out[2] = 'D'; out[3] = '1';
    pake_benchmark_put_u32(out + 4, pake_benchmark_diagnostics.reason);
    pake_benchmark_put_u32(out + 8, pake_benchmark_diagnostics.clock_hz);
    pake_benchmark_put_u32(out + 12, pake_benchmark_diagnostics.demcr_before);
    pake_benchmark_put_u32(out + 16, pake_benchmark_diagnostics.demcr_after);
    pake_benchmark_put_u32(out + 20, pake_benchmark_diagnostics.ctrl_before);
    pake_benchmark_put_u32(out + 24, pake_benchmark_diagnostics.ctrl_after);
    pake_benchmark_put_u32(out + 28, pake_benchmark_diagnostics.first_cycle);
    pake_benchmark_put_u32(out + 32, pake_benchmark_diagnostics.second_cycle);
    pake_benchmark_put_u32(out + 36, pake_benchmark_diagnostics.ready_flags);
    return PAKE_BENCHMARK_DIAGNOSTIC_BYTES;
}

#if PAKE_EMV_SYSTICK_BENCHMARK
/* Cached SysTick diagnostics; all numeric fields are unsigned big-endian. */
static unsigned short pake_benchmark_systick_snapshot(unsigned char *out)
{
    out[0] = 'P'; out[1] = 'E'; out[2] = 'S'; out[3] = '1';
    pake_benchmark_put_u32(out + 4, pake_systick_diagnostics.reason);
    pake_benchmark_put_u32(out + 8, pake_systick_diagnostics.clock_hz);
    pake_benchmark_put_u32(out + 12, pake_systick_diagnostics.ctrl);
    pake_benchmark_put_u32(out + 16, pake_systick_diagnostics.load);
    pake_benchmark_put_u32(out + 20, pake_systick_diagnostics.value);
    pake_benchmark_put_u32(out + 24, pake_systick_diagnostics.icsr);
    pake_benchmark_put_u32(out + 28, pake_systick_diagnostics.masks);
    pake_benchmark_put_u32(out + 32, pake_systick_diagnostics.wraps);
    pake_benchmark_put_u32(out + 36, pake_systick_diagnostics.flags);
    return PAKE_BENCHMARK_DIAGNOSTIC_BYTES;
}
#endif

#endif /* PAKE_EMV_BENCHMARK */
#endif /* PAKE_EMV_BENCHMARK_H */
