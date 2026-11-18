#ifndef PAKE_SYSTICK_BENCHMARK_H
#define PAKE_SYSTICK_BENCHMARK_H

/*
 * Optional fallback for this audited standalone protocol profile. SysTick runs
 * at the core clock and retains its existing maximum reload value. Overflow
 * interrupts must be serviced within one 2^24-cycle period (159.8 ms at 105 MHz).
 * The successful C1/B2/50 path does not mask IRQs or call flash-write routines.
 * Re-audit that assumption when changing firmware or vendor libraries.
 */
#define PAKE_SYSTICK_CTRL       0xE000E010u
#define PAKE_SYSTICK_LOAD       0xE000E014u
#define PAKE_SYSTICK_VAL        0xE000E018u
#define PAKE_SYSTICK_ICSR       0xE000ED04u
#define PAKE_SYSTICK_SHPR3      0xE000ED20u
#define PAKE_SYSTICK_MASK       0x00FFFFFFu
#define PAKE_SYSTICK_TICKINT    2u
#define PAKE_SYSTICK_PENDSET    (1u << 26)
#define PAKE_SYSTICK_PENDCLR    (1u << 25)
#define PAKE_SYSTICK_PRIORITY   0xFF000000u
#define PAKE_SYSTICK_RETRIES    8u
#define PAKE_SYSTICK_IRQ_PROBES 1024u

#ifndef PAKE_BENCHMARK_READ_MASKS
static uint32_t pake_systick_interrupt_masks(void)
{
    uint32_t primask, faultmask, basepri;
    __asm volatile ("mrs %0, primask" : "=r" (primask));
    __asm volatile ("mrs %0, faultmask" : "=r" (faultmask));
    __asm volatile ("mrs %0, basepri" : "=r" (basepri));
    return (primask & 1u) | ((faultmask & 1u) << 1) | ((basepri & 255u) << 8);
}
#define PAKE_BENCHMARK_READ_MASKS() pake_systick_interrupt_masks()
#endif

#ifndef PAKE_BENCHMARK_BARRIER
#if defined(__arm__) || defined(__thumb__)
#define PAKE_BENCHMARK_BARRIER() __asm volatile ("dsb sy\n\tisb sy" ::: "memory")
#else
#define PAKE_BENCHMARK_BARRIER() ((void)0)
#endif
#endif

typedef struct {
    uint32_t reason, clock_hz, ctrl, load, value, icsr, masks, wraps, flags;
} PakeSystickDiagnostics;

static PakeSystickDiagnostics pake_systick_diagnostics;
static volatile uint32_t pake_systick_wraps;
static volatile uint32_t pake_systick_owned;
static uint32_t pake_systick_saved_priority;
static uint32_t pake_systick_saved_ctrl;

/* Called only by the existing SysTick vector through the production wrapper. */
static unsigned char pake_systick_interrupt(void)
{
    if (!pake_systick_owned) return 0u;
    ++pake_systick_wraps;
    return 1u;
}

static void pake_systick_stop(void)
{
    uint32_t current;
    if (!pake_systick_owned) return;
    /* Restore only the IRQ-enable bit and priority byte that we own. */
    current = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_CTRL);
    PAKE_BENCHMARK_WRITE_REG(PAKE_SYSTICK_CTRL,
        (current & 5u) | (pake_systick_saved_ctrl & PAKE_SYSTICK_TICKINT));
    PAKE_BENCHMARK_WRITE_REG(PAKE_SYSTICK_ICSR, PAKE_SYSTICK_PENDCLR);
    pake_systick_owned = 0u;
    current = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_SHPR3);
    PAKE_BENCHMARK_WRITE_REG(PAKE_SYSTICK_SHPR3,
        (current & ~PAKE_SYSTICK_PRIORITY) | pake_systick_saved_priority);
    PAKE_BENCHMARK_BARRIER();
}

static void pake_systick_fail(uint32_t reason)
{
    pake_systick_diagnostics.reason = reason;
    pake_systick_diagnostics.flags = 0u;
    pake_systick_diagnostics.wraps = pake_systick_wraps;
    pake_benchmark_drop_measurements();
    pake_systick_stop();
}

/* Snapshot a coherent epoch without suppressing any interrupts. */
static unsigned char pake_systick_sample(uint32_t *timestamp)
{
    uint32_t attempt;
    for (attempt = 0u; attempt < PAKE_SYSTICK_RETRIES; ++attempt) {
        uint32_t before = pake_systick_wraps;
        uint32_t pending_before = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_ICSR);
        uint32_t value = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_VAL) & PAKE_SYSTICK_MASK;
        uint32_t pending_after = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_ICSR);
        uint32_t after = pake_systick_wraps;
        pake_systick_diagnostics.value = value;
        pake_systick_diagnostics.icsr = pending_after;
        pake_systick_diagnostics.wraps = after;
        if (before == after &&
            ((pending_before ^ pending_after) & PAKE_SYSTICK_PENDSET) == 0u) {
            uint32_t epoch = before + ((pending_after & PAKE_SYSTICK_PENDSET) != 0u);
            /* The IRQ is asserted on 1 -> 0, so low bits wrap at VAL == 0. */
            *timestamp = (epoch << 24) + ((0u - value) & PAKE_SYSTICK_MASK);
            return 1u;
        }
    }
    return 0u;
}

static unsigned char pake_systick_configuration_valid(void)
{
    uint32_t priority;
    pake_systick_diagnostics.ctrl = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_CTRL);
    pake_systick_diagnostics.load = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_LOAD);
    pake_systick_diagnostics.masks = PAKE_BENCHMARK_READ_MASKS();
    priority = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_SHPR3);
    return (pake_systick_diagnostics.ctrl & 7u) == 7u &&
        pake_systick_diagnostics.load == PAKE_SYSTICK_MASK &&
        (pake_systick_diagnostics.masks & 3u) == 0u &&
        (priority & PAKE_SYSTICK_PRIORITY) == 0u &&
        SystemCoreClock == pake_systick_diagnostics.clock_hz;
}

static uint32_t pake_systick_now(void)
{
    uint32_t timestamp;
    if (!pake_systick_owned || !pake_systick_configuration_valid()) {
        pake_systick_fail(7u);
        return 0u;
    }
    if (!pake_systick_sample(&timestamp)) {
        pake_systick_fail(8u);
        return 0u;
    }
    return timestamp;
}

static void pake_systick_start(void)
{
    uint32_t first, second, priority, initial_wraps, timestamp;
    volatile uint32_t probe;
    pake_systick_diagnostics.clock_hz = SystemCoreClock;
    if (SystemCoreClock == 0u) {
        pake_systick_fail(2u);
        return;
    }
    pake_systick_diagnostics.masks = PAKE_BENCHMARK_READ_MASKS();
    if ((pake_systick_diagnostics.masks & 3u) != 0u) {
        pake_systick_fail(4u);
        return;
    }
    pake_systick_diagnostics.ctrl = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_CTRL);
    pake_systick_diagnostics.load = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_LOAD);
    pake_systick_diagnostics.value = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_VAL);
    pake_systick_diagnostics.icsr = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_ICSR);
    if ((pake_systick_diagnostics.ctrl & 7u) != 5u ||
        pake_systick_diagnostics.load != PAKE_SYSTICK_MASK ||
        (pake_systick_diagnostics.icsr & PAKE_SYSTICK_PENDSET) != 0u) {
        pake_systick_fail(3u);
        return;
    }
    pake_systick_saved_ctrl = pake_systick_diagnostics.ctrl;
    priority = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_SHPR3);
    pake_systick_saved_priority = priority & PAKE_SYSTICK_PRIORITY;
    pake_systick_wraps = 0u;
    pake_systick_owned = 1u;
    PAKE_BENCHMARK_WRITE_REG(PAKE_SYSTICK_SHPR3, priority & ~PAKE_SYSTICK_PRIORITY);
    PAKE_BENCHMARK_WRITE_REG(PAKE_SYSTICK_CTRL,
        (pake_systick_saved_ctrl & 5u) | PAKE_SYSTICK_TICKINT);
    PAKE_BENCHMARK_BARRIER();
    if (!pake_systick_configuration_valid()) {
        pake_systick_fail(3u);
        return;
    }
    first = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_VAL) & PAKE_SYSTICK_MASK;
    for (probe = 0u; probe < 32u; ++probe) { /* Counter movement only, not a time estimate. */ }
    second = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_VAL) & PAKE_SYSTICK_MASK;
    pake_systick_diagnostics.value = second;
    if (first == second) {
        pake_systick_fail(5u);
        return;
    }
    initial_wraps = pake_systick_wraps;
    /* A software-pended test verifies this image's actual SysTick vector. Its
     * extra epoch occurs before measurement and cancels in all deltas. */
    PAKE_BENCHMARK_WRITE_REG(PAKE_SYSTICK_ICSR, PAKE_SYSTICK_PENDSET);
    PAKE_BENCHMARK_BARRIER();
    for (probe = 0u; probe < PAKE_SYSTICK_IRQ_PROBES; ++probe) {
        pake_systick_diagnostics.icsr = PAKE_BENCHMARK_READ_REG(PAKE_SYSTICK_ICSR);
        if (pake_systick_wraps != initial_wraps &&
            (pake_systick_diagnostics.icsr & PAKE_SYSTICK_PENDSET) == 0u) break;
    }
    if (probe == PAKE_SYSTICK_IRQ_PROBES) {
        pake_systick_fail(6u);
        return;
    }
    if (!pake_systick_configuration_valid()) {
        pake_systick_fail(7u);
        return;
    }
    if (!pake_systick_sample(&timestamp)) {
        pake_systick_fail(8u);
        return;
    }
    pake_systick_diagnostics.reason = 1u;
    pake_systick_diagnostics.flags = PAKE_BENCHMARK_SYSTICK_READY;
    pake_benchmark_counters.flags = PAKE_BENCHMARK_SYSTICK_READY;
}

#endif /* PAKE_SYSTICK_BENCHMARK_H */
