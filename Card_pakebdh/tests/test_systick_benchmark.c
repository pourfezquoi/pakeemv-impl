/* Host-only correctness fixtures; these do not measure card performance. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t read_register(uint32_t address);
static void write_register(uint32_t address, uint32_t value);
static uint32_t interrupt_masks(void);
#define PAKE_EMV_BENCHMARK 1
#define PAKE_EMV_SYSTICK_BENCHMARK 1
#define PAKE_BENCHMARK_READ_REG(address) read_register(address)
#define PAKE_BENCHMARK_WRITE_REG(address, value) write_register(address, value)
#define PAKE_BENCHMARK_READ_MASKS() interrupt_masks()
#include "../Demo/pake_benchmark.h"

uint32_t SystemCoreClock = 105000000u;
static uint32_t demcr, dwt_ctrl, dwt_value;
static uint32_t ctrl, load, value, icsr, shpr3, masks;
static unsigned int reads, writes, systick_reads, systick_writes;
static unsigned int value_step, deliver_irq, reject_irq_enable;

typedef struct {
    uint32_t address, result, set_wraps;
    unsigned char change_wraps;
} ReadEvent;
static ReadEvent events[64];
static unsigned int event_count, event_offset;

static uint32_t interrupt_masks(void) { return masks; }

static void service_irq(void)
{
    if (deliver_irq && (icsr & PAKE_SYSTICK_PENDSET) && (ctrl & 7u) == 7u &&
        (masks & 3u) == 0u && (shpr3 & PAKE_SYSTICK_PRIORITY) == 0u) {
        icsr &= ~PAKE_SYSTICK_PENDSET;
        assert(pake_systick_interrupt() == 1u);
    }
}

static uint32_t read_register(uint32_t address)
{
    uint32_t result;
    ++reads;
    if (address == PAKE_SYSTICK_ICSR || address == PAKE_SYSTICK_VAL ||
        address == PAKE_SYSTICK_CTRL || address == PAKE_SYSTICK_LOAD ||
        address == PAKE_SYSTICK_SHPR3) ++systick_reads;
    if (event_offset < event_count &&
        (address == PAKE_SYSTICK_ICSR || address == PAKE_SYSTICK_VAL)) {
        ReadEvent event = events[event_offset++];
        assert(event.address == address);
        if (event.change_wraps) pake_systick_wraps = event.set_wraps;
        return event.result;
    }
    switch (address) {
        case PAKE_BENCHMARK_DEMCR: return demcr;
        case PAKE_BENCHMARK_DWT_CTRL: return dwt_ctrl;
        case PAKE_BENCHMARK_DWT_CYCCNT: return ++dwt_value;
        case PAKE_SYSTICK_CTRL: return ctrl;
        case PAKE_SYSTICK_LOAD: return load;
        case PAKE_SYSTICK_ICSR: return icsr;
        case PAKE_SYSTICK_SHPR3: return shpr3;
        case PAKE_SYSTICK_VAL:
            result = value;
            if (value_step && (ctrl & 5u) == 5u) {
                if (value == 0u) value = PAKE_SYSTICK_MASK;
                else {
                    --value;
                    if (value == 0u && (ctrl & PAKE_SYSTICK_TICKINT)) {
                        icsr |= PAKE_SYSTICK_PENDSET;
                        service_irq();
                    }
                }
            }
            return result;
        default: assert(0); return 0u;
    }
}

static void write_register(uint32_t address, uint32_t next)
{
    ++writes;
    switch (address) {
        case PAKE_BENCHMARK_DEMCR: demcr = next; return;
        case PAKE_BENCHMARK_DWT_CTRL: dwt_ctrl = next; return;
        case PAKE_SYSTICK_CTRL:
            ++systick_writes;
            ctrl = reject_irq_enable ? next & ~PAKE_SYSTICK_TICKINT : next;
            return;
        case PAKE_SYSTICK_SHPR3: ++systick_writes; shpr3 = next; return;
        case PAKE_SYSTICK_ICSR:
            ++systick_writes;
            assert(next == PAKE_SYSTICK_PENDSET || next == PAKE_SYSTICK_PENDCLR);
            if (next == PAKE_SYSTICK_PENDSET) {
                icsr |= PAKE_SYSTICK_PENDSET;
                service_irq();
            } else icsr &= ~PAKE_SYSTICK_PENDSET;
            return;
        /* The fallback must never reset the live timer or change its reload. */
        case PAKE_SYSTICK_LOAD:
        case PAKE_SYSTICK_VAL:
        default: assert(0);
    }
}

static void configure(void)
{
    event_count = event_offset = 0u;
    pake_systick_stop();
    SystemCoreClock = 105000000u;
    demcr = dwt_value = 0u;
    dwt_ctrl = PAKE_BENCHMARK_NOCYCCNT;
    ctrl = 5u; load = PAKE_SYSTICK_MASK; value = 0x123456u;
    icsr = masks = 0u; shpr3 = 0xA1B2C3D4u;
    value_step = deliver_irq = 1u;
    reject_irq_enable = 0u;
    reads = writes = systick_reads = systick_writes = 0u;
}

static uint32_t u32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | p[3];
}

static void seed_measurements(void)
{
    pake_benchmark_counters.command_count = 7u;
    pake_benchmark_counters.pake_cycles = 11u;
    pake_benchmark_counters.certificate_cycles = 12u;
    pake_benchmark_counters.establish_key_cycles = 13u;
}

static void unavailable(uint32_t reason)
{
    unsigned char bytes[40];
    unsigned int reads_before = reads, writes_before = writes;
    assert(pake_benchmark_counters.flags == 0u);
    assert(pake_benchmark_counters.command_count == 0u);
    assert(pake_benchmark_counters.pake_cycles == 0u);
    assert(pake_benchmark_counters.certificate_cycles == 0u);
    assert(pake_benchmark_counters.establish_key_cycles == 0u);
    assert(pake_systick_owned == 0u);
    assert(pake_systick_diagnostics.reason == reason);
    assert(pake_systick_diagnostics.flags == 0u);
    pake_benchmark_record(0xC1u, 1u, 9u);
    assert(pake_benchmark_counters.command_count == 0u);
    assert(pake_benchmark_systick_snapshot(bytes) == 40u);
    assert(memcmp(bytes, "PES1", 4u) == 0);
    assert(u32(bytes + 4) == reason && u32(bytes + 36) == 0u);
    assert(reads == reads_before && writes == writes_before);
}

static void test_not_attempted_and_dwt_preferred(void)
{
    unsigned char packet[40];
    const unsigned char initial[40] = {'P', 'E', 'S', '1'};
    assert(pake_benchmark_systick_snapshot(packet) == 40u);
    assert(memcmp(packet, initial, sizeof(initial)) == 0);
    assert(reads == 0u && writes == 0u);
    configure();
    dwt_ctrl = 0u;
    pake_benchmark_reset();
    assert(pake_benchmark_counters.flags == 1u);
    assert(pake_systick_owned == 0u && pake_systick_diagnostics.reason == 0u);
    assert(systick_reads == 0u && systick_writes == 0u);
}

static void test_fallback_readiness_and_cached_packets(void)
{
    unsigned char diagnostic[40], counters[40], dwt[40];
    unsigned int reads_before, writes_before;
    uint32_t start, end;
    configure(); masks = 0x8000u; /* BASEPRI cannot mask priority zero. */
    pake_benchmark_reset();
    assert(pake_benchmark_counters.flags == 3u && pake_systick_owned == 1u);
    assert(pake_systick_diagnostics.reason == 1u && pake_systick_wraps >= 1u);
    assert(ctrl == 7u && shpr3 == 0x00B2C3D4u && load == PAKE_SYSTICK_MASK);
    pake_benchmark_diagnostic_snapshot(dwt);
    assert(u32(dwt + 4) == 4u && u32(dwt + 36) == 0u);
    start = pake_benchmark_now(); value -= 100u; end = pake_benchmark_now();
    pake_benchmark_record(0xC1u, start, end);
    assert(pake_benchmark_counters.command_count == 1u);
    assert(pake_benchmark_counters.pake_cycles == 101u);
    reads_before = reads; writes_before = writes;
    pake_benchmark_snapshot(counters);
    pake_benchmark_systick_snapshot(diagnostic);
    assert(u32(counters + 4) == 3u && u32(counters + 12) == 1u);
    assert(u32(diagnostic + 4) == 1u && u32(diagnostic + 8) == 105000000u);
    assert(u32(diagnostic + 12) == 7u && u32(diagnostic + 16) == PAKE_SYSTICK_MASK);
    assert(u32(diagnostic + 28) == 0x8000u && u32(diagnostic + 36) == 3u);
    assert(reads == reads_before && writes == writes_before);
    assert(pake_systick_owned == 1u); /* Snapshots do not stop the running backend. */
    assert(pake_systick_wraps >= 1u);
}

static void test_initialization_failures_restore_ownership(void)
{
    configure(); SystemCoreClock = 0u; pake_benchmark_reset(); unavailable(2u);
    assert(reads == 0u && writes == 0u && pake_systick_diagnostics.wraps == 0u);
    configure(); masks = 1u; pake_benchmark_reset(); unavailable(4u);
    assert(systick_reads == 0u && systick_writes == 0u && masks == 1u);
    configure(); masks = 2u; pake_benchmark_reset(); unavailable(4u);
    assert(systick_reads == 0u && systick_writes == 0u && masks == 2u);
    configure(); load = 12u; pake_benchmark_reset(); unavailable(3u);
    assert(systick_writes == 0u && load == 12u);
    configure(); ctrl = 7u; pake_benchmark_reset(); unavailable(3u);
    assert(systick_writes == 0u && ctrl == 7u); /* Another owner retains its IRQ. */
    configure(); reject_irq_enable = 1u; pake_benchmark_reset(); unavailable(3u);
    assert(ctrl == 5u && shpr3 == 0xA1B2C3D4u);
    configure(); value_step = 0u; pake_benchmark_reset(); unavailable(5u);
    assert(ctrl == 5u && shpr3 == 0xA1B2C3D4u);
    configure(); deliver_irq = 0u; pake_benchmark_reset(); unavailable(6u);
    assert((icsr & PAKE_SYSTICK_PENDSET) == 0u);
    assert((pake_systick_diagnostics.icsr & PAKE_SYSTICK_PENDSET) != 0u);
    assert(ctrl == 5u && shpr3 == 0xA1B2C3D4u);
}

static void event(uint32_t address, uint32_t result, uint32_t wrap, int change)
{
    assert(event_count < sizeof(events) / sizeof(events[0]));
    events[event_count++] = (ReadEvent){address, result, wrap, (unsigned char)change};
}

static void sample_events(uint32_t pending_a, uint32_t val, uint32_t pending_b,
                          uint32_t changed_wrap, int change)
{
    event(PAKE_SYSTICK_ICSR, pending_a, 0u, 0);
    event(PAKE_SYSTICK_VAL, val, 0u, 0);
    event(PAKE_SYSTICK_ICSR, pending_b, changed_wrap, change);
}

static uint32_t scripted_sample(uint32_t wraps)
{
    uint32_t timestamp = 0u;
    pake_systick_wraps = wraps;
    assert(pake_systick_sample(&timestamp) == 1u);
    assert(event_offset == event_count);
    event_count = event_offset = 0u;
    return timestamp;
}

static void test_pending_wraps_isr_races_and_modulo32(void)
{
    uint32_t pending, delivered, last, next;
    configure();
    sample_events(0u, PAKE_SYSTICK_MASK - 4u, 0u, 0u, 0);
    assert(scripted_sample(7u) == 0x07000005u);
    sample_events(PAKE_SYSTICK_PENDSET, PAKE_SYSTICK_MASK - 2u,
                  PAKE_SYSTICK_PENDSET, 0u, 0);
    pending = scripted_sample(7u);
    sample_events(0u, PAKE_SYSTICK_MASK - 2u, 0u, 0u, 0);
    delivered = scripted_sample(8u);
    assert(pending == delivered && pending == 0x08000003u);
    sample_events(PAKE_SYSTICK_PENDSET, 0u, PAKE_SYSTICK_PENDSET, 0u, 0);
    assert(scripted_sample(7u) == 0x08000000u);
    sample_events(0u, 0u, PAKE_SYSTICK_PENDSET, 0u, 0);
    sample_events(PAKE_SYSTICK_PENDSET, PAKE_SYSTICK_MASK - 1u,
                  PAKE_SYSTICK_PENDSET, 0u, 0);
    assert(scripted_sample(7u) == 0x08000002u);
    sample_events(PAKE_SYSTICK_PENDSET, PAKE_SYSTICK_MASK - 1u, 0u, 8u, 1);
    sample_events(0u, PAKE_SYSTICK_MASK - 3u, 0u, 0u, 0);
    assert(scripted_sample(7u) == 0x08000004u);
    sample_events(0u, 1u, 0u, 0u, 0); last = scripted_sample(255u);
    sample_events(PAKE_SYSTICK_PENDSET, 0u, PAKE_SYSTICK_PENDSET, 0u, 0);
    next = scripted_sample(255u);
    assert(last == UINT32_MAX && next == 0u && (uint32_t)(next - last) == 1u);
}

static void test_runtime_failure_invalidates_all_phases_and_restores_scoped_fields(void)
{
    unsigned int kind, attempt;
    for (kind = 0u; kind < 5u; ++kind) {
        configure(); pake_benchmark_reset(); seed_measurements();
        if (kind == 0u) ctrl = 3u;
        else if (kind == 1u) load = 7u;
        else if (kind == 2u) masks = 1u;
        else if (kind == 3u) SystemCoreClock = 96000000u;
        else shpr3 = 0xFF112233u;
        if (kind == 0u) shpr3 = 0x00112233u;
        assert(pake_benchmark_now() == 0u); unavailable(7u);
        assert((ctrl & PAKE_SYSTICK_TICKINT) == 0u);
        if (kind == 0u) assert(ctrl == 1u && shpr3 == 0xA1112233u);
        if (kind == 2u) assert(masks == 1u);
    }
    configure(); pake_benchmark_reset(); seed_measurements();
    for (attempt = 0u; attempt < PAKE_SYSTICK_RETRIES; ++attempt) {
        sample_events(0u, 100u, PAKE_SYSTICK_PENDSET, 0u, 0);
    }
    assert(pake_benchmark_now() == 0u); unavailable(8u);
    assert(event_offset == event_count);
    event_count = event_offset = 0u;
    configure(); pake_benchmark_reset();
    pake_systick_wraps = 17u;
    SystemCoreClock = 0u;
    pake_benchmark_reset(); unavailable(2u);
    assert(pake_systick_diagnostics.wraps == 0u);
    assert(ctrl == 5u && shpr3 == 0xA1B2C3D4u);
}

int main(void)
{
    test_not_attempted_and_dwt_preferred();
    test_fallback_readiness_and_cached_packets();
    test_initialization_failures_restore_ownership();
    test_pending_wraps_isr_races_and_modulo32();
    test_runtime_failure_invalidates_all_phases_and_restores_scoped_fields();
    puts("PASS: SysTick ownership, IRQ readiness, pending-wrap races, modulo deltas, invalidation and cached PES1");
    return 0;
}
