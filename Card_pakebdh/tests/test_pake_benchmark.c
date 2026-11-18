/*
 * Host-only tests of packet encoding/cycle arithmetic. No hardware timing is
 * measured or simulated as a performance result.
 *
 * cc -std=c99 -Wall -Wextra -Werror \
 *   Card_pakebdh/tests/test_pake_benchmark.c -o /tmp/test_pake_benchmark
 * /tmp/test_pake_benchmark
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t fake_demcr;
static uint32_t fake_ctrl;
static uint32_t fake_counter;
static uint32_t fake_counter_step;
static uint32_t fake_demcr_drop_bits;
static uint32_t fake_ctrl_drop_bits;
static unsigned int fake_reads;
static unsigned int fake_writes;

static uint32_t fake_read(uint32_t address);
static void fake_write(uint32_t address, uint32_t value);

#define PAKE_EMV_BENCHMARK 1
#define PAKE_BENCHMARK_READ_REG(address) fake_read(address)
#define PAKE_BENCHMARK_WRITE_REG(address, value) fake_write(address, value)
#include "../Demo/pake_benchmark.h"

uint32_t SystemCoreClock = 105000000u;

static uint32_t fake_read(uint32_t address)
{
    uint32_t result;
    ++fake_reads;
    switch (address) {
        case PAKE_BENCHMARK_DEMCR: return fake_demcr;
        case PAKE_BENCHMARK_DWT_CTRL: return fake_ctrl;
        case PAKE_BENCHMARK_DWT_CYCCNT:
            result = fake_counter;
            if ((fake_demcr & PAKE_BENCHMARK_TRCENA) &&
                (fake_ctrl & PAKE_BENCHMARK_CYCCNTENA)) {
                fake_counter += fake_counter_step;
            }
            return result;
        default: assert(0); return 0u;
    }
}

static void fake_write(uint32_t address, uint32_t value)
{
    ++fake_writes;
    switch (address) {
        case PAKE_BENCHMARK_DEMCR: fake_demcr = value & ~fake_demcr_drop_bits; break;
        case PAKE_BENCHMARK_DWT_CTRL: fake_ctrl = value & ~fake_ctrl_drop_bits; break;
        case PAKE_BENCHMARK_DWT_CYCCNT: fake_counter = value; break;
        default: assert(0);
    }
}

static void configure_counter(void)
{
    fake_demcr = 0u;
    fake_ctrl = 0u;
    fake_counter = 100u;
    fake_counter_step = 1u;
    fake_demcr_drop_bits = fake_ctrl_drop_bits = 0u;
    fake_reads = fake_writes = 0u;
    SystemCoreClock = 105000000u;
}

static void ready_counter(void)
{
    configure_counter();
    pake_benchmark_reset();
    assert(pake_benchmark_counters.flags == PAKE_BENCHMARK_READY);
    assert((fake_demcr & PAKE_BENCHMARK_TRCENA) != 0u);
    assert((fake_ctrl & PAKE_BENCHMARK_CYCCNTENA) != 0u);
    assert(pake_benchmark_now() == 102u);
}

static uint32_t read_u32(const unsigned char *value)
{
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | value[3];
}

static void test_diagnostics_before_reset_do_not_touch_registers(void)
{
    unsigned char packet[40];
    const unsigned char expected[40] = {'P', 'E', 'D', '1'};
    assert(pake_benchmark_diagnostics.reason == PAKE_BENCHMARK_DIAG_NOT_RESET);
    assert(pake_benchmark_diagnostic_snapshot(packet) == sizeof(packet));
    assert(memcmp(packet, expected, sizeof(packet)) == 0);
    assert(fake_reads == 0u && fake_writes == 0u);
}

static void test_ready_diagnostics_are_big_endian_and_cached(void)
{
    unsigned char packet[40];
    const unsigned char expected[40] = {
        'P', 'E', 'D', '1',
        0, 0, 0, 1,                 /* ready */
        0x06, 0x42, 0x2C, 0x40,     /* 105000000 Hz */
        0, 0, 0, 0x20,              /* DEMCR before */
        1, 0, 0, 0x20,              /* DEMCR after */
        0, 0, 0, 0x40,              /* CTRL before */
        0, 0, 0, 0x41,              /* CTRL after */
        1, 2, 3, 4,                 /* first cycle */
        2, 4, 6, 8,                 /* second cycle */
        0, 0, 0, 1                  /* PEB1 ready flags */
    };
    unsigned int reads_before;
    unsigned int writes_before;
    configure_counter();
    fake_demcr = 0x20u;
    fake_ctrl = 0x40u;
    fake_counter = 0x01020304u;
    fake_counter_step = 0x01020304u;
    pake_benchmark_reset();
    assert(pake_benchmark_counters.flags == PAKE_BENCHMARK_READY);
    assert(fake_reads == 6u && fake_writes == 2u);
    reads_before = fake_reads;
    writes_before = fake_writes;
    /* Serialization must use the reset's cache, even if live state changes. */
    fake_demcr = fake_ctrl = fake_counter = 0u;
    SystemCoreClock = 0u;
    pake_benchmark_record(0xC1u, 1u, 8u);
    assert(pake_benchmark_diagnostic_snapshot(packet) == sizeof(packet));
    assert(memcmp(packet, expected, sizeof(packet)) == 0);
    assert(fake_reads == reads_before && fake_writes == writes_before);
    assert(pake_benchmark_counters.command_count == 1u);
    assert(pake_benchmark_counters.pake_cycles == 7u);
    SystemCoreClock = 105000000u;
}

static void test_packet_and_phase_accounting(void)
{
    unsigned char packet[40];
    const unsigned char expected[40] = {
        'P', 'E', 'B', '1',
        0, 0, 0, 1,                 /* ready */
        0x06, 0x42, 0x2C, 0x40,     /* 105000000 Hz */
        0, 0, 0, 4,                 /* four core APDUs */
        0, 0, 0, 0, 0, 0, 0, 42,   /* PAKE = 10 + 32, one wrap */
        0, 0, 0, 0, 0, 0, 0, 30,   /* certificate */
        0, 0, 0, 0, 0, 0, 0, 40    /* establish key */
    };
    ready_counter();
    pake_benchmark_record(0xC1u, 100u, 110u);
    pake_benchmark_record(0xC1u, 0xFFFFFFF0u, 0x00000010u);
    pake_benchmark_record(0xB2u, 200u, 230u);
    pake_benchmark_record(0x50u, 500u, 540u);
    pake_benchmark_record(0xF7u, 0u, 10000u);
    pake_benchmark_record(0xF6u, 0u, 10000u);
    pake_benchmark_record(0xF3u, 0u, 10000u);
    assert(pake_benchmark_snapshot(packet) == sizeof(packet));
    assert(memcmp(packet, expected, sizeof(packet)) == 0);
}

static void test_64_bit_accumulation_and_reset(void)
{
    unsigned char packet[40];
    ready_counter();
    pake_benchmark_record(0xC1u, 0u, 0xFFFFFFF0u);
    pake_benchmark_record(0xC1u, 0u, 32u);
    assert(pake_benchmark_counters.pake_cycles == UINT64_C(0x100000010));
    pake_benchmark_snapshot(packet);
    assert(packet[19] == 1u && packet[23] == 16u);
    pake_benchmark_reset();
    assert(pake_benchmark_counters.flags == PAKE_BENCHMARK_READY);
    assert(pake_benchmark_counters.command_count == 0u);
    assert(pake_benchmark_counters.pake_cycles == 0u);
    assert(pake_benchmark_counters.certificate_cycles == 0u);
    assert(pake_benchmark_counters.establish_key_cycles == 0u);
}

static void assert_counter_unavailable(uint32_t reason)
{
    unsigned char packet[40];
    unsigned int reads_before = fake_reads;
    unsigned int writes_before = fake_writes;
    assert(pake_benchmark_counters.flags == 0u);
    assert(pake_benchmark_diagnostics.reason == reason);
    assert(pake_benchmark_diagnostics.ready_flags == 0u);
    assert(pake_benchmark_now() == 0u);
    pake_benchmark_record(0xC1u, 1u, 100u);
    assert(pake_benchmark_counters.command_count == 0u);
    assert(pake_benchmark_counters.pake_cycles == 0u);
    assert(pake_benchmark_counters.certificate_cycles == 0u);
    assert(pake_benchmark_counters.establish_key_cycles == 0u);
    assert(pake_benchmark_diagnostic_snapshot(packet) == sizeof(packet));
    assert(memcmp(packet, "PED1", 4) == 0);
    assert(read_u32(packet + 4) == reason);
    assert(read_u32(packet + 36) == 0u);
    assert(fake_reads == reads_before && fake_writes == writes_before);
}

static void test_unavailable_counter_reasons_and_early_returns(void)
{
    unsigned char packet[40];
    const unsigned char unknown_clock[40] = {'P', 'E', 'D', '1', 0, 0, 0, 2};
    ready_counter();
    pake_benchmark_record(0xC1u, 1u, 100u);
    configure_counter();
    SystemCoreClock = 0u;
    pake_benchmark_reset();
    assert_counter_unavailable(PAKE_BENCHMARK_DIAG_UNKNOWN_CLOCK);
    assert(fake_reads == 0u && fake_writes == 0u);
    pake_benchmark_diagnostic_snapshot(packet);
    /* A failed reset must not retain readbacks or counts from a prior reset. */
    assert(memcmp(packet, unknown_clock, sizeof(packet)) == 0);

    configure_counter();
    fake_demcr = 0x20u;
    fake_ctrl = 0x40u;
    fake_demcr_drop_bits = PAKE_BENCHMARK_TRCENA;
    pake_benchmark_reset();
    assert_counter_unavailable(PAKE_BENCHMARK_DIAG_TRACE_NOT_ENABLED);
    assert(fake_reads == 2u && fake_writes == 1u);
    assert(fake_demcr == 0x20u && fake_ctrl == 0x40u);
    assert(pake_benchmark_diagnostics.demcr_before == 0x20u);
    assert(pake_benchmark_diagnostics.demcr_after == 0x20u);
    assert(pake_benchmark_diagnostics.ctrl_before == 0u);
    assert(pake_benchmark_diagnostics.ctrl_after == 0u);
    assert(pake_benchmark_diagnostics.first_cycle == 0u);
    assert(pake_benchmark_diagnostics.second_cycle == 0u);

    configure_counter();
    fake_ctrl = PAKE_BENCHMARK_NOCYCCNT | 0x40u;
    pake_benchmark_reset();
    assert_counter_unavailable(PAKE_BENCHMARK_DIAG_NO_CYCLE_COUNTER);
    assert(fake_reads == 3u && fake_writes == 1u);
    assert(fake_ctrl == (PAKE_BENCHMARK_NOCYCCNT | 0x40u));
    assert(pake_benchmark_diagnostics.ctrl_before == fake_ctrl);
    assert(pake_benchmark_diagnostics.ctrl_after == 0u);
    assert(pake_benchmark_diagnostics.first_cycle == 0u);

    configure_counter();
    fake_ctrl = 0x40u;
    fake_ctrl_drop_bits = PAKE_BENCHMARK_CYCCNTENA;
    pake_benchmark_reset();
    assert_counter_unavailable(PAKE_BENCHMARK_DIAG_COUNTER_NOT_ENABLED);
    assert(fake_reads == 4u && fake_writes == 2u);
    assert(fake_ctrl == 0x40u);
    assert(pake_benchmark_diagnostics.ctrl_before == 0x40u);
    assert(pake_benchmark_diagnostics.ctrl_after == 0x40u);
    assert(pake_benchmark_diagnostics.first_cycle == 0u);

    configure_counter();
    fake_counter_step = 0u;
    pake_benchmark_reset();
    assert_counter_unavailable(PAKE_BENCHMARK_DIAG_COUNTER_STOPPED);
    assert(fake_reads == 6u && fake_writes == 2u);
    assert(pake_benchmark_diagnostics.first_cycle == 100u);
    assert(pake_benchmark_diagnostics.second_cycle == 100u);
}

static void test_reset_preserves_other_trace_settings_and_hardware_count(void)
{
    /* Neither enabling our counter nor clearing our totals owns other trace bits. */
    configure_counter();
    fake_demcr = 0x20u;
    fake_ctrl = 0x40u;
    fake_counter = 123456u;
    fake_counter_step = 2u;
    SystemCoreClock = 105000000u;
    pake_benchmark_reset();
    assert(fake_demcr == (0x20u | PAKE_BENCHMARK_TRCENA));
    assert(fake_ctrl == (0x40u | PAKE_BENCHMARK_CYCCNTENA));
    assert(fake_counter == 123460u); /* Two readiness reads; no write to CYCCNT. */
    assert(pake_benchmark_counters.flags == PAKE_BENCHMARK_READY);
    pake_benchmark_record(0xB2u, 10u, 40u);
    pake_benchmark_reset();
    assert(fake_counter == 123464u);
    assert(pake_benchmark_counters.command_count == 0u);
    assert(pake_benchmark_counters.certificate_cycles == 0u);
}

int main(void)
{
    test_diagnostics_before_reset_do_not_touch_registers();
    test_ready_diagnostics_are_big_endian_and_cached();
    test_packet_and_phase_accounting();
    test_64_bit_accumulation_and_reset();
    test_unavailable_counter_reasons_and_early_returns();
    test_reset_preserves_other_trace_settings_and_hardware_count();
    puts("PASS: packets, phase totals, wrap arithmetic, reset, cached diagnostics, all unavailable reasons, trace settings");
    return 0;
}
