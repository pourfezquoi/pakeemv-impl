/*
 * Exercise the real SCard_Demo loop with mocked SCI I/O and MMIO registers.
 * Crypto stubs abort unless the wrong-confirmation test explicitly enables a
 * deterministic, non-cryptographic Hash mock to exercise the rejection branch.
 * This is a dispatch regression test, not a hardware or protocol timing result.
 *
 * Run from the repository root with PAKE_EMV_BENCHMARK=0 and =1:
 * cc -std=c99 -Wall -Wextra -Wno-unused-function -Wno-unused-variable \
 *   -Wno-type-limits -fsanitize=undefined -fno-sanitize-recover=all \
 *   -DPAKE_EMV_BENCHMARK=0 \
 *   -ICard_pakebdh/Demo -ICard_pakebdh/Source -ICard_pakebdh/Library \
 *   -ICard_pakebdh/ml-kem/h -ICard_pakebdh/aes/h \
 *   Card_pakebdh/tests/test_t1_dispatch.c -o /tmp/test_t1_dispatch
 * /tmp/test_t1_dispatch
 */
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../Demo/demo.h"

static volatile unsigned int fake_mcgcr, fake_sci_cr1, fake_sci_tcr;
static volatile unsigned int fake_sci_sr, fake_sci_ecr;
static volatile unsigned int fake_systcsr, fake_systcvr, fake_systrvr;
#undef MCGCR
#undef SCI_CR1
#undef SCI_TCR
#undef SCI_SR
#undef SCI_ECR
#undef SYSTCSR
#undef SYSTCVR
#undef SYSTRVR
#define MCGCR fake_mcgcr
#define SCI_CR1 fake_sci_cr1
#define SCI_TCR fake_sci_tcr
#define SCI_SR fake_sci_sr
#define SCI_ECR fake_sci_ecr
#define SYSTCSR fake_systcsr
#define SYSTCVR fake_systcvr
#define SYSTRVR fake_systrvr

static uint32_t fake_dwt_read(uint32_t address);
static void fake_dwt_write(uint32_t address, uint32_t value);
static uint32_t fake_systick_masks;
#define PAKE_BENCHMARK_READ_REG(address) fake_dwt_read(address)
#define PAKE_BENCHMARK_WRITE_REG(address, value) fake_dwt_write(address, value)
#define PAKE_BENCHMARK_READ_MASKS() fake_systick_masks

/* Include the production translation unit, including its live dispatch branch. */
#include "../Demo/smartcard_demo.c"
#undef receive_data
#undef send_data
#include "../Demo/pake_emv_crypto.c"
#include "../../protocol/pake_emv/pake_emv.c"

/* Exercise the linked production IRQ vector as well as its owner callback.
 * Avoid the duplicate vendor register header after redirecting test MMIO. */
#define __GPIO_H__
#define GPIO_GP0_SPI0SCK 0u
void gpio_out(unsigned char gpio, unsigned char level);
#include "../ml-kem/c/systick.c"

uint32_t SystemCoreClock = 105000000u;
unsigned short etu_clk[256];
static uint32_t fake_dwt_clock;
static uint32_t fake_dwt_demcr, fake_dwt_ctrl;
static unsigned int fake_dwt_reads, fake_dwt_writes;
static uint32_t fake_systick_icsr, fake_systick_shpr3;
static unsigned int fake_gpio_calls;
static jmp_buf end_of_input;
static unsigned char input_bytes[2048], output_bytes[2048];
static size_t input_size, input_offset, output_size;
static int prepare_m3_state;
static int prepare_diag_state;
static int allow_noncrypto_hash;
static unsigned int mock_hash_inits, mock_hash_updates, mock_hash_finals;

static uint32_t fake_dwt_read(uint32_t address)
{
    ++fake_dwt_reads;
    switch (address) {
        case 0xE000EDFCu: return fake_dwt_demcr;
        case 0xE0001000u: return fake_dwt_ctrl;
        case 0xE0001004u:
            if ((fake_dwt_demcr & (1u << 24)) && (fake_dwt_ctrl & 1u)) {
                return ++fake_dwt_clock;
            }
            return fake_dwt_clock;
        case 0xE000E010u: return fake_systcsr;
        case 0xE000E014u: return fake_systrvr;
        case 0xE000E018u:
            return fake_systcvr-- & 0x00FFFFFFu;
        case 0xE000ED04u: return fake_systick_icsr;
        case 0xE000ED20u: return fake_systick_shpr3;
        default: abort();
    }
}

static void fake_dwt_write(uint32_t address, uint32_t value)
{
    ++fake_dwt_writes;
    switch (address) {
        case 0xE000EDFCu: fake_dwt_demcr = value; break;
        case 0xE0001000u: fake_dwt_ctrl = value; break;
        case 0xE000E010u: fake_systcsr = value; break;
        case 0xE000ED20u: fake_systick_shpr3 = value; break;
        case 0xE000ED04u:
            if (value == (1u << 25)) fake_systick_icsr &= ~(1u << 26);
            else {
                assert(value == (1u << 26));
                fake_systick_icsr |= 1u << 26;
                SysTick_Handler();
                fake_systick_icsr &= ~(1u << 26);
            }
            break;
        default: abort();
    }
}

void gpio_out(unsigned char gpio, unsigned char level)
{
    assert(gpio == 0u && level == 2u);
    ++fake_gpio_calls;
}

#define EXPECTED_PROFILE_CAPABILITIES \
    (PAKE_EMV_BENCHMARK ? (PAKE_EMV_SYSTICK_BENCHMARK ? 63u : 31u) : 7u)

unsigned char receive_data(unsigned char *dst, unsigned short len)
{
    if (input_offset == input_size) longjmp(end_of_input, 1);
    if (input_offset == 0u && prepare_m3_state) {
        /* Install only the rejection-path fixture after SCard_Demo resets RAM. */
        assert(protocol_phase == TX_NEEDS_BEGIN);
        protocol_phase = TX_EXPECT_M3;
        transaction_retries = 0;
        memset(protocol_tk, 0x5A, sizeof(protocol_tk));
        memset(protocol_ctx, 0x5A, sizeof(protocol_ctx));
        prepare_m3_state = 0;
    }
    if (input_offset == 0u && prepare_diag_state) {
        protocol_phase = TX_EXPECT_M3;
        transaction_retries = 1;
        recorded_key_valid = 1;
        memset(recorded_key, 0x33, sizeof(recorded_key));
        memset(protocol_tk, 0xA5, sizeof(protocol_tk));
        memset(protocol_ctx, 0xA6, sizeof(protocol_ctx));
        prepare_diag_state = 0;
    }
    assert(input_offset + len <= input_size);
    memcpy(dst, input_bytes + input_offset, len);
    input_offset += len;
    return (unsigned char)len;
}

void send_data(unsigned char *src, unsigned short len)
{
    assert(output_size + len <= sizeof(output_bytes));
    memcpy(output_bytes + output_size, src, len);
    output_size += len;
}

void SCI_Pad_Init(unsigned char device) { assert(device == 0u); }
void send_byte(unsigned char value) { (void)value; abort(); }
void send_time_out(unsigned short clocks) { (void)clocks; abort(); }
void WriteFlash(unsigned int *p, unsigned int a, unsigned int n)
{ (void)p; (void)a; (void)n; abort(); }
void SectorEraseFlash(unsigned int a) { (void)a; abort(); }
void ReadFlash_B(unsigned char *p, unsigned int a, unsigned int n)
{ (void)p; (void)a; (void)n; abort(); }
unsigned int Hash_Init(HASH_CTX *ctx, unsigned int type)
{
    (void)ctx;
    if (!allow_noncrypto_hash) abort();
    assert(type == SHA_256);
    ++mock_hash_inits;
    return 0u;
}
void Hash_Updata(HASH_CTX *ctx, unsigned char *p, unsigned int n)
{
    (void)ctx; (void)p; (void)n;
    if (!allow_noncrypto_hash) abort();
    ++mock_hash_updates;
}
void Hash_Final(HASH_CTX *ctx, unsigned char *p)
{
    (void)ctx;
    if (!allow_noncrypto_hash) abort();
    /* Deliberately not SHA-256: force a known nonmatching confirmation value. */
    memset(p, 0xA5, 32);
    ++mock_hash_finals;
}
int randombytes(uint8_t *p, size_t n) { (void)p; (void)n; abort(); }
int chic_respond(uint8_t key[CHIC_KEY_BYTES], uint8_t msg2[CHIC_MSG2_BYTES],
                 const uint8_t msg1[CHIC_MSG1_BYTES],
                 const uint8_t password[CHIC_PASSWORD_BYTES],
                 const uint8_t sid[CHIC_SID_BYTES])
{ (void)key; (void)msg2; (void)msg1; (void)password; (void)sid; abort(); }
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; abort(); }
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; abort(); }
void aes_gcm_encrypt_full(const unsigned char *key, const unsigned char *iv,
    const unsigned char *plain, unsigned int plain_len, const unsigned char *aad,
    unsigned int aad_len, unsigned char *cipher, unsigned char *tag)
{
    (void)key; (void)iv; (void)plain; (void)plain_len; (void)aad;
    (void)aad_len; (void)cipher; (void)tag; abort();
}
int aes_gcm_decrypt_verify(const unsigned char *key, const unsigned char *iv,
    const unsigned char *cipher, unsigned int cipher_len, const unsigned char *aad,
    unsigned int aad_len, const unsigned char *tag, unsigned char *plain)
{
    (void)key; (void)iv; (void)cipher; (void)cipher_len; (void)aad;
    (void)aad_len; (void)tag; (void)plain; abort();
}

static void append_request(unsigned char pcb, const unsigned char *apdu, size_t size)
{
    size_t i;
    unsigned char lrc = (unsigned char)(pcb ^ size);
    assert(size <= 255u && input_size + size + 4u <= sizeof(input_bytes));
    input_bytes[input_size++] = 0u;
    input_bytes[input_size++] = pcb;
    input_bytes[input_size++] = (unsigned char)size;
    for (i = 0u; i < size; ++i) {
        input_bytes[input_size++] = apdu[i];
        lrc ^= apdu[i];
    }
    input_bytes[input_size++] = lrc;
}

static void run_card(void)
{
    input_offset = 0u;
    output_size = 0u;
    fake_sci_sr = SCI_SR_CNTOR;
    if (setjmp(end_of_input) == 0) SCard_Demo();
    assert(input_offset == input_size);
    assert(output_size >= sizeof(ATR));
    assert(memcmp(output_bytes, ATR, sizeof(ATR)) == 0);
}

static const unsigned char *response(size_t *offset, unsigned char pcb, size_t size)
{
    size_t i;
    unsigned char lrc = 0u;
    const unsigned char *frame = output_bytes + *offset;
    assert(*offset + size + 4u <= output_size);
    assert(frame[0] == 0u && frame[1] == pcb && frame[2] == size);
    for (i = 0u; i < size + 3u; ++i) lrc ^= frame[i];
    assert(frame[size + 3u] == lrc);
    *offset += size + 4u;
    return frame + 3;
}

static void test_connection_diagnostics_without_crypto_or_timing_reset(void)
{
    const unsigned char echo_a[] = {0x80, INS_ECHO, 0x3A, 0xC7, 0};
    const unsigned char echo_b[] = {0x80, INS_ECHO, 0xA6, 0x5D, 0};
    const unsigned char ping[] = {0x80, INS_PING, 0, 0, 1};
    const unsigned char trace[] = {0x80, INS_TRACE_LAST_CMD, 0, 0, 0};
    const unsigned char profile[] = {0x80, INS_GET_PROFILE, 0, 0, 0};
    const unsigned char expected_a[] = {0x3A, 0xC7, 0x90, 0};
    const unsigned char expected_b[] = {0xA6, 0x5D, 0x90, 0};
    const unsigned char expected_ping[] = {1, 0x90, 0};
    const unsigned char *reply;
    size_t offset = sizeof(ATR);
    unsigned int reads_before = fake_dwt_reads;
    unsigned int writes_before = fake_dwt_writes;
#if PAKE_EMV_BENCHMARK
    PakeBenchmarkCounters counters_before = pake_benchmark_counters;
    /* This test runs before any F7 request, matching connection diagnostics. */
    assert(counters_before.flags == 0u);
#endif
    assert(allow_noncrypto_hash == 0 && prepare_m3_state == 0);
    input_size = 0u;
    append_request(0x00, echo_a, sizeof(echo_a));
    append_request(0x00, echo_b, sizeof(echo_b));
    append_request(0x00, ping, sizeof(ping));
    append_request(0x00, trace, sizeof(trace));
    append_request(0x00, profile, sizeof(profile));
    run_card();

    reply = response(&offset, 0x00, sizeof(expected_a));
    assert(memcmp(reply, expected_a, sizeof(expected_a)) == 0);
    reply = response(&offset, 0x00, sizeof(expected_b));
    assert(memcmp(reply, expected_b, sizeof(expected_b)) == 0);
    reply = response(&offset, 0x00, sizeof(expected_ping));
    assert(memcmp(reply, expected_ping, sizeof(expected_ping)) == 0);
    reply = response(&offset, 0x00, 7);
    assert(memcmp(reply, ping, sizeof(ping)) == 0);
    assert(reply[5] == 0x90 && reply[6] == 0);
    reply = response(&offset, 0x00, 14);
    assert(memcmp(reply, "PEM1\0\0\0\3\0\0\0", 11) == 0);
    assert(reply[11] == EXPECTED_PROFILE_CAPABILITIES);
    assert(reply[12] == 0x90 && reply[13] == 0);
    assert(offset == output_size && protocol_phase == TX_NEEDS_BEGIN);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
#if PAKE_EMV_BENCHMARK
    assert(pake_benchmark_counters.flags == counters_before.flags);
    assert(pake_benchmark_counters.command_count == counters_before.command_count);
    assert(pake_benchmark_counters.pake_cycles == counters_before.pake_cycles);
    assert(pake_benchmark_counters.certificate_cycles == counters_before.certificate_cycles);
    assert(pake_benchmark_counters.establish_key_cycles == counters_before.establish_key_cycles);
#endif
}

static void test_cached_counter_diagnostics_before_reset_and_validation(void)
{
    const unsigned char diagnostic[] = {0x80, 0xF7, 2, 0, 0};
    const unsigned char invalid_p1[] = {0x80, 0xF7, 4, 0, 0};
    const unsigned char invalid_p2[] = {0x80, 0xF7, 2, 1, 0};
    const unsigned char with_data[] = {0x80, 0xF7, 2, 0, 1, 0xA5};
    const unsigned char *reply;
    size_t offset = sizeof(ATR);
    unsigned int reads_before = fake_dwt_reads;
    unsigned int writes_before = fake_dwt_writes;
    input_size = 0u;
    append_request(0x00, diagnostic, sizeof(diagnostic));
    append_request(0x00, invalid_p1, sizeof(invalid_p1));
    append_request(0x00, invalid_p2, sizeof(invalid_p2));
    append_request(0x00, with_data, sizeof(with_data));
    run_card();
#if PAKE_EMV_BENCHMARK
    {
        const unsigned char expected[40] = {'P', 'E', 'D', '1'};
        unsigned int i;
        reply = response(&offset, 0x00, 42);
        assert(memcmp(reply, expected, sizeof(expected)) == 0);
        assert(reply[40] == 0x90 && reply[41] == 0);
        for (i = 0u; i < 3u; ++i) {
            reply = response(&offset, 0x00, 2);
            assert(reply[0] == SW1_WRONG_P1P2 && reply[1] == 0);
        }
        assert(pake_benchmark_counters.flags == 0u);
        assert(pake_benchmark_diagnostics.reason == PAKE_BENCHMARK_DIAG_NOT_RESET);
    }
#else
    {
        unsigned int i;
        for (i = 0u; i < 4u; ++i) {
            reply = response(&offset, 0x00, 2);
            assert(reply[0] == 0x6D && reply[1] == 0);
        }
    }
#endif
    assert(offset == output_size && protocol_phase == TX_NEEDS_BEGIN);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
}

static void test_timing_probe_then_both_pake_sequence_values(void)
{
    const unsigned char timing[] = {0x80, 0xF7, 0, 0, 0};
    const unsigned char begin[] = {0x80, INS_BEGIN_TRANSACTION, 0, 0, 0};
    const unsigned char profile[] = {0x80, INS_GET_PROFILE, 0, 0, 0};
    const unsigned char trace[] = {0x80, INS_TRACE_LAST_CMD, 0, 0, 0};
    unsigned char fragment[225];
    const unsigned char *reply;
    size_t offset = sizeof(ATR);
    memset(fragment, 0xA5, sizeof(fragment));
    fragment[0] = 0x80; fragment[1] = INS_PAKE_INIT;
    fragment[2] = 1; fragment[3] = 0; fragment[4] = 220;
    input_size = 0u;
    append_request(0x00, timing, sizeof(timing));
    append_request(0x00, begin, sizeof(begin));
    append_request(0x40, fragment, sizeof(fragment));
    append_request(0x00, fragment, sizeof(fragment));
    append_request(0x40, trace, sizeof(trace));
    append_request(0x00, trace, sizeof(trace));
    append_request(0x40, profile, sizeof(profile));
    run_card();

#if PAKE_EMV_BENCHMARK
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, "PEB1", 4) == 0 && reply[7] == 1u);
    assert(reply[40] == 0x90 && reply[41] == 0x00);
    assert(pake_benchmark_counters.command_count == 2u);
#else
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == 0x6D && reply[1] == 0x00);
#endif
    reply = response(&offset, 0x00, 2); /* F9 begin is outside phase timing. */
    assert(reply[0] == 0x90 && reply[1] == 0x00);
    reply = response(&offset, 0x40, 2);
    assert(reply[0] == 0x90 && reply[1] == 0x00);
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == 0x90 && reply[1] == 0x00);
    reply = response(&offset, 0x40, 7);
    assert(memcmp(reply, fragment, 5) == 0);
    assert(reply[5] == 0x90 && reply[6] == 0x00);
    reply = response(&offset, 0x00, 7);
    assert(memcmp(reply, fragment, 5) == 0); /* TRACE does not replace itself. */
    reply = response(&offset, 0x40, 14);
    assert(memcmp(reply, "PEM1\0\0\0\3\0\0\0", 11) == 0);
    assert(reply[11] == EXPECTED_PROFILE_CAPABILITIES);
    assert(reply[12] == 0x90 && reply[13] == 0x00);
    assert(offset == output_size);
    assert(protocol_x1_len == 440u); /* Complete X1 includes the SID prefix. */
    assert(protocol_phase == TX_COLLECT_M1); /* No crypto operation reached. */
}

static void test_cached_counter_diagnostics_while_ready_do_not_touch_registers(void)
{
    const unsigned char diagnostic[] = {0x80, 0xF7, 2, 0, 0};
    const unsigned char snapshot[] = {0x80, 0xF7, 1, 0, 0};
    const unsigned char profile[] = {0x80, INS_GET_PROFILE, 0, 0, 0};
    const unsigned char *reply;
    size_t offset = sizeof(ATR);
    unsigned int reads_before = fake_dwt_reads;
    unsigned int writes_before = fake_dwt_writes;
#if PAKE_EMV_BENCHMARK
    unsigned char expected_diagnostics[40];
    unsigned char expected_counters[40];
    assert(pake_benchmark_counters.flags == PAKE_BENCHMARK_READY);
    assert(pake_benchmark_diagnostic_snapshot(expected_diagnostics) == 40u);
    assert(pake_benchmark_snapshot(expected_counters) == 40u);
#endif
    input_size = 0u;
    append_request(0x00, diagnostic, sizeof(diagnostic));
    append_request(0x00, diagnostic, sizeof(diagnostic));
    append_request(0x00, snapshot, sizeof(snapshot));
    append_request(0x00, profile, sizeof(profile));
    run_card();
#if PAKE_EMV_BENCHMARK
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, expected_diagnostics, 40) == 0);
    assert(reply[40] == 0x90 && reply[41] == 0);
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, expected_diagnostics, 40) == 0);
    assert(reply[40] == 0x90 && reply[41] == 0);
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, expected_counters, 40) == 0);
    assert(reply[40] == 0x90 && reply[41] == 0);
    {
        unsigned char actual[40];
        pake_benchmark_snapshot(actual);
        assert(memcmp(actual, expected_counters, sizeof(actual)) == 0);
        pake_benchmark_diagnostic_snapshot(actual);
        assert(memcmp(actual, expected_diagnostics, sizeof(actual)) == 0);
    }
#else
    {
        unsigned int i;
        for (i = 0u; i < 3u; ++i) {
            reply = response(&offset, 0x00, 2);
            assert(reply[0] == 0x6D && reply[1] == 0);
        }
    }
#endif
    reply = response(&offset, 0x00, 14);
    assert(memcmp(reply, "PEM1", 4) == 0);
    assert(reply[11] == EXPECTED_PROFILE_CAPABILITIES);
    assert(reply[12] == 0x90 && reply[13] == 0);
    assert(offset == output_size && protocol_phase == TX_NEEDS_BEGIN);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
}

static void test_f7_never_mutates_protocol_state_or_record(void)
{
    const unsigned char reset[] = {0x80, 0xF7, 0, 0, 0};
    const unsigned char snapshot[] = {0x80, 0xF7, 1, 0, 0};
    const unsigned char diagnostics[] = {0x80, 0xF7, 2, 0, 0};
    size_t offset = sizeof(ATR);
    input_size = 0;
    prepare_diag_state = 1;
    append_request(0, reset, sizeof(reset));
    append_request(0, snapshot, sizeof(snapshot));
    append_request(0, diagnostics, sizeof(diagnostics));
    run_card();
    for (unsigned int i = 0; i < 3; ++i) {
        const unsigned char *reply = response(&offset, 0, PAKE_EMV_BENCHMARK ? 42 : 2);
        assert(reply[PAKE_EMV_BENCHMARK ? 40 : 0] == (PAKE_EMV_BENCHMARK ? 0x90 : 0x6D));
        assert(reply[PAKE_EMV_BENCHMARK ? 41 : 1] == 0);
    }
    assert(offset == output_size && protocol_phase == TX_EXPECT_M3 && transaction_retries == 1);
    assert(recorded_key_valid == 1);
    for (unsigned int i = 0; i < 32; ++i) {
        assert(recorded_key[i] == 0x33 && protocol_tk[i] == 0xA5 && protocol_ctx[i] == 0xA6);
    }
}

static void test_profile_request_validation(void)
{
    const unsigned char profile[] = {0x80, INS_GET_PROFILE, 0, 0, 0};
    const unsigned char invalid[] = {0x80, INS_GET_PROFILE, 1, 0, 0};
    const unsigned char with_data[] = {0x80, INS_GET_PROFILE, 0, 0, 1, 0xA5};
    const unsigned char *reply;
    size_t offset = sizeof(ATR);
    input_size = 0u;
    append_request(0x00, profile, sizeof(profile));
    append_request(0x40, invalid, sizeof(invalid));
    append_request(0x00, with_data, sizeof(with_data));
    run_card();
    reply = response(&offset, 0x00, 14);
    assert(memcmp(reply, "PEM1", 4) == 0);
    reply = response(&offset, 0x40, 2);
    assert(reply[0] == SW1_WRONG_P1P2 && reply[1] == 0);
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == SW1_WRONG_P1P2 && reply[1] == 0);
    assert(offset == output_size && protocol_x1_len == 0u);
}

static void test_rejected_confirmation_still_sends_status_and_accepts_profile(int wrong_mac)
{
    const unsigned char profile[] = {0x80, INS_GET_PROFILE, 0, 0, 0};
    unsigned char confirmation[69] = {0x80, INS_READ_CERTS, 0, 0, 64};
    const unsigned char *reply;
    size_t offset = sizeof(ATR);
    size_t command_size = wrong_mac ? sizeof(confirmation) : sizeof(confirmation)-1u;
    confirmation[4] = (unsigned char)(command_size-5u);
    input_size = 0u;
    prepare_m3_state = 1;
    allow_noncrypto_hash = wrong_mac;
    mock_hash_inits = mock_hash_updates = mock_hash_finals = 0u;
#if PAKE_EMV_BENCHMARK
    pake_benchmark_reset();
#endif
    append_request(0x00, confirmation, command_size);
    append_request(0x40, profile, sizeof(profile));
    run_card();
    allow_noncrypto_hash = 0;
    if (wrong_mac) {
        reply = response(&offset, 0x00, 7);
        assert(memcmp(reply, "RETRY\x90\x00", 7) == 0);
        assert(protocol_phase == TX_EXPECT_M1 && transaction_retries == 1);
    } else {
        reply = response(&offset, 0x00, 2);
        assert(reply[0] == 0x67 && reply[1] == 0);
        assert(protocol_phase == TX_HALTED && transaction_retries == 0);
    }
    reply = response(&offset, 0x40, 14);
    assert(memcmp(reply, "PEM1", 4) == 0);
    assert(reply[12] == 0x90 && reply[13] == 0x00);
    assert(offset == output_size && prepare_m3_state == 0);
    assert(mock_hash_inits == (wrong_mac ? 1u : 0u));
    assert(mock_hash_updates == (wrong_mac ? 4u : 0u));
    assert(mock_hash_finals == (wrong_mac ? 1u : 0u));
#if PAKE_EMV_BENCHMARK
    assert(pake_benchmark_counters.command_count == 1u);
    assert(pake_benchmark_counters.certificate_cycles > 0u);
#endif
}

#if PAKE_EMV_BENCHMARK && PAKE_EMV_SYSTICK_BENCHMARK
static void test_systick_fallback_profile_irq_vector_and_cache_only_query(void)
{
    const unsigned char reset[] = {0x80, 0xF7, 0, 0, 0};
    const unsigned char begin[] = {0x80, INS_BEGIN_TRANSACTION, 0, 0, 0};
    const unsigned char systick[] = {0x80, 0xF7, 3, 0, 0};
    const unsigned char dwt[] = {0x80, 0xF7, 2, 0, 0};
    const unsigned char snapshot[] = {0x80, 0xF7, 1, 0, 0};
    const unsigned char profile[] = {0x80, INS_GET_PROFILE, 0, 0, 0};
    unsigned char fragment[225] = {0x80, INS_PAKE_INIT, 1, 0, 220};
    unsigned char cached[40];
    const unsigned char *reply;
    size_t offset = sizeof(ATR);
    unsigned int reads_before, writes_before;
    fake_dwt_ctrl = PAKE_BENCHMARK_NOCYCCNT;
    fake_systcsr = 5u; fake_systrvr = 0x00FFFFFFu; fake_systcvr = 0x123456u;
    fake_systick_icsr = fake_systick_masks = 0u;
    fake_systick_shpr3 = 0xA1B2C3D4u;
    g_systick_count = 9u; fake_gpio_calls = 0u;
    input_size = 0u;
    append_request(0x00, reset, sizeof(reset));
    append_request(0x00, systick, sizeof(systick));
    append_request(0x00, dwt, sizeof(dwt));
    append_request(0x00, profile, sizeof(profile));
    append_request(0x00, begin, sizeof(begin));
    append_request(0x00, fragment, sizeof(fragment));
    append_request(0x00, snapshot, sizeof(snapshot));
    run_card();
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, "PEB1", 4u) == 0 && reply[7] == 3u && reply[15] == 0u);
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, "PES1", 4u) == 0 && reply[7] == 1u && reply[39] == 3u);
    assert(reply[19] == 0xFFu && reply[35] >= 1u);
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, "PED1", 4u) == 0 && reply[7] == 4u && reply[39] == 0u);
    reply = response(&offset, 0x00, 14);
    assert(memcmp(reply, "PEM1", 4u) == 0 && reply[11] == 0x3Fu);
    reply = response(&offset, 0x00, 2); /* F9 */
    assert(reply[0] == 0x90u && reply[1] == 0u);
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == 0x90u && reply[1] == 0u);
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, "PEB1", 4u) == 0 && reply[7] == 3u && reply[15] == 1u);
    assert(offset == output_size && pake_benchmark_counters.pake_cycles > 0u);
    assert(g_systick_count == 9u && fake_gpio_calls == 0u);
    assert(pake_systick_owned && fake_systcsr == 7u && fake_systick_shpr3 == 0x00B2C3D4u);

    pake_benchmark_systick_snapshot(cached);
    reads_before = fake_dwt_reads; writes_before = fake_dwt_writes;
    input_size = 0u; offset = sizeof(ATR);
    append_request(0x00, systick, sizeof(systick));
    append_request(0x40, systick, sizeof(systick));
    run_card();
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, cached, sizeof(cached)) == 0);
    reply = response(&offset, 0x40, 42);
    assert(memcmp(reply, cached, sizeof(cached)) == 0);
    assert(offset == output_size);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
    assert(pake_benchmark_counters.flags == 3u && pake_benchmark_counters.command_count == 1u);

    fake_dwt_ctrl = 0u;
    pake_benchmark_reset();
    assert(pake_benchmark_counters.flags == 1u && pake_systick_owned == 0u);
    assert(fake_systcsr == 5u && fake_systick_shpr3 == 0xA1B2C3D4u);
    fake_systcsr |= SYSTICK_COUNTFLAG;
    SysTick_Handler();
    assert(g_systick_count == 0u && fake_gpio_calls == 1u);
    fake_systcsr = 5u;
}
#endif

int main(void)
{
    test_connection_diagnostics_without_crypto_or_timing_reset();
    test_cached_counter_diagnostics_before_reset_and_validation();
    test_timing_probe_then_both_pake_sequence_values();
    test_cached_counter_diagnostics_while_ready_do_not_touch_registers();
    test_f7_never_mutates_protocol_state_or_record();
    test_profile_request_validation();
    test_rejected_confirmation_still_sends_status_and_accepts_profile(0);
    test_rejected_confirmation_still_sends_status_and_accepts_profile(1);
#if PAKE_EMV_BENCHMARK && PAKE_EMV_SYSTICK_BENCHMARK
    test_systick_fallback_profile_irq_vector_and_cache_only_query();
#endif
    printf("PASS: live/cache diagnostics, T=1 dispatch, N(S)=0/1, F7 then C1, TRACE, F8 and rejected pi1 (benchmark=%d)\n",
           PAKE_EMV_BENCHMARK);
    return 0;
}
