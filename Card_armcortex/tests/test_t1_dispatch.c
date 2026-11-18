/*
 * Exercise the real SCard_Demo loop with mocked SCI I/O and MMIO registers.
 * Crypto stubs abort unless a test explicitly enables deterministic stand-ins.
 * The full transcript fixture tests dispatch and byte accounting, not crypto.
 * This is a dispatch regression test, not a hardware or protocol timing result.
 *
 * Run from the repository root with PAKE_EMV_BENCHMARK=0 and =1:
 * cc -std=c99 -Wall -Wextra -Wno-unused-function -Wno-unused-variable \
 *   -Wno-type-limits -fsanitize=undefined -fno-sanitize-recover=all \
 *   -DPAKE_EMV_BENCHMARK=0 \
 *   -ICard_armcortex/Demo -ICard_armcortex/Source -ICard_armcortex/Library \
 *   -ICard_armcortex/ml-kem/h -ICard_armcortex/aes/h \
 *   Card_armcortex/tests/test_t1_dispatch.c -o /tmp/test_t1_dispatch
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
static unsigned char input_bytes[16384], output_bytes[32768];
static size_t input_size, input_offset, output_size;
static int allow_noncrypto;
static int certificate_only_mock;
static int prepare_certificate_state;
static unsigned int certificate_encrypt_calls;
static unsigned char certificate_poison;
static int advance_io_clock;
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
    (PAKE_EMV_BENCHMARK ? (PAKE_EMV_SYSTICK_BENCHMARK ? 127u : 95u) : 7u)

unsigned char receive_data(unsigned char *dst, unsigned short len)
{
    if (advance_io_clock) fake_dwt_clock += 1000u;
    if (input_offset == input_size) longjmp(end_of_input, 1);
    if (input_offset == 0u && prepare_certificate_state) {
        /* Install a narrow B2 fixture after the production startup reset. */
        assert(card_state == STATE_IDLE);
        card_state = STATE_KEM_ENCAP_DONE;
        memset(global_k1, 0x42, sizeof(global_k1));
        memset(cert_payload_plain, certificate_poison, sizeof(cert_payload_plain));
        memset(cert_payload_cipher, 0xE9, sizeof(cert_payload_cipher));
        prepare_certificate_state = 0;
    }
    assert(input_offset + len <= input_size);
    memcpy(dst, input_bytes + input_offset, len);
    input_offset += len;
    return (unsigned char)len;
}

void send_data(unsigned char *src, unsigned short len)
{
    if (advance_io_clock) fake_dwt_clock += 1000u;
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
    if (!allow_noncrypto || certificate_only_mock) abort();
    assert(type == SHA_256);
    ++mock_hash_inits;
    return 0u;
}
void Hash_Updata(HASH_CTX *ctx, unsigned char *p, unsigned int n)
{
    (void)ctx; (void)p; (void)n;
    if (!allow_noncrypto || certificate_only_mock) abort();
    ++mock_hash_updates;
}
void Hash_Final(HASH_CTX *ctx, unsigned char *p)
{
    (void)ctx;
    if (!allow_noncrypto || certificate_only_mock) abort();
    /* Deliberately not SHA-256: deterministic transcript fixture only. */
    memset(p, 0xA5, 32);
    ++mock_hash_finals;
}
int randombytes(uint8_t *p, size_t n)
{
    assert(allow_noncrypto);
    memset(p, 0x3C, n);
    return 0;
}
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    (void)pk;
    assert(allow_noncrypto && !certificate_only_mock);
    memset(ct, 0xC1, CRYPTO_CIPHERTEXTBYTES);
    memset(ss, 0x11, CRYPTO_BYTES);
    fake_dwt_clock += 15u;
    return 0;
}
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    (void)ct; (void)sk;
    assert(allow_noncrypto && !certificate_only_mock);
    memset(ss, 0x22, CRYPTO_BYTES);
    fake_dwt_clock += 15u;
    return 0;
}
void aes_gcm_encrypt_full(const unsigned char *key, const unsigned char *iv,
    const unsigned char *plain, unsigned int plain_len, const unsigned char *aad,
    unsigned int aad_len, unsigned char *cipher, unsigned char *tag)
{
    (void)key; (void)iv; (void)aad;
    assert(allow_noncrypto && aad_len == 0u);
    if (certificate_only_mock) {
        unsigned int i;
        assert(plain_len == 8192u);
        for (i = 0u; i < 32u; ++i) assert(key[i] == 0x42u);
        ++certificate_encrypt_calls;
    }
    memcpy(cipher, plain, plain_len);
    memset(tag, 0x5A, 16u);
    fake_dwt_clock += 15u;
}
int aes_gcm_decrypt_verify(const unsigned char *key, const unsigned char *iv,
    const unsigned char *cipher, unsigned int cipher_len, const unsigned char *aad,
    unsigned int aad_len, const unsigned char *tag, unsigned char *plain)
{
    (void)key; (void)iv; (void)aad; (void)tag;
    assert(allow_noncrypto && aad_len == 0u);
    memcpy(plain, cipher, cipher_len);
    fake_dwt_clock += 15u;
    return 0;
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

/* Capture the real B2 wire path. AES is an explicit identity stand-in so its
 * plaintext layout can be inspected independently of the production encoder. */
static void test_padded_certificate_envelope_and_fragment_status(void)
{
    const unsigned char initial[] = {0x80, INS_READ_CERTS, 0, 0, 0};
    const unsigned char continuation[] = {0x80, INS_READ_CERTS, 1, 0, 0};
    unsigned char wire[8220];
    unsigned int run;
    for (run = 0u; run < 2u; ++run) {
        const unsigned char *plain;
        size_t offset = sizeof(ATR), copied = 0u, fragment_count = 0u;
        size_t certificate_c_len, certificate_is_len, marker, i;
        input_size = 0u;
        append_request(0x00, initial, sizeof(initial));
        for (i = 0u; i < 34u; ++i) {
            append_request(0x00, continuation, sizeof(continuation));
        }
        certificate_poison = run == 0u ? 0xD7u : 0x18u;
        prepare_certificate_state = 1;
        certificate_encrypt_calls = 0u;
        allow_noncrypto = 1;
        certificate_only_mock = 1;
        run_card();
        certificate_only_mock = 0;
        allow_noncrypto = 0;
        assert(prepare_certificate_state == 0 && certificate_encrypt_calls == 1u);
        while (copied < sizeof(wire)) {
            size_t fragment = sizeof(wire) - copied;
            size_t remaining;
            const unsigned char *reply;
            if (fragment > 240u) fragment = 240u;
            reply = response(&offset, 0x00, fragment + 2u);
            memcpy(wire + copied, reply, fragment);
            copied += fragment;
            remaining = sizeof(wire) - copied;
            assert(reply[fragment] == (remaining ? 0x61u : 0x90u));
            assert(reply[fragment + 1u] ==
                   (remaining ? (remaining > 255u ? 0u : remaining) : 0u));
            ++fragment_count;
        }
        assert(copied == 8220u && fragment_count == 35u && offset == output_size);
        for (i = 0u; i < 12u; ++i) assert(wire[i] == 0x3Cu);
        for (i = sizeof(wire) - 16u; i < sizeof(wire); ++i) assert(wire[i] == 0x5Au);
        plain = wire + 12u;
        certificate_c_len = ((size_t)plain[0] << 8) | plain[1];
        certificate_is_len = ((size_t)plain[2] << 8) | plain[3];
        assert(certificate_c_len == certC_der_len && certificate_is_len == certIS_der_len);
        assert(memcmp(plain + 4u, certC_der, certificate_c_len) == 0);
        assert(memcmp(plain + 4u + certificate_c_len, certIS_der, certificate_is_len) == 0);
        marker = 4u + certificate_c_len + certificate_is_len;
        assert(marker < 8192u && plain[marker] == 0x80u);
        for (i = marker + 1u; i < 8192u; ++i) assert(plain[i] == 0u);
        for (i = 0u; i < sizeof(cert_payload_plain); ++i) assert(cert_payload_plain[i] == 0u);
        for (i = 0u; i < sizeof(cert_payload_cipher); ++i) assert(cert_payload_cipher[i] == 0u);
        assert(cert_tx_pending == 0u && cert_tx_offset == 0u && cert_tx_len == 0u);
        assert(card_state == STATE_KEM_ENCAP_DONE);
    }
}

static void test_certificate_request_validation_without_encryption(void)
{
    static const struct {
        unsigned char command[6];
        unsigned char length;
        unsigned char sw1;
        unsigned char sw2;
    } cases[] = {
        {{0x80, INS_READ_CERTS, 1, 0, 0, 0}, 5, 0x69, 0x82},
        {{0x80, INS_READ_CERTS, 0, 0, 1, 0xA5}, 6, 0x67, 0},
        {{0x80, INS_READ_CERTS, 0, 0, 1, 0}, 5, 0x67, 0},
        {{0x80, INS_READ_CERTS, 2, 0, 0, 0}, 5, 0x6B, 0},
        {{0x80, INS_READ_CERTS, 0, 1, 0, 0}, 5, 0x6B, 0}
    };
    size_t i;
    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const unsigned char *reply;
        size_t offset = sizeof(ATR);
        input_size = 0u;
        append_request(0x00, cases[i].command, cases[i].length);
        certificate_poison = 0xF1u;
        prepare_certificate_state = 1;
        certificate_encrypt_calls = 0u;
        allow_noncrypto = 1;
        certificate_only_mock = 1;
        run_card();
        certificate_only_mock = 0;
        allow_noncrypto = 0;
        reply = response(&offset, 0x00, 2u);
        assert(reply[0] == cases[i].sw1 && reply[1] == cases[i].sw2);
        assert(offset == output_size && certificate_encrypt_calls == 0u);
        assert(card_state == STATE_IDLE && cert_tx_pending == 0u);
        assert(cert_tx_len == 0u && cert_tx_offset == 0u);
    }
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
    assert(allow_noncrypto == 0);
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
    assert(memcmp(reply, "PQM1\0\0\0\2\0\0\0", 11) == 0);
    assert(reply[11] == EXPECTED_PROFILE_CAPABILITIES);
    assert(reply[12] == 0x90 && reply[13] == 0);
    assert(offset == output_size && card_state == STATE_IDLE);
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
    const unsigned char invalid_p1[] = {0x80, 0xF7, 5, 0, 0};
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
    assert(offset == output_size && card_state == STATE_IDLE);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
}

static void test_timing_probe_then_pq_fragments(void)
{
    const unsigned char timing[] = {0x80, 0xF7, 0, 0, 0};
    const unsigned char profile[] = {0x80, INS_GET_PROFILE, 0, 0, 0};
    const unsigned char trace[] = {0x80, INS_TRACE_LAST_CMD, 0, 0, 0};
    unsigned char fragment[225];
    const unsigned char *reply;
    size_t offset = sizeof(ATR);
    memset(fragment, 0xA5, sizeof(fragment));
    fragment[0] = 0x80; fragment[1] = INS_KEM_ENCAP;
    fragment[2] = 1; fragment[3] = 0; fragment[4] = 220;
    input_size = 0u;
    append_request(0x00, timing, sizeof(timing));
    append_request(0x00, fragment, sizeof(fragment));
    append_request(0x00, fragment, sizeof(fragment));
    append_request(0x00, trace, sizeof(trace));
    append_request(0x00, trace, sizeof(trace));
    append_request(0x00, profile, sizeof(profile));
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
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == 0x90 && reply[1] == 0x00);
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == 0x90 && reply[1] == 0x00);
    reply = response(&offset, 0x00, 7);
    assert(memcmp(reply, fragment, 5) == 0);
    assert(reply[5] == 0x90 && reply[6] == 0x00);
    reply = response(&offset, 0x00, 7);
    assert(memcmp(reply, fragment, 5) == 0); /* TRACE does not replace itself. */
    reply = response(&offset, 0x00, 14);
    assert(memcmp(reply, "PQM1\0\0\0\2\0\0\0", 11) == 0);
    assert(reply[11] == EXPECTED_PROFILE_CAPABILITIES);
    assert(reply[12] == 0x90 && reply[13] == 0x00);
    assert(offset == output_size);
    assert(kem_pk_accum_len == 440u); /* Both original PQ fragments contain only public-key bytes. */
    assert(card_state == STATE_IDLE); /* No cryptographic operation was reached. */
}

static void test_cached_counter_diagnostics_while_ready_do_not_touch_registers(void)
{
    const unsigned char diagnostic[] = {0x80, 0xF7, 2, 0, 0};
    const unsigned char snapshot[] = {0x80, 0xF7, 1, 0, 0};
    const unsigned char pin_snapshot[] = {0x80, 0xF7, 4, 0, 0};
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
    append_request(0x00, pin_snapshot, sizeof(pin_snapshot));
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
    assert(memcmp(reply, "PQM1", 4) == 0);
    assert(reply[11] == EXPECTED_PROFILE_CAPABILITIES);
    assert(reply[12] == 0x90 && reply[13] == 0);
#if PAKE_EMV_BENCHMARK
    reply = response(&offset, 0x00, 26);
    assert(memcmp(reply, "PQP1", 4) == 0 && reply[7] == 1u);
    assert(reply[15] == 0u && reply[23] == 0u && reply[24] == 0x90u && reply[25] == 0u);
#else
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == 0x6Du && reply[1] == 0u);
#endif
    assert(offset == output_size && card_state == STATE_IDLE);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
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
    append_request(0x00, invalid, sizeof(invalid));
    append_request(0x00, with_data, sizeof(with_data));
    run_card();
    reply = response(&offset, 0x00, 14);
    assert(memcmp(reply, "PQM1", 4) == 0);
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == SW1_WRONG_P1P2 && reply[1] == 0);
    reply = response(&offset, 0x00, 2);
    assert(reply[0] == SW1_WRONG_P1P2 && reply[1] == 0);
    assert(offset == output_size && kem_pk_accum_len == 0u);
}

#if PAKE_EMV_BENCHMARK && PAKE_EMV_SYSTICK_BENCHMARK
static void test_systick_fallback_profile_irq_vector_and_cache_only_query(void)
{
    const unsigned char reset[] = {0x80, 0xF7, 0, 0, 0};
    const unsigned char systick[] = {0x80, 0xF7, 3, 0, 0};
    const unsigned char dwt[] = {0x80, 0xF7, 2, 0, 0};
    const unsigned char snapshot[] = {0x80, 0xF7, 1, 0, 0};
    const unsigned char profile[] = {0x80, INS_GET_PROFILE, 0, 0, 0};
    unsigned char fragment[225] = {0x80, INS_KEM_ENCAP, 1, 0, 220};
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
    assert(memcmp(reply, "PQM1", 4u) == 0 && reply[11] == 0x7Fu);
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
    append_request(0x00, systick, sizeof(systick));
    run_card();
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, cached, sizeof(cached)) == 0);
    reply = response(&offset, 0x00, 42);
    assert(memcmp(reply, cached, sizeof(cached)) == 0);
    assert(offset == output_size);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
    assert(pake_benchmark_counters.flags == 3u && pake_benchmark_counters.command_count == 1u);

    /* PIN uses the same source; losing timer validity invalidates its totals. */
    pq_benchmark_record(INS_VERIFY_PIN, 100u, 140u);
    assert(pq_benchmark_pin_count == 1u && pq_benchmark_pin_cycles == 40u);
    fake_systick_masks = 1u;
    (void)pake_benchmark_now();
    assert(pake_benchmark_counters.flags == 0u);
    reads_before = fake_dwt_reads; writes_before = fake_dwt_writes;
    assert(pq_benchmark_pin_snapshot(cached) == 24u);
    assert(cached[7] == 0u && cached[15] == 0u && cached[23] == 0u);
    assert(pq_benchmark_pin_count == 0u && pq_benchmark_pin_cycles == 0u);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
    fake_systick_masks = 0u;

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

/* Exercise the complete existing transcript with deterministic crypto stand-ins. */
static void test_complete_core_transcript_and_separate_pin(int wrong_pin)
{
    const unsigned char reset[] = {0x80, 0xF7, 0, 0, 0};
    const unsigned char core_snapshot[] = {0x80, 0xF7, 1, 0, 0};
    const unsigned char pin_snapshot[] = {0x80, 0xF7, 4, 0, 0};
    const unsigned char proof[] = {0x80, INS_KEY_PROOF_K2, 0, 0, 32};
    unsigned char apdu[245], pin_command[40] = {0x80, INS_VERIFY_PIN, 0, 0, 34};
    const unsigned char *reply;
    size_t offset = sizeof(ATR), core_tx = 0u, core_rx = 0u;
    size_t remaining, fragment;
    unsigned int i;
    input_size = 0u;
    fake_dwt_ctrl = 0u;
    mock_hash_inits = mock_hash_updates = mock_hash_finals = 0u;
    append_request(0x00, reset, sizeof(reset));
    /* A corrupt T=1 request must not enter a handler or its counters. */
    apdu[0] = 0x80; apdu[1] = INS_KEM_ENCAP;
    apdu[2] = 0; apdu[3] = 0; apdu[4] = 0;
    append_request(0x00, apdu, 5u);
    input_bytes[input_size - 1u] ^= 1u;

    /* Four public-key uploads and three ciphertext continuation requests. */
    remaining = CRYPTO_PUBLICKEYBYTES;
    while (remaining) {
        fragment = remaining > 240u ? 240u : remaining;
        memset(apdu, 0xA5, sizeof(apdu));
        apdu[0] = 0x80; /* Preserve the original PQ upload's P1 continuation. */
        apdu[1] = INS_KEM_ENCAP;
        apdu[2] = remaining > fragment ? 1 : 0;
        apdu[3] = 0; apdu[4] = (unsigned char)fragment;
        append_request(0x00, apdu, fragment + 5u);
        core_tx += fragment + 5u;
        remaining -= fragment;
    }
    apdu[0] = 0x80; apdu[1] = INS_KEM_ENCAP;
    apdu[2] = 1; apdu[3] = 0; apdu[4] = 0;
    for (i = 0; i < 3u; ++i) {
        append_request(0x00, apdu, 5u); core_tx += 5u;
    }

    /* The padded certificate envelope needs 35 responses of at most 240 data bytes. */
    apdu[1] = INS_READ_CERTS; apdu[2] = 0;
    for (i = 0; i < 35u; ++i) {
        append_request(0x00, apdu, 5u); core_tx += 5u;
        apdu[2] = 1;
    }

    remaining = 12u + CRYPTO_CIPHERTEXTBYTES + 16u;
    while (remaining) {
        fragment = remaining > 240u ? 240u : remaining;
        memset(apdu, 0xD2, sizeof(apdu));
        apdu[0] = 0x80;
        apdu[1] = INS_ESTABLISH_KEY;
        apdu[2] = remaining > fragment ? 1 : 0;
        apdu[3] = 0; apdu[4] = (unsigned char)fragment;
        append_request(0x00, apdu, fragment + 5u);
        core_tx += fragment + 5u;
        remaining -= fragment;
    }
    append_request(0x00, core_snapshot, sizeof(core_snapshot));
    append_request(0x00, proof, sizeof(proof));
    memcpy(pin_command + 17u, "123456", 6u);
    if (wrong_pin) pin_command[17] = '0';
    /* Preserve the original case-4 trailing Le: 34-byte data, 40-byte command. */
    append_request(0x00, pin_command, sizeof(pin_command));
    append_request(0x00, pin_snapshot, sizeof(pin_snapshot));
    append_request(0x00, core_snapshot, sizeof(core_snapshot));
    allow_noncrypto = 1;
    advance_io_clock = 1;
    run_card();
    advance_io_clock = 0;
    allow_noncrypto = 0;

#if PAKE_EMV_BENCHMARK
    reply = response(&offset, 0x00, 42u);
    assert(memcmp(reply, "PEB1", 4u) == 0 && reply[7] == 1u && reply[15] == 0u);
#else
    reply = response(&offset, 0x00, 2u);
    assert(reply[0] == SW1_INS_NOT_SUP && reply[1] == 0u);
#endif
    for (i = 0u; i < 3u; ++i) {
        reply = response(&offset, 0x00, 2u); core_rx += 2u;
        assert(reply[0] == 0x90u && reply[1] == 0u);
    }
    remaining = CRYPTO_CIPHERTEXTBYTES;
    while (remaining) {
        fragment = remaining > 240u ? 240u : remaining;
        reply = response(&offset, 0x00, fragment + 2u); core_rx += fragment + 2u;
        assert(reply[0] == 0xC1u);
        remaining -= fragment;
        assert(reply[fragment] == (remaining ? 0x61u : 0x90u));
    }
    remaining = 8220u;
    while (remaining) {
        fragment = remaining > 240u ? 240u : remaining;
        reply = response(&offset, 0x00, fragment + 2u); core_rx += fragment + 2u;
        remaining -= fragment;
        assert(reply[fragment] == (remaining ? 0x61u : 0x90u));
    }
    for (i = 0u; i < 4u; ++i) {
        reply = response(&offset, 0x00, 2u); core_rx += 2u;
        assert(reply[0] == 0x90u && reply[1] == 0u);
    }
#if PAKE_EMV_BENCHMARK
    reply = response(&offset, 0x00, 42u);
    assert(memcmp(reply, "PEB1", 4u) == 0 && reply[15] == 46u);
#else
    reply = response(&offset, 0x00, 2u);
    assert(reply[0] == SW1_INS_NOT_SUP);
#endif
    reply = response(&offset, 0x00, 34u);
    for (i = 0u; i < 32u; ++i) assert(reply[i] == 0xA5u);
    assert(reply[32] == 0x90u && reply[33] == 0u);
    reply = response(&offset, 0x00, 2u);
    assert(reply[0] == (wrong_pin ? 0x63u : 0x90u));
    assert(reply[1] == (wrong_pin ? 0xC2u : 0u));
#if PAKE_EMV_BENCHMARK
    reply = response(&offset, 0x00, 26u);
    assert(memcmp(reply, "PQP1", 4u) == 0 && reply[7] == 1u && reply[15] == 1u);
    assert(reply[23] == 16u && reply[24] == 0x90u && reply[25] == 0u);
    reply = response(&offset, 0x00, 42u);
    assert(memcmp(reply, "PEB1", 4u) == 0 && reply[15] == 46u);
    assert(pake_benchmark_counters.command_count == 46u);
    assert(pake_benchmark_counters.pake_cycles == 22u);
    assert(pake_benchmark_counters.certificate_cycles == 50u);
    assert(pake_benchmark_counters.establish_key_cycles == 34u);
    assert(pq_benchmark_pin_count == 1u && pq_benchmark_pin_cycles == 16u);
    /* Each mocked blocking I/O call advanced 1000 cycles, all excluded above. */
    assert(fake_dwt_clock > 100000u);
#else
    for (i = 0u; i < 2u; ++i) {
        reply = response(&offset, 0x00, 2u);
        assert(reply[0] == SW1_INS_NOT_SUP);
    }
#endif
    assert(card_state == (wrong_pin ? STATE_IDLE : STATE_PIN_VERIFIED));
    assert(offset == output_size);
    assert(core_tx == 1826u && core_rx == 9080u);
    assert(core_tx + core_rx == 10906u);
    assert(mock_hash_inits == 2u && mock_hash_updates == 2u && mock_hash_finals == 2u);
}

#if PAKE_EMV_BENCHMARK
static void test_pin_snapshot_reset_failure_and_cache_only(void)
{
    unsigned char packet[24];
    unsigned int reads_before = fake_dwt_reads, writes_before = fake_dwt_writes;
    assert(pq_benchmark_pin_snapshot(packet) == sizeof(packet));
    assert(packet[15] == 1u && packet[23] == 16u);
    assert(packet[8] == 0x06u && packet[9] == 0x42u &&
           packet[10] == 0x2Cu && packet[11] == 0x40u);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
    pq_benchmark_reset();
    assert(pq_benchmark_pin_count == 0u && pq_benchmark_pin_cycles == 0u);
    pq_benchmark_record(0x20u, 0xFFFFFFF0u, 0x20u);
    assert(pq_benchmark_pin_count == 1u && pq_benchmark_pin_cycles == 48u);
    assert(pake_benchmark_counters.command_count == 0u);
    pake_benchmark_counters.flags = 0u;
    reads_before = fake_dwt_reads; writes_before = fake_dwt_writes;
    assert(pq_benchmark_pin_snapshot(packet) == sizeof(packet));
    assert(packet[7] == 0u && packet[15] == 0u && packet[23] == 0u);
    assert(fake_dwt_reads == reads_before && fake_dwt_writes == writes_before);
}
#endif

int main(void)
{
    test_connection_diagnostics_without_crypto_or_timing_reset();
    test_cached_counter_diagnostics_before_reset_and_validation();
    test_timing_probe_then_pq_fragments();
    test_cached_counter_diagnostics_while_ready_do_not_touch_registers();
    test_profile_request_validation();
    test_complete_core_transcript_and_separate_pin(0);
#if PAKE_EMV_BENCHMARK
    test_pin_snapshot_reset_failure_and_cache_only();
#endif
    test_complete_core_transcript_and_separate_pin(1);
    test_padded_certificate_envelope_and_fragment_status();
    test_certificate_request_validation_without_encryption();
#if PAKE_EMV_BENCHMARK && PAKE_EMV_SYSTICK_BENCHMARK
    test_systick_fallback_profile_irq_vector_and_cache_only_query();
#endif
    printf("PASS: live/cache diagnostics, T=1 dispatch, fixed PCB=00, full CA/B2/50, 8220-byte padded certificates, separate PIN, cached F7, TRACE and F8 (benchmark=%d)\n",
           PAKE_EMV_BENCHMARK);
    return 0;
}
