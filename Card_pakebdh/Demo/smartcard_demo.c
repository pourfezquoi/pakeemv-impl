/***************************************************************
*
* Copyright (c) 2018-2024, HSEC@YAWEE & Modified for KEM
* All rights reserved.
*
**************************************************************/
#include "demo.h"
#include "kem.h"
#include "hash_v101.h"
#include "aes_gcm.h"
#include "flash_v103.h"
#include "randombytes.h"
#include "cert_blobs.h"
#include "sk_c_m4.h"
#include "pake_benchmark.h"
#include "../../third_party/chic/chic.h"
#include "../../protocol/pake_emv/pake_emv.h"
#include "pake_emv_credential_keys.h"

#if PAKE_EMV_BENCHMARK && PAKE_EMV_SYSTICK_BENCHMARK
/* One owner in this translation unit; the linked SysTick vector calls here. */
unsigned char pake_benchmark_systick_irq(void)
{
    return pake_systick_interrupt();
}
#endif




/* Application phases correspond to Resp1, Resp2 and Resp3. APDU collection
 * and transmission phases only frame a single fixed-size protocol message. */
typedef enum {
    TX_NEEDS_BEGIN = 0,
    TX_EXPECT_M1,
    TX_COLLECT_M1,
    TX_SEND_M2,
    TX_EXPECT_M3,
    TX_SEND_M4,
    TX_EXPECT_M5,
    TX_COLLECT_M5,
    TX_HALTED
} PakeEmvPhase;

#define MAX_PIN_RETRIES 2u
static PakeEmvPhase protocol_phase = TX_NEEDS_BEGIN;
static unsigned char transaction_retries = 0;

/* Only these two values form the algorithm state returned by Resp1/Resp2. */
static unsigned char protocol_tk[PAKE_EMV_HASH_BYTES];
static unsigned char protocol_ctx[PAKE_EMV_HASH_BYTES];

/* Message framing buffers, erased immediately after the local step or send. */
static unsigned char protocol_x1[PAKE_EMV_X1_BYTES];
static unsigned short protocol_x1_len = 0;
static unsigned char protocol_tx[PAKE_EMV_ECERT_BYTES];
static unsigned short protocol_tx_len = 0;
static unsigned short protocol_tx_offset = 0;
static unsigned char protocol_m5[PAKE_EMV_M5_BYTES];
static unsigned short protocol_m5_len = 0;
static unsigned char cert_payload_plain[PAKE_EMV_CERT_PLAINTEXT_BYTES];

/* The key-output record is separate from running protocol state. It is never
 * exposed by APDU, and survives post-halt rejection until a new local F9 begin. */
static unsigned char recorded_key[PAKE_EMV_HASH_BYTES];
static unsigned char recorded_key_valid = 0;
unsigned char pin[PIN_LEN] = {'1', '2', '3', '4', '5', '6'};
extern unsigned short etu_clk[256];

// T=1 only ATR: TS=3B, T0=80 (only TD1 present), TD1=01 (protocol T=1), TCK=81
static unsigned char ATR[] = {0x3B, 0x80, 0x01, 0x81};
static unsigned char cmd[5];
static unsigned char last_cmd[5] = {0, 0, 0, 0, 0};
static unsigned char Lc[2];
static unsigned char sw[2];
static unsigned char t1_rx_pcb = 0x00;
static unsigned char trng[8] = {0x67, 0x67, 0x67, 0x67, 0x67, 0x67, 0x67, 0x67};
static unsigned char ping_ok[1] = {0x01};
static unsigned short etu_clocks;
static unsigned char t1_rx_buf[280];
static unsigned short t1_rx_len = 0;
static unsigned short t1_rx_off = 0;
static unsigned char t1_tx_buf[1200];
static unsigned short t1_tx_len = 0;
static unsigned char t1_last_i_payload[1200];
static unsigned short t1_last_i_len = 0;
static unsigned char t1_last_i_pcb = 0x00;
static unsigned char test_data[16] =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

// =============================================================
// Legacy performance totals, in CPU cycles
// =============================================================
static volatile unsigned int perf_t2c_cycles = 0;      // Terminal -> Card receive time
static volatile unsigned int perf_c2t_cycles = 0;      // Card -> Terminal send time
static volatile unsigned int perf_card_proc_cycles = 0;// Card local compute
static unsigned char perf_timer_inited = 0;

static unsigned int perf_cycle_now(void)
{
    return SYSTCVR & 0x00FFFFFFu; // SysTick 24-bit down counter
}

static unsigned int perf_cycle_diff(unsigned int start, unsigned int end)
{
    return (start >= end) ? (start - end) : (start + (0x01000000u - end));
}

static void perf_timer_init(void)
{
    if (perf_timer_inited) return;
    SYSTRVR = 0x00FFFFFFu;
    SYSTCVR = 0;
    SYSTCSR = 0x00000005u; // ENABLE=1, CLKSOURCE=1, TICKINT=0
    perf_timer_inited = 1;
}

// =============================================================
// Security helpers and low-level wrappers
// =============================================================

static void Delay(unsigned int j)
{
    unsigned int i;
    for(i = 0; i < j; i++);
}

// Constant-time comparison to avoid data-dependent timing
// Returns 1 for equality and 0 otherwise.
static unsigned char constant_time_cmp(const unsigned char *a, const unsigned char *b, unsigned int len) 
{
    unsigned char result = 0;
    for (unsigned int i = 0; i < len; i++) {
        result |= (a[i] ^ b[i]);
    }
    return (result == 0) ? 1 : 0; 
}

// Explicit clearing that the compiler must not optimize away
static void secure_memzero(void *ptr, unsigned int len) 
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

// Drain unexpected input from the FIFO to prevent overflow and stale data.
static void discard_data(unsigned short len)
{
    unsigned char tmp[16];
    while (len > 0) {
        unsigned short n = (len > (unsigned short)sizeof(tmp)) ? (unsigned short)sizeof(tmp) : len;
        receive_data(tmp, n);
        len -= n;
    }
}

static void perf_receive_data(unsigned char *dst, unsigned short len)
{
    unsigned int t0 = perf_cycle_now();
    receive_data(dst, len);
    perf_t2c_cycles += perf_cycle_diff(t0, perf_cycle_now());
}

static void perf_send_data(unsigned char *src, unsigned short len)
{
    unsigned int t0 = perf_cycle_now();
    send_data(src, len);
    perf_c2t_cycles += perf_cycle_diff(t0, perf_cycle_now());
}

#define receive_data perf_receive_data
#define send_data    perf_send_data

#define PERF_PROC_WRAP(expr) do { unsigned int __t0 = perf_cycle_now(); (expr); perf_card_proc_cycles += perf_cycle_diff(__t0, perf_cycle_now()); } while (0)
#define PERF_PROC_CALL_INT(dst, expr) do { unsigned int __t0 = perf_cycle_now(); (dst) = (expr); perf_card_proc_cycles += perf_cycle_diff(__t0, perf_cycle_now()); } while (0)


static void put_u32_be(unsigned char *dst, unsigned int v)
{
    dst[0] = (unsigned char)((v >> 24) & 0xFF);
    dst[1] = (unsigned char)((v >> 16) & 0xFF);
    dst[2] = (unsigned char)((v >> 8) & 0xFF);
    dst[3] = (unsigned char)(v & 0xFF);
}

static unsigned short build_timing_tlv(unsigned char *out)
{
    put_u32_be(out + 0, perf_t2c_cycles);
    put_u32_be(out + 4, perf_c2t_cycles);
    put_u32_be(out + 8, perf_card_proc_cycles);
    put_u32_be(out + 12, 0u);
    return 16;
}

/* Public, side-effect-free profile query; no key or session data is returned. */
static unsigned short build_protocol_profile(unsigned char *out)
{
    unsigned int capabilities = 0x00000007u; /* C1, B2, and 50 handlers */
#if PAKE_EMV_BENCHMARK
    capabilities |= 0x00000018u; /* F7 timing and cached counter diagnostics. */
#if PAKE_EMV_SYSTICK_BENCHMARK
    capabilities |= 0x00000020u; /* Optional core-clock SysTick IRQ fallback. */
#endif
#endif
    out[0] = 'P'; out[1] = 'E'; out[2] = 'M'; out[3] = '1';
    put_u32_be(out + 4, 3u); /* Manuscript six-message protocol with full CHIC. */
    put_u32_be(out + 8, capabilities);
    return 12;
}

static void send_proc_byte_if_t0(unsigned char ins)
{
    (void)ins;
    // T=1 mode: no T=0 procedure byte exchange.
}


static void t1_send_response_block(unsigned char pcb, const unsigned char *payload, unsigned short len)
{
    (void)pcb;
    if (len > 0) {
        send_data((unsigned char *)payload, len);
    }
}


/* Erase the returned algorithm state and all framing/scratch buffers. This
 * intentionally leaves the separately recorded K and transaction retry n. */
static void clear_running_state(void)
{
    secure_memzero(protocol_tk, sizeof(protocol_tk));
    secure_memzero(protocol_ctx, sizeof(protocol_ctx));
    secure_memzero(protocol_x1, sizeof(protocol_x1));
    secure_memzero(protocol_tx, sizeof(protocol_tx));
    secure_memzero(protocol_m5, sizeof(protocol_m5));
    secure_memzero(cert_payload_plain, sizeof(cert_payload_plain));
    protocol_x1_len = 0;
    protocol_tx_len = 0;
    protocol_tx_offset = 0;
    protocol_m5_len = 0;
}

static void halt_protocol(void)
{
    clear_running_state();
    protocol_phase = TX_HALTED;
}

static void begin_transaction(void)
{
    clear_running_state();
    secure_memzero(recorded_key, sizeof(recorded_key));
    recorded_key_valid = 0;
    transaction_retries = 0;
    protocol_phase = TX_EXPECT_M1;
}

static unsigned short reject_protocol(unsigned char *out, unsigned char sw1)
{
    halt_protocol();
    out[0] = sw1;
    out[1] = sw1 == SW1_SEC_STATUS_NOT_SATISFIED ? SW2_SEC_STATUS_NOT_SATISFIED : SW2_00;
    return 2;
}

/* SHA-256 PIN adaptation is explicit input preparation, outside CHIC's HIC. */
static void password_input(unsigned char out[CHIC_PASSWORD_BYTES])
{
    HASH_CTX hash;
    Hash_Init(&hash, SHA_256);
    Hash_Updata(&hash, pin, PIN_LEN);
    Hash_Final(&hash, out);
    secure_memzero(&hash, sizeof(hash));
}

/* Resp1: preserve the exact author's Respond and bind the complete public X1
 * (including its explicit SID prefix), X2 and suite in ctx1. */
static int resp_1(void)
{
    unsigned char pw[CHIC_PASSWORD_BYTES];
    int result;
    PERF_PROC_WRAP(password_input(pw));
    PERF_PROC_CALL_INT(result, chic_respond(protocol_tk, protocol_tx,
                          protocol_x1 + CHIC_SID_BYTES, pw, protocol_x1));
    secure_memzero(pw, sizeof(pw));
    if (result != 0) return -1;
    pake_emv_ctx1(protocol_ctx, protocol_x1, protocol_tx);
    secure_memzero(protocol_x1, sizeof(protocol_x1));
    protocol_x1_len = 0;
    protocol_tx_len = PAKE_EMV_X2_BYTES;
    protocol_tx_offset = 0;
    protocol_phase = TX_SEND_M2;
    return 0;
}

/* Return at most 240 payload bytes, then the appropriate continuation SW.
 * Only public outgoing message bytes remain in this temporary framing state. */
static unsigned short next_protocol_fragment(unsigned char *out)
{
    unsigned short remaining = (unsigned short)(protocol_tx_len - protocol_tx_offset);
    unsigned short fragment = remaining > 240u ? 240u : remaining;
    memcpy(out, protocol_tx + protocol_tx_offset, fragment);
    protocol_tx_offset = (unsigned short)(protocol_tx_offset + fragment);
    remaining = (unsigned short)(protocol_tx_len - protocol_tx_offset);
    if (remaining != 0) {
        out[fragment] = 0x61;
        out[fragment + 1] = remaining > 255u ? 0 : (unsigned char)remaining;
    } else {
        PakeEmvPhase next = protocol_phase == TX_SEND_M2 ? TX_EXPECT_M3 : TX_EXPECT_M5;
        secure_memzero(protocol_tx, sizeof(protocol_tx));
        protocol_tx_len = 0;
        protocol_tx_offset = 0;
        protocol_phase = next;
        out[fragment] = SW1_SUCCESS;
        out[fragment + 1] = SW2_00;
    }
    return (unsigned short)(fragment + 2);
}

/* Resp2: only a well-formed M3 with an incorrect pi1 may emit RETRY. Other
 * failures return -1; no encryption/decryption result is used after failure. */
static int resp_2(const unsigned char m3[PAKE_EMV_M3_BYTES])
{
    unsigned char expected[PAKE_EMV_TAG_BYTES];
    unsigned char ctx2[PAKE_EMV_HASH_BYTES];
    unsigned char cert_key[PAKE_EMV_HASH_BYTES];
    unsigned char iv[12];
    unsigned char tag[16];
    int result = -1;
    pake_emv_kc1(expected, protocol_tk, protocol_ctx, m3);
    if (!constant_time_cmp(expected, m3 + PAKE_EMV_NONCE_BYTES, sizeof(expected))) {
        secure_memzero(expected, sizeof(expected));
        return -2;
    }
    secure_memzero(expected, sizeof(expected));
    pake_emv_ctx2(ctx2, m3, protocol_ctx);
    pake_emv_cert_key(cert_key, protocol_tk, ctx2);
    if (pake_emv_pad_certificates(cert_payload_plain, certC_der, certC_der_len,
                                 certIS_der, certIS_der_len) == 0 &&
        randombytes(iv, sizeof(iv)) == 0) {
        aes_gcm_encrypt_full(cert_key, iv, cert_payload_plain, sizeof(cert_payload_plain),
                             NULL, 0, protocol_tx + 12, tag);
        memcpy(protocol_tx, iv, sizeof(iv));
        memcpy(protocol_tx + 12 + sizeof(cert_payload_plain), tag, sizeof(tag));
        pake_emv_ctx3(protocol_ctx, protocol_tx, ctx2);
        protocol_tx_len = PAKE_EMV_ECERT_BYTES;
        protocol_tx_offset = 0;
        protocol_phase = TX_SEND_M4;
        result = 0;
    }
    secure_memzero(ctx2, sizeof(ctx2));
    secure_memzero(cert_key, sizeof(cert_key));
    secure_memzero(iv, sizeof(iv));
    secure_memzero(tag, sizeof(tag));
    secure_memzero(cert_payload_plain, sizeof(cert_payload_plain));
    return result;
}

/* Resp3: an implicit-rejection ML-KEM result is accepted only through pi2.
 * No candidate K is recorded before that confirmation verifies. */
static int resp_3(unsigned char pi3[PAKE_EMV_M6_BYTES])
{
    unsigned char ec_key[PAKE_EMV_HASH_BYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss[CRYPTO_BYTES];
    unsigned char ctx4[PAKE_EMV_HASH_BYTES];
    unsigned char ctx5[PAKE_EMV_HASH_BYTES];
    unsigned char pkh[PAKE_EMV_HASH_BYTES];
    unsigned char expected[PAKE_EMV_TAG_BYTES];
    pake_emv_keys keys;
    int result = -1;
    pake_emv_ec_key(ec_key, protocol_tk, protocol_ctx);
    if (aes_gcm_decrypt_verify(ec_key, protocol_m5, protocol_m5 + 12,
                               CRYPTO_CIPHERTEXTBYTES, NULL, 0,
                               protocol_m5 + 12 + CRYPTO_CIPHERTEXTBYTES, ct) == 0 &&
        crypto_kem_dec(ss, ct, sk_c_raw) == 0) {
        pake_emv_ctx4(ctx4, protocol_m5, protocol_ctx);
        pake_emv_pkh(pkh, pake_emv_card_public_key, pake_emv_issuer_public_key);
        pake_emv_derive_keys(&keys, protocol_tk, ss, pkh, ctx4);
        pake_emv_kc2(expected, keys.k2, ctx4);
        if (constant_time_cmp(expected, protocol_m5 + PAKE_EMV_EC_BYTES, sizeof(expected))) {
            pake_emv_ctx5(ctx5, protocol_m5 + PAKE_EMV_EC_BYTES, ctx4);
            pake_emv_kc3(pi3, keys.k3, ctx5);
            memcpy(recorded_key, keys.key, sizeof(recorded_key));
            recorded_key_valid = 1;
            result = 0;
        }
    }
    secure_memzero(ec_key, sizeof(ec_key));
    secure_memzero(ct, sizeof(ct));
    secure_memzero(ss, sizeof(ss));
    secure_memzero(ctx4, sizeof(ctx4));
    secure_memzero(ctx5, sizeof(ctx5));
    secure_memzero(pkh, sizeof(pkh));
    secure_memzero(expected, sizeof(expected));
    secure_memzero(&keys, sizeof(keys));
    if (result != 0) secure_memzero(pi3, PAKE_EMV_M6_BYTES);
    halt_protocol();
    return result;
}

// =============================================================
// Main protocol processing
// =============================================================

void SCard_Demo(void)
{
    perf_timer_init();
    // ------------------------------
    // Initialize the ISO 7816 hardware.
    // ------------------------------
    SCI_Pad_Init(0);
    MCGCR |= SCI_CLKEN;

    // Enable T=1 protocol mode at SCI controller level.
    SCI_CR1 = SCI_CR1_SRST | SCI_CR1_T;

    SCI_TCR = SCI_TCR_CNTEN | 0x190;
    while(!(SCI_SR & SCI_SR_CNTOR));
    SCI_SR = SCI_SR_CNTOR;

    send_data(ATR, (unsigned short)sizeof(ATR));

    SCI_CR1 &= ~0x000000E0;  // not retry

    etu_clocks = 372;
    
    // Clear security state at startup.
    clear_running_state();
    secure_memzero(recorded_key, sizeof(recorded_key));
    recorded_key_valid = 0;
    transaction_retries = 0;
    protocol_phase = TX_NEEDS_BEGIN;

    while(1)
    {
        unsigned char t1hdr[3];
        receive_data(t1hdr, 3);

        // Minimal T=1 block handling for reader interoperability:
        // - I-block bit 6 is N(S); both sequence values carry APDUs.
        // - S-block request: echo as S-block response (set response bit)
        // - Application-level APDU fragmentation keeps each INF below 256 bytes.
        // - This minimal handler does not implement T=1 R-block recovery.
        {
            unsigned char pcb = t1hdr[1];
            unsigned char len = t1hdr[2];
            unsigned char inf[300];
            unsigned char lrc;
            unsigned char calc = t1hdr[0] ^ t1hdr[1] ^ t1hdr[2];
            if (len > 0) {
                receive_data(inf, len);
                for (unsigned short i = 0; i < len; i++) calc ^= inf[i];
            }
            receive_data(&lrc, 1);
            if (calc != lrc) {
                continue;
            }

            if ((pcb & 0xC0) == 0xC0) { // S-block
                if ((pcb & 0x20) == 0x00) {
                    unsigned char rh[3] = {t1hdr[0], (unsigned char)(pcb | 0x20), len};
                    unsigned char rl = rh[0] ^ rh[1] ^ rh[2];
                    for (unsigned short i = 0; i < len; i++) rl ^= inf[i];
                    send_data(rh, 3);
                    if (len > 0) send_data(inf, len);
                    send_data(&rl, 1);
                }
                continue;
            }

            if ((pcb & 0x80) == 0 && len < 5) {
                /* A valid transport block with a truncated APDU is a decoding
                 * failure, not a new transaction or an implicit retry. */
                unsigned char malformed[2] = {SW1_WRONG_LC, SW2_00};
                unsigned char rh[3] = {t1hdr[0], (unsigned char)(pcb & 0x40), 2};
                unsigned char rl = (unsigned char)(rh[0] ^ rh[1] ^ rh[2] ^ malformed[0]);
                halt_protocol();
                send_data(rh, sizeof(rh));
                send_data(malformed, sizeof(malformed));
                send_data(&rl, 1);
                continue;
            }

            if ((pcb & 0x80) == 0x00 && len >= 5) { // I-block APDU in INF; N(S) may be 0 or 1
#if PAKE_EMV_BENCHMARK
                unsigned char benchmark_core_command =
                    ((inf[APDU_CLA] & 0xEF) == CLA_VENDOR &&
                     (inf[APDU_INS] == INS_PAKE_INIT ||
                      inf[APDU_INS] == INS_READ_CERTS ||
                      inf[APDU_INS] == INS_ESTABLISH_KEY));
                uint32_t benchmark_start = benchmark_core_command ? pake_benchmark_now() : 0u;
#endif
                memcpy(cmd, inf, 5);
                unsigned char cla_base_t1 = (unsigned char)(cmd[APDU_CLA] & 0xEF);
                unsigned char out[242];
                unsigned short outLen = 0;

                /* TRACE must describe the preceding APDU, not its own request. */
                if (!(cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_TRACE_LAST_CMD)) {
                    memcpy(last_cmd, cmd, sizeof(cmd));
                }

                if (cla_base_t1 == CLA_ISO7816 && cmd[APDU_INS] == INS_GET_CHALLENGE && (cmd[APDU_LC] == 4 || cmd[APDU_LC] == 8)) {
                    memcpy(out, trng, cmd[APDU_LC]); outLen = cmd[APDU_LC];
                    out[outLen++] = SW1_SUCCESS; out[outLen++] = SW2_00;
                } else if (cla_base_t1 == CLA_ISO7816 && cmd[APDU_INS] == INS_PING && (cmd[APDU_LC] == 4 || cmd[APDU_LC] == 8)) {
                    memcpy(out, trng, cmd[APDU_LC]); outLen = cmd[APDU_LC];
                    out[outLen++] = SW1_SUCCESS; out[outLen++] = SW2_00;
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_PING) {
                    out[0] = ping_ok[0]; out[1] = SW1_SUCCESS; out[2] = SW2_00; outLen = 3;
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_TRACE_LAST_CMD) {
                    memcpy(out, last_cmd, 5); out[5] = SW1_SUCCESS; out[6] = SW2_00; outLen = 7;
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_ECHO) {
                    out[0] = cmd[APDU_P1]; out[1] = cmd[APDU_P2]; out[2] = SW1_SUCCESS; out[3] = SW2_00; outLen = 4;
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_GET_TIMING) {
                    outLen = build_timing_tlv(out);
                    out[outLen++] = SW1_SUCCESS;
                    out[outLen++] = SW2_00;
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_GET_PROFILE) {
                    if (len != 5 || cmd[APDU_P1] != 0 || cmd[APDU_P2] != 0) {
                        out[0] = SW1_WRONG_P1P2; out[1] = SW2_00; outLen = 2;
                    } else {
                        outLen = build_protocol_profile(out);
                        out[outLen++] = SW1_SUCCESS;
                        out[outLen++] = SW2_00;
                    }
#if PAKE_EMV_BENCHMARK
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == PAKE_BENCHMARK_INS) {
                    if (len != 5 || cmd[APDU_P2] != 0 ||
                        cmd[APDU_P1] > (PAKE_EMV_SYSTICK_BENCHMARK ? 3u : 2u)) {
                        out[0] = SW1_WRONG_P1P2; out[1] = SW2_00; outLen = 2;
                    } else {
#if PAKE_EMV_SYSTICK_BENCHMARK
                        if (cmd[APDU_P1] == 3) {
                            outLen = pake_benchmark_systick_snapshot(out);
                        } else
#endif
                        if (cmd[APDU_P1] == 2) {
                            outLen = pake_benchmark_diagnostic_snapshot(out);
                        } else {
                            if (cmd[APDU_P1] == 0) pake_benchmark_reset();
                            outLen = pake_benchmark_snapshot(out);
                        }
                        out[outLen++] = SW1_SUCCESS;
                        out[outLen++] = SW2_00;
                    }
#else
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == 0xF7) {
                    /* Unsupported measurement diagnostics do not change the
                     * independently running protocol, retry n or key record. */
                    out[0] = SW1_INS_NOT_SUP; out[1] = SW2_00; outLen = 2;
#endif
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_BEGIN_TRANSACTION) {
                    /* Local transport activation, outside M1..M6 and timings. */
                    if (len != 5 || cmd[APDU_LC] != 0 || cmd[APDU_P1] != 0 || cmd[APDU_P2] != 0) {
                        out[0] = SW1_WRONG_LC; out[1] = SW2_00; outLen = 2;
                    } else {
                        begin_transaction();
                        out[0] = SW1_SUCCESS; out[1] = SW2_00; outLen = 2;
                    }
                } else if (cla_base_t1 == CLA_VENDOR &&
                           (cmd[APDU_INS] == INS_KEY_PROOF || cmd[APDU_INS] == INS_KEY_PROOF_K2 ||
                            cmd[APDU_INS] == INS_SS2_PROOF)) {
                    out[0] = SW1_INS_NOT_SUP; out[1] = SW2_00; outLen = 2;
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_PAKE_INIT) {
                    unsigned short data_len = (unsigned short)(len - 5);
                    if (cmd[APDU_P2] != 0 || cmd[APDU_P1] > 1 || cmd[APDU_LC] != data_len) {
                        outLen = reject_protocol(out, SW1_WRONG_LC);
                    } else if (data_len == 0) {
                        if (cmd[APDU_P1] == 1 && protocol_phase == TX_SEND_M2) {
                            outLen = next_protocol_fragment(out);
                        } else {
                            outLen = reject_protocol(out, SW1_SEC_STATUS_NOT_SATISFIED);
                        }
                    } else if (protocol_phase != TX_EXPECT_M1 && protocol_phase != TX_COLLECT_M1) {
                        outLen = reject_protocol(out, SW1_SEC_STATUS_NOT_SATISFIED);
                    } else if (protocol_x1_len + data_len > PAKE_EMV_X1_BYTES) {
                        outLen = reject_protocol(out, SW1_WRONG_LENGTH);
                    } else {
                        memcpy(protocol_x1 + protocol_x1_len, inf + 5, data_len);
                        protocol_x1_len = (unsigned short)(protocol_x1_len + data_len);
                        protocol_phase = TX_COLLECT_M1;
                        if (cmd[APDU_P1] == 1 && protocol_x1_len < PAKE_EMV_X1_BYTES) {
                            out[0] = SW1_SUCCESS; out[1] = SW2_00; outLen = 2;
                        } else if (cmd[APDU_P1] == 1 || protocol_x1_len != PAKE_EMV_X1_BYTES) {
                            outLen = reject_protocol(out, SW1_WRONG_LENGTH);
                        } else if (resp_1() != 0) {
                            outLen = reject_protocol(out, SW1_INTERNAL_ERR);
                        } else {
                            outLen = next_protocol_fragment(out);
                        }
                    }
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_READ_CERTS) {
                    unsigned short data_len = (unsigned short)(len - 5);
                    if (cmd[APDU_P2] != 0 || cmd[APDU_P1] > 1 || cmd[APDU_LC] != data_len) {
                        outLen = reject_protocol(out, SW1_WRONG_LC);
                    } else if (cmd[APDU_P1] == 1) {
                        if (data_len == 0 && protocol_phase == TX_SEND_M4) {
                            outLen = next_protocol_fragment(out);
                        } else {
                            outLen = reject_protocol(out, SW1_SEC_STATUS_NOT_SATISFIED);
                        }
                    } else if (protocol_phase != TX_EXPECT_M3) {
                        outLen = reject_protocol(out, SW1_SEC_STATUS_NOT_SATISFIED);
                    } else if (data_len != PAKE_EMV_M3_BYTES) {
                        outLen = reject_protocol(out, SW1_WRONG_LC);
                    } else {
                        int result = resp_2(inf + 5);
                        if (result == 0) {
                            outLen = next_protocol_fragment(out);
                        } else if (result == -2 && transaction_retries < MAX_PIN_RETRIES) {
                            /* Retry preserves n and no previous PAKE/context state. */
                            ++transaction_retries;
                            clear_running_state();
                            protocol_phase = TX_EXPECT_M1;
                            memcpy(out, "RETRY", 5);
                            out[5] = SW1_SUCCESS; out[6] = SW2_00; outLen = 7;
                        } else {
                            outLen = reject_protocol(out, SW1_SEC_STATUS_NOT_SATISFIED);
                        }
                    }
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_ESTABLISH_KEY) {
                    unsigned short data_len = (unsigned short)(len - 5);
                    if (cmd[APDU_P2] != 0 || cmd[APDU_P1] > 1 || cmd[APDU_LC] != data_len) {
                        outLen = reject_protocol(out, SW1_WRONG_LC);
                    } else if (protocol_phase != TX_EXPECT_M5 && protocol_phase != TX_COLLECT_M5) {
                        outLen = reject_protocol(out, SW1_SEC_STATUS_NOT_SATISFIED);
                    } else if (data_len == 0 || protocol_m5_len + data_len > PAKE_EMV_M5_BYTES) {
                        outLen = reject_protocol(out, SW1_WRONG_LENGTH);
                    } else {
                        memcpy(protocol_m5 + protocol_m5_len, inf + 5, data_len);
                        protocol_m5_len = (unsigned short)(protocol_m5_len + data_len);
                        protocol_phase = TX_COLLECT_M5;
                        if (cmd[APDU_P1] == 1 && protocol_m5_len < PAKE_EMV_M5_BYTES) {
                            out[0] = SW1_SUCCESS; out[1] = SW2_00; outLen = 2;
                        } else if (cmd[APDU_P1] == 1 || protocol_m5_len != PAKE_EMV_M5_BYTES) {
                            outLen = reject_protocol(out, SW1_WRONG_LENGTH);
                        } else if (resp_3(out) == 0) {
                            out[PAKE_EMV_M6_BYTES] = SW1_SUCCESS;
                            out[PAKE_EMV_M6_BYTES + 1] = SW2_00;
                            outLen = PAKE_EMV_M6_BYTES + 2;
                        } else {
                            outLen = reject_protocol(out, SW1_SEC_STATUS_NOT_SATISFIED);
                        }
                    }
                } else {
                    outLen = reject_protocol(out, SW1_INS_NOT_SUP);
                }

                unsigned char rh[3] = {t1hdr[0], (unsigned char)(pcb & 0x40), (unsigned char)outLen};
                unsigned char rl = rh[0] ^ rh[1] ^ rh[2];
                for (unsigned short i = 0; i < outLen; i++) rl ^= out[i];
#if PAKE_EMV_BENCHMARK
                if (benchmark_core_command) {
                    pake_benchmark_record(cmd[APDU_INS], benchmark_start, pake_benchmark_now());
                }
#endif
                send_data(rh, 3);
                send_data(out, outLen);
                send_data(&rl, 1);
                continue;
            }
            continue;
        }

        /* Only the advertised T=1 dispatcher is supported. */
    }
}
