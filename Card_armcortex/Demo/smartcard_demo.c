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
#include "pq_benchmark.h"
#include "../../protocol/pake_emv/certificate_envelope.h"

#if PAKE_EMV_BENCHMARK
static unsigned char benchmark_timer_inited;

static void benchmark_timer_init(void)
{
    if (benchmark_timer_inited) return;
    SYSTRVR = 0x00FFFFFFu;
    SYSTCVR = 0;
    SYSTCSR = 0x00000005u; /* ENABLE=1, CLKSOURCE=1, TICKINT=0. */
    benchmark_timer_inited = 1;
}
#endif

#if PAKE_EMV_BENCHMARK && PAKE_EMV_SYSTICK_BENCHMARK
/* One owner in this translation unit; the linked SysTick vector calls here. */
unsigned char pake_benchmark_systick_irq(void)
{
    return pake_systick_interrupt();
}
#endif

/* Public, side-effect-free query identifying PQ CA/B2/50 support. */
static unsigned short build_protocol_profile(unsigned char *out)
{
    uint32_t capabilities = 0x00000007u; /* CA, B2, and 50 handlers. */
#if PAKE_EMV_BENCHMARK
    capabilities |= 0x00000058u; /* F7, cached DWT diagnostics, separate PIN timing. */
#if PAKE_EMV_SYSTICK_BENCHMARK
    capabilities |= 0x00000020u; /* SysTick fallback and cached diagnostics. */
#endif
#endif
    out[0] = 'P'; out[1] = 'Q'; out[2] = 'M'; out[3] = '1';
    out[4] = 0; out[5] = 0; out[6] = 0; out[7] = 2;
    out[8] = (unsigned char)(capabilities >> 24);
    out[9] = (unsigned char)(capabilities >> 16);
    out[10] = (unsigned char)(capabilities >> 8);
    out[11] = (unsigned char)capabilities;
    return 12;
}

/*
 * NOTE FOR HOST SIDE:
 * The Android CCID side must use bmTCCKST1 = 0x10 for T=1 + LRC (direct convention),
 * not 0x00. The original host code used 0x00 while this card computes LRC only.
 * If the host and card disagree on the T=1 checksum parameter, the card will reject
 * the block and the reader will time out.
 */



// =============================================================
// Security state machine
// =============================================================
#define STATE_IDLE             0x00  // Initial/idle state
#define STATE_KEM_ENCAP_DONE   0x01  // KEM encapsulation completed; k1 is available
#define STATE_KEM_ESTABLISHED  0x02  // Final session key k2 established
#define STATE_GET_CHALLENGE    0x03
#define STATE_PIN_VERIFIED     0x04  // Peer authentication completed

static unsigned char card_state = STATE_IDLE;

// Flash address and maximum count for failed PIN attempts
// WARNING: erasing PIN_RETRY_ADDR also erases any other data in that flash sector.
#define PIN_RETRY_ADDR         0x0800F000 
#define MAX_PIN_RETRY          3

// =============================================================
// Global buffers avoid large stack allocations
// =============================================================
extern unsigned short etu_clk[256];
extern void WriteFlash(unsigned int *buff, unsigned int addr, unsigned int len);
extern void SectorEraseFlash(unsigned int addr);
extern void ReadFlash_B(unsigned char *buff, unsigned int addr, unsigned int blen);

unsigned char buff[MAX_BUFF_LEN];
unsigned char cert_payload_plain[PAKE_EMV_CERT_PLAINTEXT_BYTES];
static unsigned char cert_payload_cipher[PAKE_EMV_ECERT_BYTES];
unsigned char cert_buff[CERT_LEN];
unsigned char skc[KYBER_SECRETKEYBYTES];
unsigned char nonce[NONCE_LEN];
unsigned char pin[PIN_LEN] = {'1', '2', '3', '4', '5', '6'};
unsigned char MK_AC[MK_AC_LEN]; 

// Global buffers used by the KEM
//testing
unsigned char global_ct_test[5]; // Ciphertext
static unsigned char debug_magic_buf[5];
static unsigned char debug_ss2_buf[CRYPTO_BYTES];


unsigned char global_ct[CRYPTO_CIPHERTEXTBYTES]; // Ciphertext
unsigned char global_ss[2*CRYPTO_BYTES];
unsigned char global_ss_1[CRYPTO_BYTES];         // Shared secret
unsigned char global_ss_2[CRYPTO_BYTES];
unsigned char global_k1[CRYPTO_BYTES];           // Derived key
unsigned char global_k2[CRYPTO_BYTES];           // Derived key

// KEM input accumulator for application-level APDU chaining
static unsigned char kem_pk_accum[CRYPTO_PUBLICKEYBYTES];
static unsigned short kem_pk_accum_len = 0;
static unsigned short kem_ct_tx_offset = 0;
static unsigned char kem_ct_pending = 0;
static unsigned short cert_tx_offset = 0;
static unsigned short cert_tx_len = 0;
static unsigned char cert_tx_pending = 0;
static unsigned short est_c2_len = 0;
static unsigned char t1_pin_retry_cnt = MAX_PIN_RETRY;

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


// Send a ciphertext fragment; return 61xx when additional fragments remain.
static void send_kem_ct_fragment(void)
{
    const unsigned short CHUNK = 240;
    unsigned short remaining = (unsigned short)CRYPTO_CIPHERTEXTBYTES - kem_ct_tx_offset;
    unsigned short to_send = (remaining > CHUNK) ? CHUNK : remaining;

    if (to_send > 0) {
        // Do not add a procedure byte for KEM input; some readers would wait for additional data.
        send_data(global_ct + kem_ct_tx_offset, to_send);
        kem_ct_tx_offset += to_send;
    }

    if (kem_ct_tx_offset < (unsigned short)CRYPTO_CIPHERTEXTBYTES) {
        unsigned short left = (unsigned short)CRYPTO_CIPHERTEXTBYTES - kem_ct_tx_offset;
        sw[0] = 0x61;
        sw[1] = (left > 0xFF) ? 0x00 : (unsigned char)left;
        kem_ct_pending = 1;
    } else {
        sw[0] = SW1_SUCCESS;
        sw[1] = SW2_00;
        kem_ct_pending = 0;
        kem_ct_tx_offset = 0;
    }
}

// Clear session material on an error, reset, or transaction completion.
static void reset_security_state(void) 
{
    card_state = STATE_IDLE;
    
    // Clear all derived keys and shared secrets.
    secure_memzero(global_k1, sizeof(global_k1));
    secure_memzero(global_k2, sizeof(global_k2));
    secure_memzero(global_ss, sizeof(global_ss));
    secure_memzero(global_ss_1, sizeof(global_ss_1));
    secure_memzero(global_ss_2, sizeof(global_ss_2));
    
    // Clear RAM copies of the long-term private key and master key.
    secure_memzero(skc, sizeof(skc));
    secure_memzero(MK_AC, sizeof(MK_AC));
    
    // Clear challenges and temporary plaintext/ciphertext buffers.
    secure_memzero(nonce, sizeof(nonce));
    secure_memzero(global_ct, sizeof(global_ct));
    secure_memzero(buff, sizeof(buff)); 
    secure_memzero(cert_payload_plain, sizeof(cert_payload_plain));
    secure_memzero(cert_payload_cipher, sizeof(cert_payload_cipher));
    cert_tx_offset = 0;
    cert_tx_len = 0;
    cert_tx_pending = 0;

    // Clear the KEM fragment accumulator.
    secure_memzero(kem_pk_accum, sizeof(kem_pk_accum));
    kem_pk_accum_len = 0;
    kem_ct_tx_offset = 0;
    kem_ct_pending = 0;
}

/* The certificate envelope uses its own exact-size buffer: the common 8192
 * byte plaintext plus the existing 12-byte nonce and 16-byte GCM tag. */
static unsigned short next_certificate_fragment(unsigned char *out)
{
    unsigned short remaining = (unsigned short)(cert_tx_len - cert_tx_offset);
    unsigned short fragment = remaining > 240u ? 240u : remaining;
    memcpy(out, cert_payload_cipher + cert_tx_offset, fragment);
    cert_tx_offset = (unsigned short)(cert_tx_offset + fragment);
    remaining = (unsigned short)(cert_tx_len - cert_tx_offset);
    if (remaining != 0) {
        out[fragment] = 0x61;
        out[fragment + 1] = remaining > 255u ? 0 : (unsigned char)remaining;
    } else {
        cert_tx_pending = 0;
        cert_tx_offset = 0;
        cert_tx_len = 0;
        secure_memzero(cert_payload_cipher, sizeof(cert_payload_cipher));
        out[fragment] = SW1_SUCCESS;
        out[fragment + 1] = SW2_00;
    }
    return (unsigned short)(fragment + 2);
}

// Matches the host derive_k1(ss): SHA-256(ss).
static void k_derive(unsigned char *kOut, const unsigned char *kIn, unsigned int len)
{
    HASH_CTX ctx;
    Hash_Init(&ctx, SHA_256);
    Hash_Updata(&ctx, (unsigned char *)kIn, len);
    Hash_Final(&ctx, kOut);
}

// Update the flash retry count by erasing its sector and writing one word.
static void update_pin_retry_counter(unsigned char retry_cnt)
{
    unsigned int retry_word = (unsigned int)retry_cnt; // Convert to an unsigned 32-bit word.
    SectorEraseFlash(PIN_RETRY_ADDR);                  // Erase the corresponding sector.
    WriteFlash(&retry_word, PIN_RETRY_ADDR, 1);        // Write one word.
}

// =============================================================
// PPS handling
// =============================================================
static void handle_pps(void)
{
    etu_clocks = etu_clk[cmd[APDU_P1]];

    if(etu_clocks != 0)
    {
        send_data(cmd, 4);
        SCI_ECR = etu_clocks;
        return;
    }
    while(1);
}

static unsigned short extern_lc(unsigned char lc){
	unsigned short ans;
	/* if(lc==0x00){
		receive_data(Lc, 2);
		ans = ((unsigned short)Lc[0] << 8) | Lc[1];
	}else{
		ans = lc;
	} */
	ans = lc;
	return ans;
}

// =============================================================
// Main protocol loop
// =============================================================

void SCard_Demo(void)
{
#if PAKE_EMV_BENCHMARK
    /* Match the PAKE timer configuration before any measured exchange. */
    benchmark_timer_init();
#endif
    // ------------------------------
    // 7816 hardware initialization
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
    
    // Clear all session state during initialization.
    reset_security_state();

		//testing
		debug_magic_buf[0] = 0x77;

    while(1)
    {
        unsigned char t1hdr[3];
        receive_data(t1hdr, 3);

        // Minimal T=1 block handling for reader interoperability:
        // - Handle all T=1 PCB classes (I/R/S) when NAD=0x00
        // - S-block request: echo as S-block response (set response bit)
        // - I-block carrying short APDU probes (GET CHALLENGE / PING / vendor diagnostics)
        // (PCB bit7=0) and caused plain-APDU fallback mis-parse + host read timeout.
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

            if ((pcb & 0xC0) == 0x00 && len >= 5) { // I-block APDU in INF
#if PAKE_EMV_BENCHMARK
                unsigned char benchmark_measured_command =
                    ((inf[APDU_CLA] & 0xEF) == CLA_VENDOR &&
                     (inf[APDU_INS] == INS_KEM_ENCAP ||
                      inf[APDU_INS] == INS_READ_CERTS ||
                      inf[APDU_INS] == INS_ESTABLISH_KEY ||
                      inf[APDU_INS] == INS_VERIFY_PIN));
                uint32_t benchmark_start = benchmark_measured_command ? pake_benchmark_now() : 0u;
#endif
                memcpy(cmd, inf, 5);
                unsigned char cla_base_t1 = (unsigned char)(cmd[APDU_CLA] & 0xEF);
                unsigned char out[9000];
                unsigned short outLen = 0;

                /* TRACE describes the preceding APDU, not its own request. */
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
                        cmd[APDU_P1] > 4u ||
                        (!PAKE_EMV_SYSTICK_BENCHMARK && cmd[APDU_P1] == 3u)) {
                        out[0] = SW1_WRONG_P1P2; out[1] = SW2_00; outLen = 2;
                    } else {
#if PAKE_EMV_SYSTICK_BENCHMARK
                        if (cmd[APDU_P1] == 3) {
                            outLen = pake_benchmark_systick_snapshot(out);
                        } else
#endif
                        if (cmd[APDU_P1] == 4) {
                            outLen = pq_benchmark_pin_snapshot(out);
                        } else if (cmd[APDU_P1] == 2) {
                            outLen = pake_benchmark_diagnostic_snapshot(out);
                        } else {
                            if (cmd[APDU_P1] == 0) pq_benchmark_reset();
                            outLen = pake_benchmark_snapshot(out);
                        }
                        out[outLen++] = SW1_SUCCESS;
                        out[outLen++] = SW2_00;
                    }
#endif
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_KEY_PROOF) {
                    unsigned char proofLen = cmd[APDU_LC];
                    if (proofLen == 0 || proofLen > CRYPTO_BYTES) proofLen = 16;
                    memcpy(out, global_k1, proofLen);
                    out[proofLen] = SW1_SUCCESS;
                    out[proofLen + 1] = SW2_00;
                    outLen = (unsigned short)(proofLen + 2);
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_KEY_PROOF_K2) {
                    unsigned char proofLen = cmd[APDU_LC];
                    if (proofLen == 0 || proofLen > CRYPTO_BYTES) proofLen = 16;
                    if (card_state != STATE_KEM_ESTABLISHED && card_state != STATE_PIN_VERIFIED) {
                        out[0] = SW1_SEC_STATUS_NOT_SATISFIED; out[1] = SW2_SEC_STATUS_NOT_SATISFIED; outLen = 2;
                    } else {
                        memcpy(out, global_k2, proofLen);
                        out[proofLen] = SW1_SUCCESS;
                        out[proofLen + 1] = SW2_00;
                        outLen = (unsigned short)(proofLen + 2);
                    }
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_SS2_PROOF) {
                    unsigned char proofLen = cmd[APDU_LC];
                    unsigned char ss2_hash[CRYPTO_BYTES];
                    if (proofLen == 0 || proofLen > CRYPTO_BYTES) proofLen = 16;
                    if (card_state != STATE_KEM_ESTABLISHED && card_state != STATE_PIN_VERIFIED) {
                        out[0] = SW1_SEC_STATUS_NOT_SATISFIED; out[1] = SW2_SEC_STATUS_NOT_SATISFIED; outLen = 2;
                    } else {
												//testing
                        //k_derive(ss2_hash, global_ss_2, CRYPTO_BYTES); // SHA-256(ss2)
                        k_derive(ss2_hash, debug_ss2_buf, CRYPTO_BYTES); // SHA-256(ss2)
												
												memcpy(out, ss2_hash, proofLen);
											
												
                        secure_memzero(ss2_hash, sizeof(ss2_hash));
                        out[proofLen] = SW1_SUCCESS;
                        out[proofLen + 1] = SW2_00;
                        outLen = (unsigned short)(proofLen + 2);
                    }
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_VERIFY_PIN) {
                    unsigned short apduDataLen = (len >= 5) ? (unsigned short)(len - 5) : 0;
                    unsigned char retry_cnt = t1_pin_retry_cnt;
                    if (retry_cnt > MAX_PIN_RETRY) retry_cnt = MAX_PIN_RETRY;
                    if (card_state != STATE_KEM_ESTABLISHED) {
                        out[0] = SW1_SEC_STATUS_NOT_SATISFIED; out[1] = SW2_SEC_STATUS_NOT_SATISFIED; outLen = 2;
                        reset_security_state();
                    } else if (retry_cnt == 0) {
												out[0] = SW1_WARNING; out[1] = SW2_PIN_BLOCKED; outLen = 2;
                        
												reset_security_state();
                    } else if (apduDataLen < 28) {
                        out[0] = SW1_WRONG_LENGTH; out[1] = SW2_00; outLen = 2;
                    } else {
												apduDataLen = apduDataLen - 1; //delete the tail 00 length
                        unsigned int cipher_len = apduDataLen - 28;
                        unsigned char *iv_ptr = inf + 5;
                        unsigned char *cipher_ptr = inf + 5 + 12;
                        unsigned char *tag_ptr = inf + 5 + 12 + cipher_len;
                        unsigned char plain_pin[64];
                        if (aes_gcm_decrypt_verify(global_k2, iv_ptr, cipher_ptr, cipher_len, NULL, 0, tag_ptr, plain_pin) != 0) {
                            
														out[0] = SW1_WARNING; out[1] = SW2_AUTH_FAILED; outLen = 2;
														
                        } else {
						
														
                            unsigned char is_pin_ok = constant_time_cmp(plain_pin, pin, PIN_LEN);
                            secure_memzero(plain_pin, sizeof(plain_pin));
                            if (!is_pin_ok) {
                                retry_cnt--;
                                t1_pin_retry_cnt = retry_cnt;
																out[0] = SW1_WARNING; out[1] = SW2_PIN_RETRY_BASE | retry_cnt; outLen = 2;
																
																reset_security_state();
                            } else {
                                retry_cnt = MAX_PIN_RETRY;
                                t1_pin_retry_cnt = retry_cnt;
                                card_state = STATE_PIN_VERIFIED;
                                out[0] = SW1_SUCCESS; out[1] = SW2_00; outLen = 2;
                            }
                        }
                    }
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_READ_CERTS) {
                    if (card_state != STATE_KEM_ENCAP_DONE) {
                        out[0] = SW1_SEC_STATUS_NOT_SATISFIED; out[1] = SW2_SEC_STATUS_NOT_SATISFIED; outLen = 2;
                        reset_security_state();
                    } else if (len != 5 || cmd[APDU_LC] != 0) {
                        out[0] = SW1_WRONG_LC; out[1] = SW2_00; outLen = 2;
                        reset_security_state();
                    } else if (cmd[APDU_P2] != 0 || cmd[APDU_P1] > 1) {
                        out[0] = SW1_WRONG_P1P2; out[1] = SW2_00; outLen = 2;
                        reset_security_state();
                    } else if (cmd[APDU_P1] == 1) {
                        if (cert_tx_pending) {
                            outLen = next_certificate_fragment(out);
                        } else {
                            out[0] = SW1_SEC_STATUS_NOT_SATISFIED;
                            out[1] = SW2_SEC_STATUS_NOT_SATISFIED; outLen = 2;
                            reset_security_state();
                        }
                    } else {
                        unsigned char iv[12];
                        unsigned char tag[16];
                        if (pake_emv_encode_certificate_plaintext(cert_payload_plain,
                                certC_der, certC_der_len, certIS_der, certIS_der_len) != 0 ||
                            randombytes(iv, sizeof(iv)) != 0) {
                            out[0] = SW1_WRONG_LENGTH; out[1] = SW2_00; outLen = 2;
                            reset_security_state();
                        } else {
                            aes_gcm_encrypt_full(global_k1, iv, cert_payload_plain,
                                                 sizeof(cert_payload_plain), NULL, 0,
                                                 cert_payload_cipher + sizeof(iv), tag);
                            memcpy(cert_payload_cipher, iv, sizeof(iv));
                            memcpy(cert_payload_cipher + sizeof(iv) + sizeof(cert_payload_plain),
                                   tag, sizeof(tag));
                            secure_memzero(cert_payload_plain, sizeof(cert_payload_plain));
                            cert_tx_len = sizeof(cert_payload_cipher);
                            cert_tx_offset = 0;
                            cert_tx_pending = 1;
                            outLen = next_certificate_fragment(out);
                        }
                        secure_memzero(iv, sizeof(iv));
                        secure_memzero(tag, sizeof(tag));
                    }
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_ESTABLISH_KEY) {
                    unsigned short apduDataLen = (len >= 5) ? (unsigned short)(len - 5) : 0;
                    if (card_state != STATE_KEM_ENCAP_DONE) {
                        out[0] = SW1_SEC_STATUS_NOT_SATISFIED; out[1] = SW2_SEC_STATUS_NOT_SATISFIED; outLen = 2;
                        reset_security_state();
                    } else if (apduDataLen == 0) {
                        out[0] = SW1_WRONG_LC; out[1] = SW2_00; outLen = 2;
                        reset_security_state();
                    } else if ((unsigned int)est_c2_len + (unsigned int)apduDataLen > sizeof(buff)) {
                        out[0] = SW1_WRONG_LENGTH; out[1] = SW2_00; outLen = 2;
                        est_c2_len = 0;
                        reset_security_state();
                    } else {
                        memcpy(buff + est_c2_len, inf + 5, apduDataLen);
                        est_c2_len = (unsigned short)(est_c2_len + apduDataLen);
                        unsigned char more = ((cmd[APDU_CLA] & 0x10) || (cmd[APDU_P1] == 0x01 && cmd[APDU_P2] == 0x00)) ? 1 : 0;
                        if (more) {
                            out[0] = SW1_SUCCESS; out[1] = SW2_00; outLen = 2;
                        } else {
                            if (est_c2_len < 28) {
                                out[0] = SW1_WRONG_LENGTH; out[1] = SW2_00; outLen = 2;
                                est_c2_len = 0;
                                reset_security_state();
                            } else {
                                unsigned int encrypted_ct2_len = est_c2_len - 28;
                                unsigned char *iv_ptr = buff;
                                unsigned char *cipher_ptr = buff + 12;
                                unsigned char *tag_ptr = buff + 12 + encrypted_ct2_len;
                                if (aes_gcm_decrypt_verify(global_k1, iv_ptr, cipher_ptr, encrypted_ct2_len, NULL, 0, tag_ptr, global_ct) != 0) {
                                    out[0] = SW1_WARNING; out[1] = SW2_AUTH_FAILED; outLen = 2;
                                    est_c2_len = 0;
                                    reset_security_state();
                                } else {
                                    memcpy(skc, sk_c_raw, KYBER_SECRETKEYBYTES);
                                    if (crypto_kem_dec(global_ss_2, global_ct, skc) != 0) {
                                        out[0] = SW1_INTERNAL_ERR; out[1] = SW2_AUTH_FAILED; outLen = 2;
                                        est_c2_len = 0;
                                        reset_security_state();
                                    } else {
																				//testing
																				memcpy(debug_magic_buf, global_ct+CRYPTO_CIPHERTEXTBYTES-5, 5);
																				memcpy(debug_ss2_buf, global_ss_2, CRYPTO_BYTES);
																			
                                        memcpy(global_ss, global_ss_1, CRYPTO_BYTES);
                                        memcpy(global_ss + CRYPTO_BYTES, global_ss_2, CRYPTO_BYTES);
                                        k_derive(global_k2, global_ss, 2 * CRYPTO_BYTES);
                                        secure_memzero(skc, KYBER_SECRETKEYBYTES);
                                        secure_memzero(global_ss, 2 * CRYPTO_BYTES);
                                        secure_memzero(global_ss_1, CRYPTO_BYTES);
                                        secure_memzero(global_ss_2, CRYPTO_BYTES);
                                        secure_memzero(global_k1, CRYPTO_BYTES);
                                        secure_memzero(global_ct, CRYPTO_CIPHERTEXTBYTES);
                                        secure_memzero(buff, MAX_BUFF_LEN);
                                        est_c2_len = 0;
                                        t1_pin_retry_cnt = MAX_PIN_RETRY;
                                        card_state = STATE_KEM_ESTABLISHED;
                                        out[0] = SW1_SUCCESS; out[1] = SW2_00; outLen = 2;
                                    }
                                }
                            }
                        }
                    }
                } else if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_KEM_ENCAP) {
                    unsigned short apduDataLen = (len >= 5) ? (unsigned short)(len - 5) : 0;

                    if (apduDataLen == 0) {
                        if (cmd[APDU_P1] == 0x01 && cmd[APDU_P2] == 0x00 && kem_ct_pending) {
                            unsigned short rem = (unsigned short)(CRYPTO_CIPHERTEXTBYTES - kem_ct_tx_offset);
                            unsigned short frag = (rem > 240) ? 240 : rem;
                            memcpy(out, global_ct + kem_ct_tx_offset, frag);
                            kem_ct_tx_offset = (unsigned short)(kem_ct_tx_offset + frag);
                            if (kem_ct_tx_offset < (unsigned short)CRYPTO_CIPHERTEXTBYTES) {
                                unsigned short left = (unsigned short)(CRYPTO_CIPHERTEXTBYTES - kem_ct_tx_offset);
                                out[frag] = 0x61;
                                out[frag + 1] = (left > 0xFF) ? 0x00 : (unsigned char)left;
                                outLen = (unsigned short)(frag + 2);
                            } else {
                                kem_ct_pending = 0;
                                kem_ct_tx_offset = 0;
                                out[frag] = SW1_SUCCESS;
                                out[frag + 1] = SW2_00;
                                outLen = (unsigned short)(frag + 2);
                            }
                        } else {
                            out[0] = SW1_WRONG_LC; out[1] = SW2_00; outLen = 2;
                            reset_security_state();
                        }
                    } else {
                        if ((unsigned int)kem_pk_accum_len + (unsigned int)apduDataLen > (unsigned int)CRYPTO_PUBLICKEYBYTES) {
                            out[0] = SW1_WRONG_LENGTH; out[1] = SW2_00; outLen = 2;
                            reset_security_state();
                        } else {
                            memcpy(kem_pk_accum + kem_pk_accum_len, inf + 5, apduDataLen);
                            kem_pk_accum_len = (unsigned short)(kem_pk_accum_len + apduDataLen);

                            unsigned char is_pk_more = ((cmd[APDU_CLA] & 0x10) || (cmd[APDU_P1] == 0x01 && cmd[APDU_P2] == 0x00)) ? 1 : 0;
                            if (is_pk_more) {
                                out[0] = SW1_SUCCESS; out[1] = SW2_00; outLen = 2;
                            } else if (kem_pk_accum_len != (unsigned short)CRYPTO_PUBLICKEYBYTES) {
                                out[0] = SW1_WRONG_LENGTH; out[1] = SW2_00; outLen = 2;
                                reset_security_state();
                            } else {
                                secure_memzero(global_k1, sizeof(global_k1));
                                secure_memzero(global_k2, sizeof(global_k2));
                                secure_memzero(global_ss, sizeof(global_ss));
                                secure_memzero(global_ss_1, sizeof(global_ss_1));
                                secure_memzero(global_ss_2, sizeof(global_ss_2));
                                secure_memzero(global_ct, sizeof(global_ct));

                                crypto_kem_enc(global_ct, global_ss_1, kem_pk_accum);
                                k_derive(global_k1, global_ss_1, CRYPTO_BYTES);
                                card_state = STATE_KEM_ENCAP_DONE;
                                kem_ct_pending = 1;
                                kem_ct_tx_offset = 0;
                                secure_memzero(kem_pk_accum, sizeof(kem_pk_accum));
                                kem_pk_accum_len = 0;

                                unsigned short rem = (unsigned short)CRYPTO_CIPHERTEXTBYTES;
                                unsigned short frag = (rem > 240) ? 240 : rem;
                                memcpy(out, global_ct, frag);
                                kem_ct_tx_offset = frag;
                                if (kem_ct_tx_offset < (unsigned short)CRYPTO_CIPHERTEXTBYTES) {
                                    unsigned short left = (unsigned short)(CRYPTO_CIPHERTEXTBYTES - kem_ct_tx_offset);
                                    out[frag] = 0x61;
                                    out[frag + 1] = (left > 0xFF) ? 0x00 : (unsigned char)left;
                                    outLen = (unsigned short)(frag + 2);
                                } else {
                                    kem_ct_pending = 0;
                                    kem_ct_tx_offset = 0;
                                    out[frag] = SW1_SUCCESS;
                                    out[frag + 1] = SW2_00;
                                    outLen = (unsigned short)(frag + 2);
                                }
                            }
                        }
                    }
                } else {
                    out[0] = SW1_INS_NOT_SUP; out[1] = SW2_00; outLen = 2;
                }

                unsigned char rh[3] = {t1hdr[0], (unsigned char)(pcb & 0x40), (unsigned char)outLen};
                unsigned char rl = rh[0] ^ rh[1] ^ rh[2];
                for (unsigned short i = 0; i < outLen; i++) rl ^= out[i];
#if PAKE_EMV_BENCHMARK
                if (benchmark_measured_command) {
                    pq_benchmark_record(cmd[APDU_INS], benchmark_start, pake_benchmark_now());
                }
#endif
                send_data(rh, 3);
                send_data(out, outLen);
                send_data(&rl, 1);
                continue;
            }
            continue;
        }

        // SYNC-SAFETY-MARKER (2026-05-06):
        // Reader/CCID stack handles T=1 framing; app logic MUST consume plain APDU bytes only.
        // If you still see undeclared tmp/n/t1_send_response_block compile errors in this loop,
        // you are building an older branch that has not merged the cleanup commits.
        cmd[0] = t1hdr[0];
        cmd[1] = t1hdr[1];
        cmd[2] = t1hdr[2];
        receive_data(&cmd[3], 1);
        if(cmd[APDU_CLA] != CLA_PPS) {
            receive_data(&cmd[APDU_LC], 1);
        } else {
            handle_pps();
            continue;
        }

        if(cmd[APDU_CLA] != CLA_PPS)
        {
            unsigned char cla_base_for_trace;
            // Do not overwrite last_cmd with the TRACE request itself.
            cla_base_for_trace = (unsigned char)(cmd[APDU_CLA] & 0xEF);
            if (!(cla_base_for_trace == CLA_VENDOR && cmd[APDU_INS] == INS_TRACE_LAST_CMD)) {
                memcpy(last_cmd, cmd, sizeof(cmd));
            }
        } else { handle_pps(); continue; }

        sw[0] = SW1_SUCCESS;
        sw[1] = SW2_00;

        unsigned char cla_chain = (cmd[APDU_CLA] & 0x10) ? 1 : 0;
        unsigned char cla_base  = (unsigned char)(cmd[APDU_CLA] & 0xEF);
        unsigned char cla_base_t1 = cla_base; // compatibility with older in-loop fast-path snippets
        unsigned char tmp[16];
        unsigned short n = 0;

        switch(cla_base)
        {
            case CLA_ISO7816:
                switch(cmd[APDU_INS])
                {
                    case INS_GET_CHALLENGE: // 00 84
                        if(cmd[APDU_LC] != 4 && cmd[APDU_LC] != 8)
                        {
                            sw[0] = SW1_WRONG_LENGTH;
                            sw[1] = 8; 
                        }
                        else
                        {
														send_proc_byte_if_t0(INS_GET_CHALLENGE);
                            send_data(trng, cmd[APDU_LC]);
                        }
                        break;
                    case INS_PING: // 00 F0: ISO diagnostic probe with the same payload pattern as 00 84
                        if(cmd[APDU_LC] != 4 && cmd[APDU_LC] != 8)
                        {
                            sw[0] = SW1_WRONG_LENGTH;
                            sw[1] = 8;
                        }
                        else
                        {
                            // A procedure byte must match the current instruction to avoid a reader timeout.
                            send_proc_byte_if_t0(INS_PING);
                            send_data(trng, cmd[APDU_LC]);
                        }
                        break;
                    case INS_READ_BINARY: // 00 B0
                        if(cmd[APDU_LC] > MAX_BUFF_LEN) {
                            sw[0] = SW1_WRONG_LENGTH; sw[1] = SW2_00; break;
                        }
												send_proc_byte_if_t0(INS_READ_BINARY);
                        send_data(buff, cmd[APDU_LC]);
                        break;
                    case INS_UPDATE_BINARY: // 00 D6
                        if(cmd[APDU_LC] > MAX_BUFF_LEN) {
                            sw[0] = SW1_WRONG_LENGTH; sw[1] = SW2_00; break;
                        }
												send_proc_byte_if_t0(INS_UPDATE_BINARY);
                        receive_data(buff, cmd[APDU_LC]);
                        break;
                    default:
                        sw[0] = SW1_INS_NOT_SUP; 
                        sw[1] = SW2_00;
                        break;
                }
                break;

						case CLA_VENDOR:
														//testing
														debug_magic_buf[0] = 0x88;
						
														switch(cmd[APDU_INS])
														{
																case INS_PING: // 80 F0: terminal/card connectivity probe
																		{
																				// Allow terminals to use P3 as the expected response length Le.
																				// No input data is received; return 0x01.
																				send_proc_byte_if_t0(INS_PING);
																				send_data(ping_ok, 1);
																		}
																		break;
																case INS_TRACE_LAST_CMD: // 80 F1: return the preceding five-byte APDU header
																		{
																				send_proc_byte_if_t0(INS_TRACE_LAST_CMD);
																				send_data(last_cmd, sizeof(last_cmd));
																		}
																		break;
																case INS_ECHO: // 80 F2: public echo for request/response diagnostics
																		{
																				// Echo only P1/P2 without waiting for optional diagnostic data.
																				unsigned char echo[2] = {cmd[APDU_P1], cmd[APDU_P2]};
																				if (cmd[APDU_LC] > 0) {
																						// Drain unexpected data to prevent stale FIFO input affecting the next APDU.
																						unsigned short lc_total = extern_lc(cmd[APDU_LC]);
																						discard_data(lc_total);
																				}
																				send_proc_byte_if_t0(INS_ECHO);
																				send_data(echo, sizeof(echo));
																		}
																		break;

																case INS_KEM_ENCAP: // 80/90 CA supports chained input fragments
																		{
																				unsigned short lc_total = extern_lc(cmd[APDU_LC]);
																				if (lc_total == 0) {
																						// Host acknowledgement/next ciphertext request: 80 CA 01 00 00
																						if (cmd[APDU_P1] == 0x01 && cmd[APDU_P2] == 0x00 && kem_ct_pending) {
																								send_kem_ct_fragment();
																								break;
																						}
																						sw[0] = SW1_WRONG_LC; sw[1] = SW2_00;
																						reset_security_state();
																						break;
																				}

																				// For Lc > 0, send the procedure byte before receiving the fragment.
																				send_proc_byte_if_t0(INS_KEM_ENCAP);

																				if ((unsigned int)kem_pk_accum_len + (unsigned int)lc_total > (unsigned int)CRYPTO_PUBLICKEYBYTES) {
																						sw[0] = SW1_WRONG_LENGTH; sw[1] = SW2_00;
																						discard_data(lc_total); // Drain the FIFO to avoid blocking.
																						reset_security_state();
																						break;
																				}

																				receive_data(kem_pk_accum + kem_pk_accum_len, lc_total);
																				kem_pk_accum_len += lc_total;

																				// Accept either continuation indication:
																				// 1) CLA chaining bit (0x10)
																				// 2) P1=0x01 for host compatibility
																				unsigned char is_pk_more = (cla_chain || (cmd[APDU_P1] == 0x01 && cmd[APDU_P2] == 0x00)) ? 1 : 0;
																				if (is_pk_more) {
																						// An intermediate fragment receives 9000; wait for the next fragment.
																						sw[0] = SW1_SUCCESS;
																						sw[1] = SW2_00;
																						break;
																				}

																				// The final accumulated length must equal the public-key length.
																				if (kem_pk_accum_len != (unsigned short)CRYPTO_PUBLICKEYBYTES) {
																						sw[0] = SW1_WRONG_LENGTH; sw[1] = SW2_00;
																						reset_security_state();
																						break;
																				}

																				// Clear old session material while retaining the complete new public key.
																				secure_memzero(global_k1, sizeof(global_k1));
																				secure_memzero(global_k2, sizeof(global_k2));
																				secure_memzero(global_ss, sizeof(global_ss));
																				secure_memzero(global_ss_1, sizeof(global_ss_1));
																				secure_memzero(global_ss_2, sizeof(global_ss_2));
																				secure_memzero(global_ct, sizeof(global_ct));
																				card_state = STATE_IDLE;

																				crypto_kem_enc(global_ct, global_ss_1, kem_pk_accum);
																				k_derive(global_k1, global_ss_1, CRYPTO_BYTES);
																				kem_ct_tx_offset = 0;
																				kem_ct_pending = 1;
																				send_kem_ct_fragment();
																				secure_memzero(kem_pk_accum, sizeof(kem_pk_accum));
																				kem_pk_accum_len = 0;
																				card_state = STATE_KEM_ENCAP_DONE; // Advance the protocol state.
																		}
																		break;

																case INS_READ_CERTS: // 0xB2 
																		{
																				// Require completed KEM encapsulation.
																				if (card_state != STATE_KEM_ENCAP_DONE) {
																						sw[0] = SW1_SEC_STATUS_NOT_SATISFIED; sw[1] = SW2_SEC_STATUS_NOT_SATISFIED; 
																						reset_security_state(); // Destroy the session on an out-of-order command.
																						break;
																				}

																				unsigned int cert_addr = CERT_ADDR; 
																				unsigned int cert_len  = CERT_LEN;
																				ReadFlash_B(cert_buff, cert_addr, cert_len);
																				
																				unsigned char iv[12];
																				randombytes(iv, 12); 
																				unsigned char tag[16];
																				
																				aes_gcm_encrypt_full(global_k1, iv, cert_buff, cert_len, NULL, 0, buff, tag);
																				send_proc_byte_if_t0(INS_READ_CERTS);
																				send_data(iv, 12);
																				send_data(buff, (unsigned short)cert_len);
																				send_data(tag, 16);
																		}
																		break;

																case INS_ESTABLISH_KEY: //50
																		{
																				//testing
																				debug_magic_buf[0] = 0x66;
																			
																				// Require the preceding protocol step.
																				if (card_state != STATE_KEM_ENCAP_DONE) {
																						//testing
																						debug_magic_buf[0] = 0x11;
																					
																						sw[0] = SW1_SEC_STATUS_NOT_SATISFIED; sw[1] = SW2_SEC_STATUS_NOT_SATISFIED; 
																						if (cmd[APDU_LC] > 0) receive_data(buff, cmd[APDU_LC]); // Drain the FIFO to avoid blocking.
																						reset_security_state(); // Destroy the session on an out-of-order command.
																						break;
																				}

																				if ( cmd[APDU_LC] > MAX_BUFF_LEN) { 
																						//testing
																						debug_magic_buf[0] = 0x22;
																					
																						sw[0] = SW1_WRONG_LENGTH; sw[1] = SW2_00; 
																						receive_data(buff, cmd[APDU_LC]); 
																						reset_security_state(); 
																						break;
																				}
																				
																				//testing
																				debug_magic_buf[0] = 0x33;
																					
																				
																				receive_data(buff, extern_lc(cmd[APDU_LC]));
																				unsigned int encrypted_ct2_len = cmd[APDU_LC] - 28;
																				
																				unsigned char *iv_ptr = buff;
																				unsigned char *cipher_ptr = buff + 12;
																				unsigned char *tag_ptr = buff + 12 + encrypted_ct2_len;
																				
																				
																				if( aes_gcm_decrypt_verify(global_k1, iv_ptr, cipher_ptr, encrypted_ct2_len, NULL, 0, tag_ptr, global_ct) != 0) {
																						//testing
																						debug_magic_buf[0] = 0x44;
																					
																						sw[0] = SW1_WARNING; sw[1] = SW2_AUTH_FAILED;
																						reset_security_state(); 
																						break;
																				}
																				//testing
																				//memcpy(debug_magic_buf, global_ct, 5);
																				debug_magic_buf[0] = 0x55;

																				memcpy(skc, sk_c_raw, KYBER_SECRETKEYBYTES);
																				
																				

																				if (crypto_kem_dec(global_ss_2, global_ct, skc) != 0) {
																						sw[0] = SW1_INTERNAL_ERR; sw[1] = SW2_AUTH_FAILED;
																						reset_security_state(); 
																						break;
																				}

																				memcpy(global_ss, global_ss_1, CRYPTO_BYTES);
																				memcpy(global_ss + CRYPTO_BYTES, global_ss_2, CRYPTO_BYTES);
																				k_derive(global_k2, global_ss, 2 * CRYPTO_BYTES);
																				
																				// Clear the private key and intermediate values from RAM.
																				//testing
																				/*
																				secure_memzero(skc, KYBER_SECRETKEYBYTES);
																				secure_memzero(global_ss, 2 * CRYPTO_BYTES);
																				secure_memzero(global_ss_1, CRYPTO_BYTES);
																				secure_memzero(global_ss_2, CRYPTO_BYTES);
																				secure_memzero(global_k1, CRYPTO_BYTES); 
																				secure_memzero(global_ct, CRYPTO_CIPHERTEXTBYTES);
																				secure_memzero(buff, MAX_BUFF_LEN);*/

																				card_state = STATE_KEM_ESTABLISHED; // Advance the protocol state.
																		}
																		break;

																case INS_GET_CHALLENGE: 
																		{
																				// Require an established secure channel.
																				if (card_state < STATE_KEM_ESTABLISHED) {
																						sw[0] = SW1_SEC_STATUS_NOT_SATISFIED; sw[1] = SW2_SEC_STATUS_NOT_SATISFIED; 
																						reset_security_state(); // Destroy the session on an out-of-order command.
																						break;
																				}
																				randombytes(nonce, NONCE_LEN);
																				send_proc_byte_if_t0(INS_GET_CHALLENGE);
																				send_data(nonce, NONCE_LEN);
																				card_state = STATE_GET_CHALLENGE; // Advance the protocol state.
																		}
																		break;

																case INS_VERIFY_PIN:
																		{
																				// Check the required protocol state.
																				if (card_state < STATE_GET_CHALLENGE) {
																						sw[0] = SW1_SEC_STATUS_NOT_SATISFIED; sw[1] = SW2_SEC_STATUS_NOT_SATISFIED; 
																						if (cmd[APDU_LC] > 0) receive_data(buff, cmd[APDU_LC]);
																						reset_security_state(); // Destroy the session on an out-of-order command.
																						break;
																				}

																				if ( cmd[APDU_LC] > MAX_BUFF_LEN) { 
																						sw[0] = SW1_WRONG_LENGTH; sw[1] = SW2_00; 
																						receive_data(buff, cmd[APDU_LC]); 
																						reset_security_state(); 
																						break;
																				}
																				
																				receive_data(buff, extern_lc(cmd[APDU_LC]));

																				unsigned char retry_cnt;
																				ReadFlash_B(&retry_cnt, PIN_RETRY_ADDR, 1);
																				
																				if (retry_cnt > MAX_PIN_RETRY) {
																						retry_cnt = MAX_PIN_RETRY;
																						update_pin_retry_counter(retry_cnt);
																				}

																				if (retry_cnt == 0) {
																						sw[0] = SW1_WARNING; sw[1] = SW2_PIN_BLOCKED; 
																						reset_security_state(); // Clear the session when the PIN is blocked.
																						break;
																				}
																				
																				retry_cnt--;
																				update_pin_retry_counter(retry_cnt);

																				unsigned int cipher_len = cmd[APDU_LC] - 28;
																				unsigned char *iv_ptr = buff;
																				unsigned char *cipher_ptr = buff + 12;
																				unsigned char *tag_ptr = buff + 12 + cipher_len;

																				unsigned char plain_pin[64]; 

																				if (aes_gcm_decrypt_verify(global_k2, iv_ptr, cipher_ptr, cipher_len, NULL, 0, tag_ptr, plain_pin) != 0) 
																				{
																						sw[0] = SW1_WARNING; sw[1] = SW2_AUTH_FAILED;
																						reset_security_state(); 
																						break;
																				}

																				unsigned char is_pin_ok = constant_time_cmp(plain_pin, pin, PIN_LEN);
																				secure_memzero(plain_pin, sizeof(plain_pin)); 

																				if (!is_pin_ok) 
																				{
																						sw[0] = SW1_WARNING; 
																						sw[1] = SW2_PIN_RETRY_BASE | retry_cnt; 
																					 secure_memzero(buff, sizeof(buff));
																						reset_security_state(); // Invalidate the secure channel after an incorrect PIN.
																						break;
																				}

																				retry_cnt = MAX_PIN_RETRY;
																				update_pin_retry_counter(retry_cnt);
																				secure_memzero(buff, sizeof(buff));
																				card_state = STATE_PIN_VERIFIED; // Advance the protocol state.
																		}
																		break;

																case INS_GENERATE_AC:
																		{
																				// Check the required protocol state.
																				if (card_state != STATE_PIN_VERIFIED) {
																						sw[0] = SW1_SEC_STATUS_NOT_SATISFIED; sw[1] = SW2_SEC_STATUS_NOT_SATISFIED; 
																						if (cmd[APDU_LC] > 0) receive_data(buff, cmd[APDU_LC]);
																						reset_security_state(); // Destroy the session on an out-of-order command.
																						break;
																				}
																				
																				if ( cmd[APDU_LC] > MAX_BUFF_LEN) { 
																						sw[0] = SW1_WRONG_LENGTH; sw[1] = SW2_00; 
																						receive_data(buff, cmd[APDU_LC]); 
																						reset_security_state(); 
																						break;
																				}

																				receive_data(buff, extern_lc(cmd[APDU_LC]));
																				unsigned char nonce_T[32];
																				unsigned int nonce_T_len = cmd[APDU_LC];
																				memcpy(nonce_T, buff, nonce_T_len);

																				unsigned char TC[8];
																				ReadFlash_B(MK_AC, MK_AC_ADDR, MK_AC_LEN);
																				
																				unsigned char transInfo[16] = {0xAA, 0xBB, 0xCC, 0xDD}; 
																				unsigned int transInfo_len = 16; 

																				unsigned char padded_info[64];
																				memcpy(padded_info, transInfo, transInfo_len);
																				padded_info[transInfo_len] = 0x80;
																				unsigned int pad_len = transInfo_len + 1;
																				while (pad_len % 16 != 0) {
																						padded_info[pad_len++] = 0x00;
																				}

																				unsigned char cbc_iv[16] = {0}; 
																				unsigned char cipher_out[64];
																				AES_Encrypt(MK_AC, AES_256, padded_info, cipher_out, pad_len, cbc_iv, CBC);

																				memcpy(TC, &cipher_out[pad_len - 16], 8);
																				
																				secure_memzero(MK_AC, MK_AC_LEN);
																				secure_memzero(cipher_out, sizeof(cipher_out));

																				unsigned char sdad_plain[64];
																				unsigned int offset = 0;
																				
																				memcpy(sdad_plain + offset, nonce, NONCE_LEN);  offset += NONCE_LEN;
																				memcpy(sdad_plain + offset, TC, 8);             offset += 8;
																				memcpy(sdad_plain + offset, nonce_T, nonce_T_len); offset += nonce_T_len;

																				unsigned char sdad_iv[12];
																				randombytes(sdad_iv, 12);
																				unsigned char sdad_cipher[64];
																				unsigned char sdad_tag[16];

																				aes_gcm_encrypt_full(global_k2, sdad_iv, sdad_plain, offset, NULL, 0, sdad_cipher, sdad_tag);
																				// Data has already been received; omit an extra procedure byte before the response.
																				send_data(sdad_iv, 12);
																				send_data(sdad_cipher, offset);
																				send_data(sdad_tag, 16);
																				
                                        secure_memzero(nonce_T, sizeof(nonce_T));
                                        secure_memzero(buff, sizeof(buff));
														 						secure_memzero(sdad_plain, sizeof(sdad_plain));
																				reset_security_state(); // End the session after successful completion.
																		}
																		break;
																		
																default:
																		sw[0] = SW1_INS_NOT_SUP; 
																		sw[1] = SW2_00;
																		reset_security_state(); // Clear the session after an unknown instruction.
																		break;
														}
														break;
																		
															

            case CLA_TEST:
                switch(cmd[APDU_INS])
                {
                    case INS_LONG_TASK: // C0 DD
                        if(cmd[APDU_LC] > 16)
                        {
                            sw[0] = SW1_WRONG_LENGTH;
                            sw[1] = 16; 
                        }
                        else
                        {
                            SCI_CR1 |= SCI_CR1_TRE;
                            send_time_out(etu_clocks);
                            Delay(1000);
                            disnable_send_time_out();
                            send_proc_byte_if_t0(INS_LONG_TASK);
                            send_data(test_data, cmd[APDU_LC]);
                        }
                        break;
                    default:
                        sw[0] = SW1_INS_NOT_SUP; 
                        sw[1] = SW2_00;
                        break;
                }
                n = cmd[APDU_LC];
                memcpy(tmp, trng, n);
                tmp[n++] = SW1_SUCCESS; tmp[n++] = SW2_00;
                t1_send_response_block(t1_rx_pcb, tmp, n);
                continue;
            }

            if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_PING) {
								tmp[0] = ping_ok[0];      // 0x01
								tmp[1] = SW1_SUCCESS;     // 0x90
								tmp[2] = SW2_00;          // 0x00
								t1_send_response_block(t1_rx_pcb, tmp, 3);
                continue;
            }

            if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_TRACE_LAST_CMD) {
                memcpy(tmp, last_cmd, 5);
                tmp[5] = SW1_SUCCESS;
                tmp[6] = SW2_00;
                t1_send_response_block(t1_rx_pcb, tmp, 7);
                continue;
            }

            if (cla_base_t1 == CLA_VENDOR && cmd[APDU_INS] == INS_ECHO) {
                tmp[0] = cmd[APDU_P1];
                tmp[1] = cmd[APDU_P2];
                tmp[2] = SW1_SUCCESS;
                tmp[3] = SW2_00;
                t1_send_response_block(t1_rx_pcb, tmp, 4);
                continue;
            }

            tmp[0] = SW1_INS_NOT_SUP;
            tmp[1] = SW2_00;
            t1_send_response_block(t1_rx_pcb, tmp, 2);
            continue;
        }

        sw[0] = SW1_SUCCESS;
        sw[1] = SW2_00;
        kem_ct_pending = 0;
        kem_ct_tx_offset = 0;
    }
