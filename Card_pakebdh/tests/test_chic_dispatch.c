/* Host regression for the real card APDU path and pinned author CHIC core.
 * Vendor SCI/MMIO are mocked; SHA-256 and AES-GCM use OpenSSL. This is not a
 * hardware performance test. Run tests/run_chic_dispatch.sh from this directory.
 */
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include "../Demo/demo.h"
#include "../../third_party/chic/chic.h"
#include "../../protocol/pake_emv/pake_emv.h"

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

/* Including the production translation unit exercises its live dispatch. */
#include "../Demo/smartcard_demo.c"
#undef receive_data
#undef send_data

uint32_t SystemCoreClock = 105000000u;
unsigned short etu_clk[256];
static jmp_buf end_of_input;
static unsigned char input_bytes[32768], output_bytes[32768];
static size_t input_size, input_offset, output_size;
static void (*when_input_exhausted)(void);
static unsigned char init_msg[800], init_pk[800], init_sk[1632], init_sid[32];


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

unsigned char receive_data(unsigned char *dst, unsigned short len)
{
    if (input_offset == input_size && when_input_exhausted != NULL) {
        when_input_exhausted();
    }
    if (input_offset == input_size) longjmp(end_of_input, 1);
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
    EVP_MD_CTX *md;
    assert(type == SHA_256);
    md = EVP_MD_CTX_new();
    assert(md != NULL && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1);
    ctx->TempBuf = (unsigned int *)md;
    return 0u;
}
void Hash_Updata(HASH_CTX *ctx, unsigned char *p, unsigned int n)
{
    assert(EVP_DigestUpdate((EVP_MD_CTX *)ctx->TempBuf, p, n) == 1);
}
void Hash_Final(HASH_CTX *ctx, unsigned char *p)
{
    unsigned int size = 0;
    assert(EVP_DigestFinal_ex((EVP_MD_CTX *)ctx->TempBuf, p, &size) == 1);
    assert(size == 32u);
    EVP_MD_CTX_free((EVP_MD_CTX *)ctx->TempBuf);
    ctx->TempBuf = NULL;
}
int randombytes(uint8_t *p, size_t n)
{
    while (n > 0u) {
        ssize_t got = getrandom(p, n, 0);
        assert(got > 0);
        p += got;
        n -= (size_t)got;
    }
    return 0;
}
int chic_randombytes(uint8_t *p, size_t n) { return randombytes(p, n); }

void aes_gcm_encrypt_full(const unsigned char *key, const unsigned char *iv,
    const unsigned char *plain, unsigned int plain_len, const unsigned char *aad,
    unsigned int aad_len, unsigned char *cipher, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int count = 0, total = 0;
    assert(ctx != NULL && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 1);
    if (aad_len) assert(EVP_EncryptUpdate(ctx, NULL, &count, aad, (int)aad_len) == 1);
    assert(EVP_EncryptUpdate(ctx, cipher, &count, plain, (int)plain_len) == 1);
    total += count;
    assert(EVP_EncryptFinal_ex(ctx, cipher + total, &count) == 1);
    assert(total + count == (int)plain_len);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1);
    EVP_CIPHER_CTX_free(ctx);
}
int aes_gcm_decrypt_verify(const unsigned char *key, const unsigned char *iv,
    const unsigned char *cipher, unsigned int cipher_len, const unsigned char *aad,
    unsigned int aad_len, const unsigned char *tag, unsigned char *plain)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int count = 0, total = 0, result;
    assert(ctx != NULL && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) == 1);
    if (aad_len) assert(EVP_DecryptUpdate(ctx, NULL, &count, aad, (int)aad_len) == 1);
    assert(EVP_DecryptUpdate(ctx, plain, &count, cipher, (int)cipher_len) == 1);
    total += count;
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1);
    result = EVP_DecryptFinal_ex(ctx, plain + total, &count);
    EVP_CIPHER_CTX_free(ctx);
    return result == 1 ? 0 : -1;
}

/* This terminal fixture computes the manuscript hash/HKDF independently with
 * OpenSSL. Card production code uses the portable helpers and vendor Hash API. */
static void hash_parts(uint8_t out[32], const pake_emv_part *parts, size_t count)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int size;
    assert(ctx != NULL && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    for (size_t i = 0; i < count; ++i)
        assert(EVP_DigestUpdate(ctx, parts[i].data, parts[i].length) == 1);
    assert(EVP_DigestFinal_ex(ctx, out, &size) == 1 && size == 32);
    EVP_MD_CTX_free(ctx);
}

static void ctx_hash(uint8_t out[32], const char *label,
                     const uint8_t *message, size_t message_len, const uint8_t previous[32])
{
    const pake_emv_part parts[] = {{(const uint8_t *)label,strlen(label)},
                                 {message,message_len},{previous,32}};
    hash_parts(out, parts, 3);
}

static void kc_hash(uint8_t out[32], const char *label,
                    const uint8_t key[32], const uint8_t context[32])
{
    const pake_emv_part parts[] = {{(const uint8_t *)label,strlen(label)}, {key,32},{context,32}};
    hash_parts(out, parts, 3);
}

static void kdf(uint8_t out[32], const uint8_t tk[32], const uint8_t *info, size_t info_len)
{
    uint8_t salt[32] = {0}, prk[32], expanded[160];
    unsigned int size;
    assert(info_len + 1 <= sizeof(expanded));
    assert(HMAC(EVP_sha256(), salt, sizeof(salt), tk, 32, prk, &size) != NULL && size == 32);
    memcpy(expanded, info, info_len);
    expanded[info_len] = 1;
    assert(HMAC(EVP_sha256(), prk, sizeof(prk), expanded, info_len+1, out, &size) != NULL && size == 32);
    memset(prk, 0, sizeof(prk));
}

static void labeled_key(uint8_t out[32], const uint8_t tk[32], const char *label, const uint8_t ctx[32])
{
    uint8_t info[64];
    size_t label_len = strlen(label);
    assert(label_len + 32 <= sizeof(info));
    memcpy(info, label, label_len);
    memcpy(info+label_len, ctx, 32);
    kdf(out, tk, info, label_len+32);
}

static void final_keys(pake_emv_keys *keys, const uint8_t tk[32], const uint8_t ss[32],
                        const uint8_t pkh[32], const uint8_t ctx4[32])
{
    const char *labels[] = {"FINAL", "CONF2", "CONF3"};
    uint8_t *outputs[] = {keys->key, keys->k2, keys->k3};
    uint8_t info[101];
    for (size_t i = 0; i < 3; ++i) {
        size_t label_len = strlen(labels[i]);
        memcpy(info, ss, 32);
        memcpy(info+32, labels[i], label_len);
        memcpy(info+32+label_len, pkh, 32);
        memcpy(info+64+label_len, ctx4, 32);
        kdf(outputs[i], tk, info, 96+label_len);
    }
}

static void run_card(void)
{
    input_offset = output_size = 0u;
    fake_sci_sr = SCI_SR_CNTOR;
    if (setjmp(end_of_input) == 0) SCard_Demo();
    assert(input_offset == input_size && output_size >= sizeof(ATR));
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

static void expect_sw(size_t *offset, unsigned char pcb, unsigned int expected)
{
    const unsigned char *reply = response(offset, pcb, 2);
    assert((((unsigned int)reply[0] << 8) | reply[1]) == expected);
}

static void make_init(const char *password)
{
    unsigned char pw[32];
    unsigned int size;
    assert(EVP_Digest(password, 6, pw, &size, EVP_sha256(), NULL) == 1 && size == 32);
    assert(randombytes(init_sid, sizeof(init_sid)) == 0);
    assert(chic_init_start(init_msg, init_pk, init_sk, pw, init_sid) == 0);
    memset(pw, 0, sizeof(pw));
}

static void append_begin(void)
{
    const unsigned char begin[] = {0x80, 0xF9, 0, 0, 0};
    append_request(0, begin, sizeof(begin));
}

static void append_init(size_t payload_size, int read_all)
{
    unsigned char payload[832], apdu[225];
    const unsigned char next[] = {0x80, INS_PAKE_INIT, 1, 0, 0};
    size_t off;
    unsigned int i;
    assert(payload_size <= sizeof(payload));
    memcpy(payload, init_sid, sizeof(init_sid));
    memcpy(payload + sizeof(init_sid), init_msg, sizeof(init_msg));
    for (off = 0; off < payload_size;) {
        size_t count = payload_size - off > 220 ? 220 : payload_size - off;
        apdu[0] = 0x80; apdu[1] = INS_PAKE_INIT;
        apdu[2] = off + count < payload_size ? 1 : 0;
        apdu[3] = 0; apdu[4] = (unsigned char)count;
        memcpy(apdu + 5, payload + off, count);
        append_request((off / 220) & 1 ? 0x40 : 0, apdu, count + 5);
        off += count;
    }
    if (read_all) for (i = 0; i < 3; ++i) append_request(0, next, sizeof(next));
}

static void read_chic_reply(size_t *offset, unsigned char msg2[800], int all)
{
    unsigned int i;
    size_t out_off = 0;
    const unsigned char *reply;
    for (i = 0; i < 3; ++i) expect_sw(offset, i & 1 ? 0x40 : 0, 0x9000);
    for (i = 0; i < (all ? 4u : 1u); ++i) {
        size_t count = i == 3 ? 80 : 240;
        reply = response(offset, i == 0 ? 0x40 : 0, count + 2);
        memcpy(msg2 + out_off, reply, count);
        out_off += count;
        if (i == 3) assert(reply[count] == 0x90 && reply[count + 1] == 0);
        else assert(reply[count] == 0x61 && reply[count + 1] == (i == 2 ? 80 : 0));
    }
    if (all) assert(out_off == 800u);
}

static int all_zero(const unsigned char *p, size_t count)
{
    unsigned char acc = 0;
    while (count--) acc |= *p++;
    return acc == 0;
}

static void extract_public_key(const uint8_t *der, size_t der_len, uint8_t *out, size_t out_len)
{
    const uint8_t *cursor = der, *raw;
    int raw_len;
    X509 *cert = d2i_X509(NULL, &cursor, (long)der_len);
    assert(cert != NULL && cursor == der + der_len);
    assert(X509_PUBKEY_get0_param(NULL, &raw, &raw_len, NULL, X509_get_X509_PUBKEY(cert)) == 1);
    assert(raw_len == (int)out_len);
    memcpy(out, raw, out_len);
    X509_free(cert);
}

static void append_m5(const uint8_t m5[828])
{
    uint8_t apdu[245];
    for (size_t off = 0; off < 828;) {
        size_t count = 828-off > 240 ? 240 : 828-off;
        apdu[0] = 0x80; apdu[1] = INS_ESTABLISH_KEY;
        apdu[2] = off+count < 828 ? 1 : 0;
        apdu[3] = 0; apdu[4] = (uint8_t)count;
        memcpy(apdu+5, m5+off, count);
        append_request(0, apdu, count+5);
        off += count;
    }
}

enum scenario { COMPLETE, WRONG_PIN, BAD_PI2, BAD_EC, BAD_M3_LENGTH, RETRY_TWICE,
                RETRY_THEN_COMPLETE, POST_HALT_RECORD, ABANDON_THEN_REPLAY_M1 };
static enum scenario scenario;
static unsigned int step, retries, complete_m6;
static size_t read_offset, ecert_len;
static uint8_t terminal_tk[32], terminal_ctx[32], terminal_m3[64], ecert[8220];
static uint8_t expected_pi3[32];
static pake_emv_keys terminal_keys;

static void protocol_step(void)
{
    if (step == 0) {
        const uint8_t label[] = "PAKE-EMV", suite[] = PAKE_EMV_SUITE;
        uint8_t msg2[800], x1[832], candidate[32];
        read_chic_reply(&read_offset, msg2, 1);
        assert(read_offset == output_size && protocol_phase == TX_EXPECT_M3);
        if (scenario == WRONG_PIN) {
            memset(terminal_tk, 0xA5, sizeof(terminal_tk));
            assert(chic_init_end(terminal_tk, msg2, init_msg, init_pk, init_sk, init_sid) != 0);
            assert(all_zero(terminal_tk, 32));
            assert(!recorded_key_valid && transaction_retries == 0);
            /* Finish failure terminates locally; no dummy M3 or retry request. */
            when_input_exhausted = NULL;
            step = 9;
            return;
        }
        assert(chic_init_end(terminal_tk, msg2, init_msg, init_pk, init_sk, init_sid) == 0);
        if (scenario == ABANDON_THEN_REPLAY_M1) {
            /* A fresh M1 cannot silently restart an attempt waiting for M3. */
            uint8_t replay[6] = {0x80, INS_PAKE_INIT, 1, 0, 1, 0};
            append_request(0, replay, sizeof(replay));
            step = 5;
            return;
        }
        msg2[0] ^= 1;
        memset(candidate, 0xA5, 32);
        assert(chic_init_end(candidate, msg2, init_msg, init_pk, init_sk, init_sid) != 0);
        assert(all_zero(candidate, 32));
        msg2[0] ^= 1;
        memcpy(x1, init_sid, 32); memcpy(x1+32, init_msg, 800);
        const pake_emv_part ctx1_parts[] = {{label,sizeof(label)-1},{suite,sizeof(suite)-1},{x1,832},{msg2,800}};
        hash_parts(terminal_ctx, ctx1_parts, 4);
        assert(memcmp(terminal_ctx, protocol_ctx, 32) == 0);
        assert(memcmp(terminal_tk, protocol_tk, 32) == 0);
        assert(randombytes(terminal_m3, 32) == 0);
        const pake_emv_part kc1_parts[] = {{(const uint8_t *)"KC1",3},{terminal_tk,32},{terminal_ctx,32},{terminal_m3,32}};
        hash_parts(terminal_m3+32, kc1_parts, 4);
        if ((scenario == RETRY_TWICE) || (scenario == RETRY_THEN_COMPLETE && retries == 0)) terminal_m3[63] ^= 1;
        uint8_t apdu[69] = {0x80, INS_READ_CERTS, 0, 0, 64};
        memcpy(apdu+5, terminal_m3, 64);
        if (scenario == BAD_M3_LENGTH) {
            apdu[4] = 63;
            append_request(0, apdu, sizeof(apdu)-1);
        } else append_request(0, apdu, sizeof(apdu));
        ctx_hash(terminal_ctx, "ctx2", terminal_m3, 64, terminal_ctx);
        ecert_len = 0;
        step = 1;
        return;
    }
    if (step == 1) {
        if (scenario == BAD_M3_LENGTH) {
            const uint8_t *reply = response(&read_offset, 0, 2);
            assert(reply[0] != 0x90 && !(reply[0] == 0x61));
            assert(protocol_phase == TX_HALTED && transaction_retries == 0 && !recorded_key_valid);
            assert(all_zero(protocol_tk, 32));
            when_input_exhausted = NULL; step = 9;
            return;
        }
        if (scenario == RETRY_TWICE || (scenario == RETRY_THEN_COMPLETE && retries == 0)) {
            if (retries == 2) {
                expect_sw(&read_offset, 0, 0x6982);
                assert(protocol_phase == TX_HALTED && transaction_retries == 2 && !recorded_key_valid);
                assert(all_zero(protocol_tk, 32));
                when_input_exhausted = NULL; step = 9;
                return;
            }
            const uint8_t *retry = response(&read_offset, 0, 7);
            assert(memcmp(retry, "RETRY\x90\x00", 7) == 0);
            ++retries;
            assert(protocol_phase == TX_EXPECT_M1 && transaction_retries == retries);
            assert(all_zero(protocol_tk, 32) && all_zero(protocol_ctx, 32));
            make_init("123456");
            append_init(832, 1); /* No F9: the retry keeps this transaction. */
            step = 0;
            return;
        }
        const uint8_t *frame = output_bytes+read_offset;
        size_t count = frame[2];
        const uint8_t *reply = response(&read_offset, 0, count);
        assert(count >= 2 && count <= 242 && ecert_len+count-2 <= sizeof(ecert));
        memcpy(ecert+ecert_len, reply, count-2); ecert_len += count-2;
        if (reply[count-2] == 0x61) {
            const uint8_t next[] = {0x80, INS_READ_CERTS, 1, 0, 0};
            assert(protocol_phase == TX_SEND_M4);
            append_request(0, next, sizeof(next));
            return;
        }
        assert(reply[count-2] == 0x90 && reply[count-1] == 0);
        assert(ecert_len == 8220 && protocol_phase == TX_EXPECT_M5 && !recorded_key_valid);
        uint8_t cert_key[32], plain[8192], card_pk[800], issuer_pk[1312], pkh[32];
        uint8_t ct[768], ss[32], ec_key[32], m5[828];
        labeled_key(cert_key, terminal_tk, "CERT", terminal_ctx);
        assert(aes_gcm_decrypt_verify(cert_key, ecert, ecert+12, 8192, NULL, 0, ecert+8204, plain) == 0);
        size_t len_c = ((size_t)plain[0]<<8)|plain[1], len_is = ((size_t)plain[2]<<8)|plain[3];
        assert(len_c == certC_der_len && len_is == certIS_der_len);
        assert(memcmp(plain+4, certC_der, len_c) == 0 && memcmp(plain+4+len_c, certIS_der, len_is) == 0);
        size_t padding_off = 4+len_c+len_is;
        assert(plain[padding_off] == 0x80 && all_zero(plain+padding_off+1, 8192-padding_off-1));
        pake_emv_certificates parsed;
        assert(pake_emv_parse_certificates(&parsed, plain, sizeof(plain)) == 0);
        plain[padding_off] = 0;
        assert(pake_emv_parse_certificates(&parsed, plain, sizeof(plain)) != 0);
        plain[padding_off] = 0x80; plain[8191] ^= 1;
        assert(pake_emv_parse_certificates(&parsed, plain, sizeof(plain)) != 0);
        ecert[8219] ^= 1;
        assert(aes_gcm_decrypt_verify(cert_key, ecert, ecert+12, 8192, NULL, 0, ecert+8204, plain) != 0);
        ecert[8219] ^= 1;
        extract_public_key(certC_der, certC_der_len, card_pk, sizeof(card_pk));
        extract_public_key(certIS_der, certIS_der_len, issuer_pk, sizeof(issuer_pk));
        assert(crypto_kem_enc(ct, ss, card_pk) == 0); /* The actual outer card ML-KEM, not a mock. */
        ctx_hash(terminal_ctx, "ctx3", ecert, sizeof(ecert), terminal_ctx);
        assert(memcmp(terminal_ctx, protocol_ctx, 32) == 0);
        labeled_key(ec_key, terminal_tk, "EC2", terminal_ctx);
        assert(randombytes(m5, 12) == 0);
        aes_gcm_encrypt_full(ec_key, m5, ct, sizeof(ct), NULL, 0, m5+12, m5+780);
        ctx_hash(terminal_ctx, "ctx4", m5, 796, terminal_ctx);
        const pake_emv_part pkh_parts[] = {{(const uint8_t *)"pkh",3},{card_pk,800},{issuer_pk,1312}};
        hash_parts(pkh, pkh_parts, 3);
        final_keys(&terminal_keys, terminal_tk, ss, pkh, terminal_ctx);
        assert(memcmp(terminal_keys.key, terminal_keys.k2, 32) != 0 && memcmp(terminal_keys.key, terminal_keys.k3, 32) != 0);
        kc_hash(m5+796, "KC2", terminal_keys.k2, terminal_ctx);
        ctx_hash(terminal_ctx, "ctx5", m5+796, 32, terminal_ctx);
        kc_hash(expected_pi3, "KC3", terminal_keys.k3, terminal_ctx);
        if (scenario == BAD_PI2) m5[827] ^= 1;
        if (scenario == BAD_EC) m5[795] ^= 1;
        append_m5(m5);
        memset(ss, 0, sizeof(ss)); memset(cert_key, 0, 32); memset(ec_key, 0, 32);
        step = 2;
        return;
    }
    if (step == 2) {
        for (unsigned int i = 0; i < 3; ++i) expect_sw(&read_offset, 0, 0x9000);
        if (scenario == BAD_PI2 || scenario == BAD_EC) {
            const uint8_t *reply = response(&read_offset, 0, 2);
            assert(reply[0] != 0x90 && reply[0] != 0x61);
            assert(protocol_phase == TX_HALTED && !recorded_key_valid);
            assert(all_zero(recorded_key, 32));
        } else {
            const uint8_t *m6 = response(&read_offset, 0, 34);
            assert(memcmp(m6, expected_pi3, 32) == 0 && m6[32] == 0x90 && m6[33] == 0);
            assert(protocol_phase == TX_HALTED && recorded_key_valid);
            assert(memcmp(recorded_key, terminal_keys.key, 32) == 0);
            uint8_t tampered[32]; memcpy(tampered, m6, 32); tampered[0] ^= 1;
            assert(memcmp(tampered, expected_pi3, 32) != 0); /* Init4 rejects, retains recorded K, sends nothing. */
            complete_m6 = 1;
            if (scenario == POST_HALT_RECORD) {
                const uint8_t timing[] = {0x80, 0xF7, 0, 0, 0};
                const uint8_t raw[] = {0x80, INS_KEY_PROOF_K2, 0, 0, 32};
                const uint8_t unexpected[] = {0x80, INS_READ_CERTS, 1, 0, 0};
                const uint8_t short_apdu[] = {0x80, INS_PAKE_INIT};
                append_request(0, timing, sizeof(timing));
                append_request(0, raw, sizeof(raw));
                append_request(0, unexpected, sizeof(unexpected));
                append_request(0, short_apdu, sizeof(short_apdu));
                step = 3;
                return;
            }
        }
        assert(all_zero(protocol_tk, 32) && all_zero(protocol_ctx, 32));
        assert(read_offset == output_size);
        when_input_exhausted = NULL; step = 9;
        return;
    }
    if (step == 3) {
        expect_sw(&read_offset, 0, 0x6D00); /* Disabled F7 is read-only. */
        expect_sw(&read_offset, 0, 0x6D00);
        expect_sw(&read_offset, 0, 0x6982);
        expect_sw(&read_offset, 0, 0x6700);
        assert(protocol_phase == TX_HALTED && recorded_key_valid);
        assert(memcmp(recorded_key, terminal_keys.key, 32) == 0);
        append_begin();
        step = 4;
        return;
    }
    if (step == 4) {
        expect_sw(&read_offset, 0, 0x9000);
        assert(protocol_phase == TX_EXPECT_M1 && !recorded_key_valid);
        assert(all_zero(recorded_key, 32) && transaction_retries == 0);
        assert(read_offset == output_size);
        when_input_exhausted = NULL; step = 9;
        return;
    }
    if (step == 5) {
        expect_sw(&read_offset, 0, 0x6982);
        assert(protocol_phase == TX_HALTED && transaction_retries == 0 && !recorded_key_valid);
        assert(all_zero(protocol_tk, 32) && all_zero(protocol_ctx, 32));
        assert(read_offset == output_size);
        when_input_exhausted = NULL; step = 9;
    }
}

static void begin_then_protocol(void)
{
    expect_sw(&read_offset, 0, 0x9000);
    assert(!recorded_key_valid && transaction_retries == 0);
    when_input_exhausted = protocol_step;
    protocol_step();
}

static void execute_protocol(enum scenario selected)
{
    scenario = selected;
    step = retries = complete_m6 = 0;
    input_size = 0;
    read_offset = sizeof(ATR);
    make_init(scenario == WRONG_PIN ? "654321" : "123456");
    append_begin(); append_init(832, 1);
    when_input_exhausted = begin_then_protocol;
    /* Only the first callback consumes F9's response. */
    run_card();
    assert(step == 9 && read_offset == output_size);
    if (selected == COMPLETE || selected == RETRY_THEN_COMPLETE) assert(complete_m6);
}

static void test_explicit_begin_phase_errors_and_final_record_lifetime(void)
{
    const uint8_t premature[] = {0x80, INS_READ_CERTS, 0, 0, 1, 0};
    const uint8_t raw_f3[] = {0x80, INS_KEY_PROOF, 0, 0, 32};
    const uint8_t raw_f4[] = {0x80, INS_KEY_PROOF_K2, 0, 0, 32};
    const uint8_t raw_f5[] = {0x80, INS_SS2_PROOF, 0, 0, 32};
    size_t offset = sizeof(ATR);
    input_size = 0; when_input_exhausted = NULL;
    append_request(0, premature, sizeof(premature));
    append_request(0, raw_f3, sizeof(raw_f3));
    append_request(0, raw_f4, sizeof(raw_f4));
    append_request(0, raw_f5, sizeof(raw_f5));
    run_card();
    expect_sw(&offset, 0, 0x6982);
    for (unsigned int i = 0; i < 3; ++i) expect_sw(&offset, 0, 0x6D00);
    assert(protocol_phase == TX_HALTED && !recorded_key_valid && offset == output_size);

    input_size = 0; offset = sizeof(ATR);
    append_begin(); append_init(831, 0);
    run_card();
    expect_sw(&offset, 0, 0x9000);
    for (unsigned int i = 0; i < 3; ++i) expect_sw(&offset, i&1 ? 0x40 : 0, 0x9000);
    const uint8_t *reply = response(&offset, 0x40, 2);
    assert(reply[0] != 0x90 && protocol_phase == TX_HALTED && !recorded_key_valid);
    assert(transaction_retries == 0 && all_zero(protocol_tk, 32));
}

int main(void)
{
    test_explicit_begin_phase_errors_and_final_record_lifetime();
    execute_protocol(COMPLETE);
    execute_protocol(WRONG_PIN);
    execute_protocol(BAD_PI2);
    execute_protocol(BAD_EC);
    execute_protocol(BAD_M3_LENGTH);
    execute_protocol(RETRY_TWICE);
    execute_protocol(RETRY_THEN_COMPLETE);
    execute_protocol(POST_HALT_RECORD);
    execute_protocol(ABANDON_THEN_REPLAY_M1);
    puts("PASS: six-message PAKE-EMV card APDUs, actual CHIC/ML-KEM, independent transcript/HKDF, padded certs, KC1/KC2/KC3, retry/phase gates");
    return 0;
}
