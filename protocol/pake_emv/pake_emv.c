#include "pake_emv.h"
#include <string.h>

static void clear_bytes(void *buffer, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length-- != 0u) *p++ = 0;
}

/* Every internal HMAC key has length32 and each message has at most5 parts. */
static void hmac_sha256(uint8_t out[32], const uint8_t key[32],
                         const pake_emv_part *message, size_t count)
{
    uint8_t ipad[64], opad[64], inner[32];
    pake_emv_part parts[6];
    size_t i;
    for (i = 0; i < 64u; ++i) {
        uint8_t b = i < 32u ? key[i] : 0;
        ipad[i] = (uint8_t)(b ^ 0x36u);
        opad[i] = (uint8_t)(b ^ 0x5cu);
    }
    parts[0].data = ipad;
    parts[0].length = sizeof(ipad);
    for (i = 0; i < count; ++i) parts[i + 1u] = message[i];
    pake_emv_sha256_parts(inner, parts, count + 1u);
    parts[0].data = opad;
    parts[0].length = sizeof(opad);
    parts[1].data = inner;
    parts[1].length = sizeof(inner);
    pake_emv_sha256_parts(out, parts, 2u);
    clear_bytes(ipad, sizeof(ipad));
    clear_bytes(opad, sizeof(opad));
    clear_bytes(inner, sizeof(inner));
}

static void kdf2_parts(uint8_t out[32], const uint8_t tk[32],
                        const pake_emv_part *info, size_t count)
{
    const uint8_t salt[32] = {0};
    const uint8_t counter = 1;
    uint8_t prk[32];
    pake_emv_part extract = {tk, 32u};
    pake_emv_part expand[5];
    size_t i;
    hmac_sha256(prk, salt, &extract, 1u);
    for (i = 0; i < count; ++i) expand[i] = info[i];
    expand[count].data = &counter;
    expand[count].length = 1u;
    hmac_sha256(out, prk, expand, count + 1u);
    clear_bytes(prk, sizeof(prk));
}

void pake_emv_kdf2(uint8_t out[32], const uint8_t tk[32], const uint8_t *info, size_t info_len)
{
    pake_emv_part part = {info, info_len};
    kdf2_parts(out, tk, &part, 1u);
}

void pake_emv_ctx1(uint8_t out[32], const uint8_t x1[832], const uint8_t x2[800])
{
    static const uint8_t label[] = "PAKE-EMV";
    static const uint8_t suite[] = PAKE_EMV_SUITE;
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {suite, sizeof(suite)-1u},
                                  {x1, PAKE_EMV_X1_BYTES}, {x2, PAKE_EMV_X2_BYTES}};
    pake_emv_sha256_parts(out, parts, 4u);
}

void pake_emv_kc1(uint8_t out[32], const uint8_t tk[32], const uint8_t ctx1[32], const uint8_t nu[32])
{
    static const uint8_t label[] = "KC1";
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {tk,32u}, {ctx1,32u}, {nu,32u}};
    pake_emv_sha256_parts(out, parts, 4u);
}

void pake_emv_ctx2(uint8_t out[32], const uint8_t m3[64], const uint8_t ctx1[32])
{
    static const uint8_t label[] = "ctx2";
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {m3,PAKE_EMV_M3_BYTES}, {ctx1,32u}};
    pake_emv_sha256_parts(out, parts, 3u);
}

void pake_emv_cert_key(uint8_t out[32], const uint8_t tk[32], const uint8_t ctx2[32])
{
    static const uint8_t label[] = "CERT";
    const pake_emv_part info[] = {{label, sizeof(label)-1u}, {ctx2,32u}};
    kdf2_parts(out, tk, info, 2u);
}

void pake_emv_ctx3(uint8_t out[32], const uint8_t ecert[8220], const uint8_t ctx2[32])
{
    static const uint8_t label[] = "ctx3";
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {ecert,PAKE_EMV_ECERT_BYTES}, {ctx2,32u}};
    pake_emv_sha256_parts(out, parts, 3u);
}

void pake_emv_ec_key(uint8_t out[32], const uint8_t tk[32], const uint8_t ctx3[32])
{
    static const uint8_t label[] = "EC2";
    const pake_emv_part info[] = {{label, sizeof(label)-1u}, {ctx3,32u}};
    kdf2_parts(out, tk, info, 2u);
}

void pake_emv_ctx4(uint8_t out[32], const uint8_t ec[796], const uint8_t ctx3[32])
{
    static const uint8_t label[] = "ctx4";
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {ec,PAKE_EMV_EC_BYTES}, {ctx3,32u}};
    pake_emv_sha256_parts(out, parts, 3u);
}

void pake_emv_pkh(uint8_t out[32], const uint8_t pk_c[800], const uint8_t pk_is[1312])
{
    static const uint8_t label[] = "pkh";
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {pk_c,PAKE_EMV_CARD_KEY_BYTES},
                                  {pk_is,PAKE_EMV_ISSUER_KEY_BYTES}};
    pake_emv_sha256_parts(out, parts, 3u);
}

void pake_emv_derive_keys(pake_emv_keys *out, const uint8_t tk[32], const uint8_t ss[32],
                          const uint8_t pkh[32], const uint8_t ctx4[32])
{
    static const uint8_t final_label[] = "FINAL";
    static const uint8_t conf2_label[] = "CONF2";
    static const uint8_t conf3_label[] = "CONF3";
    pake_emv_part info[] = {{ss,32u}, {final_label,sizeof(final_label)-1u}, {pkh,32u}, {ctx4,32u}};
    kdf2_parts(out->key, tk, info, 4u);
    info[1].data = conf2_label;
    info[1].length = sizeof(conf2_label)-1u;
    kdf2_parts(out->k2, tk, info, 4u);
    info[1].data = conf3_label;
    info[1].length = sizeof(conf3_label)-1u;
    kdf2_parts(out->k3, tk, info, 4u);
}

void pake_emv_kc2(uint8_t out[32], const uint8_t k2[32], const uint8_t ctx4[32])
{
    static const uint8_t label[] = "KC2";
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {k2,32u}, {ctx4,32u}};
    pake_emv_sha256_parts(out, parts, 3u);
}

void pake_emv_ctx5(uint8_t out[32], const uint8_t pi2[32], const uint8_t ctx4[32])
{
    static const uint8_t label[] = "ctx5";
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {pi2,32u}, {ctx4,32u}};
    pake_emv_sha256_parts(out, parts, 3u);
}

void pake_emv_kc3(uint8_t out[32], const uint8_t k3[32], const uint8_t ctx5[32])
{
    static const uint8_t label[] = "KC3";
    const pake_emv_part parts[] = {{label, sizeof(label)-1u}, {k3,32u}, {ctx5,32u}};
    pake_emv_sha256_parts(out, parts, 3u);
}

int pake_emv_pad_certificates(uint8_t out[8192], const uint8_t *cert_c, size_t cert_c_len,
                              const uint8_t *cert_is, size_t cert_is_len)
{
    return pake_emv_encode_certificate_plaintext(out, cert_c, cert_c_len, cert_is, cert_is_len);
}

int pake_emv_parse_certificates(pake_emv_certificates *out, const uint8_t *plain, size_t plain_len)
{
    size_t len_c, len_is, end, i;
    uint8_t bad_padding = 0;
    if (out == NULL) return -1;
    out->cert_c = NULL;
    out->cert_c_len = 0u;
    out->cert_is = NULL;
    out->cert_is_len = 0u;
    if (plain == NULL || plain_len != PAKE_EMV_CERT_PLAINTEXT_BYTES) return -1;
    len_c = ((size_t)plain[0] << 8) | plain[1];
    len_is = ((size_t)plain[2] << 8) | plain[3];
    if (len_c == 0u || len_is == 0u || len_c > PAKE_EMV_CERT_PLAINTEXT_BYTES-5u ||
        len_is > PAKE_EMV_CERT_PLAINTEXT_BYTES-5u-len_c) return -1;
    end = 4u + len_c + len_is;
    if (plain[end] != 0x80u) return -1;
    for (i = end + 1u; i < plain_len; ++i) bad_padding |= plain[i];
    if (bad_padding != 0u) return -1;
    out->cert_c = plain + 4u;
    out->cert_c_len = len_c;
    out->cert_is = plain + 4u + len_c;
    out->cert_is_len = len_is;
    return 0;
}
