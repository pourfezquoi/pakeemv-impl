#include "pake_emv.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)

/* Host-test provider only. The smartcard supplies its streaming SHA-256 API. */
void pake_emv_sha256_parts(uint8_t out[32], const pake_emv_part *parts, size_t count)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int length = 0;
    size_t i;
    CHECK(ctx != NULL);
    CHECK(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    for (i = 0; i < count; ++i) {
        if (parts[i].length != 0)
            CHECK(EVP_DigestUpdate(ctx, parts[i].data, parts[i].length) == 1);
    }
    CHECK(EVP_DigestFinal_ex(ctx, out, &length) == 1 && length == 32);
    EVP_MD_CTX_free(ctx);
}

static void pattern(uint8_t *out, size_t length, unsigned int seed)
{
    size_t i;
    for (i = 0; i < length; ++i) out[i] = (uint8_t)(17 * i + seed);
}

static void emit(const char *name, const uint8_t bytes[32])
{
    size_t i;
    printf("%s=", name);
    for (i = 0; i < 32; ++i) printf("%02x", bytes[i]);
    putchar('\n');
}

static int all_zero(const uint8_t *bytes, size_t length)
{
    size_t i;
    uint8_t difference = 0;
    for (i = 0; i < length; ++i) difference |= bytes[i];
    return difference == 0;
}

static void reject_padding(uint8_t *plain, size_t length)
{
    pake_emv_certificates certs;
    memset(&certs, 0xa5, sizeof(certs));
    CHECK(pake_emv_parse_certificates(&certs, plain, length) != 0);
    CHECK(certs.cert_c == NULL && certs.cert_c_len == 0);
    CHECK(certs.cert_is == NULL && certs.cert_is_len == 0);
}

int main(void)
{
    uint8_t tk[32], ss[32], x1[832], x2[800], nu[32], m3[64];
    uint8_t ecert[8220], ec[796], pk_c[800], pk_is[1312];
    uint8_t ctx1[32], pi1[32], ctx2[32], kcert[32], ctx3[32], kec[32];
    uint8_t ctx4[32], pkh[32], pi2[32], ctx5[32], pi3[32], changed[32];
    uint8_t cert_c[4096], cert_is[4096], padded[8193], snapshot[8192];
    const size_t response_positions[] = {0, 31, 32, 799};
    const size_t encrypted_positions[] = {0, 12, 795};
    pake_emv_keys keys, changed_keys;
    pake_emv_certificates certs;
    pake_emv_part padded_part;
    size_t i;

    pattern(tk, sizeof(tk), 1); pattern(ss, sizeof(ss), 2);
    pattern(x1, sizeof(x1), 3); pattern(x2, sizeof(x2), 4);
    pattern(nu, sizeof(nu), 5); pattern(ecert, sizeof(ecert), 6);
    pattern(ec, sizeof(ec), 7); pattern(pk_c, sizeof(pk_c), 8);
    pattern(pk_is, sizeof(pk_is), 9);
    pake_emv_ctx1(ctx1, x1, x2); emit("ctx1", ctx1);
    pake_emv_kc1(pi1, tk, ctx1, nu); emit("pi1", pi1);
    memcpy(m3, nu, 32); memcpy(m3 + 32, pi1, 32);
    pake_emv_ctx2(ctx2, m3, ctx1); emit("ctx2", ctx2);
    pake_emv_cert_key(kcert, tk, ctx2); emit("kcert", kcert);
    pake_emv_ctx3(ctx3, ecert, ctx2); emit("ctx3", ctx3);
    pake_emv_ec_key(kec, tk, ctx3); emit("kec", kec);
    pake_emv_ctx4(ctx4, ec, ctx3); emit("ctx4", ctx4);
    pake_emv_pkh(pkh, pk_c, pk_is); emit("pkh", pkh);
    pake_emv_derive_keys(&keys, tk, ss, pkh, ctx4);
    emit("key", keys.key); emit("k2", keys.k2); emit("k3", keys.k3);
    pake_emv_kc2(pi2, keys.k2, ctx4); emit("pi2", pi2);
    pake_emv_ctx5(ctx5, pi2, ctx4); emit("ctx5", ctx5);
    pake_emv_kc3(pi3, keys.k3, ctx5); emit("pi3", pi3);

    /* The serialized card reuses one context buffer between local steps. */
    memcpy(changed, ctx1, 32); pake_emv_ctx2(changed, m3, changed);
    CHECK(memcmp(changed, ctx2, 32) == 0);
    pake_emv_ctx3(changed, ecert, changed);
    CHECK(memcmp(changed, ctx3, 32) == 0);
    pake_emv_ctx4(changed, ec, changed);
    CHECK(memcmp(changed, ctx4, 32) == 0);
    pake_emv_ctx5(changed, pi2, changed);
    CHECK(memcmp(changed, ctx5, 32) == 0);

    CHECK(memcmp(keys.key, keys.k2, 32) != 0);
    CHECK(memcmp(keys.key, keys.k3, 32) != 0);
    CHECK(memcmp(keys.k2, keys.k3, 32) != 0);
    pake_emv_cert_key(changed, tk, ctx3);
    CHECK(memcmp(changed, kec, 32) != 0); /* CERT vs EC2 label */
    pake_emv_kc2(changed, keys.k3, ctx5);
    CHECK(memcmp(changed, pi3, 32) != 0); /* KC2 vs KC3 label */

    x1[0] ^= 1; pake_emv_ctx1(changed, x1, x2); x1[0] ^= 1;
    CHECK(memcmp(changed, ctx1, 32) != 0); /* includes external SID */
    x1[831] ^= 1; pake_emv_ctx1(changed, x1, x2); x1[831] ^= 1;
    CHECK(memcmp(changed, ctx1, 32) != 0);
    for (i = 0; i < sizeof(response_positions) / sizeof(response_positions[0]); ++i) {
        size_t p = response_positions[i];
        x2[p] ^= 1; pake_emv_ctx1(changed, x1, x2); x2[p] ^= 1;
        CHECK(memcmp(changed, ctx1, 32) != 0);
    }
    nu[31] ^= 1; pake_emv_kc1(changed, tk, ctx1, nu); nu[31] ^= 1;
    CHECK(memcmp(changed, pi1, 32) != 0);
    m3[63] ^= 1; pake_emv_ctx2(changed, m3, ctx1); m3[63] ^= 1;
    CHECK(memcmp(changed, ctx2, 32) != 0);
    ecert[8219] ^= 1; pake_emv_ctx3(changed, ecert, ctx2); ecert[8219] ^= 1;
    CHECK(memcmp(changed, ctx3, 32) != 0);
    for (i = 0; i < sizeof(encrypted_positions) / sizeof(encrypted_positions[0]); ++i) {
        size_t p = encrypted_positions[i];
        ec[p] ^= 1; pake_emv_ctx4(changed, ec, ctx3); ec[p] ^= 1;
        CHECK(memcmp(changed, ctx4, 32) != 0);
    }
    pk_c[799] ^= 1; pake_emv_pkh(changed, pk_c, pk_is); pk_c[799] ^= 1;
    CHECK(memcmp(changed, pkh, 32) != 0);
    pk_is[1311] ^= 1; pake_emv_pkh(changed, pk_c, pk_is); pk_is[1311] ^= 1;
    CHECK(memcmp(changed, pkh, 32) != 0);
    ss[0] ^= 1; pake_emv_derive_keys(&changed_keys, tk, ss, pkh, ctx4); ss[0] ^= 1;
    CHECK(memcmp(changed_keys.key, keys.key, 32) != 0);
    CHECK(memcmp(changed_keys.k2, keys.k2, 32) != 0);
    CHECK(memcmp(changed_keys.k3, keys.k3, 32) != 0);
    pkh[0] ^= 1; pake_emv_derive_keys(&changed_keys, tk, ss, pkh, ctx4); pkh[0] ^= 1;
    CHECK(memcmp(changed_keys.key, keys.key, 32) != 0);
    ctx4[0] ^= 1; pake_emv_derive_keys(&changed_keys, tk, ss, pkh, ctx4); ctx4[0] ^= 1;
    CHECK(memcmp(changed_keys.key, keys.key, 32) != 0);
    pi2[31] ^= 1; pake_emv_ctx5(changed, pi2, ctx4); pi2[31] ^= 1;
    CHECK(memcmp(changed, ctx5, 32) != 0);

    pattern(cert_c, sizeof(cert_c), 10); pattern(cert_is, sizeof(cert_is), 11);
    CHECK(pake_emv_pad_certificates(padded, cert_c, 1200, cert_is, 2400) == 0);
    padded_part.data = padded; padded_part.length = 8192;
    pake_emv_sha256_parts(changed, &padded_part, 1); emit("padded_sha256", changed);
    CHECK(pake_emv_parse_certificates(&certs, padded, 8192) == 0);
    CHECK(certs.cert_c_len == 1200 && certs.cert_is_len == 2400);
    CHECK(memcmp(certs.cert_c, cert_c, 1200) == 0);
    CHECK(memcmp(certs.cert_is, cert_is, 2400) == 0);
    memcpy(snapshot, padded, 8192);
    padded[3604] = 0; reject_padding(padded, 8192); memcpy(padded, snapshot, 8192);
    padded[8191] = 1; reject_padding(padded, 8192); memcpy(padded, snapshot, 8192);
    padded[0] = 0xff; padded[1] = 0xff; reject_padding(padded, 8192);
    memcpy(padded, snapshot, 8192);
    padded[0] = 0; padded[1] = 0; reject_padding(padded, 8192);
    memcpy(padded, snapshot, 8192);
    padded[2] = 0; padded[3] = 0; reject_padding(padded, 8192);
    memcpy(padded, snapshot, 8192);
    reject_padding(padded, 8191); reject_padding(padded, 8193);
    CHECK(pake_emv_pad_certificates(padded, cert_c, 4096, cert_is, 4091) == 0);
    CHECK(padded[8191] == 0x80);
    CHECK(pake_emv_parse_certificates(&certs, padded, 8192) == 0);
    CHECK(certs.cert_c_len == 4096 && certs.cert_is_len == 4091);
    CHECK(pake_emv_pad_certificates(padded, cert_c, 4096, cert_is, 4092) != 0);
    CHECK(all_zero(padded, 8192));
    CHECK(pake_emv_pad_certificates(padded, cert_c, 0, cert_is, 12) != 0);
    CHECK(all_zero(padded, 8192));
    CHECK(pake_emv_pad_certificates(padded, cert_c, 12, cert_is, 0) != 0);
    CHECK(all_zero(padded, 8192));
    fprintf(stderr, "PAKE-EMV C: %u checks passed\n", checks);
    return 0;
}
