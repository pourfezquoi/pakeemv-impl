#ifndef PAKE_EMV_PROTOCOL_PROFILE_H
#define PAKE_EMV_PROTOCOL_PROFILE_H

#include <stddef.h>
#include <stdint.h>
#include "certificate_envelope.h"

#define PAKE_EMV_SUITE "PAKE-EMV-v3:CHIC-ddf94132-Kyber512:ML-KEM-512:ML-DSA-44:SHA256:HKDF-SHA256:AES256-GCM:CERT8192"
#define PAKE_EMV_HASH_BYTES 32u
#define PAKE_EMV_NONCE_BYTES 32u
#define PAKE_EMV_TAG_BYTES 32u
#define PAKE_EMV_X1_BYTES 832u
#define PAKE_EMV_X2_BYTES 800u
#define PAKE_EMV_CARD_KEY_BYTES 800u
#define PAKE_EMV_ISSUER_KEY_BYTES 1312u
#define PAKE_EMV_EC_BYTES 796u
#define PAKE_EMV_M3_BYTES 64u
#define PAKE_EMV_M5_BYTES 828u
#define PAKE_EMV_M6_BYTES 32u

typedef struct {
    const uint8_t *data;
    size_t length;
} pake_emv_part;

typedef struct {
    uint8_t key[PAKE_EMV_HASH_BYTES];
    uint8_t k2[PAKE_EMV_HASH_BYTES];
    uint8_t k3[PAKE_EMV_HASH_BYTES];
} pake_emv_keys;

typedef struct {
    const uint8_t *cert_c;
    size_t cert_c_len;
    const uint8_t *cert_is;
    size_t cert_is_len;
} pake_emv_certificates;

/* The platform supplies ordinary SHA-256 over these ordered byte slices.
 * Hash streaming must consume all slices before writing out, allowing an
 * output context to reuse its previous input buffer. There is no allocation.
 */
void pake_emv_sha256_parts(uint8_t out[32], const pake_emv_part *parts, size_t count);

/* Fixed-array callers validate message lengths before entering these helpers.
 * Labels and suite are ASCII bytes without terminators or length prefixes;
 * every following field has the public fixed size above.
 */
void pake_emv_ctx1(uint8_t out[32], const uint8_t x1[832], const uint8_t x2[800]);
void pake_emv_kc1(uint8_t out[32], const uint8_t tk[32], const uint8_t ctx1[32], const uint8_t nu[32]);
void pake_emv_ctx2(uint8_t out[32], const uint8_t m3[64], const uint8_t ctx1[32]);
void pake_emv_cert_key(uint8_t out[32], const uint8_t tk[32], const uint8_t ctx2[32]);
void pake_emv_ctx3(uint8_t out[32], const uint8_t ecert[8220], const uint8_t ctx2[32]);
void pake_emv_ec_key(uint8_t out[32], const uint8_t tk[32], const uint8_t ctx3[32]);
void pake_emv_ctx4(uint8_t out[32], const uint8_t ec[796], const uint8_t ctx3[32]);
void pake_emv_pkh(uint8_t out[32], const uint8_t pk_c[800], const uint8_t pk_is[1312]);
/* The three-key output struct must not overlap any of its input fields. */
void pake_emv_derive_keys(pake_emv_keys *out, const uint8_t tk[32], const uint8_t ss[32],
                          const uint8_t pkh[32], const uint8_t ctx4[32]);
void pake_emv_kc2(uint8_t out[32], const uint8_t k2[32], const uint8_t ctx4[32]);
void pake_emv_ctx5(uint8_t out[32], const uint8_t pi2[32], const uint8_t ctx4[32]);
void pake_emv_kc3(uint8_t out[32], const uint8_t k3[32], const uint8_t ctx5[32]);

/* RFC5869 HKDF-SHA256: Extract(salt=0^32, IKM=tk), Expand(info, L=32). */
void pake_emv_kdf2(uint8_t out[32], const uint8_t tk[32], const uint8_t *info, size_t info_len);

/* Padded certs: lenC_u16BE || lenIS_u16BE || derC || derIS || 0x80 || 0*.
 * Inputs/output must be distinct. Return 0 on success, -1 on invalid input.
 * Build clears its output on failure; parse clears all returned slices on
 * failure. DER validation is the certificate verifier's separate operation.
 */
int pake_emv_pad_certificates(uint8_t out[8192], const uint8_t *cert_c, size_t cert_c_len,
                              const uint8_t *cert_is, size_t cert_is_len);
int pake_emv_parse_certificates(pake_emv_certificates *out, const uint8_t *plain, size_t plain_len);

#endif
