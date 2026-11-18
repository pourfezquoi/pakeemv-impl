#ifndef EMV_CERTIFICATE_ENVELOPE_H
#define EMV_CERTIFICATE_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PAKE_EMV_CERT_PLAINTEXT_BYTES 8192u
#define PAKE_EMV_ECERT_BYTES 8220u

/* Shared certificate plaintext for both measured protocols:
 * two big-endian 16-bit lengths, both DER certificates, 0x80 and zero padding.
 * The output must have room for the fixed length and must not overlap the inputs.
 */
static inline int pake_emv_encode_certificate_plaintext(
    uint8_t out[PAKE_EMV_CERT_PLAINTEXT_BYTES], const uint8_t *cert_c, size_t cert_c_len,
    const uint8_t *cert_is, size_t cert_is_len)
{
    if (out == NULL) return -1;
    volatile uint8_t *p = out;
    for (size_t remaining = PAKE_EMV_CERT_PLAINTEXT_BYTES; remaining != 0; --remaining) {
        *p++ = 0;
    }
    if (cert_c == NULL || cert_is == NULL || cert_c_len == 0u || cert_is_len == 0u ||
        cert_c_len > PAKE_EMV_CERT_PLAINTEXT_BYTES - 5u ||
        cert_is_len > PAKE_EMV_CERT_PLAINTEXT_BYTES - 5u - cert_c_len) return -1;

    out[0] = (uint8_t)(cert_c_len >> 8);
    out[1] = (uint8_t)cert_c_len;
    out[2] = (uint8_t)(cert_is_len >> 8);
    out[3] = (uint8_t)cert_is_len;
    memcpy(out + 4u, cert_c, cert_c_len);
    memcpy(out + 4u + cert_c_len, cert_is, cert_is_len);
    out[4u + cert_c_len + cert_is_len] = 0x80u;
    return 0;
}

#endif
