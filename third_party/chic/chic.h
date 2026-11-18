#ifndef EMV_CHIC_H
#define EMV_CHIC_H
#include <stddef.h>
#include <stdint.h>

#define CHIC_MSG1_BYTES 800
#define CHIC_MSG2_BYTES 800
#define CHIC_PUBLICKEY_BYTES 800
#define CHIC_SECRETKEY_BYTES 1632
#define CHIC_KEY_BYTES 32
#define CHIC_SID_BYTES 32
#define CHIC_PASSWORD_BYTES 32

#ifdef __cplusplus
extern "C" {
#endif

/* Platform CSPRNG: fill all bytes and return 0, or return nonzero on error.
 * No default provider or non-cryptographic fallback is supplied.
 */
int chic_randombytes(uint8_t *out, size_t length);

/* Inputs and outputs must refer to distinct, correctly sized arrays.
 * The adapter preserves the author's complete CHIC-512 construction.
 * Start/respond return -1 and clear every output after an entropy failure.
 */
int chic_init_start(uint8_t msg1[CHIC_MSG1_BYTES],
                    uint8_t pk[CHIC_PUBLICKEY_BYTES],
                    uint8_t sk[CHIC_SECRETKEY_BYTES],
                    const uint8_t pw[CHIC_PASSWORD_BYTES],
                    const uint8_t sid[CHIC_SID_BYTES]);
int chic_respond(uint8_t key[CHIC_KEY_BYTES],
                 uint8_t msg2[CHIC_MSG2_BYTES],
                 const uint8_t msg1[CHIC_MSG1_BYTES],
                 const uint8_t pw[CHIC_PASSWORD_BYTES],
                 const uint8_t sid[CHIC_SID_BYTES]);
/* Returns 0 only for the author's verified responder tag. On any failure,
 * including a failed Finish into a previously accepted key buffer, key is zero.
 */
int chic_init_end(uint8_t key[CHIC_KEY_BYTES],
                  const uint8_t msg2[CHIC_MSG2_BYTES],
                  const uint8_t msg1[CHIC_MSG1_BYTES],
                  const uint8_t pk[CHIC_PUBLICKEY_BYTES],
                  const uint8_t sk[CHIC_SECRETKEY_BYTES],
                  const uint8_t sid[CHIC_SID_BYTES]);
void chic_clear(void *buffer, size_t length);

#ifdef __cplusplus
}
#endif
#endif
