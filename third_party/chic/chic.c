#include "chic.h"
#include <string.h>

/* These are declarations of the unmodified reference implementation.
 * Keep upstream's private Kyber typedefs/macros out of application headers.
 */
void chic_ref_initStart(uint8_t *, uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
int chic_ref_initEnd(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *);
void chic_ref_resp(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *);

#if defined(__CC_ARM) || defined(CHIC_SINGLE_THREADED)
/* The smartcard dispatches one APDU at a time and has no threads. */
static int entropy_failed;
#else
/* Android and host callers may run independent sessions concurrently. */
static _Thread_local int entropy_failed;
#endif

void chic_clear(void *buffer, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length-- != 0) *p++ = 0;
}

/* Upstream's void randombytes interface cannot report failure itself. A
 * failed provider yields initialized scratch bytes; the outer adapter then
 * rejects and erases the complete result before releasing any output.
 */
void chic_ref_randombytes(uint8_t *out, size_t length)
{
    if (chic_randombytes(out, length) != 0) {
        entropy_failed = 1;
        chic_clear(out, length);
    }
}

int chic_init_start(uint8_t msg1[CHIC_MSG1_BYTES],
                    uint8_t pk[CHIC_PUBLICKEY_BYTES],
                    uint8_t sk[CHIC_SECRETKEY_BYTES],
                    const uint8_t pw[CHIC_PASSWORD_BYTES],
                    const uint8_t sid[CHIC_SID_BYTES])
{
    entropy_failed = 0;
    chic_ref_initStart(msg1, pk, sk, pw, sid);
    if (entropy_failed) {
        chic_clear(msg1, CHIC_MSG1_BYTES);
        chic_clear(pk, CHIC_PUBLICKEY_BYTES);
        chic_clear(sk, CHIC_SECRETKEY_BYTES);
        return -1;
    }
    return 0;
}

int chic_respond(uint8_t key[CHIC_KEY_BYTES],
                 uint8_t msg2[CHIC_MSG2_BYTES],
                 const uint8_t msg1[CHIC_MSG1_BYTES],
                 const uint8_t pw[CHIC_PASSWORD_BYTES],
                 const uint8_t sid[CHIC_SID_BYTES])
{
    entropy_failed = 0;
    chic_ref_resp(key, msg2, msg1, pw, sid);
    if (entropy_failed) {
        chic_clear(key, CHIC_KEY_BYTES);
        chic_clear(msg2, CHIC_MSG2_BYTES);
        return -1;
    }
    return 0;
}

int chic_init_end(uint8_t key[CHIC_KEY_BYTES],
                  const uint8_t msg2[CHIC_MSG2_BYTES],
                  const uint8_t msg1[CHIC_MSG1_BYTES],
                  const uint8_t pk[CHIC_PUBLICKEY_BYTES],
                  const uint8_t sk[CHIC_SECRETKEY_BYTES],
                  const uint8_t sid[CHIC_SID_BYTES])
{
    int result;
    chic_clear(key, CHIC_KEY_BYTES);
    result = chic_ref_initEnd(key, msg2, msg1, pk, sk, sid);
    if (result != 0) {
        chic_clear(key, CHIC_KEY_BYTES);
        return -1;
    }
    return 0;
}
