#define _GNU_SOURCE
#include "chic.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

/* Direct entry points are the untouched author's code, isolated by namespace. */
void chic_ref_initStart(uint8_t *, uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
int chic_ref_initEnd(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *);
void chic_ref_resp(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *);
void chic_ref_hic_eval(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *);
void chic_ref_hic_inv(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *);

static unsigned int checks;
static unsigned char randomness[8192];
static size_t randomness_length;
static size_t randomness_position;
static int replay;
static int fail_randomness;
static uint8_t previous_response[CHIC_MSG2_BYTES];
static int previous_response_available;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

/* Test-only entropy recorder: production never links this file. */
int chic_randombytes(uint8_t *out, size_t length)
{
    size_t offset = 0;
    if (fail_randomness) {
        memset(out, 0, length);
        return -1;
    }
    if (replay) {
        CHECK(randomness_position + length <= randomness_length);
        memcpy(out, randomness + randomness_position, length);
        randomness_position += length;
        return 0;
    }
    while (offset < length) {
        ssize_t result = getrandom(out + offset, length - offset, 0);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) {
            perror("getrandom");
            exit(EXIT_FAILURE);
        }
        offset += (size_t)result;
    }
    CHECK(randomness_length + length <= sizeof(randomness));
    memcpy(randomness + randomness_length, out, length);
    randomness_length += length;
    return 0;
}

static void start_recording(void)
{
    replay = 0;
    randomness_length = 0;
    randomness_position = 0;
}

static void start_replay(void)
{
    replay = 1;
    randomness_position = 0;
}

static void finish_replay(void)
{
    CHECK(randomness_position == randomness_length);
    start_recording();
}

static int all_zero(const uint8_t *bytes, size_t length)
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < length; ++i) difference |= bytes[i];
    return difference == 0;
}

static void reject(const uint8_t *response, const uint8_t *message,
                   const uint8_t *public_key, const uint8_t *secret_key,
                   const uint8_t *sid)
{
    uint8_t key[CHIC_KEY_BYTES];
    memset(key, 0xa5, sizeof(key));
    CHECK(chic_init_end(key, response, message, public_key, secret_key, sid) != 0);
    CHECK(all_zero(key, sizeof(key)));
}

static void exercise_session(void)
{
    uint8_t pw[CHIC_PASSWORD_BYTES], sid[CHIC_SID_BYTES];
    uint8_t message[CHIC_MSG1_BYTES], pk[CHIC_PUBLICKEY_BYTES], sk[CHIC_SECRETKEY_BYTES];
    uint8_t reference_message[CHIC_MSG1_BYTES], reference_pk[CHIC_PUBLICKEY_BYTES];
    uint8_t reference_sk[CHIC_SECRETKEY_BYTES], reference_response[CHIC_MSG2_BYTES];
    uint8_t response[CHIC_MSG2_BYTES], responder_key[CHIC_KEY_BYTES];
    uint8_t reference_key[CHIC_KEY_BYTES], initiator_key[CHIC_KEY_BYTES];
    uint8_t copy[CHIC_SECRETKEY_BYTES], inverse[CHIC_PUBLICKEY_BYTES];
    size_t i;

    start_recording();
    chic_randombytes(pw, sizeof(pw));
    chic_randombytes(sid, sizeof(sid));
    start_recording();
    CHECK(chic_init_start(message, pk, sk, pw, sid) == 0);
    start_replay();
    chic_ref_initStart(reference_message, reference_pk, reference_sk, pw, sid);
    finish_replay();
    CHECK(memcmp(message, reference_message, sizeof(message)) == 0);
    CHECK(memcmp(pk, reference_pk, sizeof(pk)) == 0);
    CHECK(memcmp(sk, reference_sk, sizeof(sk)) == 0);

    chic_ref_hic_inv(inverse, message, pw, sid);
    CHECK(memcmp(inverse, pk, sizeof(pk)) == 0);
    chic_ref_hic_eval(reference_message, inverse, pw, sid);
    CHECK(memcmp(reference_message, message, sizeof(message)) == 0);

    start_recording();
    CHECK(chic_respond(responder_key, response, message, pw, sid) == 0);
    start_replay();
    chic_ref_resp(reference_key, reference_response, message, pw, sid);
    finish_replay();
    CHECK(memcmp(response, reference_response, sizeof(response)) == 0);
    CHECK(memcmp(responder_key, reference_key, sizeof(responder_key)) == 0);
    CHECK(chic_init_end(initiator_key, reference_response, message, pk, sk, sid) == 0);
    CHECK(memcmp(initiator_key, responder_key, sizeof(initiator_key)) == 0);
    CHECK(chic_ref_initEnd(reference_key, response, message, pk, sk, sid) == 0);
    CHECK(memcmp(reference_key, initiator_key, sizeof(initiator_key)) == 0);
    if (previous_response_available) reject(previous_response, message, pk, sk, sid);
    memcpy(previous_response, response, sizeof(previous_response));
    previous_response_available = 1;

    /* Every tag byte and representative ciphertext positions must authenticate. */
    for (i = 0; i < CHIC_KEY_BYTES; ++i) {
        memcpy(copy, response, sizeof(response));
        copy[i] ^= 1;
        reject(copy, message, pk, sk, sid);
    }
    for (i = CHIC_KEY_BYTES; i < CHIC_MSG2_BYTES; i += 127) {
        memcpy(copy, response, sizeof(response));
        copy[i] ^= 0x80;
        reject(copy, message, pk, sk, sid);
    }
    memcpy(copy, response, sizeof(response));
    copy[CHIC_MSG2_BYTES - 1] ^= 1;
    reject(copy, message, pk, sk, sid);

    memcpy(copy, sid, sizeof(sid));
    copy[0] ^= 1;
    reject(response, message, pk, sk, copy);
    memcpy(copy, pk, sizeof(pk));
    copy[0] ^= 1;
    reject(response, message, copy, sk, sid);
    memcpy(copy, message, sizeof(message));
    copy[0] ^= 1;
    reject(response, copy, pk, sk, sid);
    memcpy(copy, sk, sizeof(sk));
    copy[0] ^= 1;
    reject(response, message, pk, copy, sid);

    /* A responder with another password or SID cannot establish the key. */
    memcpy(copy, pw, sizeof(pw));
    copy[0] ^= 1;
    CHECK(chic_respond(reference_key, reference_response, message, copy, sid) == 0);
    reject(reference_response, message, pk, sk, sid);
    memcpy(copy, sid, sizeof(sid));
    copy[0] ^= 1;
    CHECK(chic_respond(reference_key, reference_response, message, pw, copy) == 0);
    reject(reference_response, message, pk, sk, sid);

    /* Repeat a failure after success: no previously accepted key may survive. */
    CHECK(chic_init_end(initiator_key, response, message, pk, sk, sid) == 0);
    response[0] ^= 1;
    CHECK(chic_init_end(initiator_key, response, message, pk, sk, sid) != 0);
    CHECK(all_zero(initiator_key, sizeof(initiator_key)));

    /* Failed entropy must invalidate every output, and must not poison the next call. */
    fail_randomness = 1;
    memset(reference_message, 0xa5, sizeof(reference_message));
    memset(reference_pk, 0xa5, sizeof(reference_pk));
    memset(reference_sk, 0xa5, sizeof(reference_sk));
    CHECK(chic_init_start(reference_message, reference_pk, reference_sk, pw, sid) != 0);
    CHECK(all_zero(reference_message, sizeof(reference_message)));
    CHECK(all_zero(reference_pk, sizeof(reference_pk)));
    CHECK(all_zero(reference_sk, sizeof(reference_sk)));
    memset(reference_key, 0xa5, sizeof(reference_key));
    memset(reference_response, 0xa5, sizeof(reference_response));
    CHECK(chic_respond(reference_key, reference_response, message, pw, sid) != 0);
    CHECK(all_zero(reference_key, sizeof(reference_key)));
    CHECK(all_zero(reference_response, sizeof(reference_response)));
    fail_randomness = 0;
    CHECK(chic_respond(reference_key, reference_response, message, pw, sid) == 0);
    CHECK(chic_init_end(initiator_key, reference_response, message, pk, sk, sid) == 0);
    CHECK(memcmp(initiator_key, reference_key, sizeof(initiator_key)) == 0);
    start_recording();
}

int main(void)
{
    unsigned int session;
    CHECK(CHIC_MSG1_BYTES == 800);
    CHECK(CHIC_MSG2_BYTES == 800);
    CHECK(CHIC_PUBLICKEY_BYTES == 800);
    CHECK(CHIC_SECRETKEY_BYTES == 1632);
    for (session = 0; session < 16; ++session) exercise_session();
    printf("CHIC: %u checks passed across %u independent sessions\n", checks, session);
    return EXIT_SUCCESS;
}
