#include <jni.h>
#include <stdint.h>
#include "chic.h"

#define KEY_BYTES 32
#define MSG_BYTES 800
#define SK_BYTES 1632

static void erase(void *buffer, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length--) *p++ = 0;
}

static void throw_exception(JNIEnv *env, const char *name, const char *message)
{
    jclass exception = (*env)->FindClass(env, name);
    if (exception != NULL) (*env)->ThrowNew(env, exception, message);
}

static int exact_array(JNIEnv *env, jbyteArray input, jsize length)
{
    if (input == NULL || (*env)->GetArrayLength(env, input) != length) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Invalid CHIC input array length.");
        return 0;
    }
    return 1;
}

JNIEXPORT void JNICALL
Java_com_example_pakebdh_17816_ChicPake_00024Native_initStart(
    JNIEnv *env, jclass klass, jbyteArray msg1, jbyteArray pk, jbyteArray sk,
    jbyteArray password, jbyteArray sid)
{
    struct {
        uint8_t msg1[MSG_BYTES], pk[MSG_BYTES], sk[SK_BYTES], password[KEY_BYTES], sid[KEY_BYTES];
    } state = {0};
    (void)klass;
    if (!exact_array(env, msg1, MSG_BYTES) || !exact_array(env, pk, MSG_BYTES)
            || !exact_array(env, sk, SK_BYTES) || !exact_array(env, password, KEY_BYTES)
            || !exact_array(env, sid, KEY_BYTES)) goto cleanup;
    (*env)->GetByteArrayRegion(env, password, 0, KEY_BYTES, (jbyte *)state.password);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->GetByteArrayRegion(env, sid, 0, KEY_BYTES, (jbyte *)state.sid);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    if (chic_init_start(state.msg1, state.pk, state.sk, state.password, state.sid) != 0) {
        throw_exception(env, "java/lang/IllegalStateException", "CHIC cryptographic random source failed.");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, msg1, 0, MSG_BYTES, (const jbyte *)state.msg1);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->SetByteArrayRegion(env, pk, 0, MSG_BYTES, (const jbyte *)state.pk);
    if ((*env)->ExceptionCheck(env)) goto cleanup;
    (*env)->SetByteArrayRegion(env, sk, 0, SK_BYTES, (const jbyte *)state.sk);
cleanup:
    erase(&state, sizeof(state));
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_pakebdh_17816_ChicPake_00024Native_initEnd(
    JNIEnv *env, jclass klass, jbyteArray response, jbyteArray msg1,
    jbyteArray pk, jbyteArray sk, jbyteArray sid)
{
    struct {
        uint8_t response[MSG_BYTES], msg1[MSG_BYTES], pk[MSG_BYTES], sk[SK_BYTES];
        uint8_t sid[KEY_BYTES], key[KEY_BYTES];
    } state = {0};
    jbyteArray result = NULL;
    (void)klass;
    if (!exact_array(env, response, MSG_BYTES) || !exact_array(env, msg1, MSG_BYTES)
            || !exact_array(env, pk, MSG_BYTES) || !exact_array(env, sk, SK_BYTES)
            || !exact_array(env, sid, KEY_BYTES)) goto cleanup;
#define COPY_INPUT(name, length) \
    (*env)->GetByteArrayRegion(env, name, 0, length, (jbyte *)state.name); \
    if ((*env)->ExceptionCheck(env)) goto cleanup
    COPY_INPUT(response, MSG_BYTES);
    COPY_INPUT(msg1, MSG_BYTES);
    COPY_INPUT(pk, MSG_BYTES);
    COPY_INPUT(sk, SK_BYTES);
    COPY_INPUT(sid, KEY_BYTES);
#undef COPY_INPUT
    if (chic_init_end(state.key, state.response, state.msg1, state.pk, state.sk, state.sid) != 0) {
        throw_exception(env, "java/lang/SecurityException", "CHIC response authentication failed.");
        goto cleanup;
    }
    result = (*env)->NewByteArray(env, KEY_BYTES);
    if (result != NULL) (*env)->SetByteArrayRegion(env, result, 0, KEY_BYTES, (const jbyte *)state.key);
cleanup:
    erase(&state, sizeof(state));
    return result;
}
