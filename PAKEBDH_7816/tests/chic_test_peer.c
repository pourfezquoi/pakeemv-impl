#include <jni.h>
#include <stdint.h>
#include "chic.h"

/* Never linked into the Android APK. Supplies the real C responder to JNI tests. */
JNIEXPORT jbyteArray JNICALL
Java_com_example_pakebdh_17816_ChicJniIntegrationTest_respond(
    JNIEnv *env, jclass klass, jbyteArray message, jbyteArray password, jbyteArray sid)
{
    uint8_t msg[800], pw[32], session[32], output[832];
    jbyteArray result;
    (void)klass;
    (*env)->GetByteArrayRegion(env, message, 0, 800, (jbyte *)msg);
    (*env)->GetByteArrayRegion(env, password, 0, 32, (jbyte *)pw);
    (*env)->GetByteArrayRegion(env, sid, 0, 32, (jbyte *)session);
    if ((*env)->ExceptionCheck(env)) return NULL;
    if (chic_respond(output, output + 32, msg, pw, session) != 0) {
        jclass error = (*env)->FindClass(env, "java/lang/IllegalStateException");
        (*env)->ThrowNew(env, error, "Test responder RNG failed");
        return NULL;
    }
    result = (*env)->NewByteArray(env, 832);
    if (result != NULL) (*env)->SetByteArrayRegion(env, result, 0, 832, (jbyte *)output);
    return result;
}
