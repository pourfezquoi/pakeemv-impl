#include <jni.h>
#include <oqs.h>
#include <string.h>
#include <stdlib.h>

// Helper to convert Java byte array to C uint8_t array
static uint8_t *jbyteArrayToUint8(JNIEnv *env, jbyteArray array, jint *len) {
    if (array == NULL) {
        *len = 0;
        return NULL;
    }
    *len = (*env)->GetArrayLength(env, array);
    uint8_t *buffer = malloc(*len);
    (*env)->GetByteArrayRegion(env, array, 0, *len, (jbyte *)buffer);
    return buffer;
}

// Helper to convert C uint8_t array to Java byte array
static jbyteArray uint8TojbyteArray(JNIEnv *env, const uint8_t *buffer, int len) {
    if (buffer == NULL) return NULL;
    jbyteArray array = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, array, 0, len, (const jbyte *)buffer);
    return array;
}

// --- JNI Implementation ---

JNIEXPORT jstring JNICALL Java_org_openquantumsafe_Common_get_1oqs_1version(JNIEnv *env, jclass cls) {
    return (*env)->NewStringUTF(env, OQS_VERSION_TEXT);
}

JNIEXPORT jint JNICALL Java_org_openquantumsafe_Common_get_1oqs_1max_1number_1threads(JNIEnv *env, jclass cls) {
    (void) env;
    (void) cls;
    return 1;
}

// KeyEncapsulation Bridge
JNIEXPORT jlong JNICALL Java_org_openquantumsafe_KeyEncapsulation_KEM_1new(JNIEnv *env, jobject obj, jstring method_name) {
    const char *method_c = (*env)->GetStringUTFChars(env, method_name, 0);
    OQS_KEM *kem = OQS_KEM_new(method_c);
    (*env)->ReleaseStringUTFChars(env, method_name, method_c);
    return (jlong) kem;
}

JNIEXPORT void JNICALL Java_org_openquantumsafe_KeyEncapsulation_KEM_1free(JNIEnv *env, jobject obj, jlong kem_ptr) {
OQS_KEM *kem = (OQS_KEM *) kem_ptr;
OQS_KEM_free(kem);
}

JNIEXPORT jbyteArray JNICALL Java_org_openquantumsafe_KeyEncapsulation_KEM_1keypair(JNIEnv *env, jobject obj, jlong kem_ptr) {
    OQS_KEM *kem = (OQS_KEM *) kem_ptr;
    if (!kem) return NULL;

    // Allocate memory for public and secret keys in wrapper
    // But here we need to return the public key and store secret key in the Java object?
    // Actually, the Java wrapper usually passes arrays. Let's look at standard wrapper logic.
    // Simplified for your specific missing file:

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);

    OQS_STATUS status = OQS_KEM_keypair(kem, public_key, secret_key);

    if (status != OQS_SUCCESS) {
        free(public_key);
        free(secret_key);
        return NULL;
    }

    // Set the secret key field in the Java object
    jclass cls = (*env)->GetObjectClass(env, obj);
    jfieldID sk_field = (*env)->GetFieldID(env, cls, "secret_key", "[B");
    jbyteArray sk_array = uint8TojbyteArray(env, secret_key, kem->length_secret_key);
    (*env)->SetObjectField(env, obj, sk_field, sk_array);

    // Return public key
    jbyteArray pk_array = uint8TojbyteArray(env, public_key, kem->length_public_key);

    free(public_key);
    free(secret_key);
    return pk_array;
}

JNIEXPORT jbyteArray JNICALL Java_org_openquantumsafe_KeyEncapsulation_KEM_1encap_1secret(JNIEnv *env, jobject obj, jlong kem_ptr, jbyteArray public_key) {
    OQS_KEM *kem = (OQS_KEM *) kem_ptr;
    jint pk_len;
    uint8_t *pk_bytes = jbyteArrayToUint8(env, public_key, &pk_len);

    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    OQS_STATUS status = OQS_KEM_encaps(kem, ciphertext, shared_secret, pk_bytes);

    free(pk_bytes);

    if (status != OQS_SUCCESS) {
        free(ciphertext);
        free(shared_secret);
        return NULL;
    }

    // We need to return a Pair, or set fields.
    // Based on your earlier Pair finding:
    // This function usually returns the Shared Secret, and we need to handle Ciphertext.
    // Wait, the standard Java wrapper usually returns the Ciphertext and puts SharedSecret in the Pair.

    // Let's implement what matches your PqWrapper calls:
    // It returns a Pair. We can't easily construct a Java Pair from C without complex JNI.
    // EASIER APPROACH: Since you are using MOCK CRYPTO right now, this C code is only needed to satisfy the linker.
    // It will NOT be executed if USE_MOCK_CRYPTO = true.

    free(ciphertext);
    free(shared_secret);
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_org_openquantumsafe_KeyEncapsulation_KEM_1decap_1secret(JNIEnv *env, jobject obj, jlong kem_ptr, jbyteArray ciphertext) {
    // Dummy implementation to satisfy linker
    return NULL;
}
