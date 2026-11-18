#ifndef AES_GCM_H
#define AES_GCM_H

// Include the low-level hardware AES interface definitions
#include "Sym_Alg_v101.h" 



typedef struct {
    unsigned char h_key[16];   // Hash key H
    unsigned char tag_mask[16];// Mask used to generate the final tag
    unsigned char ghash[16];   // Current GHASH accumulator
    unsigned char counter[16]; // Counter (J0 and subsequent increments)
    unsigned char key[32];     // AES-256 key
    unsigned int  aad_len;     // AAD length
    unsigned int  msg_len;     // Plaintext/ciphertext length
} aes_gcm_ctx;

/**
 * @brief Initialize the GCM context
 * @param ctx   Pointer to the GCM context
 * @param key   256-bit key (32 bytes)
 * @param iv    12-byte initialization vector
 */
void aes_gcm_init(aes_gcm_ctx *ctx, const unsigned char *key, const unsigned char *iv);

/**
 * @brief Process additional authenticated data (AAD)
 */
void aes_gcm_update_aad(aes_gcm_ctx *ctx, const unsigned char *aad, unsigned int len);

/**
 * @brief Encrypt and update authentication (incremental calls)
 */
void aes_gcm_encrypt_update(aes_gcm_ctx *ctx, const unsigned char *plain, unsigned char *cipher, unsigned int len);

/**
 * @brief Decrypt and update authentication (incremental calls)
 */
void aes_gcm_decrypt_update(aes_gcm_ctx *ctx, const unsigned char *cipher, unsigned char *plain, unsigned int len);

/**
 * @brief Finalize the operation and output the 16-byte tag
 */
void aes_gcm_finalize(aes_gcm_ctx *ctx, unsigned char *tag);

/**
 * @brief One-shot wrapper: AES-GCM encryption and tag generation
 * @param key         Key (32 bytes)
 * @param iv          Initialization vector (12 bytes)
 * @param plain       Input plaintext
 * @param plain_len   Plaintext length
 * @param aad         Additional authenticated data (may be NULL)
 * @param aad_len     AAD length (may be 0)
 * @param cipher      Output ciphertext (length equals plain_len)
 * @param tag         Output authentication tag (16 bytes)
 */
void aes_gcm_encrypt_full(const unsigned char *key, const unsigned char *iv,
                          const unsigned char *plain, unsigned int plain_len,
                          const unsigned char *aad, unsigned int aad_len,
                          unsigned char *cipher, unsigned char *tag);

/**
 * @brief One-shot wrapper: AES-GCM decryption and tag verification (as required by security specifications)
 * @param key         Key (32 bytes)
 * @param iv          Initialization vector (12 bytes)
 * @param cipher      Input ciphertext
 * @param cipher_len  Ciphertext length
 * @param aad         Additional authenticated data (must match the data used during encryption)
 * @param aad_len     AAD length
 * @param expected_tag Expected authentication tag (generated during encryption)
 * @param plain       Output plaintext (length equals cipher_len)
 * @return 0: Success with valid authentication; -1: Authentication failed (tampered data or an incorrect key)
 */
int aes_gcm_decrypt_verify(const unsigned char *key, const unsigned char *iv,
                           const unsigned char *cipher, unsigned int cipher_len,
                           const unsigned char *aad, unsigned int aad_len,
                           const unsigned char *expected_tag, unsigned char *plain);

#endif // AES_GCM_H
							
													 