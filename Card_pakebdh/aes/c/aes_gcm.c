#include "aes_gcm.h"
#include <string.h>

// Multiplication in GF(2^128), using the GCM reduction polynomial: x^128 + x^7 + x^2 + x + 1
static void gf_mult(unsigned char *x, const unsigned char *y) {
    unsigned char res[16] = {0};
    unsigned char V[16];
    memcpy(V, y, 16);

    for (int i = 0; i < 128; i++) {
        if ((x[i >> 3] >> (7 - (i & 7))) & 1) {
            for (int j = 0; j < 16; j++) res[j] ^= V[j];
        }
        unsigned char carry = V[15] & 1;
        for (int j = 15; j > 0; j--) V[j] = (V[j] >> 1) | (V[j-1] << 7);
        V[0] >>= 1;
        if (carry) V[0] ^= 0xE1; 
    }
    memcpy(x, res, 16);
}

// Increment the counter (big-endian; increment only the low 32 bits)
static void inc_counter(unsigned char *counter) {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0) break;
    }
}

/* --- GCM core function implementations --- */

void aes_gcm_init(aes_gcm_ctx *ctx, const unsigned char *key, const unsigned char *iv) {
    unsigned char zero[16] = {0};
    unsigned char j0[16] = {0};
    
    memset(ctx, 0, sizeof(aes_gcm_ctx));
    
    // Save the key, assuming AES-256 (32 bytes)
    memcpy(ctx->key, key, 32); 
    
    // 1. Generate the hash key H = AES_ECB(K, 0^128)
    // Interface parameters: keylen=32 bytes, blen=16 bytes, algmod=0 (ECB mode)
    AES_Encrypt((unsigned char*)key, 32, zero, ctx->h_key, 16, NULL, 0);

    // 2. Generate J0 = IV (assumed to be 12 bytes) || 0^31 || 1
    memcpy(j0, iv, 12);
    j0[15] = 1;

    // 3. Generate the tag mask = AES_ECB(K, J0)
    AES_Encrypt((unsigned char*)key, 32, j0, ctx->tag_mask, 16, NULL, 0);

    // 4. Start the encryption counter at J0 + 1
    memcpy(ctx->counter, j0, 16);
    inc_counter(ctx->counter);

    ctx->aad_len = 0;
    ctx->msg_len = 0;
}

// Update additional authenticated data (AAD)
void aes_gcm_update_aad(aes_gcm_ctx *ctx, const unsigned char *aad, unsigned int len) {
    for (unsigned int i = 0; i < len; i += 16) {
        unsigned int block_len = (len - i) < 16 ? (len - i) : 16;
        for (unsigned int j = 0; j < block_len; j++) {
            ctx->ghash[j] ^= aad[i + j];
        }
        gf_mult(ctx->ghash, ctx->h_key);
    }
    ctx->aad_len += len;
}

// Encryption function
void aes_gcm_encrypt_update(aes_gcm_ctx *ctx, const unsigned char *plain, unsigned char *cipher, unsigned int len) {
    if (len == 0) return;

    unsigned int full_blocks_len = (len / 16) * 16;
    unsigned int remainder = len % 16;

    // 1. Process all complete 16-byte blocks together
    if (full_blocks_len > 0) {
        // Invoke hardware CTR mode (algmod=3) with the current counter
        AES_Encrypt(ctx->key, 32, (unsigned char*)plain, cipher, full_blocks_len, ctx->counter, 3);
        
        // Update GHASH
        for (unsigned int i = 0; i < full_blocks_len; i += 16) {
            for (int j = 0; j < 16; j++) {
                ctx->ghash[j] ^= cipher[i + j];
            }
            gf_mult(ctx->ghash, ctx->h_key);
        }
        
        // Synchronize the counter stored in the context structure
        unsigned int num_blocks = full_blocks_len / 16;
        for (unsigned int k = 0; k < num_blocks; k++) {
            inc_counter(ctx->counter);
        }
    }

    // 2. Process the trailing partial block of fewer than 16 bytes
    if (remainder > 0) {
        unsigned char temp_plain[16] = {0};
        unsigned char temp_cipher[16] = {0};
        
        memcpy(temp_plain, plain + full_blocks_len, remainder);

        // The hardware requires blen to be a multiple of 16
        AES_Encrypt(ctx->key, 32, temp_plain, temp_cipher, 16, ctx->counter, 3);
        memcpy(cipher + full_blocks_len, temp_cipher, remainder);

        // Update GHASH (pad to 16 bytes with zeros before XORing)
        unsigned char padded_cipher[16] = {0};
        memcpy(padded_cipher, temp_cipher, remainder); // Copy the valid ciphertext bytes; leave the rest as zeros
        for (unsigned int j = 0; j < 16; j++) {
            ctx->ghash[j] ^= padded_cipher[j];
        }
        gf_mult(ctx->ghash, ctx->h_key);

        inc_counter(ctx->counter);
    }
    
    ctx->msg_len += len;
}

// Decryption function
void aes_gcm_decrypt_update(aes_gcm_ctx *ctx, const unsigned char *cipher, unsigned char *plain, unsigned int len) {
    if (len == 0) return;

    unsigned int full_blocks_len = (len / 16) * 16;
    unsigned int remainder = len % 16;

    if (full_blocks_len > 0) {
        // During decryption, update GHASH with the ciphertext first
        for (unsigned int i = 0; i < full_blocks_len; i += 16) {
            for (int j = 0; j < 16; j++) {
                ctx->ghash[j] ^= cipher[i + j];
            }
            gf_mult(ctx->ghash, ctx->h_key);
        }

        // Decrypt using hardware CTR mode
        AES_Encrypt(ctx->key, 32, (unsigned char*)cipher, plain, full_blocks_len, ctx->counter, 3);
        
        unsigned int num_blocks = full_blocks_len / 16;
        
    }

    if (remainder > 0) {
        // Compute GHASH for the trailing ciphertext first (with zero padding)
        unsigned char padded_cipher[16] = {0};
        memcpy(padded_cipher, cipher + full_blocks_len, remainder);
        for (unsigned int j = 0; j < 16; j++) {
            ctx->ghash[j] ^= padded_cipher[j];
        }
        gf_mult(ctx->ghash, ctx->h_key);

        unsigned char temp_cipher[16] = {0};
        unsigned char temp_plain[16] = {0};
        memcpy(temp_cipher, cipher + full_blocks_len, remainder);

        AES_Encrypt(ctx->key, 32, temp_cipher, temp_plain, 16, ctx->counter, 3);
        memcpy(plain + full_blocks_len, temp_plain, remainder);

        inc_counter(ctx->counter);
    }
    
    ctx->msg_len += len;
}

void aes_gcm_finalize(aes_gcm_ctx *ctx, unsigned char *tag) {
    // 1. Populate the length block (len_block)
    unsigned char len_block[16];
    unsigned long long aad_bits = (unsigned long long)ctx->aad_len * 8;
    unsigned long long msg_bits = (unsigned long long)ctx->msg_len * 8;

    // Store the AAD length in bits (high 8 bytes, big-endian)
    for (int i = 0; i < 8; i++) {
        len_block[i] = (unsigned char)(aad_bits >> (56 - i * 8));
    }
    // Store the message length in bits (low 8 bytes, big-endian)
    for (int i = 0; i < 8; i++) {
        len_block[i + 8] = (unsigned char)(msg_bits >> (56 - i * 8));
    }
    
    // 2. Mix the length block into GHASH
    for (int j = 0; j < 16; j++) ctx->ghash[j] ^= len_block[j];
    gf_mult(ctx->ghash, ctx->h_key);

    // 3. Final tag = GHASH XOR tag_mask
    for (int i = 0; i < 16; i++) {
        tag[i] = ctx->ghash[i] ^ ctx->tag_mask[i];
    }
}

/* --- One-shot wrappers and secure verification --- */

void aes_gcm_encrypt_full(const unsigned char *key, const unsigned char *iv,
                          const unsigned char *plain, unsigned int plain_len,
                          const unsigned char *aad, unsigned int aad_len,
                          unsigned char *cipher, unsigned char *tag) {
    aes_gcm_ctx ctx;
    
    // 1. Initialize
    aes_gcm_init(&ctx, key, iv);
    
    // 2. Process AAD (if present)
    if (aad != NULL && aad_len > 0) {
        aes_gcm_update_aad(&ctx, aad, aad_len);
    }
    
    // 3. Encrypt the plaintext (if present)
    if (plain != NULL && plain_len > 0) {
        aes_gcm_encrypt_update(&ctx, plain, cipher, plain_len);
    }
    
    // 4. Generate the final tag
    aes_gcm_finalize(&ctx, tag);
}

int aes_gcm_decrypt_verify(const unsigned char *key, const unsigned char *iv,
                           const unsigned char *cipher, unsigned int cipher_len,
                           const unsigned char *aad, unsigned int aad_len,
                           const unsigned char *expected_tag, unsigned char *plain) {
    aes_gcm_ctx ctx;
    unsigned char computed_tag[16];
    
    // 1. Initialize
    aes_gcm_init(&ctx, key, iv);
    
    // 2. Process AAD
    if (aad != NULL && aad_len > 0) {
        aes_gcm_update_aad(&ctx, aad, aad_len);
    }
    
    // 3. Decrypt the ciphertext
    if (cipher != NULL && cipher_len > 0) {
        aes_gcm_decrypt_update(&ctx, cipher, plain, cipher_len);
    }
    
    // 4. Compute the tag for the decryption operation
    aes_gcm_finalize(&ctx, computed_tag);
    
    // 5. Compare tags securely (constant-time comparison to prevent timing attacks)
    int diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (computed_tag[i] ^ expected_tag[i]);
    }
    
    // 6. Check the verification result
    if (diff != 0) {
        // Authentication failed: clear the decrypted plaintext so the application cannot use unauthenticated data!
        if (plain != NULL && cipher_len > 0) {
            memset(plain, 0, cipher_len);
        }
        return -1; // Return an error code
    }
    
    return 0; // Success
}