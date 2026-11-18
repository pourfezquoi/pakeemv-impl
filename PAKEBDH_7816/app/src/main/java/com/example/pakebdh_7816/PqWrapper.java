package com.example.pakebdh_7816;

import android.util.Log;

import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;


public class PqWrapper {
    private static final String TAG = "PQC_WRAPPER";
    private static final String KEM_ALG = "ML-KEM-512";
    private static final int EXPECTED_PUBLIC_KEY_LEN = 800; // ML-KEM-512 public key length

    private KeyEncapsulation kem;
    private byte[] public_key;
    private byte[] secret_key;

    public PqWrapper() {
        try {
            Log.d(TAG, "Initializing Real Liboqs for " + KEM_ALG);
            this.kem = new KeyEncapsulation(KEM_ALG);
        } catch (Throwable t) {
            Log.e(TAG, "Crypto Init Failed", t);
            this.kem = null;
        }
    }

    public byte[] generateKey() {
        try {
            if (this.kem == null) {
                Log.e(TAG, "Key Gen Failed: KEM not initialized.");
                return null;
            }
            Log.d(TAG, "Generating Real Keys...");
            this.kem.generate_keypair();

            this.public_key = kem.export_public_key();
            this.secret_key = kem.export_secret_key();

            if (this.public_key == null || this.public_key.length != EXPECTED_PUBLIC_KEY_LEN) {
                Log.e(TAG, "Unexpected public key length for " + KEM_ALG + ": "
                        + (this.public_key == null ? -1 : this.public_key.length)
                        + " (expected " + EXPECTED_PUBLIC_KEY_LEN + ").");
                return null;
            }

            Log.d(TAG, "Keys Generated. Size: " + this.public_key.length);
            return this.public_key;
        } catch (Throwable t) {
            Log.e(TAG, "Key Gen Failed", t);
            return null;
        }
    }

    public byte[] decapsulate(byte[] ciphertext) {
        try {
            if (this.kem == null) {
                Log.e(TAG, "Decapsulation Failed: KEM not initialized.");
                return null;
            }
            Log.d(TAG, "Decapsulating Real Ciphertext...");
            byte[] sharedSecret = kem.decap_secret(ciphertext);
            if (sharedSecret == null || sharedSecret.length == 0) {
                return null;
            }
            return sharedSecret;
        } catch (Throwable t) {
            Log.e(TAG, "Decapsulation Failed", t);
            return null;
        }
    }

    public Pair<byte[], byte[]> encapsulate(byte[] publicKey) {
        try {
            if (this.kem == null) {
                Log.e(TAG, "Encapsulation Failed: KEM not initialized.");
                return null;
            }
            Log.d(TAG, "Encapsulating secret with peer public key...");
            return kem.encap_secret(publicKey);
        } catch (Throwable t) {
            Log.e(TAG, "Encapsulation Failed", t);
            return null;
        }
    }

    public byte[] getPublicKey() {
        return this.public_key;
    }
}
