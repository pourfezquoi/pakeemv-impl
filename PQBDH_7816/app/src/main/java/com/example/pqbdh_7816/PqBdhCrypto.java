package com.example.pqbdh_7816;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.openquantumsafe.Signature;

/** Crypto and certificate operations for the fixed certificate-envelope profile. */
final class PqBdhCrypto {
    static final int CERT_PLAINTEXT_BYTES = 8192;
    static final int CERT_CIPHERTEXT_BYTES = CERT_PLAINTEXT_BYTES + 12 + 16;
    private static final int AES_GCM_NONCE_LEN = 12;
    private static final int AES_GCM_TAG_LEN_BITS = 128;

    private PqBdhCrypto() {
    }

    static byte[] sha256(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    static CertBundle decryptAndParseCertPayload(byte[] k1, byte[] encryptedPayload) throws Exception {
        if (k1 == null || k1.length != 32) {
            throw new IllegalArgumentException("K1 must be 32 bytes (SHA-256 output).");
        }
        if (encryptedPayload == null || encryptedPayload.length != CERT_CIPHERTEXT_BYTES) {
            throw new IllegalArgumentException("Certificate ciphertext must contain exactly 8220 bytes.");
        }

        byte[] nonce = Arrays.copyOfRange(encryptedPayload, 0, AES_GCM_NONCE_LEN);
        byte[] ciphertextAndTag = Arrays.copyOfRange(encryptedPayload, AES_GCM_NONCE_LEN, encryptedPayload.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(k1, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AES_GCM_TAG_LEN_BITS, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        // Authenticate the complete AEAD envelope before interpreting any length or DER byte.
        byte[] plaintext = cipher.doFinal(ciphertextAndTag);
        try {
            return parseCertificatePlaintext(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static CertBundle parseCertificatePlaintext(byte[] plaintext) {
        if (plaintext.length != CERT_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException("Certificate plaintext must contain exactly 8192 bytes.");
        }
        int certCLen = ((plaintext[0] & 255) << 8) | (plaintext[1] & 255);
        int certISLen = ((plaintext[2] & 255) << 8) | (plaintext[3] & 255);
        int end = 4 + certCLen + certISLen;
        if (certCLen == 0 || certISLen == 0 || end >= plaintext.length
                || plaintext[end] != (byte) 0x80) {
            throw new IllegalArgumentException("Invalid certificate lengths or padding marker.");
        }
        int badPadding = 0;
        for (int i = end + 1; i < plaintext.length; i++) badPadding |= plaintext[i];
        if (badPadding != 0) throw new IllegalArgumentException("Nonzero certificate padding.");
        byte[] certC = Arrays.copyOfRange(plaintext, 4, 4 + certCLen);
        byte[] certIS = Arrays.copyOfRange(plaintext, 4 + certCLen, end);
        return new CertBundle(certC, certIS);
    }

    static byte[] aesGcmEncrypt(byte[] key, byte[] plaintext) throws Exception {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("AES key must be 32 bytes.");
        }
        byte[] nonce = new byte[AES_GCM_NONCE_LEN];
        new java.security.SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AES_GCM_TAG_LEN_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] ciphertextAndTag = cipher.doFinal(plaintext);
        byte[] out = new byte[nonce.length + ciphertextAndTag.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ciphertextAndTag, 0, out, nonce.length, ciphertextAndTag.length);
        return out;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static byte[] deriveFinalSessionKey(byte[] ss1, byte[] ss2) throws Exception {
        if (ss1 == null || ss2 == null) {
            throw new IllegalArgumentException("ss1/ss2 must not be null.");
        }
        byte[] merged = new byte[ss1.length + ss2.length];
        System.arraycopy(ss1, 0, merged, 0, ss1.length);
        System.arraycopy(ss2, 0, merged, ss1.length, ss2.length);
        return sha256(merged);
    }

    static void verifyCertificateSignature(byte[] certDerBytes, byte[] signerPublicKeyRaw) throws Exception {
        X509CertificateHolder holder = new X509CertificateHolder(certDerBytes);
        String sigAlg = mapSigOidToOqsAlg(holder.getSignatureAlgorithm().getAlgorithm().getId());
        byte[] tbs = holder.toASN1Structure().getTBSCertificate().getEncoded();
        byte[] signature = holder.getSignature();

        Signature oqsSig = new Signature(sigAlg);
        try {
            if (!oqsSig.verify(tbs, signature, signerPublicKeyRaw)) {
                throw new SecurityException("Certificate signature invalid for algorithm " + sigAlg);
            }
        } finally {
            oqsSig.dispose_sig();
        }
    }

    static byte[] extractRawPublicKey(X509CertificateHolder holder) {
        return holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    }

    static String mapSigOidToOqsAlg(String sigOid) {
        if ("2.16.840.1.101.3.4.3.17".equals(sigOid)) {
            return "ML-DSA-44";
        }
        throw new IllegalArgumentException("Unsupported PQC signature OID: " + sigOid);
    }

    static void ensurePqcProviders() {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            if (Security.getProvider("BCPQC") == null) {
                Security.addProvider(new BouncyCastlePQCProvider());
            }
        } catch (Throwable ignored) {
            // Fallback to default providers when BC/BCPQC registration is unavailable.
        }
    }

    static final class CertBundle {
        final byte[] certC;
        final byte[] certIS;

        CertBundle(byte[] certC, byte[] certIS) {
            this.certC = certC;
            this.certIS = certIS;
        }
    }
}
