package com.example.pakebdh_7816;

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

/** Outer-protocol crypto and certificate operations shared by the terminal and benchmark. */
final class PakeEmvCrypto {
    private static final int AES_GCM_NONCE_LEN = 12;
    private static final int AES_GCM_TAG_LEN_BITS = 128;

    private PakeEmvCrypto() {
    }

    static byte[] sha256(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    static CertBundle decryptAndParseCertPayload(byte[] certKey, byte[] encryptedPayload) throws Exception {
        if (certKey == null || certKey.length != 32) {
            throw new IllegalArgumentException("Certificate AE key must contain 32 bytes.");
        }
        if (encryptedPayload == null || encryptedPayload.length < AES_GCM_NONCE_LEN + 16) {
            throw new IllegalArgumentException("Invalid encrypted payload length.");
        }

        byte[] nonce = Arrays.copyOfRange(encryptedPayload, 0, AES_GCM_NONCE_LEN);
        byte[] ciphertextAndTag = Arrays.copyOfRange(encryptedPayload, AES_GCM_NONCE_LEN, encryptedPayload.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(certKey, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AES_GCM_TAG_LEN_BITS, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        byte[] plaintext = cipher.doFinal(ciphertextAndTag);
        try {
            PakeEmvProtocol.Certificates parsed = PakeEmvProtocol.parseCertificates(plaintext);
            return new CertBundle(parsed.certC, parsed.certIS);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
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
