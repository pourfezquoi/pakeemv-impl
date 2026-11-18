package com.example.pakebdh_7816;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Concrete encodings and derivations of the manuscript's six-message figure. */
final class PakeEmvProtocol {
    static final String SUITE = "PAKE-EMV-v3:CHIC-ddf94132-Kyber512:ML-KEM-512:ML-DSA-44:SHA256:HKDF-SHA256:AES256-GCM:CERT8192";
    static final int HASH_BYTES = 32;
    static final int NONCE_BYTES = 32;
    static final int TAG_BYTES = 32;
    static final int X1_BYTES = 832;
    static final int X2_BYTES = 800;
    static final int CARD_KEY_BYTES = 800;
    static final int ISSUER_KEY_BYTES = 1312;
    static final int CERT_PLAINTEXT_BYTES = 8192;
    static final int ECERT_BYTES = 8220;
    static final int EC_BYTES = 796;
    static final int M3_BYTES = 64;
    static final int M5_BYTES = 828;
    static final int M6_BYTES = 32;

    private PakeEmvProtocol() { }

    static byte[] ctx1(byte[] x1, byte[] x2) throws GeneralSecurityException {
        length(x1, X1_BYTES, "X1");
        length(x2, X2_BYTES, "X2");
        return hash(ascii("PAKE-EMV"), ascii(SUITE), x1, x2);
    }

    static byte[] kc1(byte[] tk, byte[] ctx1, byte[] nu) throws GeneralSecurityException {
        length(tk, HASH_BYTES, "tk");
        length(ctx1, HASH_BYTES, "ctx1");
        length(nu, NONCE_BYTES, "nu");
        return hash(ascii("KC1"), tk, ctx1, nu);
    }

    static byte[] ctx2(byte[] m3, byte[] ctx1) throws GeneralSecurityException {
        length(m3, M3_BYTES, "M3");
        length(ctx1, HASH_BYTES, "ctx1");
        return hash(ascii("ctx2"), m3, ctx1);
    }

    static byte[] certKey(byte[] tk, byte[] ctx2) throws GeneralSecurityException {
        length(ctx2, HASH_BYTES, "ctx2");
        return kdf2Parts(tk, ascii("CERT"), ctx2);
    }

    static byte[] ctx3(byte[] ecert, byte[] ctx2) throws GeneralSecurityException {
        length(ecert, ECERT_BYTES, "ecert");
        length(ctx2, HASH_BYTES, "ctx2");
        return hash(ascii("ctx3"), ecert, ctx2);
    }

    static byte[] ec2Key(byte[] tk, byte[] ctx3) throws GeneralSecurityException {
        length(ctx3, HASH_BYTES, "ctx3");
        return kdf2Parts(tk, ascii("EC2"), ctx3);
    }

    static byte[] ctx4(byte[] ec, byte[] ctx3) throws GeneralSecurityException {
        length(ec, EC_BYTES, "ec");
        length(ctx3, HASH_BYTES, "ctx3");
        return hash(ascii("ctx4"), ec, ctx3);
    }

    static byte[] pkh(byte[] pkC, byte[] pkIS) throws GeneralSecurityException {
        length(pkC, CARD_KEY_BYTES, "pkC");
        length(pkIS, ISSUER_KEY_BYTES, "pkIS");
        return hash(ascii("pkh"), pkC, pkIS);
    }

    static Keys deriveKeys(byte[] tk, byte[] ss, byte[] pkh, byte[] ctx4)
            throws GeneralSecurityException {
        length(tk, HASH_BYTES, "tk");
        length(ss, HASH_BYTES, "ss");
        length(pkh, HASH_BYTES, "pkh");
        length(ctx4, HASH_BYTES, "ctx4");
        byte[] key = null;
        byte[] k2 = null;
        try {
            key = kdf2Parts(tk, ss, ascii("FINAL"), pkh, ctx4);
            k2 = kdf2Parts(tk, ss, ascii("CONF2"), pkh, ctx4);
            return new Keys(key, k2, kdf2Parts(tk, ss, ascii("CONF3"), pkh, ctx4));
        } catch (GeneralSecurityException | RuntimeException failed) {
            if (key != null) Arrays.fill(key, (byte) 0);
            if (k2 != null) Arrays.fill(k2, (byte) 0);
            throw failed;
        }
    }

    static byte[] kc2(byte[] k2, byte[] ctx4) throws GeneralSecurityException {
        length(k2, HASH_BYTES, "k2");
        length(ctx4, HASH_BYTES, "ctx4");
        return hash(ascii("KC2"), k2, ctx4);
    }

    static byte[] ctx5(byte[] pi2, byte[] ctx4) throws GeneralSecurityException {
        length(pi2, TAG_BYTES, "pi2");
        length(ctx4, HASH_BYTES, "ctx4");
        return hash(ascii("ctx5"), pi2, ctx4);
    }

    static byte[] kc3(byte[] k3, byte[] ctx5) throws GeneralSecurityException {
        length(k3, HASH_BYTES, "k3");
        length(ctx5, HASH_BYTES, "ctx5");
        return hash(ascii("KC3"), k3, ctx5);
    }

    /** RFC5869 Extract(salt=0^32, IKM=tk), Expand(info, L=32). */
    static byte[] kdf2(byte[] tk, byte[] info) throws GeneralSecurityException {
        if (info == null) throw new IllegalArgumentException("KDF2 info is null");
        return kdf2Parts(tk, info);
    }

    private static byte[] kdf2Parts(byte[] tk, byte[]... info) throws GeneralSecurityException {
        length(tk, HASH_BYTES, "tk");
        byte[] prk = hmac(new byte[HASH_BYTES], tk);
        try {
            Mac expand = Mac.getInstance("HmacSHA256");
            expand.init(new SecretKeySpec(prk, "HmacSHA256"));
            for (byte[] part : info) expand.update(part);
            expand.update((byte) 1);
            return expand.doFinal();
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    static byte[] paddedCertificates(byte[] certC, byte[] certIS) {
        if (certC == null || certIS == null || certC.length == 0 || certIS.length == 0
                || certC.length > 65535 || certIS.length > 65535
                || (long) certC.length + certIS.length + 5 > CERT_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException("Certificates do not fit the fixed certificate envelope");
        }
        byte[] plain = new byte[CERT_PLAINTEXT_BYTES];
        plain[0] = (byte) (certC.length >>> 8);
        plain[1] = (byte) certC.length;
        plain[2] = (byte) (certIS.length >>> 8);
        plain[3] = (byte) certIS.length;
        System.arraycopy(certC, 0, plain, 4, certC.length);
        System.arraycopy(certIS, 0, plain, 4 + certC.length, certIS.length);
        plain[4 + certC.length + certIS.length] = (byte) 0x80;
        return plain;
    }

    static Certificates parseCertificates(byte[] plain) {
        length(plain, CERT_PLAINTEXT_BYTES, "Padded certificate plaintext");
        int lenC = ((plain[0] & 255) << 8) | (plain[1] & 255);
        int lenIS = ((plain[2] & 255) << 8) | (plain[3] & 255);
        int end = 4 + lenC + lenIS;
        if (lenC == 0 || lenIS == 0 || end >= plain.length || plain[end] != (byte) 0x80) {
            throw new IllegalArgumentException("Invalid certificate lengths or padding marker");
        }
        int badPadding = 0;
        for (int i = end + 1; i < plain.length; ++i) badPadding |= plain[i];
        if (badPadding != 0) throw new IllegalArgumentException("Nonzero certificate padding");
        return new Certificates(Arrays.copyOfRange(plain, 4, 4 + lenC),
                Arrays.copyOfRange(plain, 4 + lenC, end));
    }

    private static byte[] hash(byte[]... parts) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (byte[] part : parts) digest.update(part);
        return digest.digest();
    }

    private static byte[] hmac(byte[] key, byte[] input) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(input);
    }

    private static byte[] ascii(String label) {
        return label.getBytes(StandardCharsets.US_ASCII);
    }

    private static void length(byte[] field, int expected, String name) {
        if (field == null || field.length != expected) {
            throw new IllegalArgumentException(name + " must be " + expected + " bytes");
        }
    }

    static final class Keys {
        final byte[] finalKey;
        final byte[] k2;
        final byte[] k3;

        Keys(byte[] finalKey, byte[] k2, byte[] k3) {
            this.finalKey = finalKey;
            this.k2 = k2;
            this.k3 = k3;
        }
    }

    static final class Certificates {
        final byte[] certC;
        final byte[] certIS;

        Certificates(byte[] certC, byte[] certIS) {
            this.certC = certC;
            this.certIS = certIS;
        }
    }
}
