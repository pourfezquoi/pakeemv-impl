package com.example.pqbdh_7816;

import static org.junit.Assert.*;

import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

/** Authenticated framing tests; certificate signature policy is exercised separately. */
public class PqBdhCertificateEnvelopeTest {
    private static final int PLAINTEXT_BYTES = 8192;
    private static final int CIPHERTEXT_BYTES = 8220;
    private static final byte[] KEY = sequence(32, 11);
    private static final byte[] CARD_DER = {0x30, 0x03, 0x02, 0x01, 0x01};
    private static final byte[] ISSUER_DER = {0x30, 0x03, 0x02, 0x01, 0x02};

    @Test
    public void decryptsAuthenticatedEnvelopeAndReturnsOnlyTheTwoDeclaredDerValues() throws Exception {
        byte[] ciphertext = encrypt(padded(CARD_DER, ISSUER_DER));
        assertEquals(CIPHERTEXT_BYTES, ciphertext.length);
        assertEquals(PLAINTEXT_BYTES, PqBdhCrypto.CERT_PLAINTEXT_BYTES);
        assertEquals(CIPHERTEXT_BYTES, PqBdhCrypto.CERT_CIPHERTEXT_BYTES);

        PqBdhCrypto.CertBundle parsed = PqBdhCrypto.decryptAndParseCertPayload(KEY, ciphertext);
        assertArrayEquals(CARD_DER, parsed.certC);
        assertArrayEquals(ISSUER_DER, parsed.certIS);
        assertEquals(CARD_DER.length, parsed.certC.length);
        assertEquals(ISSUER_DER.length, parsed.certIS.length);
    }

    @Test
    public void acceptsAMarkerAtTheLastPlaintextByteWithoutAddingPaddingToDerValues() throws Exception {
        byte[] card = sequence(8186, 20), issuer = {0x30};
        PqBdhCrypto.CertBundle parsed = PqBdhCrypto.decryptAndParseCertPayload(KEY,
                encrypt(padded(card, issuer)));
        assertArrayEquals(card, parsed.certC);
        assertArrayEquals(issuer, parsed.certIS);
    }

    @Test
    public void rejectsAuthenticatedEmptyOrOverclaimedCertificateLengths() throws Exception {
        for (int[] lengths : new int[][]{{0, 5}, {5, 0}, {0, 0}, {65535, 5},
                {5, 65535}, {8187, 1}, {1, 8190}}) {
            byte[] plain = padded(CARD_DER, ISSUER_DER);
            putLength(plain, 0, lengths[0]);
            putLength(plain, 2, lengths[1]);
            byte[] ciphertext = encrypt(plain);
            assertThrows(IllegalArgumentException.class,
                    () -> PqBdhCrypto.decryptAndParseCertPayload(KEY, ciphertext));
        }
    }

    @Test
    public void rejectsAuthenticatedMissingOrWrongPaddingMarkers() throws Exception {
        for (int marker : new int[]{0, 1, 0x7f, 0x81, 0xff}) {
            byte[] plain = padded(CARD_DER, ISSUER_DER);
            plain[4 + CARD_DER.length + ISSUER_DER.length] = (byte) marker;
            byte[] ciphertext = encrypt(plain);
            assertThrows(IllegalArgumentException.class,
                    () -> PqBdhCrypto.decryptAndParseCertPayload(KEY, ciphertext));
        }
    }

    @Test
    public void rejectsAuthenticatedNonzeroPaddingAnywhereAfterTheMarker() throws Exception {
        int marker = 4 + CARD_DER.length + ISSUER_DER.length;
        for (int position : new int[]{marker + 1, marker + 100, PLAINTEXT_BYTES - 1}) {
            byte[] plain = padded(CARD_DER, ISSUER_DER);
            plain[position] = (byte) 0x80;
            byte[] ciphertext = encrypt(plain);
            assertThrows(IllegalArgumentException.class,
                    () -> PqBdhCrypto.decryptAndParseCertPayload(KEY, ciphertext));
        }
    }

    @Test
    public void verifiesTheGcmTagBeforeParsingAnInvalidPlaintext() throws Exception {
        byte[] invalidPlain = padded(CARD_DER, ISSUER_DER);
        putLength(invalidPlain, 0, 65535);
        byte[] ciphertext = encrypt(invalidPlain);
        ciphertext[ciphertext.length - 1] ^= 1;
        assertThrows(AEADBadTagException.class,
                () -> PqBdhCrypto.decryptAndParseCertPayload(KEY, ciphertext));
    }

    @Test
    public void rejectsCiphertextNonceAndKeyTampering() throws Exception {
        for (int position : new int[]{0, 12, 100, CIPHERTEXT_BYTES - 1}) {
            byte[] ciphertext = encrypt(padded(CARD_DER, ISSUER_DER));
            ciphertext[position] ^= 1;
            assertThrows(AEADBadTagException.class,
                    () -> PqBdhCrypto.decryptAndParseCertPayload(KEY, ciphertext));
        }
        byte[] otherKey = KEY.clone();
        otherKey[0] ^= 1;
        byte[] ciphertext = encrypt(padded(CARD_DER, ISSUER_DER));
        assertThrows(AEADBadTagException.class,
                () -> PqBdhCrypto.decryptAndParseCertPayload(otherKey, ciphertext));
    }

    @Test
    public void rejectsTheAuthenticatedLegacyUnpaddedEnvelopeInsteadOfFallingBack() throws Exception {
        byte[] oldPlaintext = new byte[2 + 3444 + 3960];
        putLength(oldPlaintext, 0, 3444);
        byte[] legacyCiphertext = encrypt(oldPlaintext);
        assertEquals(7434, legacyCiphertext.length);
        assertThrows(IllegalArgumentException.class,
                () -> PqBdhCrypto.decryptAndParseCertPayload(KEY, legacyCiphertext));
    }

    @Test
    public void rejectsTruncatedExtendedOrMissingCiphertext() throws Exception {
        byte[] ciphertext = encrypt(padded(CARD_DER, ISSUER_DER));
        for (byte[] malformed : new byte[][]{null, new byte[0], new byte[27],
                Arrays.copyOf(ciphertext, ciphertext.length - 1),
                Arrays.copyOf(ciphertext, ciphertext.length + 1)}) {
            assertThrows(IllegalArgumentException.class,
                    () -> PqBdhCrypto.decryptAndParseCertPayload(KEY, malformed));
        }
    }

    private static byte[] padded(byte[] card, byte[] issuer) {
        byte[] plain = new byte[PLAINTEXT_BYTES];
        putLength(plain, 0, card.length);
        putLength(plain, 2, issuer.length);
        System.arraycopy(card, 0, plain, 4, card.length);
        System.arraycopy(issuer, 0, plain, 4 + card.length, issuer.length);
        plain[4 + card.length + issuer.length] = (byte) 0x80;
        return plain;
    }

    private static void putLength(byte[] input, int offset, int length) {
        input[offset] = (byte) (length >>> 8);
        input[offset + 1] = (byte) length;
    }

    private static byte[] encrypt(byte[] plaintext) throws Exception {
        // Fixed nonce is confined to independent framing fixtures, never production encryption.
        byte[] nonce = sequence(12, 91);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new GCMParameterSpec(128, nonce));
        byte[] encrypted = cipher.doFinal(plaintext);
        byte[] result = Arrays.copyOf(nonce, nonce.length + encrypted.length);
        System.arraycopy(encrypted, 0, result, nonce.length, encrypted.length);
        return result;
    }

    private static byte[] sequence(int length, int start) {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++) data[i] = (byte) (start + i);
        return data;
    }
}
