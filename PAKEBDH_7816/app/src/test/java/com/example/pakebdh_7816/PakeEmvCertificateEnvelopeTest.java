package com.example.pakebdh_7816;

import static org.junit.Assert.*;
import org.junit.Test;

public class PakeEmvCertificateEnvelopeTest {
    @Test public void decryptsTheFixedPaddedEnvelopeAndRejectsAuthenticatedBadPadding() throws Exception {
        byte[] cert = {0x30, 1, 0}, issuer = {0x30, 2, 0, 1}, key = new byte[32];
        byte[] plain = PakeEmvProtocol.paddedCertificates(cert, issuer);
        byte[] encrypted = PakeEmvCrypto.aesGcmEncrypt(key, plain);
        assertEquals(8220, encrypted.length);
        PakeEmvCrypto.CertBundle parsed = PakeEmvCrypto.decryptAndParseCertPayload(key, encrypted);
        assertArrayEquals(cert, parsed.certC);
        assertArrayEquals(issuer, parsed.certIS);
        plain[plain.length - 1] = 1;
        byte[] invalidPadding = PakeEmvCrypto.aesGcmEncrypt(key, plain);
        assertThrows(IllegalArgumentException.class,
                () -> PakeEmvCrypto.decryptAndParseCertPayload(key, invalidPadding));
        encrypted[20] ^= 1;
        assertThrows(Exception.class, () -> PakeEmvCrypto.decryptAndParseCertPayload(key, encrypted));
    }
}
