package com.example.pqbdh_7816;

import com.example.pqbdh_7816.apdu.ApduCodec;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.function.Consumer;

/** Shared application fragmentation, with an injectable APDU exchange for measurement. */
final class PqBdhIo {
    interface Exchange {
        byte[] send(byte[] command) throws Exception;
    }

    private PqBdhIo() { }

    static byte[] collectKemCiphertext(Exchange transport, byte[] firstResponse) throws Exception {
        ByteArrayOutputStream ct = new ByteArrayOutputStream();
        byte[] response = firstResponse;
        while (true) {
            if (response.length < 2) throw new IllegalStateException("Short APDU response for NegotiateKEM ciphertext.");
            byte[] payload = Arrays.copyOf(response, response.length - 2);
            if (payload.length > 0) ct.write(payload);
            byte sw1 = response[response.length - 2];
            byte sw2 = response[response.length - 1];
            if (sw1 == (byte) 0x90 && sw2 == (byte) 0x00) return ct.toByteArray();
            if (sw1 != (byte) 0x61) throw new IllegalStateException("Unexpected SW while reading NegotiateKEM ciphertext: " + String.format("%02X%02X", sw1, sw2));
            response = transport.send(ApduCodec.buildCommandApdu(0x80, 0xCA, 0x01, 0x00, null));
        }
    }

    static byte[] sendNegotiateKemFragmented(Exchange transport, byte[] payload, Consumer<String> logger) throws Exception {
        final int chunkSize = 240;
        int total = (payload.length + chunkSize - 1) / chunkSize;
        int offset = 0;
        int idx = 0;
        byte[] resp = null;
        while (offset < payload.length) {
            idx++;
            int n = Math.min(chunkSize, payload.length - offset);
            boolean more = (offset + n) < payload.length;
            byte[] frag = Arrays.copyOfRange(payload, offset, offset + n);
            byte[] apdu = ApduCodec.buildCommandApduNoLe(0x80, 0xCA, more ? 0x01 : 0x00, 0x00, frag);
            logger.accept("4." + idx + " NegotiateKEM fragment " + idx + "/" + total + " (" + n + " bytes, more=" + more + ")");
            resp = transport.send(apdu);
            if (resp == null || resp.length < 2) throw new IllegalStateException("Empty NegotiateKEM fragment response " + idx);
            byte sw1 = resp[resp.length - 2], sw2 = resp[resp.length - 1];
            if (more && (sw1 != (byte)0x90 || sw2 != (byte)0x00)) {
                throw new IllegalStateException("NegotiateKEM fragment " + idx + " SW=" + String.format("%02X%02X", sw1, sw2));
            }
            offset += n;
        }
        return resp;
    }

    static byte[] sendEstablishKeyFragmented(Exchange transport, byte[] c2, Consumer<String> logger) throws Exception {
        final int chunkSize = 240;
        int total = (c2.length + chunkSize - 1) / chunkSize;
        int offset = 0;
        int idx = 0;
        byte[] lastResp = null;
        while (offset < c2.length) {
            idx++;
            int n = Math.min(chunkSize, c2.length - offset);
            boolean more = (offset + n) < c2.length;
            byte[] frag = Arrays.copyOfRange(c2, offset, offset + n);
            int p1 = more ? 0x01 : 0x00;
            byte[] apdu = ApduCodec.buildCommandApduNoLe(0x80, 0x50, p1, 0x00, frag);
            logger.accept("10." + idx + " EstablishKey fragment " + idx + "/" + total + " (" + n + " bytes, more=" + more + ")");
            lastResp = transport.send(apdu);
            if (lastResp == null || lastResp.length < 2) {
                throw new IllegalStateException("Empty response for EstablishKey fragment " + idx);
            }
            byte sw1 = lastResp[lastResp.length - 2];
            byte sw2 = lastResp[lastResp.length - 1];
            if (sw1 != (byte) 0x90 || sw2 != (byte) 0x00) {
                throw new IllegalStateException("EstablishKey fragment " + idx + " SW=" + String.format("%02X%02X", sw1, sw2));
            }
            offset += n;
        }
        return lastResp;
    }

    static byte[] collectReadCertCiphertext(Exchange transport, byte[] firstResponse) throws Exception {
        ByteArrayOutputStream acc = new ByteArrayOutputStream(PqBdhCrypto.CERT_CIPHERTEXT_BYTES);
        byte[] resp = firstResponse;
        while (true) {
            if (resp == null || resp.length < 2) {
                throw new IllegalStateException("Read Cert fragment is truncated.");
            }
            int length = resp.length - 2;
            byte sw1 = resp[length], sw2 = resp[length + 1];
            if (acc.size() + length > PqBdhCrypto.CERT_CIPHERTEXT_BYTES) {
                throw new IllegalStateException("Certificate reply exceeds its fixed 8220-byte length.");
            }
            acc.write(resp, 0, length);
            if (sw1 == (byte) 0x90 && sw2 == 0) {
                if (acc.size() != PqBdhCrypto.CERT_CIPHERTEXT_BYTES) {
                    throw new IllegalStateException("Certificate reply must contain exactly 8220 bytes.");
                }
                return acc.toByteArray();
            }
            if (sw1 != 0x61 || length == 0 || acc.size() == PqBdhCrypto.CERT_CIPHERTEXT_BYTES) {
                throw new IllegalStateException("Invalid certificate reply continuation.");
            }
            resp = transport.send(new byte[]{(byte) 0x80, (byte) 0xB2, 0x01, 0, 0});
        }
    }
}
