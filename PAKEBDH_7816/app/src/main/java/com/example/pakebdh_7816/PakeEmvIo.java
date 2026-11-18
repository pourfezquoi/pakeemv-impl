package com.example.pakebdh_7816;

import com.example.pakebdh_7816.apdu.ApduCodec;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.function.Consumer;

/** Shared application fragmentation, with an injectable APDU exchange for measurement. */
final class PakeEmvIo {
    interface Exchange {
        byte[] send(byte[] command) throws Exception;
    }

    private PakeEmvIo() { }

    /** Collect the original CHIC tag || ciphertext, enforcing its exact length. */
    static byte[] collectPakeResponse(Exchange transport, byte[] firstResponse) throws Exception {
        ByteArrayOutputStream message = new ByteArrayOutputStream(ChicPake.RESPONSE_BYTES);
        byte[] response = firstResponse;
        while (true) {
            if (response == null || response.length < 2) {
                throw new IllegalStateException("Short APDU response for CHIC.");
            }
            int payloadLength = response.length - 2;
            if (message.size() + payloadLength > ChicPake.RESPONSE_BYTES) {
                throw new IllegalStateException("CHIC response exceeds 800 bytes.");
            }
            message.write(response, 0, payloadLength);
            byte sw1 = response[payloadLength];
            byte sw2 = response[payloadLength + 1];
            if (sw1 == (byte) 0x90 && sw2 == 0) {
                if (message.size() != ChicPake.RESPONSE_BYTES) {
                    throw new IllegalStateException("CHIC response must contain a 32-byte tag and 768-byte ciphertext.");
                }
                return message.toByteArray();
            }
            if (sw1 != (byte) 0x61) {
                throw new IllegalStateException("Unexpected SW while reading CHIC: "
                        + String.format("%02X%02X", sw1, sw2));
            }
            if (payloadLength == 0 || message.size() == ChicPake.RESPONSE_BYTES) {
                throw new IllegalStateException("CHIC response continuation made no progress or exceeded its length.");
            }
            response = transport.send(ApduCodec.buildCommandApdu(0x80, 0xC1, 0x01, 0x00, null));
        }
    }

    static byte[] sendPakeInitFragmented(Exchange transport, byte[] payload, Consumer<String> logger) throws Exception {
        if (payload == null || payload.length != PakeEmvProtocol.X1_BYTES) {
            throw new IllegalArgumentException("M1 must contain SID || CHIC msg1 (832 bytes).");
        }
        final int chunkSize = 220;
        int total = (payload.length + chunkSize - 1) / chunkSize;
        int offset = 0;
        int idx = 0;
        byte[] resp = null;
        while (offset < payload.length) {
            idx++;
            int n = Math.min(chunkSize, payload.length - offset);
            boolean more = (offset + n) < payload.length;
            byte[] frag = Arrays.copyOfRange(payload, offset, offset + n);
            byte[] apdu = ApduCodec.buildCommandApduNoLe(0x80, 0xC1, more ? 0x01 : 0x00, 0x00, frag);
            logger.accept("4." + idx + " PAKE_INIT fragment " + idx + "/" + total + " (" + n + " bytes, more=" + more + ")");
            resp = transport.send(apdu);
            if (resp == null || resp.length < 2) throw new IllegalStateException("Empty PAKE_INIT fragment response " + idx);
            byte sw1 = resp[resp.length - 2], sw2 = resp[resp.length - 1];
            if (more && (resp.length != 2 || sw1 != (byte)0x90 || sw2 != (byte)0x00)) {
                throw new IllegalStateException("PAKE_INIT fragment " + idx + " SW=" + String.format("%02X%02X", sw1, sw2));
            }
            offset += n;
        }
        return resp;
    }

    static byte[] sendEstablishKeyFragmented(Exchange transport, byte[] c2, Consumer<String> logger) throws Exception {
        if (c2 == null || c2.length != PakeEmvProtocol.M5_BYTES) {
            throw new IllegalArgumentException("M5 must contain ec || pi2 (828 bytes).");
        }
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
            if (more && (lastResp.length != 2 || sw1 != (byte) 0x90 || sw2 != (byte) 0x00)) {
                throw new IllegalStateException("EstablishKey fragment " + idx + " SW=" + String.format("%02X%02X", sw1, sw2));
            }
            offset += n;
        }
        return lastResp;
    }

    static byte[] collectReadCertCiphertext(Exchange transport, byte[] firstResponse) throws Exception {
        ByteArrayOutputStream acc = new ByteArrayOutputStream(PakeEmvProtocol.ECERT_BYTES);
        byte[] resp = firstResponse;
        while (true) {
            if (resp == null || resp.length < 2) {
                throw new IllegalStateException("M4 certificate fragment is truncated.");
            }
            int length = resp.length - 2;
            byte sw1 = resp[length], sw2 = resp[length + 1];
            if (acc.size() + length > PakeEmvProtocol.ECERT_BYTES) {
                throw new IllegalStateException("M4 exceeds its fixed 8220-byte length.");
            }
            acc.write(resp, 0, length);
            if (sw1 == (byte) 0x90 && sw2 == 0) {
                if (acc.size() != PakeEmvProtocol.ECERT_BYTES) {
                    throw new IllegalStateException("M4 must contain exactly 8220 bytes.");
                }
                return acc.toByteArray();
            }
            if (sw1 != 0x61 || length == 0 || acc.size() == PakeEmvProtocol.ECERT_BYTES) {
                throw new IllegalStateException("Invalid M4 certificate continuation.");
            }
            resp = transport.send(new byte[]{(byte) 0x80, (byte) 0xB2, 0x01, 0, 0});
        }
    }
}
