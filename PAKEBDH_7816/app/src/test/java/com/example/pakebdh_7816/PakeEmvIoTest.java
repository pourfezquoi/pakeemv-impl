package com.example.pakebdh_7816;

import static org.junit.Assert.*;

import com.example.pakebdh_7816.apdu.ApduCodec;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.junit.Test;

/** Scripted wire tests; no simulated crypto timings are reported as hardware measurements. */
public class PakeEmvIoTest {
    @Test
    public void currentProfileHas46ExchangesAndCountsPayloadSeparatelyFromApdu() throws Exception {
        ScriptedCard card = new ScriptedCard();
        byte[] init = pattern(832);
        byte[] first = PakeEmvIo.sendPakeInitFragmented(card, init, ignored -> { });
        assertArrayEquals(pattern(800), PakeEmvIo.collectPakeResponse(card, first));
        assertArrayEquals(init, card.pakeInput.toByteArray());

        byte[] mac = pattern(64);
        first = card.send(ApduCodec.buildCommandApduNoLe(0x80, 0xB2, 0, 0, mac));
        assertArrayEquals(pattern(8220), PakeEmvIo.collectReadCertCiphertext(card, first));
        assertArrayEquals(mac, card.confirmation);
        byte[] encryptedCt = pattern(828);
        assertArrayEquals(withStatus(pattern(32)),
                PakeEmvIo.sendEstablishKeyFragmented(card, encryptedCt, ignored -> { }));
        assertArrayEquals(encryptedCt, card.establishInput.toByteArray());

        assertEquals(46, card.exchanges);
        assertEquals(7, card.pakeExchanges);
        assertEquals(35, card.certExchanges);
        assertEquals(4, card.establishExchanges);
        assertEquals(1724, card.commandPayloadBytes);
        assertEquals(9052, card.responsePayloadBytes);
        assertEquals(1954, card.commandApduBytes);
        assertEquals(9144, card.responseApduBytes);
    }

    @Test
    public void pakeStopsAtFailedFragmentInsteadOfReportingPartialSuccess() {
        assertThrows(IllegalStateException.class, () -> PakeEmvIo.sendPakeInitFragmented(
                command -> new byte[]{0x63, 0}, pattern(832), ignored -> { }));
    }

    @Test
    public void establishRejectsIntermediateFailureBeforeSendingMoreFragments() {
        final int[] calls = {0};
        assertThrows(IllegalStateException.class, () -> PakeEmvIo.sendEstablishKeyFragmented(
                command -> ++calls[0] == 2 ? new byte[]{0x63, 0} : new byte[]{(byte) 0x90, 0},
                pattern(828), ignored -> { }));
        assertEquals(2, calls[0]);
    }

    @Test
    public void establishReturnsFinalRejectionForInit4WithoutAnotherCommand() throws Exception {
        final int[] calls = {0};
        byte[] response = PakeEmvIo.sendEstablishKeyFragmented(
                command -> ++calls[0] == 4 ? new byte[]{0x69, (byte) 0x82} : new byte[]{(byte) 0x90, 0},
                pattern(828), ignored -> { });
        assertArrayEquals(new byte[]{0x69, (byte) 0x82}, response);
        assertEquals(4, calls[0]);
    }

    @Test
    public void collectorsRejectUnexpectedStatusAndTruncatedResponses() {
        assertThrows(IllegalStateException.class, () -> PakeEmvIo.collectPakeResponse(
                command -> new byte[0], new byte[]{0x6A, (byte) 0x82}));
        assertThrows(IllegalStateException.class, () -> PakeEmvIo.collectReadCertCiphertext(
                command -> new byte[0], new byte[]{0x61, 0}));
    }

    @Test
    public void chicCollectorRejectsTheOldBareKemReply() {
        byte[] legacy = Arrays.copyOf(pattern(768), 770);
        legacy[768] = (byte) 0x90;
        assertThrows(IllegalStateException.class,
                () -> PakeEmvIo.collectPakeResponse(command -> null, legacy));
    }

    @Test
    public void chicCollectorRejectsOverflowAndNonProgressingContinuation() {
        byte[] overflow = new byte[803];
        overflow[801] = (byte) 0x90;
        assertThrows(IllegalStateException.class,
                () -> PakeEmvIo.collectPakeResponse(command -> null, overflow));
        assertThrows(IllegalStateException.class,
                () -> PakeEmvIo.collectPakeResponse(command -> null, new byte[]{0x61, 0}));
        byte[] extraContinuation = new byte[802];
        extraContinuation[800] = 0x61;
        assertThrows(IllegalStateException.class,
                () -> PakeEmvIo.collectPakeResponse(command -> null, extraContinuation));
    }

    private static byte[] withStatus(byte[] input) {
        byte[] response = Arrays.copyOf(input, input.length + 2);
        response[input.length] = (byte) 0x90;
        return response;
    }

    private static byte[] pattern(int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) result[i] = (byte) i;
        return result;
    }

    private static final class ScriptedCard implements PakeEmvIo.Exchange {
        final ByteArrayOutputStream pakeInput = new ByteArrayOutputStream();
        final ByteArrayOutputStream establishInput = new ByteArrayOutputStream();
        byte[] confirmation;
        int pakeOffset, certOffset;
        int exchanges, pakeExchanges, certExchanges, establishExchanges;
        long commandPayloadBytes, responsePayloadBytes, commandApduBytes, responseApduBytes;

        @Override
        public byte[] send(byte[] command) throws Exception {
            assertEquals(0x80, command[0] & 255);
            assertEquals(0, command[3]);
            int dataLength = command.length == 5 ? 0 : command[4] & 255;
            assertEquals(5 + dataLength, command.length);
            byte[] data = Arrays.copyOfRange(command, 5, command.length);
            int ins = command[1] & 255;
            byte[] response;
            switch (ins) {
                case 0xC1:
                    pakeExchanges++;
                    if (dataLength > 0) {
                        assertTrue(dataLength <= 220);
                        pakeInput.write(data);
                        boolean more = pakeInput.size() < 832;
                        assertEquals(more ? 1 : 0, command[2]);
                        response = more ? new byte[]{(byte) 0x90, 0} : nextPake();
                    } else {
                        assertEquals(1, command[2]);
                        response = nextPake();
                    }
                    break;
                case 0xB2:
                    certExchanges++;
                    if (dataLength > 0) {
                        assertEquals(0, command[2]);
                        assertEquals(64, dataLength);
                        assertNull(confirmation);
                        confirmation = data;
                    } else {
                        assertEquals(1, command[2]);
                        assertNotNull(confirmation);
                    }
                    response = fragment(pattern(8220), certOffset);
                    certOffset += response.length - 2;
                    break;
                case 0x50:
                    establishExchanges++;
                    assertTrue(dataLength > 0 && dataLength <= 240);
                    establishInput.write(data);
                    assertEquals(establishInput.size() < 828 ? 1 : 0, command[2]);
                    response = establishInput.size() < 828
                            ? new byte[]{(byte) 0x90, 0} : withStatus(pattern(32));
                    break;
                default:
                    throw new AssertionError("Unexpected instruction in core transcript: " + ins);
            }
            exchanges++;
            commandPayloadBytes += dataLength;
            responsePayloadBytes += response.length - 2;
            commandApduBytes += command.length;
            responseApduBytes += response.length;
            return response;
        }

        private byte[] nextPake() {
            assertEquals(832, pakeInput.size());
            byte[] response = fragment(pattern(800), pakeOffset);
            pakeOffset += response.length - 2;
            return response;
        }

        private static byte[] fragment(byte[] full, int offset) {
            assertTrue(offset < full.length);
            int length = Math.min(240, full.length - offset);
            int left = full.length - offset - length;
            byte[] response = new byte[length + 2];
            System.arraycopy(full, offset, response, 0, length);
            response[length] = left == 0 ? (byte) 0x90 : 0x61;
            response[length + 1] = (byte) (left > 255 ? 0 : left);
            return response;
        }
    }
}
