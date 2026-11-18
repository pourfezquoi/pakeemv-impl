package com.example.pqbdh_7816;

import static org.junit.Assert.*;

import com.example.pqbdh_7816.apdu.ApduCodec;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.junit.Test;

/** Scripted wire tests; no simulated crypto timings are reported as hardware measurements. */
public class PqBdhIoTest {
    @Test
    public void paddedProfileHas46CoreExchangesAnd47WithSeparatePin() throws Exception {
        ScriptedCard card = new ScriptedCard();
        byte[] init = pattern(800);
        byte[] first = PqBdhIo.sendNegotiateKemFragmented(card, init, ignored -> { });
        assertArrayEquals(pattern(768), PqBdhIo.collectKemCiphertext(card, first));
        assertArrayEquals(init, card.negotiateKemInput.toByteArray());

        first = card.send(ApduCodec.buildCommandApduNoLe(0x80, 0xB2, 0, 0, null));
        assertArrayEquals(pattern(8220), PqBdhIo.collectReadCertCiphertext(card, first));
        byte[] encryptedCt = pattern(796);
        assertArrayEquals(new byte[]{(byte) 0x90, 0},
                PqBdhIo.sendEstablishKeyFragmented(card, encryptedCt, ignored -> { }));
        assertArrayEquals(encryptedCt, card.establishInput.toByteArray());

        assertEquals(46, card.exchanges);
        assertEquals(7, card.negotiateKemExchanges);
        assertEquals(35, card.certExchanges);
        assertEquals(4, card.establishExchanges);
        assertEquals(1596, card.commandPayloadBytes);
        assertEquals(8988, card.responsePayloadBytes);
        assertEquals(1826, card.commandApduBytes);
        assertEquals(9080, card.responseApduBytes);
        assertEquals(10584, card.commandPayloadBytes + card.responsePayloadBytes);
        assertEquals(10906, card.commandApduBytes + card.responseApduBytes);

        // The optional encrypted PIN remains a separate case-4 exchange (34 payload bytes).
        assertArrayEquals(new byte[]{(byte) 0x90, 0},
                card.send(ApduCodec.buildCommandApdu(0x80, 0x20, 0, 0, pattern(34))));
        assertEquals(47, card.exchanges);
        assertEquals(10618, card.commandPayloadBytes + card.responsePayloadBytes);
        assertEquals(10948, card.commandApduBytes + card.responseApduBytes);
    }

    @Test
    public void negotiateKemStopsAtFailedFragmentInsteadOfReportingPartialSuccess() {
        assertThrows(IllegalStateException.class, () -> PqBdhIo.sendNegotiateKemFragmented(
                command -> new byte[]{0x63, 0}, pattern(800), ignored -> { }));
    }

    @Test
    public void establishRejectsFailureOnTheLastFragment() {
        final int[] calls = {0};
        assertThrows(IllegalStateException.class, () -> PqBdhIo.sendEstablishKeyFragmented(
                command -> ++calls[0] == 4 ? new byte[]{0x63, 0} : new byte[]{(byte) 0x90, 0},
                pattern(796), ignored -> { }));
        assertEquals(4, calls[0]);
    }

    @Test
    public void collectorsRejectUnexpectedStatusAndTruncatedResponses() {
        assertThrows(IllegalStateException.class, () -> PqBdhIo.collectKemCiphertext(
                command -> new byte[0], new byte[]{0x6A, (byte) 0x82}));
        assertThrows(IllegalStateException.class, () -> PqBdhIo.collectReadCertCiphertext(
                command -> new byte[0], new byte[]{0x61, 0}));
    }

    @Test
    public void certificateCollectorRejectsLegacyLengthAndOverflowWithoutAnotherPoll() {
        for (int length : new int[]{7434, 8219, 8221}) {
            byte[] response = Arrays.copyOf(pattern(length), length + 2);
            response[length] = (byte) 0x90;
            assertThrows(IllegalStateException.class,
                    () -> PqBdhIo.collectReadCertCiphertext(command -> {
                        throw new AssertionError("No continuation permitted after an invalid final length");
                    }, response));
        }
    }

    @Test
    public void certificateCollectorRejectsZeroProgressAndContinuationPastTheFixedEnvelope() {
        for (int length : new int[]{0, 8220}) {
            byte[] response = Arrays.copyOf(pattern(length), length + 2);
            response[length] = 0x61;
            assertThrows(IllegalStateException.class,
                    () -> PqBdhIo.collectReadCertCiphertext(command -> {
                        throw new AssertionError("No continuation permitted after zero progress or full envelope");
                    }, response));
        }
    }

    private static byte[] pattern(int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) result[i] = (byte) i;
        return result;
    }

    private static final class ScriptedCard implements PqBdhIo.Exchange {
        final ByteArrayOutputStream negotiateKemInput = new ByteArrayOutputStream();
        final ByteArrayOutputStream establishInput = new ByteArrayOutputStream();
        boolean certificatesStarted;
        int negotiateKemOffset, certOffset;
        int exchanges, negotiateKemExchanges, certExchanges, establishExchanges;
        long commandPayloadBytes, responsePayloadBytes, commandApduBytes, responseApduBytes;

        @Override
        public byte[] send(byte[] command) throws Exception {
            assertEquals(0x80, command[0] & 255);
            assertEquals(0, command[3]);
            int ins = command[1] & 255;
            int dataLength = command.length == 5 ? 0 : command[4] & 255;
            assertEquals(5 + dataLength + (ins == 0x20 ? 1 : 0), command.length);
            byte[] data = Arrays.copyOfRange(command, 5, 5 + dataLength);
            byte[] response;
            switch (ins) {
                case 0xCA:
                    negotiateKemExchanges++;
                    if (dataLength > 0) {
                        assertTrue(dataLength <= 240);
                        negotiateKemInput.write(data);
                        boolean more = negotiateKemInput.size() < 800;
                        assertEquals(more ? 1 : 0, command[2]);
                        response = more ? new byte[]{(byte) 0x90, 0} : nextNegotiateKem();
                    } else {
                        assertEquals(1, command[2]);
                        response = nextNegotiateKem();
                    }
                    break;
                case 0xB2:
                    certExchanges++;
                    assertEquals(0, dataLength);
                    assertEquals(certificatesStarted ? 1 : 0, command[2]);
                    certificatesStarted = true;
                    response = fragment(pattern(8220), certOffset);
                    certOffset += response.length - 2;
                    break;
                case 0x50:
                    establishExchanges++;
                    assertTrue(dataLength > 0 && dataLength <= 240);
                    establishInput.write(data);
                    assertEquals(establishInput.size() < 796 ? 1 : 0, command[2]);
                    response = new byte[]{(byte) 0x90, 0};
                    break;
                case 0x20:
                    assertEquals(34, dataLength);
                    assertEquals(0, command[command.length - 1]);
                    response = new byte[]{(byte) 0x90, 0};
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

        private byte[] nextNegotiateKem() {
            assertEquals(800, negotiateKemInput.size());
            byte[] response = fragment(pattern(768), negotiateKemOffset);
            negotiateKemOffset += response.length - 2;
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
