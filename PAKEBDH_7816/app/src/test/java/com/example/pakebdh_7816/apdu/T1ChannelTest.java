package com.example.pakebdh_7816.apdu;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static com.example.pakebdh_7816.apdu.T1Channel.SequenceMode.ALTERNATING;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class T1ChannelTest {
    private static final byte[] SUCCESS = bytes(0x90, 0x00);

    @Test
    public void defaultPreservesOriginalFixedZeroTransportAfterUnsupportedProbes() throws Exception {
        T1Channel channel = new T1Channel();
        OriginalDemoCard peer = new OriginalDemoCard();

        assertArrayEquals(bytes(0x6D, 0), channel.exchange(command(5, 0xF8), peer));
        assertArrayEquals(bytes(0x6D, 0), channel.exchange(command(5, 0xF7), peer));
        assertArrayEquals(SUCCESS, channel.exchange(command(225, 0xC1), peer));

        assertEquals(Arrays.asList(0, 0, 0), peer.receivedPcbs);
        assertEquals(Arrays.asList(0xF8, 0xF7, 0xC1), peer.dispatchedInstructions);
    }

    @Test
    public void forcingAlternationOnOriginalGateReproducesMuteAfterUnsupportedF8() throws Exception {
        T1Channel channel = new T1Channel(ALTERNATING);
        OriginalDemoCard peer = new OriginalDemoCard();

        assertArrayEquals(bytes(0x6D, 0), channel.exchange(command(5, 0xF8), peer));
        IOException failure = assertThrows(IOException.class,
                () -> channel.exchange(command(5, 0xF7), peer));
        assertTrue(failure.getMessage().contains("error=0xFE"));
        assertEquals(Arrays.asList(0, 0x40), peer.receivedPcbs);
        assertEquals(Arrays.asList(0xF8), peer.dispatchedInstructions);
        assertThrows(IllegalStateException.class,
                () -> channel.exchange(command(225, 0xC1), peer));
        assertEquals(2, peer.receivedPcbs.size());
    }

    @Test
    public void repeatedFixedZeroPakeFragmentsAreAllDispatchedByOriginalDemo() throws Exception {
        T1Channel channel = new T1Channel();
        OriginalDemoCard peer = new OriginalDemoCard();
        int[] lengths = {220, 220, 220, 172};
        for (int i = 0; i < lengths.length; i++) {
            byte[] fragment = command(5 + lengths[i], 0xC1);
            fragment[2] = (byte) (i + 1 < lengths.length ? 1 : 0);
            fragment[5] = (byte) i;
            assertArrayEquals(SUCCESS, channel.exchange(fragment, peer));
            assertArrayEquals(fragment, peer.dispatchedCommands.get(i));
        }
        assertEquals(Arrays.asList(0, 0, 0, 0), peer.receivedPcbs);
        assertEquals(Arrays.asList(0xC1, 0xC1, 0xC1, 0xC1), peer.dispatchedInstructions);
        assertEquals(832, peer.dispatchedCommands.stream().mapToInt(apdu -> apdu.length - 5).sum());
    }

    @Test
    public void fixedZeroModeRejectsUnexpectedResponseSequenceAndNeverContinues() throws Exception {
        T1Channel channel = new T1Channel();
        AtomicInteger sends = new AtomicInteger();
        assertArrayEquals(SUCCESS, channel.exchange(command(5, 0xC1), frame -> block(0, SUCCESS)));
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> channel.exchange(command(5, 0xC1), frame -> {
                    assertEquals(0, frame[1]);
                    sends.incrementAndGet();
                    return block(0x40, SUCCESS);
                }));
        assertTrue(failure.getMessage().contains("expected N(S)=0"));
        assertThrows(IllegalStateException.class,
                () -> channel.exchange(command(5, 0xC1), frame -> {
                    sends.incrementAndGet();
                    return block(0, SUCCESS);
                }));
        assertEquals(1, sends.get());
    }

    @Test
    public void nullSequenceModeIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new T1Channel(null));
    }

    @Test
    public void requestsAlternateZeroOneZeroAndAcceptResponsePcb40() throws Exception {
        T1Channel channel = new T1Channel(ALTERNATING);
        List<Integer> sentPcbs = new ArrayList<>();
        AtomicInteger calls = new AtomicInteger();
        byte[] command = command(5, 0xC1);
        byte[] original = command.clone();

        T1Channel.FrameExchange transport = frame -> {
            assertEquals(0, frame[0]);
            assertEquals(command.length, frame[2] & 0xFF);
            assertArrayEquals(command, Arrays.copyOfRange(frame, 3, frame.length - 1));
            assertValidLrc(frame);
            sentPcbs.add(frame[1] & 0xFF);
            int responsePcb = (calls.getAndIncrement() & 1) << 6;
            return block(responsePcb, bytes(0x12, 0x34, 0x90, 0x00));
        };

        for (int i = 0; i < 3; i++) {
            assertArrayEquals(bytes(0x12, 0x34, 0x90, 0x00), channel.exchange(command, transport));
        }
        assertEquals(Arrays.asList(0x00, 0x40, 0x00), sentPcbs);
        assertArrayEquals(original, command);
        assertEquals(3, calls.get());
    }

    @Test
    public void explicitAlternatingModeWorksWithAStandardCachingPeer() throws Exception {
        // This standard-style peer is deliberately different from the original demo.
        CachingCard duplicateSequencePeer = new CachingCard();
        byte[] oldF7 = duplicateSequencePeer.send(block(0, command(5, 0xF7)));
        byte[] oldC1 = duplicateSequencePeer.send(block(0, command(5, 0xC1)));
        assertEquals(0x6D00, statusFromFrame(oldF7));
        assertEquals(0x6D00, statusFromFrame(oldC1));
        assertArrayEquals(oldF7, oldC1);
        assertEquals(Arrays.asList(0xF7), duplicateSequencePeer.dispatchedInstructions);

        CachingCard peer = new CachingCard();
        T1Channel channel = new T1Channel(ALTERNATING);
        assertArrayEquals(bytes(0x6D, 0x00), channel.exchange(command(5, 0xF7), peer));
        assertArrayEquals(SUCCESS, channel.exchange(command(5, 0xC1), peer));
        assertEquals(Arrays.asList(0xF7, 0xC1), peer.dispatchedInstructions);
        assertEquals(Arrays.asList(0x00, 0x40), peer.receivedPcbs);
    }

    @Test
    public void staleResponseIsRejectedBeforeItsStatusCanBeUsedAndRequiresReset() throws Exception {
        T1Channel channel = new T1Channel(ALTERNATING);
        AtomicInteger sends = new AtomicInteger();
        List<Integer> pcbs = new ArrayList<>();
        T1Channel.FrameExchange transport = frame -> {
            pcbs.add(frame[1] & 0xFF);
            sends.incrementAndGet();
            return block(0, bytes(0x6D, 0x00));
        };

        assertArrayEquals(bytes(0x6D, 0x00), channel.exchange(command(5, 0xF7), transport));
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> channel.exchange(command(5, 0xC1), transport));
        assertTrue(failure.getMessage(), failure.getMessage().contains("sequence mismatch"));
        assertTrue(failure.getMessage(), failure.getMessage().contains("expected N(S)=1"));
        assertEquals(Arrays.asList(0x00, 0x40), pcbs);
        assertThrows(IllegalStateException.class,
                () -> channel.exchange(command(5, 0xC1), transport));
        assertEquals(2, sends.get());

        channel.reset();
        assertArrayEquals(SUCCESS, channel.exchange(command(5, 0xC1), frame -> {
            assertEquals(0, frame[1]);
            sends.incrementAndGet();
            return block(0, SUCCESS);
        }));
        assertEquals(3, sends.get());
    }

    @Test
    public void unexpectedInitialResponseSequenceIsRejected() {
        assertRejectedResponse(block(0x40, SUCCESS), "sequence mismatch");
    }

    @Test
    public void invalidLrcIsRejectedAndBlocksFurtherSends() {
        byte[] response = block(0, SUCCESS);
        response[response.length - 1] ^= 1;
        assertRejectedResponse(response, "LRC");
    }

    @Test
    public void nonzeroNadIsRejectedEvenWithCorrectLrc() {
        byte[] response = block(0, SUCCESS);
        response[0] = 1;
        updateLrc(response);
        assertRejectedResponse(response, "NAD");
    }

    @Test
    public void declaredLengthLargerThanReceivedPayloadIsRejected() {
        byte[] response = block(0, SUCCESS);
        response[2] = 3;
        updateLrc(response);
        assertRejectedResponse(response, "LEN");
    }

    @Test
    public void extraBytesBeyondDeclaredLengthAreRejected() {
        byte[] response = block(0, bytes(0x90, 0x00, 0x55));
        response[2] = 2;
        updateLrc(response);
        assertRejectedResponse(response, "LEN");
    }

    @Test
    public void nullAndTruncatedFramesAreRejected() {
        assertRejectedResponse(null, "too short");
        for (int length = 0; length < 4; length++) {
            assertRejectedResponse(new byte[length], "too short");
        }
    }

    @Test
    public void responseMustHaveBothStatusBytes() {
        assertRejectedResponse(block(0, new byte[0]), "status bytes");
        assertRejectedResponse(block(0, bytes(0x90)), "status bytes");
    }

    @Test
    public void rBlocksAreRejectedInsteadOfInterpretedAsApduResponses() {
        for (int pcb : new int[]{0x80, 0x81, 0x90, 0x91}) {
            assertRejectedResponse(block(pcb, SUCCESS), "control block");
        }
    }

    @Test
    public void sBlocksAreRejectedInsteadOfInterpretedAsApduResponses() {
        for (int pcb : new int[]{0xC0, 0xC1, 0xC2, 0xE0, 0xE1, 0xE2}) {
            assertRejectedResponse(block(pcb, SUCCESS), "control block");
        }
    }

    @Test
    public void chainedIBlocksAreRejected() {
        for (int pcb : new int[]{0x20, 0x60}) {
            assertRejectedResponse(block(pcb, SUCCESS), "Chained");
        }
    }

    @Test
    public void reservedIBlockFlagsAreRejected() {
        for (int flag : new int[]{0x01, 0x02, 0x04, 0x08, 0x10}) {
            assertRejectedResponse(block(flag, SUCCESS), "reserved");
            assertRejectedResponse(block(flag | 0x40, SUCCESS), "reserved");
        }
    }

    @Test
    public void everySupportedApduLengthFromFiveTo255IsSentIntact() throws Exception {
        T1Channel channel = new T1Channel(ALTERNATING);
        AtomicInteger sends = new AtomicInteger();
        for (int length = 5; length <= 255; length++) {
            byte[] command = command(length, 0xC1);
            assertArrayEquals(SUCCESS, channel.exchange(command, frame -> {
                assertEquals(command.length + 4, frame.length);
                assertEquals(command.length, frame[2] & 0xFF);
                assertArrayEquals(command, Arrays.copyOfRange(frame, 3, frame.length - 1));
                assertValidLrc(frame);
                return block((sends.getAndIncrement() & 1) << 6, SUCCESS);
            }));
        }
        assertEquals(251, sends.get());
    }

    @Test
    public void invalidArgumentsNeverSendAndDoNotInvalidateHealthyState() throws Exception {
        T1Channel channel = new T1Channel(ALTERNATING);
        AtomicInteger sends = new AtomicInteger();
        T1Channel.FrameExchange transport = frame -> {
            sends.incrementAndGet();
            assertEquals(0, frame[1]);
            return block(0, SUCCESS);
        };
        for (byte[] invalid : new byte[][]{null, new byte[0], new byte[4], new byte[256]}) {
            assertThrows(IllegalArgumentException.class, () -> channel.exchange(invalid, transport));
        }
        assertThrows(IllegalArgumentException.class, () -> channel.exchange(command(5, 0xC1), null));
        assertEquals(0, sends.get());
        assertArrayEquals(SUCCESS, channel.exchange(command(5, 0xC1), transport));
        assertEquals(1, sends.get());
    }

    @Test
    public void maximumUnsignedResponseLengthIsAccepted() throws Exception {
        byte[] payload = new byte[255];
        for (int i = 0; i < payload.length - 2; i++) payload[i] = (byte) i;
        payload[253] = (byte) 0x90;
        payload[254] = 0;
        assertArrayEquals(payload,
                new T1Channel(ALTERNATING).exchange(command(5, 0xC1), frame -> block(0, payload)));
    }

    @Test
    public void sendFailureIsNotRetriedAndRequiresExplicitReset() throws Exception {
        T1Channel channel = new T1Channel(ALTERNATING);
        AtomicInteger sends = new AtomicInteger();
        IOException cause = new IOException("Card response lost after sending command");
        T1Channel.FrameExchange failing = frame -> {
            sends.incrementAndGet();
            throw cause;
        };

        assertSame(cause, assertThrows(IOException.class,
                () -> channel.exchange(command(5, 0xC1), failing)));
        assertEquals(1, sends.get());
        assertThrows(IllegalStateException.class,
                () -> channel.exchange(command(5, 0xC1), failing));
        assertEquals(1, sends.get());

        channel.reset();
        assertArrayEquals(SUCCESS, channel.exchange(command(5, 0xC1), frame -> {
            assertEquals(0, frame[1]);
            sends.incrementAndGet();
            return block(0, SUCCESS);
        }));
        assertEquals(2, sends.get());
    }

    @Test
    public void uncheckedTransportErrorAlsoInvalidatesTheChannel() {
        T1Channel channel = new T1Channel(ALTERNATING);
        AtomicInteger sends = new AtomicInteger();
        AssertionError cause = new AssertionError("Unexpected transport failure");
        T1Channel.FrameExchange failing = frame -> {
            sends.incrementAndGet();
            throw cause;
        };
        assertSame(cause, assertThrows(AssertionError.class,
                () -> channel.exchange(command(5, 0xC1), failing)));
        assertThrows(IllegalStateException.class,
                () -> channel.exchange(command(5, 0xC1), failing));
        assertEquals(1, sends.get());
    }

    @Test
    public void resetAfterCardResetRestartsBothSequenceNumbers() throws Exception {
        T1Channel channel = new T1Channel(ALTERNATING);
        CachingCard firstCardSession = new CachingCard();
        channel.exchange(command(5, 0xC1), firstCardSession);
        channel.reset();
        CachingCard nextCardSession = new CachingCard();
        assertArrayEquals(SUCCESS, channel.exchange(command(5, 0xC1), nextCardSession));
        assertEquals(Arrays.asList(0x00), nextCardSession.receivedPcbs);
    }

    private static void assertRejectedResponse(byte[] response, String reason) {
        for (T1Channel.SequenceMode mode : T1Channel.SequenceMode.values()) {
            T1Channel channel = new T1Channel(mode);
            AtomicInteger sends = new AtomicInteger();
            T1Channel.FrameExchange transport = frame -> {
                sends.incrementAndGet();
                return response;
            };
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> channel.exchange(command(5, 0xC1), transport));
            assertTrue(failure.getMessage(), failure.getMessage().contains(reason));
            assertEquals(1, sends.get());
            assertThrows(IllegalStateException.class,
                    () -> channel.exchange(command(5, 0xC1), transport));
            assertEquals(1, sends.get());
        }
    }

    private static byte[] command(int length, int instruction) {
        byte[] command = new byte[length];
        command[0] = (byte) 0x80;
        command[1] = (byte) instruction;
        command[4] = (byte) (length - 5);
        for (int i = 5; i < length; i++) command[i] = (byte) i;
        return command;
    }

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++) result[i] = (byte) values[i];
        return result;
    }

    private static byte[] block(int pcb, byte[] payload) {
        byte[] frame = new byte[payload.length + 4];
        frame[1] = (byte) pcb;
        frame[2] = (byte) payload.length;
        System.arraycopy(payload, 0, frame, 3, payload.length);
        updateLrc(frame);
        return frame;
    }

    private static void updateLrc(byte[] frame) {
        byte checksum = 0;
        for (int i = 0; i < frame.length - 1; i++) checksum ^= frame[i];
        frame[frame.length - 1] = checksum;
    }

    private static void assertValidLrc(byte[] frame) {
        int checksum = 0;
        for (byte value : frame) checksum ^= value & 0xFF;
        assertEquals("The XOR of all frame bytes, including LRC, must be zero", 0, checksum);
    }

    private static int statusFromFrame(byte[] frame) {
        return ((frame[frame.length - 3] & 0xFF) << 8) | (frame[frame.length - 2] & 0xFF);
    }

    /**
     * Models the original live demo gate, which forwards every PCB=00 command.
     * A reader timeout is represented by an exception when that gate drops PCB=40;
     * no hardware timing or actual CCID transfer is simulated here.
     */
    private static final class OriginalDemoCard implements T1Channel.FrameExchange {
        final List<Integer> receivedPcbs = new ArrayList<>();
        final List<Integer> dispatchedInstructions = new ArrayList<>();
        final List<byte[]> dispatchedCommands = new ArrayList<>();

        @Override
        public byte[] send(byte[] frame) throws IOException {
            assertValidLrc(frame);
            int pcb = frame[1] & 0xFF;
            receivedPcbs.add(pcb);
            // This is the gate in the original card, not a complete T=1 peer.
            if ((pcb & 0xC0) != 0) {
                throw new IOException("CCID command failed: status=0x40, error=0xFE (ICC mute)");
            }
            byte[] apdu = Arrays.copyOfRange(frame, 3, frame.length - 1);
            int instruction = apdu[1] & 0xFF;
            dispatchedInstructions.add(instruction);
            dispatchedCommands.add(apdu);
            return block(0, instruction == 0xC1 ? SUCCESS : bytes(0x6D, 0));
        }
    }

    /** A standard-style peer, used only with explicitly selected alternation. */
    private static final class CachingCard implements T1Channel.FrameExchange {
        final List<Integer> receivedPcbs = new ArrayList<>();
        final List<Integer> dispatchedInstructions = new ArrayList<>();
        private int expectedRequestSequence;
        private int responseSequence;
        private byte[] cachedResponse;

        @Override
        public byte[] send(byte[] frame) {
            assertValidLrc(frame);
            int pcb = frame[1] & 0xFF;
            receivedPcbs.add(pcb);
            int requestSequence = (pcb >>> 6) & 1;
            if (requestSequence != expectedRequestSequence) {
                assertTrue("A retransmission requires a cached response", cachedResponse != null);
                return cachedResponse.clone();
            }
            int instruction = frame[4] & 0xFF;
            dispatchedInstructions.add(instruction);
            byte[] status = instruction == 0xC1 ? SUCCESS : bytes(0x6D, 0x00);
            cachedResponse = block(responseSequence << 6, status);
            expectedRequestSequence ^= 1;
            responseSequence ^= 1;
            return cachedResponse.clone();
        }
    }
}
