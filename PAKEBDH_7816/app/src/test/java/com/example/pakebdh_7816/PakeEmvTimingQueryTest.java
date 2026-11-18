package com.example.pakebdh_7816;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import org.junit.Test;

/** Optional timing must never hide a transport error or discard the card's status word. */
public class PakeEmvTimingQueryTest {
    @Test
    public void sendsResetAndSnapshotOutsideCoreProtocol() throws Exception {
        byte[] packet = ByteBuffer.allocate(42).put(new byte[]{'P', 'E', 'B', '1'})
                .putInt(1).putInt(105_000_000).putInt(0)
                .putLong(0).putLong(0).putLong(0).putShort((short) 0x9000).array();
        for (int action = 0; action <= 1; action++) {
            final int expected = action;
            assertEquals(105_000_000, PakeEmvSession.timing(command -> {
                assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xF7, (byte) expected, 0, 0}, command);
                return packet;
            }, action).clockHz);
        }
    }

    @Test
    public void unsupportedTimingRetainsRawStatusAndBuildAdvice() {
        Exception failure = assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                () -> PakeEmvSession.timing(command -> new byte[]{0x6D, 0}, 0));
        assertTrue(failure.getMessage().contains("F7 timing SW=6D00"));
        assertTrue(failure.getMessage().contains("PAKE_EMV_BENCHMARK=1"));
        assertTrue(failure.getMessage().contains("Rebuild and flash"));
    }

    @Test
    public void unavailableCounterPreservesExactReason() {
        byte[] packet = ByteBuffer.allocate(42).put(new byte[]{'P', 'E', 'B', '1'})
                .putInt(0).putInt(105_000_000).putInt(0)
                .putLong(0).putLong(0).putLong(0).putShort((short) 0x9000).array();
        Exception failure = assertThrows(PakeEmvSession.CardTimingUnavailableException.class,
                () -> PakeEmvSession.timing(command -> packet, 0));
        assertTrue(failure.getMessage().contains("SW=9000"));
        assertTrue(failure.getMessage().contains("hardware cycle counter is not ready"));
        assertTrue(failure.getMessage().contains("flags=0, clock=105000000 Hz"));
        assertFalse(failure.getMessage().contains("Rebuild"));
        assertFalse(failure.getMessage().contains("PAKE_EMV_BENCHMARK=1"));
    }

    @Test
    public void transportFailureIsFatalAndNeverConvertedToOptionalTiming() {
        IOException expected = new IOException("USB transfer failed");
        Exception actual = assertThrows(IOException.class,
                () -> PakeEmvSession.timing(command -> { throw expected; }, 0));
        assertSame(expected, actual);
        IllegalStateException framing = new IllegalStateException("T=1 response sequence mismatch");
        assertSame(framing, assertThrows(IllegalStateException.class,
                () -> PakeEmvSession.timing(command -> { throw framing; }, 1)));
    }
}
