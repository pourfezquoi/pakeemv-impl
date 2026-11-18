package com.example.pakebdh_7816.benchmark;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.Test;

/** Public hardware readiness evidence never supplies accepted protocol measurements. */
public class CardTimingDiagnosticsTest {
    private static byte[] packet(int reason, int flags) {
        return ByteBuffer.allocate(42).put(new byte[]{'P', 'E', 'D', '1'})
                .putInt(reason).putInt(105_000_000).putInt(0x80000000).putInt(0x81000000)
                .putInt(0).putInt(1).putInt(0xfffffff0).putInt(0x10).putInt(flags)
                .putShort((short) 0x9000).array();
    }

    @Test
    public void parsesUnsignedCapturedReadbacksAndExplainsEverySupportedReason() {
        String[] expected = {"not been reset", "passed the firmware readiness check", "clock frequency is unknown",
                "trace-enable bit did not remain set", "NOCYCCNT=1", "cycle-counter enable bit did not remain set",
                "did not advance"};
        for (int reason = 0; reason <= 6; reason++) {
            BenchmarkSupport.CardTimingDiagnostics diagnostic = BenchmarkSupport.CardTimingDiagnostics.parse(
                    packet(reason, reason == 1 ? 1 : 0));
            assertEquals(reason, diagnostic.reason);
            assertEquals(105_000_000L, diagnostic.clockHz);
            assertEquals(0x80000000L, diagnostic.demcrBefore);
            assertEquals(0x81000000L, diagnostic.demcrAfter);
            assertEquals(0xfffffff0L, diagnostic.firstCycle);
            assertEquals(0x10L, diagnostic.secondCycle);
            assertTrue(diagnostic.description().contains(expected[reason]));
            assertTrue(diagnostic.description().contains("DEMCR=0x80000000 -> 0x81000000"));
            assertTrue(diagnostic.description().contains("CYCCNT=0xFFFFFFF0 -> 0x00000010"));
        }
    }

    @Test
    public void unknownClockCanBeDiagnosedWithoutInventingAFrequency() {
        byte[] response = packet(2, 0);
        ByteBuffer.wrap(response).putInt(8, 0);
        assertEquals(0, BenchmarkSupport.CardTimingDiagnostics.parse(response).clockHz);
    }

    @Test
    public void rejectsWrongLengthMagicStatusAndUnsupportedReason() {
        byte[] magic = packet(6, 0);
        magic[2] = 'B';
        byte[] status = packet(6, 0);
        status[40] = 0x6D;
        byte[] lowStatus = packet(6, 0);
        lowStatus[41] = 1;
        for (byte[] response : new byte[][]{null, new byte[0], Arrays.copyOf(packet(6, 0), 41),
                Arrays.copyOf(packet(6, 0), 43), magic, status, lowStatus, packet(7, 0), packet(-1, 0)}) {
            assertThrows(IllegalArgumentException.class,
                    () -> BenchmarkSupport.CardTimingDiagnostics.parse(response));
        }
    }

    @Test
    public void rejectsUnknownOrContradictoryReadinessFlags() {
        for (byte[] response : new byte[][]{packet(6, 2), packet(6, -1), packet(6, 1), packet(1, 0)}) {
            assertThrows(IllegalArgumentException.class,
                    () -> BenchmarkSupport.CardTimingDiagnostics.parse(response));
        }
        byte[] readyWithoutClock = packet(1, 1);
        ByteBuffer.wrap(readyWithoutClock).putInt(8, 0);
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkSupport.CardTimingDiagnostics.parse(readyWithoutClock));
    }
}
