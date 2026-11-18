package com.example.pakebdh_7816.benchmark;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.Test;

public class SysTickDiagnosticsTest {
    private static byte[] packet(int reason, int flags) {
        return ByteBuffer.allocate(42).put(new byte[]{'P', 'E', 'S', '1'})
                .putInt(reason).putInt(105_000_000).putInt(7).putInt(0xffffff)
                .putInt(0xfffffe).putInt(0x04000000).putInt(0).putInt(2).putInt(flags)
                .putShort((short) 0x9000).array();
    }

    @Test
    public void parsesAndDescribesReadySysTickWithoutInventingDwtAvailability() {
        BenchmarkSupport.SysTickDiagnostics diagnostic = BenchmarkSupport.SysTickDiagnostics.parse(packet(1, 3));
        assertEquals(105_000_000L, diagnostic.clockHz);
        assertEquals(0xffffff, diagnostic.load);
        assertEquals(0xfffffe, diagnostic.val);
        assertEquals(2, diagnostic.wraps);
        assertTrue(diagnostic.description().contains("counter and interrupt readiness checks"));
        assertTrue(diagnostic.description().contains("LOAD=0x00FFFFFF"));
        assertTrue(diagnostic.description().contains("flags=3"));
    }

    @Test
    public void explainsAllUnavailableStatesAsCapturedHardwareEvidence() {
        String[] reasons = {"not been attempted", "", "clock frequency is unknown", "configuration is invalid",
                "Interrupt masking", "VAL did not advance", "interrupt self-test failed",
                "changed after initialization", "stable SysTick snapshot"};
        for (int reason : new int[]{0, 2, 3, 4, 5, 6, 7, 8}) {
            assertTrue(BenchmarkSupport.SysTickDiagnostics.parse(packet(reason, 0)).description().contains(reasons[reason]));
        }
    }

    @Test
    public void basepriDoesNotMaskPriorityZeroSysTickButGlobalMasksPreventReadyTiming() {
        byte[] response = packet(1, 3);
        ByteBuffer.wrap(response).putInt(28, 0x8000);
        assertEquals(0x8000, BenchmarkSupport.SysTickDiagnostics.parse(response).interruptMask);
        for (int mask : new int[]{1, 2, 3, 0x8001, 4, 0x10000}) {
            ByteBuffer.wrap(response).putInt(28, mask);
            assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.SysTickDiagnostics.parse(response));
        }
    }

    @Test
    public void invalidReadyCounterConfigurationCannotValidateMeasurement() {
        for (int[] change : new int[][]{{8, 0}, {12, 3}, {12, 5}, {16, 0}, {16, 0xfffffe},
                {16, 0x1000000}, {20, 0x1000000}, {32, 0}}) {
            byte[] response = packet(1, 3);
            ByteBuffer.wrap(response).putInt(change[0], change[1]);
            assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.SysTickDiagnostics.parse(response));
        }
    }

    @Test
    public void rejectsMalformedPacketsAndContradictoryFlags() {
        byte[] wrongMagic = packet(1, 3);
        wrongMagic[2] = 'D';
        byte[] wrongStatus = packet(1, 3);
        wrongStatus[40] = 0x6D;
        for (byte[] response : new byte[][]{null, new byte[0], Arrays.copyOf(packet(1, 3), 41),
                Arrays.copyOf(packet(1, 3), 43), wrongMagic, wrongStatus, packet(9, 0), packet(-1, 0),
                packet(1, 0), packet(6, 3), packet(6, 1), packet(6, -1)}) {
            assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.SysTickDiagnostics.parse(response));
        }
    }
}
