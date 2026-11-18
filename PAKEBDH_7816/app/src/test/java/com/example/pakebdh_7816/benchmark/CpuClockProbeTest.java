package com.example.pakebdh_7816.benchmark;

import static org.junit.Assert.*;
import org.junit.Test;

public class CpuClockProbeTest {
    private static CpuClockProbe.Result evaluate(long[] starts, long[] ends, long[] wall) {
        return CpuClockProbe.evaluate(starts, ends, wall, 2);
    }

    @Test public void advancingReadsPassWithoutChangingObservations() {
        long[] starts = {100, 220, 340};
        long[] ends = {200, 320, 600};
        CpuClockProbe.Result result = evaluate(starts, ends, new long[]{110, 110, 300});
        assertTrue(result.available());
        assertNull(result.unavailableReason);
        assertEquals(20, result.minimumPositiveReadIncrementNs);
        assertArrayEquals(new long[]{100, 220, 340}, starts);
        assertArrayEquals(new long[]{200, 320, 600}, ends);
    }

    @Test public void unresolvedShortWorkDoesNotBecomeZeroCpuPerformance() {
        CpuClockProbe.Result result = evaluate(new long[]{100, 100, 200},
                new long[]{100, 200, 500}, new long[]{110, 110, 400});
        assertFalse(result.available());
        assertEquals("CPU_CLOCK_SHORT_WORK_NOT_RESOLVED", result.unavailableReason);
        assertEquals(1, result.zeroShortIntervals);
        assertEquals(0, result.zeroLongIntervals);
    }

    @Test public void unresolvedLongWorkHasItsOwnReason() {
        CpuClockProbe.Result result = evaluate(new long[]{100, 220, 340},
                new long[]{200, 320, 340}, new long[]{110, 110, 400});
        assertEquals("CPU_CLOCK_LONG_WORK_NOT_RESOLVED", result.unavailableReason);
        assertEquals(1, result.zeroLongIntervals);
    }

    @Test public void unsupportedReadsRemainUnavailable() {
        CpuClockProbe.Result result = evaluate(new long[]{-1, -1, -1},
                new long[]{-1, -1, -1}, new long[]{110, 110, 400});
        assertEquals("CPU_CLOCK_UNAVAILABLE", result.unavailableReason);
        assertEquals(6, result.unavailableReads);
        assertEquals(0, result.minimumPositiveReadIncrementNs);
    }

    @Test public void backwardsReadInsideIntervalIsRejected() {
        CpuClockProbe.Result result = evaluate(new long[]{100, 220, 340},
                new long[]{200, 210, 600}, new long[]{110, 110, 400});
        assertEquals("CPU_CLOCK_NONMONOTONIC", result.unavailableReason);
        assertEquals(1, result.nonmonotonicIntervals);
    }

    @Test public void backwardsReadBetweenIntervalsIsRejected() {
        CpuClockProbe.Result result = evaluate(new long[]{100, 190, 340},
                new long[]{200, 300, 600}, new long[]{110, 120, 400});
        assertEquals("CPU_CLOCK_NONMONOTONIC", result.unavailableReason);
        assertEquals(1, result.nonmonotonicIntervals);
    }

    @Test public void cpuBeyondOuterWallIsRejected() {
        CpuClockProbe.Result result = evaluate(new long[]{100, 220, 340},
                new long[]{200, 320, 600}, new long[]{99, 110, 400});
        assertEquals("CPU_CLOCK_EXCEEDS_OUTER_WALL", result.unavailableReason);
        assertEquals(1, result.cpuExceedsWallIntervals);
    }

    @Test(expected = IllegalArgumentException.class)
    public void requiresOneLongIntervalAfterShortObservations() {
        CpuClockProbe.evaluate(new long[]{1}, new long[]{2}, new long[]{3}, 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeWallObservationsAreRejected() {
        evaluate(new long[]{100, 220, 340}, new long[]{200, 320, 600}, new long[]{110, -1, 400});
    }
}
