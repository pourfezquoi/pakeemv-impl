package com.example.pakebdh_7816.benchmark;

/** Quality checks for observations of known CPU work; no value is corrected or estimated. */
public final class CpuClockProbe {
    private CpuClockProbe() { }

    public static final class Result {
        public final String unavailableReason;
        public final int unavailableReads;
        public final int nonmonotonicIntervals;
        public final int zeroShortIntervals;
        public final int zeroLongIntervals;
        public final int cpuExceedsWallIntervals;
        public final long minimumPositiveReadIncrementNs;

        private Result(String reason, int unavailable, int backwards, int shortZeros,
                       int longZeros, int exceedsWall, long minimumIncrement) {
            unavailableReason = reason;
            unavailableReads = unavailable;
            nonmonotonicIntervals = backwards;
            zeroShortIntervals = shortZeros;
            zeroLongIntervals = longZeros;
            cpuExceedsWallIntervals = exceedsWall;
            minimumPositiveReadIncrementNs = minimumIncrement;
        }

        public boolean available() { return unavailableReason == null; }
    }

    /**
     * CPU reads must lie inside each supplied outer wall interval. All intervals
     * contain known work; the final interval is the longer observation. The
     * observed minimum increment is evidence, not a clock-resolution guarantee.
     */
    public static Result evaluate(long[] cpuStarts, long[] cpuEnds, long[] outerWallNs,
                                  int shortIntervals) {
        if (cpuStarts == null || cpuEnds == null || outerWallNs == null
                || cpuStarts.length != cpuEnds.length || cpuStarts.length != outerWallNs.length
                || shortIntervals <= 0 || cpuStarts.length != shortIntervals + 1) {
            throw new IllegalArgumentException("Expected short known-work intervals and one long interval");
        }
        int unavailable = 0, backwards = 0, shortZeros = 0, longZeros = 0, exceedsWall = 0;
        long previousEnd = -1, minimumIncrement = Long.MAX_VALUE;
        for (int i = 0; i < cpuStarts.length; i++) {
            if (outerWallNs[i] < 0) {
                throw new IllegalArgumentException("Outer wall observations cannot be negative");
            }
            long start = cpuStarts[i], end = cpuEnds[i];
            if (start < 0) unavailable++;
            if (end < 0) unavailable++;
            if (start >= 0 && previousEnd >= 0) {
                if (start < previousEnd) backwards++;
                else if (start > previousEnd) minimumIncrement = Math.min(minimumIncrement, start - previousEnd);
            }
            if (start >= 0 && end >= 0) {
                if (end < start) {
                    backwards++;
                } else {
                    long delta = end - start;
                    if (delta == 0) {
                        if (i < shortIntervals) shortZeros++;
                        else longZeros++;
                    } else {
                        minimumIncrement = Math.min(minimumIncrement, delta);
                    }
                    if (delta > outerWallNs[i]) exceedsWall++;
                }
            }
            previousEnd = end;
        }
        String reason = unavailable > 0 ? "CPU_CLOCK_UNAVAILABLE"
                : backwards > 0 ? "CPU_CLOCK_NONMONOTONIC"
                : exceedsWall > 0 ? "CPU_CLOCK_EXCEEDS_OUTER_WALL"
                : longZeros > 0 ? "CPU_CLOCK_LONG_WORK_NOT_RESOLVED"
                : shortZeros > 0 ? "CPU_CLOCK_SHORT_WORK_NOT_RESOLVED" : null;
        return new Result(reason, unavailable, backwards, shortZeros, longZeros, exceedsWall,
                minimumIncrement == Long.MAX_VALUE ? 0 : minimumIncrement);
    }
}
