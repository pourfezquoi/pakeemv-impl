package com.example.pakebdh_7816;

import android.os.Debug;
import android.os.Process;
import com.example.pakebdh_7816.benchmark.CpuClockProbe;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Thread-bound CPU clock, with known-work checks performed outside protocol timing. */
public final class TerminalCpuClock implements ProtocolMeasurements.Clock {
    private static final int SHORT_INTERVALS = 8;
    private static final long SHORT_WORK_NS = 2_000_000L;
    private static final long LONG_WORK_NS = 20_000_000L;
    private static volatile long workSink;

    private final Thread owner;
    private final String probeUnavailableReason;
    private final Map<String, Object> diagnostics;
    private volatile String readFailure;

    private TerminalCpuClock() {
        owner = Thread.currentThread();
        long[] starts = new long[SHORT_INTERVALS + 1];
        long[] ends = new long[starts.length];
        long[] wall = new long[starts.length];
        long[] blocks = new long[starts.length];
        for (int i = 0; i < starts.length; i++) {
            long wallStart = System.nanoTime();
            starts[i] = readCpu();
            blocks[i] = knownWork(i < SHORT_INTERVALS ? SHORT_WORK_NS : LONG_WORK_NS);
            ends[i] = readCpu();
            wall[i] = System.nanoTime() - wallStart;
        }
        CpuClockProbe.Result result = CpuClockProbe.evaluate(starts, ends, wall, SHORT_INTERVALS);
        probeUnavailableReason = readFailure != null ? readFailure : result.unavailableReason;
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("terminal_cpu_clock_source", "android.os.Debug.threadCpuTimeNanos");
        values.put("terminal_cpu_probe_method", "known-work-advance-v1");
        values.put("terminal_cpu_probe_linux_tid", Process.myTid());
        values.put("terminal_cpu_probe_java_thread_id", owner.getId());
        values.put("terminal_cpu_probe_thread_name", owner.getName());
        values.put("terminal_cpu_probe_short_intervals", SHORT_INTERVALS);
        values.put("terminal_cpu_probe_short_work_target_wall_ns", SHORT_WORK_NS);
        values.put("terminal_cpu_probe_long_work_target_wall_ns", LONG_WORK_NS);
        values.put("terminal_cpu_probe_cpu_start_ns", immutableList(starts));
        values.put("terminal_cpu_probe_cpu_end_ns", immutableList(ends));
        List<Long> deltas = new ArrayList<>(starts.length);
        for (int i = 0; i < starts.length; i++) {
            deltas.add(starts[i] < 0 || ends[i] < 0 ? null : ends[i] - starts[i]);
        }
        values.put("terminal_cpu_probe_cpu_delta_ns", Collections.unmodifiableList(deltas));
        values.put("terminal_cpu_probe_outer_wall_ns", immutableList(wall));
        values.put("terminal_cpu_probe_work_blocks", immutableList(blocks));
        values.put("terminal_cpu_probe_unavailable_reads", result.unavailableReads);
        values.put("terminal_cpu_probe_nonmonotonic_intervals", result.nonmonotonicIntervals);
        values.put("terminal_cpu_probe_zero_short_intervals", result.zeroShortIntervals);
        values.put("terminal_cpu_probe_zero_long_intervals", result.zeroLongIntervals);
        values.put("terminal_cpu_probe_cpu_exceeds_outer_wall_intervals", result.cpuExceedsWallIntervals);
        values.put("terminal_cpu_probe_observed_min_positive_read_increment_ns", result.minimumPositiveReadIncrementNs);
        values.put("terminal_cpu_probe_available", probeUnavailableReason == null);
        values.put("terminal_cpu_probe_unavailable_reason", probeUnavailableReason == null ? "none" : probeUnavailableReason);
        values.put("terminal_cpu_probe_scope", "Diagnostic known work only; observed increments do not establish resolution or accuracy; never subtracted from protocol measurements");
        diagnostics = Collections.unmodifiableMap(values);
    }

    /** Capture on the protocol thread before its measured phases. No result is cached globally. */
    public static TerminalCpuClock capture() { return new TerminalCpuClock(); }

    public Map<String, Object> diagnostics() { return diagnostics; }

    @Override public long wallNs() { return System.nanoTime(); }

    @Override public long cpuNs() { return readCpu(); }

    @Override public String cpuUnavailableReason() {
        if (Thread.currentThread() != owner) return "CPU_CLOCK_THREAD_CHANGED";
        return readFailure != null ? readFailure : probeUnavailableReason;
    }

    private long readCpu() {
        try {
            return Debug.threadCpuTimeNanos();
        } catch (RuntimeException | LinkageError unavailable) {
            readFailure = "CPU_CLOCK_READ_FAILED";
            return -1;
        }
    }

    private static List<Long> immutableList(long[] values) {
        List<Long> copy = new ArrayList<>(values.length);
        for (long value : values) copy.add(value);
        return Collections.unmodifiableList(copy);
    }

    private static long knownWork(long targetWallNs) {
        long value = workSink ^ System.nanoTime();
        long blocks = 0;
        long start = System.nanoTime();
        do {
            // Dependent integer work retained through a volatile sink; no crypto/session inputs.
            for (int i = 0; i < 256; i++) {
                value ^= value << 13;
                value ^= value >>> 7;
                value ^= value << 17;
            }
            blocks++;
        } while (System.nanoTime() - start < targetWallNs);
        workSink = value;
        return blocks;
    }
}
