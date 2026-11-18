package com.example.pakebdh_7816.benchmark;

import com.example.pakebdh_7816.benchmark.BenchmarkSupport.Summary;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Version 3 report formatting. Unresolved CPU observations are retained, never averaged away. */
public final class BenchmarkCsv {
    public static final int CPU_METRIC_INDEX = 6;
    public static final String[] METRICS = {
            "logical_t2c_bytes", "logical_c2t_bytes", "command_apdu_bytes",
            "response_apdu_bytes", "apdu_count", "terminal_active_wall_ns",
            "terminal_compute_cpu_ns", "apdu_roundtrip_wall_ns", "phase_wall_ns",
            "card_handler_cycles", "card_handler_ns"
    };

    private BenchmarkCsv() { }

    /** Headers and rows include their trailing newline. */
    public static String sampleHeader() {
        return "iteration,phase," + String.join(",", METRICS)
                + ",cpu_status,raw_phase_cpu_start_ns,raw_phase_cpu_end_ns,raw_io_wait_cpu_ns,"
                + "protocol_java_thread_id,io_java_thread_id\n";
    }

    public static String sampleRow(int iteration, String phase, StageResult result, long clockHz) {
        if (iteration < 0 || phase == null || result == null) {
            throw new IllegalArgumentException("A measured iteration, phase and result are required.");
        }
        List<String> cells = new ArrayList<>();
        cells.add(Integer.toString(iteration));
        cells.add(phase);
        long[] values = result.values(clockHz);
        for (int metric = 0; metric < METRICS.length; metric++) {
            cells.add(metric == CPU_METRIC_INDEX && !result.cpuTimingAvailable
                    ? "" : Long.toString(values[metric]));
        }
        cells.add(result.cpuTimingAvailable ? "ok" : unavailableReason(result));
        cells.add(Long.toString(result.phaseCpuStartNs));
        cells.add(Long.toString(result.phaseCpuEndNs));
        cells.add(Long.toString(result.ioWaitCpuNs));
        cells.add(Long.toString(result.protocolThreadId));
        cells.add(Long.toString(result.ioThreadId));
        return row(cells);
    }

    public static String summaryHeader() {
        return "phase,metric,n,mean,sd,median,p95,min,max,unit,status,valid_n,invalid_n\n";
    }

    /** A single invalid CPU observation suppresses the entire cohort's CPU statistics. */
    public static String summaryRow(String phase, int metric, List<StageResult> samples, long clockHz) {
        if (phase == null || metric < 0 || metric >= METRICS.length
                || samples == null || samples.isEmpty()) {
            throw new IllegalArgumentException("A phase, supported metric and nonempty sample cohort are required.");
        }
        List<Long> values = new ArrayList<>(samples.size());
        int invalid = 0;
        for (StageResult result : samples) {
            if (result == null) throw new IllegalArgumentException("A sample result cannot be null.");
            if (metric == CPU_METRIC_INDEX && !result.cpuTimingAvailable) invalid++;
            values.add(result.values(clockHz)[metric]);
        }
        List<String> cells = new ArrayList<>();
        cells.add(phase);
        cells.add(METRICS[metric]);
        cells.add(Integer.toString(samples.size()));
        if (invalid > 0) {
            // No positive-only or valid-only summary: every requested sample still counts in n.
            for (int statistic = 0; statistic < 6; statistic++) cells.add("");
        } else {
            Summary summary = Summary.of(values);
            cells.add(String.format(Locale.ROOT, "%.6f", summary.mean));
            cells.add(String.format(Locale.ROOT, "%.6f", summary.sd));
            cells.add(String.format(Locale.ROOT, "%.6f", summary.median));
            cells.add(Long.toString(summary.p95));
            cells.add(Long.toString(summary.min));
            cells.add(Long.toString(summary.max));
        }
        String name = METRICS[metric];
        cells.add(name.endsWith("_bytes") ? "bytes" : name.endsWith("_cycles") ? "cycles"
                : name.endsWith("_ns") ? "ns" : "count");
        cells.add(invalid == 0 ? "ok" : "unavailable_cpu_samples");
        cells.add(Integer.toString(samples.size() - invalid));
        cells.add(Integer.toString(invalid));
        return row(cells);
    }

    private static String unavailableReason(StageResult result) {
        String reason = result.cpuTimingError;
        return reason == null || reason.isEmpty() ? "unavailable" : "unavailable: " + reason;
    }

    private static String row(List<String> cells) {
        StringBuilder out = new StringBuilder();
        boolean first = true;
        for (String cell : cells) {
            if (!first) out.append(',');
            first = false;
            if (cell.indexOf(',') >= 0 || cell.indexOf('"') >= 0
                    || cell.indexOf('\n') >= 0 || cell.indexOf('\r') >= 0) {
                out.append('"').append(cell.replace("\"", "\"\"")).append('"');
            } else {
                out.append(cell);
            }
        }
        return out.append('\n').toString();
    }
}
