package com.example.pqbdh_7816.benchmark;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Stage;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import org.junit.Test;

public class BenchmarkCsvTest {
    private static final long CLOCK_HZ = 105_000_000L;

    private static final class FakeClock implements ProtocolMeasurements.Clock {
        long wall;
        long cpu;
        final String reason;

        FakeClock(String reason) { this.reason = reason; }
        @Override public long wallNs() { return wall; }
        @Override public long cpuNs() { return cpu; }
        @Override public String cpuUnavailableReason() { return reason; }
    }

    /** Model an isolated I/O exchange; this fixture does not produce hardware timing data. */
    private static StageResult result(long cpuWork, String unavailableReason) throws Exception {
        FakeClock clock = new FakeClock(unavailableReason);
        Stage stage = new Stage();
        stage.start(clock);
        clock.wall += 100;
        clock.cpu += cpuWork / 2;
        stage.exchange(new ProtocolMeasurements.Exchange() {
            @Override public byte[] send(byte[] command) {
                clock.wall += 700;
                clock.cpu += cpuWork - cpuWork / 2;
                return new byte[]{(byte) 0x90, 0};
            }
            @Override public boolean isCpuIsolated() { return true; }
            @Override public long ioThreadId() { return Thread.currentThread().getId() + 1000; }
        }, new byte[]{(byte) 0x80, (byte) 0xB2, 0, 0, 0}, 0);
        clock.wall += 200;
        return stage.finish().withCardCycles(105);
    }

    @Test
    public void validCpuExportsDirectObservationAndFullSummary() throws Exception {
        StageResult sample = result(200, null);
        assertTrue(sample.cpuTimingAvailable);
        String[] row = BenchmarkCsv.sampleRow(0, "pake", sample, CLOCK_HZ).trim().split(",", -1);
        assertEquals(19, row.length);
        assertEquals("200", row[8]);
        assertEquals("ok", row[13]);
        assertEquals("0", row[14]);
        assertEquals("200", row[15]);
        assertEquals("100", row[16]);

        String[] summary = BenchmarkCsv.summaryRow("pake", BenchmarkCsv.CPU_METRIC_INDEX,
                Collections.singletonList(sample), CLOCK_HZ).trim().split(",", -1);
        assertEquals(13, summary.length);
        assertEquals("1", summary[2]);
        assertEquals("200.000000", summary[3]);
        assertEquals("0.000000", summary[4]);
        assertEquals("ok", summary[10]);
        assertEquals("1", summary[11]);
        assertEquals("0", summary[12]);
    }

    @Test
    public void frozenClockExportsBlankCpuAndPreservesRawZeroEndpoints() throws Exception {
        StageResult sample = result(0, null);
        assertFalse(sample.cpuTimingAvailable);
        String[] row = BenchmarkCsv.sampleRow(3, "certificates", sample, CLOCK_HZ).trim().split(",", -1);
        assertEquals("", row[8]);
        assertTrue(row[13].startsWith("unavailable"));
        assertEquals("0", row[14]);
        assertEquals("0", row[15]);
        assertEquals("0", row[16]);
        assertEquals("1", row[6]);
        assertEquals("1000", row[10]);
    }

    @Test
    public void oneInvalidCpuSuppressesWholeCohortInsteadOfSelectingPositiveSamples() throws Exception {
        StageResult valid = result(200, null);
        StageResult unresolved = result(0, null);
        String[] cpu = BenchmarkCsv.summaryRow("total", BenchmarkCsv.CPU_METRIC_INDEX,
                Arrays.asList(valid, unresolved), CLOCK_HZ).trim().split(",", -1);
        assertEquals("2", cpu[2]);
        for (int field = 3; field <= 8; field++) assertEquals("", cpu[field]);
        assertEquals("ns", cpu[9]);
        assertEquals("unavailable_cpu_samples", cpu[10]);
        assertEquals("1", cpu[11]);
        assertEquals("1", cpu[12]);

        String[] wall = BenchmarkCsv.summaryRow("total", 8,
                Arrays.asList(valid, unresolved), CLOCK_HZ).trim().split(",", -1);
        assertEquals("2", wall[2]);
        assertEquals("1000.000000", wall[3]);
        assertEquals("ok", wall[10]);
        assertEquals("2", wall[11]);
        assertEquals("0", wall[12]);
    }

    @Test
    public void allInvalidCpuRetainsFullCountAndNoStatistics() throws Exception {
        String[] cpu = BenchmarkCsv.summaryRow("pake", BenchmarkCsv.CPU_METRIC_INDEX,
                Arrays.asList(result(0, null), result(0, null)), CLOCK_HZ).trim().split(",", -1);
        assertEquals("2", cpu[2]);
        for (int field = 3; field <= 8; field++) assertEquals("", cpu[field]);
        assertEquals("0", cpu[11]);
        assertEquals("2", cpu[12]);
    }

    @Test
    public void reasonContainingCsvSyntaxIsEscapedWithoutChangingItsContents() throws Exception {
        String reason = "probe, \"stalled\"\nretry on another clock";
        String row = BenchmarkCsv.sampleRow(0, "pake", result(200, reason), CLOCK_HZ);
        assertTrue(row.contains("\"unavailable: probe, \"\"stalled\"\"\nretry on another clock\""));
        assertTrue(row.contains(",,700,1000,"));
    }

    @Test
    public void headersDescribeEveryAppendedStatusAndRawDiagnostic() {
        assertEquals(19, BenchmarkCsv.sampleHeader().trim().split(",", -1).length);
        assertTrue(BenchmarkCsv.sampleHeader().contains("cpu_status,raw_phase_cpu_start_ns,raw_phase_cpu_end_ns"));
        assertTrue(BenchmarkCsv.sampleHeader().endsWith("protocol_java_thread_id,io_java_thread_id\n"));
        assertEquals(13, BenchmarkCsv.summaryHeader().trim().split(",", -1).length);
        assertTrue(BenchmarkCsv.summaryHeader().endsWith("status,valid_n,invalid_n\n"));
    }

    @Test
    public void numericFormattingDoesNotDependOnDeviceLocale() throws Exception {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.FRANCE);
            assertTrue(BenchmarkCsv.summaryRow("pake", BenchmarkCsv.CPU_METRIC_INDEX,
                    Arrays.asList(result(200, null), result(201, null)), CLOCK_HZ)
                    .contains(",200.500000,"));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    public void rejectsMissingCohortAndUnsupportedMetric() throws Exception {
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkCsv.summaryRow("pake", 0, Collections.emptyList(), CLOCK_HZ));
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkCsv.summaryRow("pake", -1, Collections.singletonList(result(200, null)), CLOCK_HZ));
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkCsv.sampleRow(-1, "pake", result(200, null), CLOCK_HZ));
    }
}
