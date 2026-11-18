package com.example.pqbdh_7816;

import static org.junit.Assert.*;
import android.os.Process;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;

/** Platform probe checks; a VM is allowed to report unavailable CPU timing. */
public class TerminalCpuClockTest {
    @Test public void captureRecordsRawEvidenceWithoutAssumingClockQuality() {
        TerminalCpuClock clock = TerminalCpuClock.capture();
        Map<String, Object> values = clock.diagnostics();
        assertEquals(Process.myTid(), values.get("terminal_cpu_probe_linux_tid"));
        assertEquals(Thread.currentThread().getId(), values.get("terminal_cpu_probe_java_thread_id"));
        assertEquals(9, ((List<?>) values.get("terminal_cpu_probe_cpu_start_ns")).size());
        assertEquals(9, ((List<?>) values.get("terminal_cpu_probe_cpu_end_ns")).size());
        assertEquals(9, ((List<?>) values.get("terminal_cpu_probe_outer_wall_ns")).size());
        assertEquals(9, ((List<?>) values.get("terminal_cpu_probe_cpu_delta_ns")).size());
        assertEquals(clock.cpuUnavailableReason() == null, values.get("terminal_cpu_probe_available"));
        if (clock.cpuUnavailableReason() != null) {
            assertEquals(clock.cpuUnavailableReason(), values.get("terminal_cpu_probe_unavailable_reason"));
        }
        try {
            values.put("changed", true);
            fail("Probe evidence must be immutable");
        } catch (UnsupportedOperationException expected) { }
    }

    @Test public void clockCannotBeReusedForAnotherThreadsCpu() throws Exception {
        TerminalCpuClock clock = TerminalCpuClock.capture();
        String originalReason = clock.cpuUnavailableReason();
        AtomicReference<String> otherReason = new AtomicReference<>();
        Thread other = new Thread(() -> otherReason.set(clock.cpuUnavailableReason()), "clock-probe-other");
        other.start();
        other.join(5000);
        assertFalse("Probe thread did not finish", other.isAlive());
        assertEquals("CPU_CLOCK_THREAD_CHANGED", otherReason.get());
        assertEquals(originalReason, clock.cpuUnavailableReason());
    }
}
