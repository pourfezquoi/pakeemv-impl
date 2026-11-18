package com.example.pakebdh_7816;

import static org.junit.Assert.*;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.util.Log;
import android.text.TextUtils;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.example.pakebdh_7816.benchmark.BenchmarkCsv;
import com.example.pakebdh_7816.benchmark.BenchmarkSupport.TimerSource;
import com.example.pakebdh_7816.benchmark.IsolatedIoExchange;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import org.json.JSONObject;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Real Android/CCID/card measurements. See PAKEBDH_7816/BENCHMARK.md. */
@RunWith(AndroidJUnit4.class)
public class PakeEmvBenchmarkTest {
    private static final String TAG = "PAKE_EMV_BENCH";
    private static final Consumer<String> QUIET = ignored -> { };
    private static final String[] PHASES = {"pake", "certificates", "establish_key", "total"};

    @Test
    public void measurePakeEmv() throws Exception {
        Bundle args = InstrumentationRegistry.getArguments();
        Assume.assumeTrue("Opt in with -e runPakeEmvBenchmark true; a real reader/card is required",
                "true".equals(args.getString("runPakeEmvBenchmark")));
        int samples = intArg(args, "benchmarkSamples", 30, 1, 10000);
        int warmup = intArg(args, "benchmarkWarmup", 5, 0, 10000);
        int vid = intArg(args, "benchmarkReaderVid", 0x076B, 0, 65535);
        int pid = intArg(args, "benchmarkReaderPid", 0x5321, 0, 65535);
        // This default is the public test PIN in Card_pakebdh, never written to reports/logs.
        String pin = args.getString("benchmarkPin", "123456");
        assertTrue("benchmarkPin must have six ASCII digits", pin.matches("[0-9]{6}"));
        String expectedPan = PakeEmvCertificates.canonicalPan(
                args.getString("benchmarkExpectedPan", PakeEmvBenchmarkConfig.EXPECTED_PAN));
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File directory = new File(context.getFilesDir(), "pake-emv-benchmark/"
                + System.currentTimeMillis() + "-" + UUID.randomUUID().toString().substring(0, 8));
        assertTrue("Cannot create report directory", directory.mkdirs());
        JSONObject metadata = metadata(args, samples, warmup, vid, pid);
        metadata.put("complete", false);
        writeMetadata(directory, metadata);
        Log.i(TAG, "Reports: " + directory.getAbsolutePath());
        List<Sample> completed = new ArrayList<>();
        String activeSession = "initialization";
        PakeEmvCrypto.ensurePqcProviders();
        try (Writer raw = new FileWriter(new File(directory, "samples.csv"))) {
            raw.write(BenchmarkCsv.sampleHeader());
            for (int i = -warmup; i < samples; i++) {
                activeSession = i < 0 ? "warm-up session " + (i + warmup + 1) + "/" + warmup
                        : "measured session " + (i + 1) + "/" + samples;
                Log.i(TAG, "Starting " + activeSession);
                Sample sample = runOnce(context, pin, expectedPan, vid, pid);
                if (i < 0) continue;
                if (!completed.isEmpty()) {
                    assertEquals("Card clock changed across samples", completed.get(0).clockHz, sample.clockHz);
                    assertEquals("Card timer source changed across samples",
                            completed.get(0).timerSource, sample.timerSource);
                }
                completed.add(sample);
                for (int phase = 0; phase < PHASES.length; phase++) {
                    raw.write(BenchmarkCsv.sampleRow(i, PHASES[phase], sample.stage(phase), sample.clockHz));
                }
                raw.flush();
                metadata.put("completed_samples", completed.size());
                metadata.put("card_clock_hz", sample.clockHz);
                metadata.put("card_timer_source", sample.timerSource.label);
                metadata.put("cert_c_der_bytes", sample.certCBytes);
                metadata.put("cert_is_der_bytes", sample.certISBytes);
                updateCpuMetadata(metadata, completed);
                writeMetadata(directory, metadata);
                Log.i(TAG, "Completed measured session " + (i + 1) + "/" + samples);
            }
            activeSession = "summary/report writing";
            writeSummary(directory, completed);
            metadata.put("complete", true);
            writeMetadata(directory, metadata);
        } catch (Exception | AssertionError failure) {
            // Keep successful raw rows, but never present a partial run as a complete experiment.
            metadata.put("complete", false);
            metadata.put("failure_type", failure.getClass().getSimpleName());
            metadata.put("failure_context", activeSession);
            metadata.put("failure_message", failure.getMessage());
            metadata.put("completed_samples", completed.size());
            updateCpuMetadata(metadata, completed);
            writeMetadata(directory, metadata);
            Log.e(TAG, "Failed during " + activeSession, failure);
            throw failure;
        }
    }

    private static Sample runOnce(Context context, String pin, String expectedPan, int vid, int pid) throws Exception {
        assertFalse("Detach the Android debugger before collecting comparison measurements", Debug.isDebuggerConnected());
        assertFalse("The terminal must not be waiting for a debugger", Debug.waitingForDebugger());
        UsbCcidTransport transport = new UsbCcidTransport(context, vid, pid, message -> Log.i(TAG, message));
        try (IsolatedIoExchange io = new IsolatedIoExchange(command -> transport.sendApdu(command, 60000))) {
            try {
                io.call(() -> { transport.connect(); return null; });
                TerminalCpuClock clock = TerminalCpuClock.capture();
                PakeEmvSession.Result result = PakeEmvSession.run(io, pin, expectedPan, clock, true, QUIET);
                assertTrue("Authentication rejected. " + result.rejectionReason, result.accepted);
                assertFalse("A debugger attached during the measured session", Debug.isDebuggerConnected());
                assertTrue("Hardware benchmark requires verified card measurements", result.hasCardTiming());
                assertNotNull("Hardware benchmark requires the verified card timer source", result.timerSource);
                return new Sample(result, clock.diagnostics(), clock.cpuUnavailableReason());
            } finally {
                closeTransport(io, transport);
            }
        }
    }

    private static void closeTransport(IsolatedIoExchange io, UsbCcidTransport transport) throws Exception {
        if (Thread.currentThread().isInterrupted()) {
            // Abort a possibly blocked USB call when dispatch can no longer be awaited.
            transport.close();
            return;
        }
        io.call(() -> { transport.close(); return null; });
    }

    private static final class Sample {
        final PakeEmvSession.Result result;
        final long clockHz;
        final TimerSource timerSource;
        final int certCBytes, certISBytes;
        final Map<String, Object> cpuClockDiagnostics;
        final String cpuClockUnavailableReason;

        Sample(PakeEmvSession.Result result, Map<String, Object> diagnostics, String cpuClockUnavailableReason) {
            this.result = result;
            clockHz = result.clockHz;
            timerSource = result.timerSource;
            certCBytes = result.certCBytes;
            certISBytes = result.certISBytes;
            cpuClockDiagnostics = diagnostics;
            this.cpuClockUnavailableReason = cpuClockUnavailableReason;
        }

        StageResult stage(int phase) {
            StageResult[] stages = {result.pake, result.certificates, result.establishKey};
            return phase < stages.length ? stages[phase] : result.total();
        }
    }

    private static int intArg(Bundle args, String name, int fallback, int min, int max) {
        int value = Integer.decode(args.getString(name, Integer.toString(fallback)));
        assertTrue(name + " is outside the supported range", value >= min && value <= max);
        return value;
    }

    private static JSONObject metadata(Bundle args, int samples, int warmup, int vid, int pid) throws Exception {
        JSONObject out = new JSONObject();
        out.put("schema", "pake-emv-benchmark-v3");
        out.put("measurement_method", ProtocolMeasurements.METHOD);
        out.put("terminal_runtime", new JSONObject(TerminalDiagnostics.capture(
                InstrumentationRegistry.getInstrumentation().getTargetContext(), true).values));
        out.put("profile", "pake-emv-v3-six-messages-chic-ddf94132");
        out.put("revision", args.getString("benchmarkRevision", "unspecified"));
        out.put("card_revision", args.getString("benchmarkCardRevision", "unspecified"));
        out.put("card_hardware", args.getString("benchmarkCardHardware", "unspecified"));
        out.put("card_compiler_flags", args.getString("benchmarkCardBuild", "unspecified"));
        out.put("terminal_manufacturer", Build.MANUFACTURER);
        out.put("terminal_model", Build.MODEL);
        out.put("terminal_hardware", Build.HARDWARE);
        out.put("terminal_abis", TextUtils.join(",", Build.SUPPORTED_ABIS));
        out.put("process_is_64_bit", android.os.Process.is64Bit());
        out.put("process_os_arch", System.getProperty("os.arch"));
        out.put("native_configuration", args.getString("benchmarkNativeBuild",
                "shared CMake Debug, default compiler optimization; see recorded build/revision"));
        out.put("android_sdk", Build.VERSION.SDK_INT);
        out.put("android_fingerprint", Build.FINGERPRINT);
        out.put("app_variant", "debug-instrumentation");
        out.put("reader_vid", vid);
        out.put("reader_pid", pid);
        out.put("requested_samples", samples);
        out.put("warmup_sessions_excluded", warmup);
        out.put("completed_samples", 0);
        out.put("cpu_measurement_complete", false);
        out.put("pake_kem", "CHIC-author-Kyber512");
        out.put("outer_kem", "ML-KEM-512");
        out.put("suite", PakeEmvProtocol.SUITE);
        out.put("certificate_signature", "ML-DSA-44");
        out.put("aead", "AES-256-GCM, 12-byte nonce, 16-byte tag");
        out.put("card_measurement", "Core cycles from card_timer_source (DWT or IRQ-extended SysTick): "
                + "complete APDU handler, excluding receive/send waits");
        out.put("terminal_active_wall", "phase wall minus measured blocking APDU calls; includes scheduling/GC");
        out.put("terminal_cpu", "Direct protocol-thread CPU delta, including computation and dispatch/wakeup bookkeeping; USB work runs on a separate serialized I/O thread. No APDU CPU subtraction or calibration subtraction.");
        out.put("cpu_unavailable_policy", "Unavailable CPU cells are blank, with cpu_status and raw diagnostic endpoints retained. If any sample in a phase is unavailable, all CPU summary statistics for that phase are blank; no valid-only subset is averaged.");
        out.put("cpu_raw_diagnostics", "Raw CPU endpoints are per phase; aggregate CPU sums included phases and does not include gaps between them. raw_io_wait_cpu_ns is protocol-thread CPU observed while waiting for dispatch, never subtracted. Thread IDs are Java thread IDs.");
        out.put("traffic_scope", "C1/B2/50 only; payload and APDU separately; excludes F7/F8/F9 management, SELECT, power-on, T=1/CCID/USB framing");
        out.put("phase_wall_scope", "sum of three phases including KC1/KC2/KC3 validation; excludes setup, management queries, reporting and gaps between phases");
        out.put("key_provisioning", "card long-term key/cert provisioning excluded; terminal ephemeral keygen included");
        out.put("implementation_note", "Init1-4/Resp1-3; complete CHIC; pinned certificate anchor and independent expected PAN; KC1/KC2/KC3; HKDF domain-separated keys; fixed padded certificate envelope");
        out.put("summary_sd", "sample standard deviation (n-1), zero for one sample");
        out.put("summary_p95", "nearest rank ceil(0.95*n)");
        return out;
    }

    private static void writeMetadata(File directory, JSONObject metadata) throws Exception {
        try (Writer writer = new FileWriter(new File(directory, "metadata.json"))) {
            writer.write(metadata.toString(2));
            writer.write("\n");
        }
    }

    private static void writeSummary(File directory, List<Sample> samples) throws IOException {
        try (Writer writer = new FileWriter(new File(directory, "summary.csv"))) {
            writer.write(BenchmarkCsv.summaryHeader());
            for (int phase = 0; phase < PHASES.length; phase++) {
                List<StageResult> stages = new ArrayList<>();
                for (Sample sample : samples) stages.add(sample.stage(phase));
                for (int metric = 0; metric < BenchmarkCsv.METRICS.length; metric++) {
                    writer.write(BenchmarkCsv.summaryRow(PHASES[phase], metric, stages, samples.get(0).clockHz));
                }
            }
        }
    }

    private static void updateCpuMetadata(JSONObject metadata, List<Sample> samples) throws Exception {
        JSONObject valid = new JSONObject();
        JSONObject invalid = new JSONObject();
        boolean allAvailable = !samples.isEmpty()
                && samples.size() == metadata.getInt("requested_samples");
        for (int phase = 0; phase < PHASES.length; phase++) {
            int unavailable = 0;
            for (Sample sample : samples) if (!sample.stage(phase).cpuTimingAvailable) unavailable++;
            valid.put(PHASES[phase], samples.size() - unavailable);
            invalid.put(PHASES[phase], unavailable);
            allAvailable &= unavailable == 0;
        }
        metadata.put("cpu_measurement_complete", allAvailable);
        metadata.put("cpu_valid_samples_by_phase", valid);
        metadata.put("cpu_invalid_samples_by_phase", invalid);
        int unavailableProbes = 0;
        for (Sample sample : samples) if (sample.cpuClockUnavailableReason != null) unavailableProbes++;
        metadata.put("cpu_clock_probe_unavailable_samples", unavailableProbes);
        if (!samples.isEmpty()) {
            metadata.put("cpu_clock_probe_first_measured", new JSONObject(samples.get(0).cpuClockDiagnostics));
            metadata.put("cpu_clock_probe_last_measured", new JSONObject(samples.get(samples.size() - 1).cpuClockDiagnostics));
        }
    }
}
