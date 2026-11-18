package com.example.pqbdh_7816;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.os.Debug;
import android.os.Process;
import android.os.PowerManager;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements;
import java.io.File;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Runtime evidence only. Capture outside protocol clocks; never adjust measured results. */
public final class TerminalDiagnostics {
    private static final int CPU_CLOCK_READS = 100;
    private static volatile long calibrationSink;

    private TerminalDiagnostics() { }

    public static final class Snapshot {
        public final Map<String, Object> values;

        private Snapshot(Map<String, Object> values) {
            this.values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        }

        /** Compact evidence suitable for the status log and a completed result. */
        public String brief() {
            return "Timing method=" + values.get("measurement_method")
                    + "; app=" + values.get("app_version_name") + " (" + values.get("app_version_code") + ")"
                    + "; debugger connected=" + values.get("debugger_connected")
                    + "; waiting=" + values.get("debugger_waiting")
                    + "; debuggable build=" + values.get("app_debuggable")
                    + "; process64=" + values.get("process_is_64_bit")
                    + "; arch=" + values.get("process_os_arch")
                    + "; main nice=" + values.get("main_thread_priority")
                    + "; capture thread nice=" + values.get("capture_thread_priority") + ".";
        }

        public String format() {
            StringBuilder text = new StringBuilder("TERMINAL RUNTIME DIAGNOSTICS\n");
            for (Map.Entry<String, Object> entry : values.entrySet()) {
                text.append(entry.getKey()).append(": ").append(entry.getValue()).append('\n');
            }
            text.append("\nA debuggable build does not imply that a debugger is attached.\n")
                    .append("Thread priorities are Linux nice values; the capture thread is identified above.\n");
            if (Boolean.TRUE.equals(values.get("cpu_clock_calibration_performed"))) {
                text.append("Calibration is the wall cost of a 100-read CPU-clock loop, including loop overhead.\n")
                        .append("It is not a crypto benchmark and is never subtracted from protocol timings.\n")
                        .append("cpu_clock_available only checks nonnegative reads. The separate known-work probe checks clock advance, monotonicity and outer wall bounds.\n")
                        .append("Observed probe increments are not a resolution or accuracy guarantee; no probe value corrects protocol timings.\n");
            }
            return text.toString();
        }
    }

    /**
     * Capture on the protocol worker or instrumentation thread, outside measured phases.
     * On Android the process leader's Linux TID equals the PID and owns the main thread.
     * No work is posted to the main Looper or sampled while the PIN dialog is active.
     */
    @SuppressWarnings("deprecation")
    public static Snapshot capture(Context context, boolean calibrate) {
        if (context == null) throw new IllegalArgumentException("A context is required");
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("measurement_method", ProtocolMeasurements.METHOD);
        values.put("debugger_connected", Debug.isDebuggerConnected());
        values.put("debugger_waiting", Debug.waitingForDebugger());
        values.put("package_name", context.getPackageName());
        ApplicationInfo app = context.getApplicationInfo();
        values.put("app_debuggable", (app.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
        values.put("base_apk_bytes", app.sourceDir == null ? 0L : new File(app.sourceDir).length());
        values.put("native_library_directory", app.nativeLibraryDir == null ? "unavailable" : app.nativeLibraryDir);
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            values.put("app_version_name", info.versionName == null ? "unspecified" : info.versionName);
            values.put("app_version_code", Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : (long) info.versionCode);
            values.put("app_last_update_time_ms", info.lastUpdateTime);
        } catch (Exception unavailable) {
            values.put("package_metadata_error", unavailable.getClass().getSimpleName());
        }
        values.put("process_is_64_bit", Process.is64Bit());
        values.put("process_os_arch", System.getProperty("os.arch", "unavailable"));
        values.put("main_thread_priority", priority(Process.myPid()));
        values.put("capture_thread_priority", priority(Process.myTid()));
        values.put("capture_thread_name", Thread.currentThread().getName());
        values.put("capture_thread_linux_tid", Process.myTid());
        capturePowerState(context, values);
        Runtime runtime = Runtime.getRuntime();
        values.put("java_heap_max_bytes", runtime.maxMemory());
        values.put("java_heap_total_bytes", runtime.totalMemory());
        values.put("java_heap_free_bytes", runtime.freeMemory());
        captureRuntimeStats(values);
        values.put("cpu_clock_calibration_performed", calibrate);
        if (calibrate) {
            calibrateCpuClock(values);
            values.putAll(TerminalCpuClock.capture().diagnostics());
        }
        return new Snapshot(values);
    }

    private static Object priority(int tid) {
        try {
            return Process.getThreadPriority(tid);
        } catch (IllegalArgumentException | SecurityException unavailable) {
            return "unavailable: " + unavailable.getClass().getSimpleName();
        }
    }

    private static void capturePowerState(Context context, Map<String, Object> values) {
        try {
            PowerManager power = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            if (power == null) {
                values.put("power_state_error", "PowerManager unavailable");
                return;
            }
            values.put("power_save_mode", power.isPowerSaveMode());
            values.put("device_idle_mode", power.isDeviceIdleMode());
            values.put("ignoring_battery_optimizations", power.isIgnoringBatteryOptimizations(context.getPackageName()));
            if (Build.VERSION.SDK_INT >= 29) {
                int thermal = power.getCurrentThermalStatus();
                String[] names = {"none", "light", "moderate", "severe", "critical", "emergency", "shutdown"};
                values.put("thermal_status", thermal);
                values.put("thermal_status_label", thermal >= 0 && thermal < names.length ? names[thermal] : "unknown");
            } else {
                values.put("thermal_status", "unavailable before API 29");
            }
        } catch (RuntimeException | LinkageError unavailable) {
            values.put("power_state_error", unavailable.getClass().getSimpleName());
        }
    }

    private static void captureRuntimeStats(Map<String, Object> values) {
        try {
            Map<String, String> stats = Debug.getRuntimeStats();
            String[] keys = {"art.gc.gc-count", "art.gc.gc-time", "art.gc.bytes-allocated",
                    "art.gc.bytes-freed", "art.gc.blocking-gc-count", "art.gc.blocking-gc-time"};
            for (String key : keys) {
                // Retain the platform's raw value and key rather than guessing its units.
                values.put("runtime_stat_" + key, stats.containsKey(key) ? stats.get(key) : "unavailable");
            }
        } catch (RuntimeException | LinkageError unavailable) {
            values.put("runtime_stats_error", unavailable.getClass().getSimpleName());
        }
    }

    private static void calibrateCpuClock(Map<String, Object> values) {
        boolean available = true;
        long lastCpu = 0L;
        long wallStart = System.nanoTime();
        for (int read = 0; read < CPU_CLOCK_READS; read++) {
            lastCpu = Debug.threadCpuTimeNanos();
            available &= lastCpu >= 0;
        }
        long elapsed = System.nanoTime() - wallStart;
        calibrationSink = lastCpu;
        values.put("cpu_clock_read_count", CPU_CLOCK_READS);
        values.put("cpu_clock_available", available);
        values.put("cpu_clock_read_loop_wall_total_ns", elapsed);
        values.put("cpu_clock_read_loop_wall_mean_ns", elapsed / (double) CPU_CLOCK_READS);
    }
}
