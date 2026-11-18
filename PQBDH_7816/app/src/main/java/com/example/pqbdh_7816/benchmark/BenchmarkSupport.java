package com.example.pqbdh_7816.benchmark;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Parsing, counter safety checks and descriptive statistics for protocol measurements. */
public final class BenchmarkSupport {
    // 90% of one 32-bit counter period, multiplied by 10^9 ns/s.
    private static final long SAFE_CYCLE_NANO_PRODUCT = (1L << 32) * 900_000_000L;

    private BenchmarkSupport() {
    }

    /** The firmware counter that supplied the measured core-cycle totals. */
    public enum TimerSource {
        DWT("DWT CYCCNT"), SYSTICK_IRQ("SysTick IRQ");

        public final String label;

        TimerSource(String label) {
            this.label = label;
        }
    }

    /**
     * Require a complete APDU round trip to fit within 90% of a counter period.
     * The card's handler is contained in this interval, so its unsigned 32-bit
     * counter difference cannot have lost a complete wrap. Division avoids
     * overflowing an elapsedNs * clockHz multiplication.
     */
    public static void validateRoundTrip(long elapsedNs, long clockHz) {
        if (elapsedNs < 0 || clockHz <= 0) {
            throw new IllegalArgumentException("Nonnegative elapsed time and positive card clock are required.");
        }
        long limitFloor = SAFE_CYCLE_NANO_PRODUCT / clockHz;
        long remainder = SAFE_CYCLE_NANO_PRODUCT % clockHz;
        if (elapsedNs > limitFloor || (elapsedNs == limitFloor && remainder == 0)) {
            throw new IllegalArgumentException(
                    "APDU round trip is too long: the single-command hardware counter may wrap.");
        }
    }

    /** A valid timing interface replied, but its hardware counter did not become ready. */
    public static final class CounterNotReadyException extends IllegalArgumentException {
        public final long clockHz;

        private CounterNotReadyException(long clockHz) {
            super("Card timing interface is present, but the hardware cycle counter is not ready "
                    + "(flags=0, clock=" + clockHz + " Hz).");
            this.clockHz = clockHz;
        }
    }

    /** Versioned F7 response; cumulative phase counters are reset before each sample. */
    public static final class CardTiming {
        public final TimerSource timerSource;
        public final long clockHz;
        public final long commandCount;
        public final long negotiateKemCycles;
        public final long certCycles;
        public final long establishCycles;

        private CardTiming(TimerSource timerSource, long clockHz, long commandCount, long negotiateKemCycles,
                           long certCycles, long establishCycles) {
            this.timerSource = timerSource;
            this.clockHz = clockHz;
            this.commandCount = commandCount;
            this.negotiateKemCycles = negotiateKemCycles;
            this.certCycles = certCycles;
            this.establishCycles = establishCycles;
        }

        public static CardTiming parse(byte[] response) {
            if (response == null || response.length != 42) {
                throw new IllegalArgumentException("Expected a 40-byte PEB1 timing payload and two status bytes.");
            }
            if ((response[40] & 0xff) != 0x90 || response[41] != 0) {
                throw new IllegalArgumentException("Card timing APDU did not return status 9000.");
            }
            if (response[0] != 'P' || response[1] != 'E'
                    || response[2] != 'B' || response[3] != '1') {
                throw new IllegalArgumentException("Unsupported card timing response: expected PEB1.");
            }
            long flags = readU32(response, 4);
            long clockHz = readU32(response, 8);
            if (flags == 0) {
                throw new CounterNotReadyException(clockHz);
            }
            if (flags != 1 && flags != 3) {
                throw new IllegalArgumentException("Unsupported card timing flags: " + flags);
            }
            if (clockHz == 0) {
                throw new IllegalArgumentException("Card benchmark clock frequency must be positive.");
            }
            return new CardTiming(flags == 1 ? TimerSource.DWT : TimerSource.SYSTICK_IRQ,
                    clockHz, readU32(response, 12),
                    readU64(response, 16), readU64(response, 24), readU64(response, 32));
        }

        private static long readU64(byte[] response, int offset) {
            if ((response[offset] & 0x80) != 0) {
                throw new IllegalArgumentException("Card cycle count exceeds Java's signed 64-bit range.");
            }
            long value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | (response[offset + i] & 0xffL);
            }
            return value;
        }
    }

    /** Captured SysTick fallback state; it cannot turn a failed timing response into a measurement. */
    public static final class SysTickDiagnostics {
        public final long reason;
        public final long clockHz;
        public final long ctrl;
        public final long load;
        public final long val;
        public final long icsr;
        public final long interruptMask;
        public final long wraps;
        public final long flags;

        private SysTickDiagnostics(byte[] response) {
            reason = readU32(response, 4);
            clockHz = readU32(response, 8);
            ctrl = readU32(response, 12);
            load = readU32(response, 16);
            val = readU32(response, 20);
            icsr = readU32(response, 24);
            interruptMask = readU32(response, 28);
            wraps = readU32(response, 32);
            flags = readU32(response, 36);
        }

        public static SysTickDiagnostics parse(byte[] response) {
            if (response == null || response.length != 42) {
                throw new IllegalArgumentException("Expected a 40-byte PES1 diagnostic payload and two status bytes.");
            }
            if ((response[40] & 255) != 0x90 || response[41] != 0) {
                throw new IllegalArgumentException("SysTick diagnostic APDU did not return status 9000.");
            }
            if (response[0] != 'P' || response[1] != 'E' || response[2] != 'S' || response[3] != '1') {
                throw new IllegalArgumentException("Unsupported SysTick diagnostic response: expected PES1.");
            }
            SysTickDiagnostics diagnostic = new SysTickDiagnostics(response);
            if (diagnostic.reason > 8) {
                throw new IllegalArgumentException("Unsupported SysTick diagnostic reason: " + diagnostic.reason);
            }
            if ((diagnostic.flags != 0 && diagnostic.flags != 3)
                    || (diagnostic.reason == 1) != (diagnostic.flags == 3)) {
                throw new IllegalArgumentException("SysTick diagnostic reason and readiness flags are inconsistent.");
            }
            if (diagnostic.flags == 3 && diagnostic.clockHz == 0) {
                throw new IllegalArgumentException("Ready SysTick diagnostics require a positive clock frequency.");
            }
            if ((diagnostic.interruptMask & ~0xff03L) != 0) {
                throw new IllegalArgumentException("SysTick diagnostics contain unsupported interrupt-mask bits.");
            }
            if (diagnostic.flags == 3 && ((diagnostic.ctrl & 7) != 7
                    || diagnostic.load != 0xffffffL || diagnostic.val > diagnostic.load
                    || diagnostic.wraps == 0 || (diagnostic.interruptMask & 3) != 0)) {
                throw new IllegalArgumentException("Ready SysTick diagnostics have invalid counter or interrupt configuration.");
            }
            return diagnostic;
        }

        public String description() {
            String explanation;
            switch ((int) reason) {
                case 0: explanation = "The SysTick fallback has not been attempted."; break;
                case 1: explanation = "SysTick passed the counter and interrupt readiness checks."; break;
                case 2: explanation = "The card core clock frequency is unknown."; break;
                case 3: explanation = "The SysTick configuration is invalid for cycle measurement."; break;
                case 4: explanation = "Interrupt masking prevents the SysTick wrap interrupt from running."; break;
                case 5: explanation = "SysTick VAL did not advance during the firmware probe."; break;
                case 6: explanation = "The SysTick interrupt self-test failed."; break;
                case 7: explanation = "The SysTick configuration or interrupt mask changed after initialization."; break;
                default: explanation = "The firmware could not obtain a stable SysTick snapshot."; break;
            }
            return "SysTick counter diagnostics (cached PES1): " + explanation + '\n'
                    + String.format(Locale.ROOT,
                    "Reason=%d; clock=%d Hz; flags=%d; CTRL=0x%08X; LOAD=0x%08X; VAL=0x%08X; "
                            + "ICSR=0x%08X; interrupt mask=0x%08X "
                            + "(PRIMASK=%d, FAULTMASK=%d, BASEPRI=0x%02X); wraps=%d.",
                    reason, clockHz, flags, ctrl, load, val, icsr, interruptMask,
                    interruptMask & 1, (interruptMask >>> 1) & 1, (interruptMask >>> 8) & 255, wraps);
        }
    }

    /** Captured F7 reset diagnostics; parsing this packet never supplies measured card time. */
    public static final class CardTimingDiagnostics {
        public final long reason;
        public final long clockHz;
        public final long demcrBefore;
        public final long demcrAfter;
        public final long dwtCtrlBefore;
        public final long dwtCtrlAfter;
        public final long firstCycle;
        public final long secondCycle;
        public final long flags;

        private CardTimingDiagnostics(byte[] response) {
            reason = readU32(response, 4);
            clockHz = readU32(response, 8);
            demcrBefore = readU32(response, 12);
            demcrAfter = readU32(response, 16);
            dwtCtrlBefore = readU32(response, 20);
            dwtCtrlAfter = readU32(response, 24);
            firstCycle = readU32(response, 28);
            secondCycle = readU32(response, 32);
            flags = readU32(response, 36);
        }

        public static CardTimingDiagnostics parse(byte[] response) {
            if (response == null || response.length != 42) {
                throw new IllegalArgumentException("Expected a 40-byte PED1 diagnostic payload and two status bytes.");
            }
            if ((response[40] & 0xff) != 0x90 || response[41] != 0) {
                throw new IllegalArgumentException("Card counter diagnostic APDU did not return status 9000.");
            }
            if (response[0] != 'P' || response[1] != 'E'
                    || response[2] != 'D' || response[3] != '1') {
                throw new IllegalArgumentException("Unsupported card counter diagnostic response: expected PED1.");
            }
            CardTimingDiagnostics diagnostic = new CardTimingDiagnostics(response);
            if (diagnostic.reason > 6) {
                throw new IllegalArgumentException("Unsupported card counter diagnostic reason: " + diagnostic.reason);
            }
            if (diagnostic.flags > 1 || (diagnostic.reason == 1) != (diagnostic.flags == 1)) {
                throw new IllegalArgumentException("Card counter diagnostic reason and readiness flags are inconsistent.");
            }
            if (diagnostic.flags == 1 && diagnostic.clockHz == 0) {
                throw new IllegalArgumentException("Ready card counter diagnostics require a positive clock frequency.");
            }
            return diagnostic;
        }

        public String description() {
            String explanation;
            switch ((int) reason) {
                case 0: explanation = "The counter has not been reset."; break;
                case 1: explanation = "The cycle counter passed the firmware readiness check."; break;
                case 2: explanation = "The card core clock frequency is unknown."; break;
                case 3: explanation = "The trace-enable bit did not remain set after the firmware write."; break;
                case 4: explanation = "DWT_CTRL reports NOCYCCNT=1; this DWT configuration does not expose a cycle counter."; break;
                case 5: explanation = "The cycle-counter enable bit did not remain set after the firmware write."; break;
                default: explanation = "The cycle counter did not advance during the firmware probe."; break;
            }
            return "Card counter diagnostics (cached PED1): " + explanation + '\n'
                    + String.format(Locale.ROOT,
                    "Reason=%d; clock=%d Hz; flags=%d; DEMCR=0x%08X -> 0x%08X; "
                            + "DWT_CTRL=0x%08X -> 0x%08X; CYCCNT=0x%08X -> 0x%08X.",
                    reason, clockHz, flags, demcrBefore, demcrAfter,
                    dwtCtrlBefore, dwtCtrlAfter, firstCycle, secondCycle);
        }
    }

    private static long readU32(byte[] response, int offset) {
        long value = 0;
        for (int i = 0; i < 4; i++) {
            value = (value << 8) | (response[offset + i] & 0xffL);
        }
        return value;
    }

    /** Statistics in the same units as the original samples; sd is sample standard deviation. */
    public static final class Summary {
        public final int count;
        public final double mean;
        public final double median;
        public final double sd;
        public final long min;
        public final long max;
        public final long p95;

        private Summary(int count, double mean, double median, double sd,
                        long min, long max, long p95) {
            this.count = count;
            this.mean = mean;
            this.median = median;
            this.sd = sd;
            this.min = min;
            this.max = max;
            this.p95 = p95;
        }

        public static Summary of(List<Long> values) {
            if (values == null || values.isEmpty()) {
                throw new IllegalArgumentException("At least one measurement is required.");
            }
            List<Long> sorted = new ArrayList<>(values.size());
            double mean = 0;
            double m2 = 0;
            int count = 0;
            for (Long value : values) {
                if (value == null || value < 0) {
                    throw new IllegalArgumentException("Measurements must be nonnegative and nonnull.");
                }
                sorted.add(value);
                count++;
                double delta = value - mean;
                mean += delta / count;
                m2 += delta * (value - mean);
            }
            Collections.sort(sorted);
            double median = count % 2 == 1 ? sorted.get(count / 2)
                    : sorted.get(count / 2 - 1) / 2.0 + sorted.get(count / 2) / 2.0;
            // ceil(0.95 * count), expressed with integers for exact nearest rank.
            int p95Index = (int) ((95L * count + 99L) / 100L) - 1;
            return new Summary(count, mean, median, count == 1 ? 0 : Math.sqrt(m2 / (count - 1)),
                    sorted.get(0), sorted.get(count - 1), sorted.get(p95Index));
        }
    }
}
