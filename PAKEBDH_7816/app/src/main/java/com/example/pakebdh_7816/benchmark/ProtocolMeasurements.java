package com.example.pakebdh_7816.benchmark;

import java.math.BigInteger;

/** Actual protocol processing and APDU traffic measurements, independent of Android. */
public final class ProtocolMeasurements {
    /** v3 isolates transport work and observes protocol-thread CPU without I/O subtraction. */
    public static final String METHOD = "terminal-isolated-io-cpu-v3";

    private ProtocolMeasurements() {
    }

    public interface Clock {
        long wallNs();
        long cpuNs();
        /** Optional preflight failure; never changes the observed wall or CPU readings. */
        default String cpuUnavailableReason() { return null; }
    }

    public interface Exchange {
        byte[] send(byte[] command) throws Exception;
        /** True only when blocking transport and its processing execute on another thread. */
        default boolean isCpuIsolated() { return false; }
        /** Java thread ID of the actual transport worker; -1 before its first dispatch. */
        default long ioThreadId() { return -1; }
    }

    /** One timed protocol phase. Transport/protocol failures invalidate the phase. */
    public static final class Stage {
        private static final int NEW = 0;
        private static final int RUNNING = 1;
        private static final int FINISHED = 2;
        private static final int FAILED = 3;

        private int state = NEW;
        private Clock clock;
        private long wallStart;
        private long cpuStart;
        private long lastWall;
        private long lastCpu = -1;
        private long logicalT2c;
        private long logicalC2t;
        private long commandBytes;
        private long responseBytes;
        private long apduCount;
        private long ioNs;
        private long ioWaitCpuNs;
        private long protocolThreadId;
        private long ioThreadId = -1;
        private String cpuTimingError;

        public void start(Clock clock) {
            if (state != NEW) throw new IllegalStateException("A measurement phase can start only once.");
            try {
                if (clock == null) throw new IllegalArgumentException("A measurement clock is required.");
                this.clock = clock;
                protocolThreadId = Thread.currentThread().getId();
                try {
                    markCpuUnavailable(clock.cpuUnavailableReason());
                } catch (RuntimeException | LinkageError failure) {
                    markCpuUnavailable("CPU-clock preflight failed: " + failure.getClass().getSimpleName());
                }
                wallStart = clock.wallNs();
                cpuStart = sampleCpu();
                lastWall = wallStart;
                state = RUNNING;
            } catch (RuntimeException | Error failure) {
                state = FAILED;
                throw failure;
            }
        }

        /**
         * Count complete short APDU buffers. The blocking transport must run on
         * an isolated I/O worker to report CPU time. CPU observed on the protocol
         * thread while it submits/waits for a response is retained as a diagnostic,
         * and is NOT subtracted: v3 measures the whole protocol-thread CPU delta.
         * Thus it includes handoff, wake-up, encoding and sampling overhead, while
         * transport processing belongs to the worker. Wall intervals still bracket
         * each complete send call, including dispatch and response delivery.
         * clockHz=0 skips only the physical card-counter wrap check.
         */
        public byte[] exchange(Exchange transport, byte[] command, long clockHz) throws Exception {
            return exchange(transport, command, clockHz, false);
        }

        /** A short case-4 data APDU, with exactly one trailing Le byte. */
        public byte[] exchangeWithLe(Exchange transport, byte[] command, long clockHz) throws Exception {
            return exchange(transport, command, clockHz, true);
        }

        private byte[] exchange(Exchange transport, byte[] command, long clockHz, boolean withLe)
                throws Exception {
            requireRunning();
            try {
                if (transport == null) throw new IllegalArgumentException("An APDU exchange is required.");
                if (clockHz < 0) throw new IllegalArgumentException("Card clock frequency cannot be negative.");
                if (command == null || command.length < 5) {
                    throw new IllegalArgumentException("Expected a short five-byte APDU header.");
                }
                int payload = command.length == 5 ? 0 : command[4] & 0xff;
                if (command.length != 5 + payload + (withLe ? 1 : 0) || (withLe && payload == 0)) {
                    throw new IllegalArgumentException(withLe
                            ? "Data APDU must contain positive short Lc and exactly one trailing Le."
                            : "Data APDU must contain short Lc and no trailing Le.");
                }
                if (!transport.isCpuIsolated()) {
                    markCpuUnavailable("Transport work was not isolated from the protocol thread.");
                }
                long startCpu = sampleCpu();
                long start = clock.wallNs();
                if (start - lastWall < 0) {
                    throw new IllegalStateException("APDU wall clock moved backwards.");
                }
                byte[] response = transport.send(command);
                long end = clock.wallNs();
                long endCpu = sampleCpu();
                long elapsed = end - start;
                if (elapsed < 0) throw new IllegalStateException("APDU wall clock moved backwards.");
                if (startCpu < 0 || endCpu < startCpu || ioWaitCpuNs < 0) {
                    ioWaitCpuNs = -1; // Unavailable diagnostic; raw phase endpoints remain retained.
                } else {
                    ioWaitCpuNs = Math.addExact(ioWaitCpuNs, endCpu - startCpu);
                }
                if (transport.isCpuIsolated()) recordIoThread(transport.ioThreadId());
                if (clockHz > 0) BenchmarkSupport.validateRoundTrip(elapsed, clockHz);
                if (response == null || response.length < 2) {
                    throw new IllegalArgumentException("APDU response must include two status bytes.");
                }
                logicalT2c = Math.addExact(logicalT2c, payload);
                logicalC2t = Math.addExact(logicalC2t, response.length - 2L);
                commandBytes = Math.addExact(commandBytes, command.length);
                responseBytes = Math.addExact(responseBytes, response.length);
                apduCount = Math.addExact(apduCount, 1);
                ioNs = Math.addExact(ioNs, elapsed);
                lastWall = end;
                return response;
            } catch (Exception | Error failure) {
                state = FAILED;
                throw failure;
            }
        }

        public StageResult finish() {
            requireRunning();
            try {
                long cpuEnd = sampleCpu();
                long wallEnd = clock.wallNs();
                long wall = wallEnd - wallStart;
                if (wallEnd - lastWall < 0 || wall < ioNs) {
                    throw new IllegalStateException("Invalid phase wall-clock accounting.");
                }
                long cpu = 0;
                if (cpuStart >= 0 && cpuEnd >= cpuStart) cpu = cpuEnd - cpuStart;
                if (cpuStart < 0 || cpuEnd < cpuStart) {
                    markCpuUnavailable("Thread CPU clock is unavailable or moved backwards.");
                } else if (cpu == 0) {
                    markCpuUnavailable("Thread CPU clock did not advance during the phase.");
                } else if (cpu > wall) {
                    markCpuUnavailable("Thread CPU increment exceeds the enclosing phase wall interval.");
                }
                // cpu=0 with invalid endpoints is an unavailable-only compatibility value,
                // never a valid zero measurement. Consumers must honor cpuTimingAvailable.
                StageResult result = new StageResult(logicalT2c, logicalC2t, commandBytes,
                        responseBytes, apduCount, wall, cpu, ioNs, 0, false,
                        cpuTimingError == null, cpuTimingError, cpuStart, cpuEnd,
                        ioWaitCpuNs, protocolThreadId, ioThreadId);
                state = FINISHED;
                return result;
            } catch (RuntimeException | Error failure) {
                state = FAILED;
                throw failure;
            }
        }

        private long sampleCpu() {
            if (Thread.currentThread().getId() != protocolThreadId) {
                markCpuUnavailable("Protocol execution changed threads during the phase.");
            }
            long value;
            try {
                value = clock.cpuNs();
            } catch (RuntimeException | LinkageError failure) {
                markCpuUnavailable("Thread CPU clock read failed: " + failure.getClass().getSimpleName());
                return -1;
            }
            if (value < 0) markCpuUnavailable("Thread CPU clock is unavailable.");
            else if (lastCpu >= 0 && value < lastCpu) {
                markCpuUnavailable("Thread CPU clock moved backwards during the phase.");
            }
            lastCpu = value;
            return value;
        }

        private void recordIoThread(long id) {
            if (id <= 0 || id == protocolThreadId) {
                markCpuUnavailable("Transport worker identity does not establish CPU isolation.");
            } else if (ioThreadId > 0 && ioThreadId != id) {
                markCpuUnavailable("Transport worker changed during the phase.");
            } else {
                ioThreadId = id;
            }
        }

        private void markCpuUnavailable(String reason) {
            if (cpuTimingError == null && reason != null && !reason.isEmpty()) cpuTimingError = reason;
        }

        private void requireRunning() {
            if (state != RUNNING) {
                throw new IllegalStateException("Measurement phase is not running or has failed.");
            }
        }
    }

    /** Immutable result. An unavailable card measurement must be shown as unavailable in the UI. */
    public static final class StageResult {
        public final long logicalT2c;
        public final long logicalC2t;
        public final long commandBytes;
        public final long responseBytes;
        public final long apduCount;
        public final long wallNs;
        public final long cpuNs;
        public final long ioNs;
        public final long cardCycles;
        public final boolean cardTimingAvailable;
        public final boolean cpuTimingAvailable;
        public final String cpuTimingError;
        /** Raw cumulative clock endpoints. For totals these span gaps between phases. */
        public final long phaseCpuStartNs;
        public final long phaseCpuEndNs;
        /** Caller CPU observed around APDU waits; diagnostic only, never subtracted. */
        public final long ioWaitCpuNs;
        public final long protocolThreadId;
        public final long ioThreadId;

        private StageResult(long logicalT2c, long logicalC2t, long commandBytes,
                            long responseBytes, long apduCount, long wallNs, long cpuNs,
                            long ioNs, long cardCycles, boolean cardTimingAvailable,
                            boolean cpuTimingAvailable, String cpuTimingError,
                            long phaseCpuStartNs, long phaseCpuEndNs, long ioWaitCpuNs,
                            long protocolThreadId, long ioThreadId) {
            this.logicalT2c = logicalT2c;
            this.logicalC2t = logicalC2t;
            this.commandBytes = commandBytes;
            this.responseBytes = responseBytes;
            this.apduCount = apduCount;
            this.wallNs = wallNs;
            this.cpuNs = cpuNs;
            this.ioNs = ioNs;
            this.cardCycles = cardCycles;
            this.cardTimingAvailable = cardTimingAvailable;
            this.cpuTimingAvailable = cpuTimingAvailable;
            this.cpuTimingError = cpuTimingError;
            this.phaseCpuStartNs = phaseCpuStartNs;
            this.phaseCpuEndNs = phaseCpuEndNs;
            this.ioWaitCpuNs = ioWaitCpuNs;
            this.protocolThreadId = protocolThreadId;
            this.ioThreadId = ioThreadId;
        }

        public StageResult withCardCycles(long cycles) {
            if (cycles < 0) throw new IllegalArgumentException("Card cycles cannot be negative.");
            return new StageResult(logicalT2c, logicalC2t, commandBytes, responseBytes,
                    apduCount, wallNs, cpuNs, ioNs, cycles, true,
                    cpuTimingAvailable, cpuTimingError, phaseCpuStartNs, phaseCpuEndNs,
                    ioWaitCpuNs, protocolThreadId, ioThreadId);
        }

        public StageResult withoutCardTiming() {
            return new StageResult(logicalT2c, logicalC2t, commandBytes, responseBytes,
                    apduCount, wallNs, cpuNs, ioNs, 0, false,
                    cpuTimingAvailable, cpuTimingError, phaseCpuStartNs, phaseCpuEndNs,
                    ioWaitCpuNs, protocolThreadId, ioThreadId);
        }

        /**
         * Eleven raw numeric columns. Consumers must omit column 6 from presented
         * measurements when cpuTimingAvailable is false; raw diagnostics are retained.
         */
        public long[] values(long clockHz) {
            if (clockHz < 0 || (cardTimingAvailable && clockHz == 0)) {
                throw new IllegalArgumentException("A positive frequency is required for available card timing.");
            }
            return new long[]{logicalT2c, logicalC2t, commandBytes, responseBytes, apduCount,
                    wallNs - ioNs, cpuNs, ioNs, wallNs, cardCycles,
                    cardTimingAvailable ? cyclesToNs(cardCycles, clockHz) : 0};
        }
    }

    /** Sum finished phases; partial card timing is never presented as a complete total. */
    public static StageResult total(StageResult... results) {
        if (results == null || results.length == 0) {
            throw new IllegalArgumentException("At least one finished phase is required.");
        }
        boolean cardAvailable = true;
        boolean cpuAvailable = true;
        String cpuError = null;
        long protocolThreadId = -1;
        long ioThreadId = -1;
        long ioWaitCpuNs = 0;
        for (StageResult result : results) {
            if (result == null) throw new IllegalArgumentException("All phases must have finished results.");
            cardAvailable &= result.cardTimingAvailable;
            if (!result.cpuTimingAvailable) {
                cpuAvailable = false;
                if (cpuError == null) cpuError = result.cpuTimingError;
            }
            if (protocolThreadId < 0) protocolThreadId = result.protocolThreadId;
            else if (protocolThreadId != result.protocolThreadId) {
                cpuAvailable = false;
                if (cpuError == null) cpuError = "Protocol thread differs between phases.";
            }
            if (result.ioThreadId > 0) {
                if (ioThreadId < 0) ioThreadId = result.ioThreadId;
                else if (ioThreadId != result.ioThreadId) {
                    cpuAvailable = false;
                    if (cpuError == null) cpuError = "Transport worker differs between phases.";
                }
            }
            ioWaitCpuNs = ioWaitCpuNs < 0 || result.ioWaitCpuNs < 0
                    ? -1 : Math.addExact(ioWaitCpuNs, result.ioWaitCpuNs);
        }
        long logicalT2c = 0, logicalC2t = 0, commandBytes = 0, responseBytes = 0;
        long apduCount = 0, wallNs = 0, cpuNs = 0, ioNs = 0, cardCycles = 0;
        for (StageResult result : results) {
            logicalT2c = Math.addExact(logicalT2c, result.logicalT2c);
            logicalC2t = Math.addExact(logicalC2t, result.logicalC2t);
            commandBytes = Math.addExact(commandBytes, result.commandBytes);
            responseBytes = Math.addExact(responseBytes, result.responseBytes);
            apduCount = Math.addExact(apduCount, result.apduCount);
            wallNs = Math.addExact(wallNs, result.wallNs);
            cpuNs = Math.addExact(cpuNs, result.cpuNs);
            ioNs = Math.addExact(ioNs, result.ioNs);
            if (cardAvailable) cardCycles = Math.addExact(cardCycles, result.cardCycles);
        }
        return new StageResult(logicalT2c, logicalC2t, commandBytes, responseBytes,
                apduCount, wallNs, cpuNs, ioNs, cardCycles, cardAvailable,
                cpuAvailable, cpuError, results[0].phaseCpuStartNs,
                results[results.length - 1].phaseCpuEndNs, ioWaitCpuNs, protocolThreadId, ioThreadId);
    }

    private static long cyclesToNs(long cycles, long clockHz) {
        // Exact integer rounding avoids overflow and floating-point loss for large totals.
        BigInteger divisor = BigInteger.valueOf(clockHz);
        BigInteger[] parts = BigInteger.valueOf(cycles).multiply(BigInteger.valueOf(1_000_000_000L))
                .divideAndRemainder(divisor);
        if (parts[1].shiftLeft(1).compareTo(divisor) >= 0) parts[0] = parts[0].add(BigInteger.ONE);
        if (parts[0].bitLength() > 63) throw new ArithmeticException("Card time exceeds signed 64-bit nanoseconds.");
        return parts[0].longValue();
    }
}
