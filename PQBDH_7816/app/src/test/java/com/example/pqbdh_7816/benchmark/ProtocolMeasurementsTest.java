package com.example.pqbdh_7816.benchmark;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Stage;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.io.IOException;
import org.junit.Test;

public class ProtocolMeasurementsTest {
    private static final byte[] COMMAND = {(byte) 0x80, (byte) 0xCA, 0, 0, 3, 1, 2, 3};
    private static final byte[] RESPONSE = {7, 8, (byte) 0x90, 0};

    private static final class FakeClock implements ProtocolMeasurements.Clock {
        long wall = 1_000;
        long cpu = 100;

        @Override public long wallNs() { return wall; }
        @Override public long cpuNs() { return cpu; }

        void advance(long wall, long cpu) {
            this.wall += wall;
            this.cpu += cpu;
        }
    }

    /**
     * Clock reads consume real thread CPU and wall time. Values are sampled
     * before that read's cost; the separate costs make boundary bias visible.
     * This fixture validates arithmetic, not Android performance.
     */
    private static final class CostlyClock implements ProtocolMeasurements.Clock {
        static final long WALL_READ_COST = 2;
        static final long CPU_READ_COST = 3;
        long wall;
        long cpu;

        @Override public long wallNs() {
            long sampled = wall;
            advance(WALL_READ_COST, WALL_READ_COST);
            return sampled;
        }

        @Override public long cpuNs() {
            long sampled = cpu;
            advance(CPU_READ_COST, CPU_READ_COST);
            return sampled;
        }

        void advance(long wall, long cpu) {
            this.wall += wall;
            this.cpu += cpu;
        }
    }

    private static StageResult measuredWithClockCosts(long outsideWall, long outsideCpu,
                                                      long exchangeCpu, boolean withLe) throws Exception {
        CostlyClock clock = new CostlyClock();
        Stage stage = new Stage();
        stage.start(clock);
        clock.advance(outsideWall, outsideCpu);
        for (int i = 0; i < 42; i++) {
            ProtocolMeasurements.Exchange transport = isolated(command -> {
                clock.advance(200, exchangeCpu);
                return RESPONSE;
            });
            if (withLe) stage.exchangeWithLe(transport, verifyPinCommandWithLe(), 0);
            else stage.exchange(transport, COMMAND, 0);
        }
        return stage.finish();
    }

    /** A contract fixture, not an actual second thread. Real dispatch has separate tests. */
    private static ProtocolMeasurements.Exchange isolated(ProtocolMeasurements.Exchange callback) {
        final long workerId = Thread.currentThread().getId() + 1;
        return new ProtocolMeasurements.Exchange() {
            @Override public byte[] send(byte[] command) throws Exception { return callback.send(command); }
            @Override public boolean isCpuIsolated() { return true; }
            @Override public long ioThreadId() { return workerId; }
        };
    }

    @Test
    public void directCpuRetainsSamplerCostAndDoesNotSubtractCallerWaitCpu() throws Exception {
        StageResult noWork = measuredWithClockCosts(0, 0, 0, false);
        assertEquals(423, noWork.cpuNs);
        assertEquals(noWork.phaseCpuEndNs - noWork.phaseCpuStartNs, noWork.cpuNs);
        assertEquals(344, noWork.wallNs - noWork.ioNs);
        assertEquals(42 * (200 + CostlyClock.WALL_READ_COST), noWork.ioNs);
        assertEquals(42, noWork.apduCount);
        assertTrue(noWork.cpuTimingAvailable);
        // Protocol-thread wake/sampling cost can fall inside the wall-timed wait.
        assertTrue(noWork.cpuNs > noWork.wallNs - noWork.ioNs);
        assertEquals("terminal-isolated-io-cpu-v3", ProtocolMeasurements.METHOD);
    }

    @Test
    public void directCpuIncludesProtocolThreadWaitCostButPreservesAllWallAndByteAccounting() throws Exception {
        StageResult lightIo = measuredWithClockCosts(50, 20, 13, false);
        StageResult heavyIo = measuredWithClockCosts(50, 20, 101, false);
        StageResult caseFourIo = measuredWithClockCosts(50, 20, 101, true);
        assertEquals(20 + 423 + 42 * 13, lightIo.cpuNs);
        assertEquals(20 + 423 + 42 * 101, heavyIo.cpuNs);
        assertEquals(heavyIo.cpuNs, caseFourIo.cpuNs);
        for (StageResult result : new StageResult[]{lightIo, heavyIo, caseFourIo}) {
            assertTrue(result.cpuTimingAvailable);
            assertEquals(50 + 344, result.wallNs - result.ioNs);
            assertEquals(42 * (200 + CostlyClock.WALL_READ_COST), result.ioNs);
        }
        assertEquals(42 * 3, lightIo.logicalT2c);
        assertEquals(42 * 8, lightIo.commandBytes);
        assertEquals(42 * 34, caseFourIo.logicalT2c);
        assertEquals(42 * 40, caseFourIo.commandBytes);
    }

    @Test
    public void delayedCallerCpuCreditInsideWaitCannotBeSubtractedIntoAFalseZero() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(isolated(command -> {
            clock.advance(200, 13);
            return RESPONSE;
        }), COMMAND, 0);
        StageResult result = stage.finish();
        assertTrue(result.cpuTimingAvailable);
        assertEquals(13, result.cpuNs);
        assertEquals(13, result.ioWaitCpuNs);
        assertEquals(0, result.wallNs - result.ioNs);
        assertEquals(Thread.currentThread().getId(), result.protocolThreadId);
        assertTrue(result.ioThreadId != result.protocolThreadId);
    }

    private static StageResult measuredPhase() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        clock.advance(20, 8);
        byte[] response = stage.exchange(isolated(command -> {
            assertSame(COMMAND, command);
            clock.advance(200, 13);
            return RESPONSE;
        }), COMMAND, 105_000_000);
        assertSame(RESPONSE, response);
        clock.advance(30, 12);
        return stage.finish();
    }

    @Test
    public void excludesExchangeWallButObservesDirectProtocolThreadCpuWhileCountingExactBuffers() throws Exception {
        StageResult result = measuredPhase();
        assertArrayEquals(new long[]{3, 2, 8, 4, 1, 50, 33, 200, 250, 0, 0}, result.values(0));
        assertFalse(result.cardTimingAvailable);
    }

    @Test
    public void countsFiveByteRequestsAsNoPayloadAndExcludesAllStatusBytes() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(command -> new byte[]{1, 2, 0x61, 0},
                new byte[]{(byte) 0x80, (byte) 0xCA, 1, 0, 0}, 0);
        stage.exchange(command -> new byte[]{(byte) 0x90, 0},
                new byte[]{(byte) 0x80, (byte) 0xB2, 1, 0, 0}, 0);
        StageResult result = stage.finish();
        assertArrayEquals(new long[]{0, 2, 10, 6, 2, 0, 0, 0, 0, 0, 0}, result.values(0));
    }

    private static byte[] verifyPinCommandWithLe() {
        byte[] command = new byte[40];
        command[0] = (byte) 0x80;
        command[1] = 0x20;
        command[4] = 34;
        return command;
    }

    @Test
    public void explicitTrailingLeCountsVerifyPinPayloadAndRawCommandWithDirectCpu() throws Exception {
        byte[] command = verifyPinCommandWithLe();
        byte[] response = {(byte) 0x90, 0};
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        clock.advance(20, 8);
        assertSame(response, stage.exchangeWithLe(apdu -> {
            assertSame(command, apdu);
            clock.advance(200, 13);
            return response;
        }, command, 105_000_000));
        clock.advance(30, 12);
        assertArrayEquals(new long[]{34, 0, 40, 2, 1, 50, 33, 200, 250, 0, 0},
                stage.finish().values(0));
    }

    @Test
    public void trailingLeMustBeExplicitAndCannotRelaxTheOriginalExchange() {
        Stage stage = new Stage();
        stage.start(new FakeClock());
        assertThrows(IllegalArgumentException.class, () -> stage.exchange(apdu -> {
            throw new AssertionError("Case-4 command requires the explicit trailing-Le method");
        }, verifyPinCommandWithLe(), 0));
        assertThrows(IllegalStateException.class, stage::finish);
    }

    @Test
    public void malformedTrailingLeCommandsFailBeforeSendingAndInvalidateThePhase() {
        byte[][] invalid = {null, new byte[4],
                {(byte) 0x80, 0x20, 0, 0, 0},
                {(byte) 0x80, 0x20, 0, 0, 0, 0},
                {(byte) 0x80, 0x20, 0, 0, 1, 7},
                {(byte) 0x80, 0x20, 0, 0, 1, 7, 0, 0}};
        for (byte[] command : invalid) {
            Stage stage = new Stage();
            stage.start(new FakeClock());
            assertThrows(IllegalArgumentException.class, () -> stage.exchangeWithLe(apdu -> {
                throw new AssertionError("Malformed command must not reach the reader");
            }, command, 0));
            assertThrows(IllegalStateException.class, stage::finish);
            assertThrows(IllegalStateException.class,
                    () -> stage.exchangeWithLe(apdu -> RESPONSE, verifyPinCommandWithLe(), 0));
        }
    }

    @Test
    public void cardTimingIsExplicitImmutableAndRequiresItsActualFrequency() throws Exception {
        StageResult original = measuredPhase();
        StageResult measured = original.withCardCycles(105_000);
        assertFalse(original.cardTimingAvailable);
        assertEquals(0, original.cardCycles);
        assertTrue(measured.cardTimingAvailable);
        assertEquals(105_000, measured.values(105_000_000)[9]);
        assertEquals(1_000_000, measured.values(105_000_000)[10]);
        assertThrows(IllegalArgumentException.class, () -> measured.values(0));
        assertThrows(IllegalArgumentException.class, () -> measured.withCardCycles(-1));
        assertFalse(measured.withoutCardTiming().cardTimingAvailable);
        assertEquals(0, measured.withoutCardTiming().cardCycles);
    }

    @Test
    public void preservesExactCycleConversionAtRoundingAndOverflowBoundaries() throws Exception {
        StageResult result = measuredPhase();
        assertEquals(3, result.withCardCycles(1).values(400_000_000)[10]);
        assertEquals(Long.MAX_VALUE, result.withCardCycles(Long.MAX_VALUE).values(1_000_000_000)[10]);
        assertThrows(ArithmeticException.class, () -> result.withCardCycles(Long.MAX_VALUE).values(1));
    }

    @Test
    public void totalsIncludeEveryPhaseAndRoundCardTimeOnce() throws Exception {
        StageResult result = measuredPhase();
        StageResult total = ProtocolMeasurements.total(result.withCardCycles(105_000),
                result.withCardCycles(210_000), result.withCardCycles(315_000));
        assertTrue(total.cardTimingAvailable);
        assertArrayEquals(new long[]{9, 6, 24, 12, 3, 150, 99, 600, 750, 630_000, 6_000_000},
                total.values(105_000_000));
        StageResult oneCycle = result.withCardCycles(1);
        assertEquals(8, ProtocolMeasurements.total(oneCycle, oneCycle, oneCycle).values(400_000_000)[10]);
    }

    @Test
    public void missingOneCardPhaseCannotProduceAnApparentlyCompleteCardTotal() throws Exception {
        StageResult result = measuredPhase();
        StageResult total = ProtocolMeasurements.total(result.withCardCycles(100), result);
        assertFalse(total.cardTimingAvailable);
        assertEquals(0, total.cardCycles);
        assertEquals(0, total.values(0)[10]);
        assertEquals(2, total.apduCount);
    }

    @Test
    public void totalsRejectMissingPhasesAndArithmeticOverflow() {
        assertThrows(IllegalArgumentException.class, () -> ProtocolMeasurements.total());
        assertThrows(IllegalArgumentException.class, () -> ProtocolMeasurements.total((StageResult[]) null));
        assertThrows(IllegalArgumentException.class, () -> ProtocolMeasurements.total((StageResult) null));
        FakeClock clock = new FakeClock();
        clock.wall = 0;
        Stage stage = new Stage();
        stage.start(clock);
        clock.wall = Long.MAX_VALUE;
        StageResult result = stage.finish();
        assertThrows(ArithmeticException.class, () -> ProtocolMeasurements.total(result, result));
    }

    @Test
    public void malformedApdusFailBeforeSendingAndPermanentlyInvalidatePhase() {
        byte[][] invalid = {null, new byte[4],
                {(byte) 0x80, (byte) 0xCA, 0, 0, 0, 0, 1},
                {(byte) 0x80, (byte) 0xCA, 0, 0, 1, 7, 0},
                {(byte) 0x80, (byte) 0xCA, 0, 0, 3, 7}};
        for (byte[] command : invalid) {
            Stage stage = new Stage();
            stage.start(new FakeClock());
            assertThrows(IllegalArgumentException.class, () -> stage.exchange(apdu -> {
                throw new AssertionError("Malformed command must not reach the reader");
            }, command, 0));
            assertThrows(IllegalStateException.class, stage::finish);
        }
    }

    @Test
    public void missingOrTruncatedResponsesCannotBecomeSuccessfulMeasurements() {
        for (byte[] response : new byte[][]{null, new byte[0], new byte[1]}) {
            Stage stage = new Stage();
            stage.start(new FakeClock());
            assertThrows(IllegalArgumentException.class,
                    () -> stage.exchange(command -> response, COMMAND, 0));
            assertThrows(IllegalStateException.class, stage::finish);
        }
    }

    @Test
    public void transportFailuresCannotBeFinishedOrRetriedAsTheSameSample() {
        Stage stage = new Stage();
        stage.start(new FakeClock());
        assertThrows(IOException.class, () -> stage.exchange(command -> {
            throw new IOException("Reader disconnected");
        }, COMMAND, 0));
        assertThrows(IllegalStateException.class, stage::finish);
        assertThrows(IllegalStateException.class, () -> stage.exchange(command -> RESPONSE, COMMAND, 0));
    }

    @Test
    public void availableCardClockAppliesTheWrapGuardToEveryExchange() {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        assertThrows(IllegalArgumentException.class, () -> stage.exchange(command -> {
            clock.advance(38_654_705_664L, 10);
            return RESPONSE;
        }, COMMAND, 100_000_000));
        assertThrows(IllegalStateException.class, stage::finish);
    }

    @Test
    public void absentCardCounterSkipsOnlyTheHardwareWrapGuard() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(command -> {
            clock.advance(50_000_000_000L, 10);
            return RESPONSE;
        }, COMMAND, 0);
        StageResult result = stage.finish();
        assertEquals(50_000_000_000L, result.ioNs);
        assertFalse(result.cardTimingAvailable);
        assertEquals(0, result.values(0)[10]);
    }

    @Test
    public void backwardsExchangeWallClockAndNegativeFrequencyInvalidateThePhase() {
        FakeClock clock = new FakeClock();
        Stage wallFailure = new Stage();
        wallFailure.start(clock);
        assertThrows(IllegalStateException.class, () -> wallFailure.exchange(command -> {
            clock.advance(-1, 1);
            return RESPONSE;
        }, COMMAND, 0));
        assertThrows(IllegalStateException.class, wallFailure::finish);
        Stage stage = new Stage();
        stage.start(new FakeClock());
        assertThrows(IllegalArgumentException.class, () -> stage.exchange(command -> RESPONSE, COMMAND, -1));
        assertThrows(IllegalStateException.class, stage::finish);
    }

    @Test
    public void backwardsCpuClockInvalidatesOnlyCpuAndRetainsWallAndTraffic() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(isolated(command -> {
            clock.advance(200, -1);
            return RESPONSE;
        }), COMMAND, 0);
        StageResult result = stage.finish();
        assertFalse(result.cpuTimingAvailable);
        assertTrue(result.cpuTimingError.contains("backwards"));
        assertEquals(99, result.phaseCpuEndNs);
        assertEquals(100, result.phaseCpuStartNs);
        assertEquals(-1, result.ioWaitCpuNs);
        assertEquals(200, result.wallNs);
        assertEquals(1, result.apduCount);
    }

    @Test
    public void finishRejectsPhaseClockTotalsSmallerThanAlreadyMeasuredIo() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(command -> {
            clock.advance(200, 50);
            return RESPONSE;
        }, COMMAND, 0);
        clock.advance(-1, -1);
        assertThrows(IllegalStateException.class, stage::finish);
        assertThrows(IllegalStateException.class, stage::finish);
    }

    @Test
    public void backwardsWallBetweenExchangesCannotBeHiddenInsideValidIoDurations() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(command -> {
            clock.advance(20, 10);
            return RESPONSE;
        }, COMMAND, 0);
        clock.advance(-1, 1);
        assertThrows(IllegalStateException.class,
                () -> stage.exchange(command -> RESPONSE, COMMAND, 0));
        assertThrows(IllegalStateException.class, stage::finish);
    }

    @Test
    public void backwardsCpuBetweenExchangesRemainsUnavailableAfterClockRecovers() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(isolated(command -> { clock.advance(20, 10); return RESPONSE; }), COMMAND, 0);
        clock.advance(10, -1);
        stage.exchange(isolated(command -> { clock.advance(20, 10); return RESPONSE; }), COMMAND, 0);
        StageResult result = stage.finish();
        assertFalse(result.cpuTimingAvailable);
        assertEquals(19, result.cpuNs);
        assertEquals(50, result.wallNs);
        assertEquals(2, result.apduCount);
    }

    @Test
    public void lifecycleRequiresOneStartAndFinishButUnavailableCpuDoesNotAbortMeasurement() throws Exception {
        Stage stage = new Stage();
        assertThrows(IllegalStateException.class, stage::finish);
        assertThrows(IllegalStateException.class, () -> stage.exchange(command -> RESPONSE, COMMAND, 0));
        stage.start(new FakeClock());
        assertThrows(IllegalStateException.class, () -> stage.start(new FakeClock()));
        stage.finish();
        assertThrows(IllegalStateException.class, stage::finish);
        assertThrows(IllegalStateException.class, () -> stage.exchange(command -> RESPONSE, COMMAND, 0));
        FakeClock unavailable = new FakeClock();
        unavailable.cpu = -1;
        Stage invalid = new Stage();
        invalid.start(unavailable);
        unavailable.advance(20, 0);
        StageResult result = invalid.finish();
        assertFalse(result.cpuTimingAvailable);
        assertEquals(-1, result.phaseCpuStartNs);
        assertEquals(-1, result.phaseCpuEndNs);
        assertEquals(20, result.wallNs);
    }

    @Test
    public void wallClockMayHaveAnArbitraryNegativeOrigin() throws Exception {
        FakeClock clock = new FakeClock();
        clock.wall = -100;
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(command -> {
            clock.advance(20, 5);
            return RESPONSE;
        }, COMMAND, 0);
        clock.advance(10, 3);
        StageResult result = stage.finish();
        assertEquals(30, result.wallNs);
        assertEquals(8, result.cpuNs);
        assertEquals(10, result.values(0)[5]);
    }

    @Test
    public void frozenCpuClockIsUnavailableInsteadOfAValidZero() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(isolated(command -> { clock.advance(200, 0); return RESPONSE; }), COMMAND, 0);
        StageResult result = stage.finish();
        assertFalse(result.cpuTimingAvailable);
        assertTrue(result.cpuTimingError.contains("did not advance"));
        assertEquals(100, result.phaseCpuStartNs);
        assertEquals(100, result.phaseCpuEndNs);
        assertEquals(0, result.cpuNs);
        assertEquals(200, result.wallNs);
    }

    @Test
    public void cpuIncrementBeyondWholePhaseWallIsUnavailableButNotClamped() {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        clock.advance(10, 20);
        StageResult result = stage.finish();
        assertFalse(result.cpuTimingAvailable);
        assertTrue(result.cpuTimingError.contains("exceeds"));
        assertEquals(20, result.cpuNs);
        assertEquals(10, result.wallNs);
    }

    @Test
    public void nonIsolatedTransportCannotReportValidCpuEvenWhenItsClockAdvances() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(command -> { clock.advance(200, 13); return RESPONSE; }, COMMAND, 0);
        StageResult result = stage.finish();
        assertFalse(result.cpuTimingAvailable);
        assertTrue(result.cpuTimingError.contains("not isolated"));
        assertEquals(13, result.cpuNs);
        assertEquals(200, result.ioNs);
    }

    @Test
    public void preflightClockFailureIsPropagatedWithoutDestroyingOtherMeasurements() {
        Stage stage = new Stage();
        stage.start(new ProtocolMeasurements.Clock() {
            long wall, cpu;
            @Override public long wallNs() { return wall += 20; }
            @Override public long cpuNs() { return ++cpu; }
            @Override public String cpuUnavailableReason() { return "Clock preflight did not advance"; }
        });
        StageResult result = stage.finish();
        assertFalse(result.cpuTimingAvailable);
        assertEquals("Clock preflight did not advance", result.cpuTimingError);
        assertEquals(1, result.cpuNs);
        assertEquals(20, result.wallNs);
    }

    @Test
    public void aFailedCpuReadDoesNotFailCardOrWallMeasurement() {
        Stage stage = new Stage();
        stage.start(new ProtocolMeasurements.Clock() {
            long wall;
            @Override public long wallNs() { return wall += 20; }
            @Override public long cpuNs() { throw new UnsupportedOperationException(); }
        });
        StageResult result = stage.finish().withCardCycles(1);
        assertFalse(result.cpuTimingAvailable);
        assertTrue(result.cpuTimingError.contains("read failed"));
        assertTrue(result.cardTimingAvailable);
        assertEquals(20, result.wallNs);
    }

    @Test
    public void changingProtocolThreadInvalidatesCpuAndRetainsCompletedPhase() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        clock.advance(100, 10);
        final StageResult[] result = new StageResult[1];
        Thread other = new Thread(() -> result[0] = stage.finish());
        other.start();
        other.join(2000);
        assertFalse(other.isAlive());
        assertFalse(result[0].cpuTimingAvailable);
        assertTrue(result[0].cpuTimingError.contains("changed threads"));
        assertEquals(100, result[0].wallNs);
    }

    @Test
    public void unavailableCpuPropagatesThroughTotalsAndCardCopies() throws Exception {
        StageResult valid = measuredPhase();
        assertTrue(valid.cpuTimingAvailable);
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        clock.advance(100, 0);
        StageResult frozen = stage.finish();
        StageResult total = ProtocolMeasurements.total(valid.withCardCycles(1), frozen.withCardCycles(2));
        assertFalse(total.cpuTimingAvailable);
        assertTrue(total.cardTimingAvailable);
        assertEquals(valid.cpuNs, total.cpuNs);
        assertEquals(valid.wallNs + frozen.wallNs, total.wallNs);
        assertEquals(valid.ioWaitCpuNs, total.ioWaitCpuNs);
        assertFalse(frozen.withCardCycles(1).cpuTimingAvailable);
        assertFalse(frozen.withoutCardTiming().cpuTimingAvailable);
    }
}
