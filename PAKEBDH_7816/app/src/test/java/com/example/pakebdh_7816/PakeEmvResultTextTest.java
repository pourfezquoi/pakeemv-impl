package com.example.pakebdh_7816;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.pakebdh_7816.benchmark.BenchmarkSupport.CardTiming;
import com.example.pakebdh_7816.benchmark.BenchmarkSupport.TimerSource;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Exchange;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Stage;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Locale;
import org.junit.Test;

/** Checks presentation and F7 attachment without executing Android, JNI or a card. */
public class PakeEmvResultTextTest {
    private static final long CLOCK_HZ = 105_000_000L;

    private static final class FakeClock implements com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Clock {
        long wall;
        long cpu;

        @Override public long wallNs() { return wall; }
        @Override public long cpuNs() { return cpu; }
    }

    /** Fake isolated transport contract; these fixtures do not execute Android or USB. */
    private static Exchange isolated(Exchange delegate) {
        return new Exchange() {
            @Override public byte[] send(byte[] command) throws Exception { return delegate.send(command); }
            @Override public boolean isCpuIsolated() { return true; }
            @Override public long ioThreadId() { return Long.MAX_VALUE; }
        };
    }

    private static StageResult phase(int requestPayload, int responsePayload) throws Exception {
        return phase(requestPayload, responsePayload, true);
    }

    private static StageResult phase(int requestPayload, int responsePayload, boolean advancingCpu)
            throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        clock.wall += 10_000_000;
        if (advancingCpu) clock.cpu += 5_000_000;
        byte[] command = new byte[5 + requestPayload];
        command[0] = (byte) 0x80;
        command[1] = (byte) 0xC1;
        command[4] = (byte) requestPayload;
        stage.exchange(isolated(apdu -> {
            clock.wall += 100_000_000;
            byte[] response = new byte[responsePayload + 2];
            response[responsePayload] = (byte) 0x90;
            return response;
        }), command, CLOCK_HZ);
        clock.wall += 20_000_000;
        if (advancingCpu) clock.cpu += 15_000_000;
        return stage.finish();
    }

    private static StageResult[] phases() throws Exception {
        return new StageResult[]{phase(3, 2), phase(4, 5), phase(6, 0)};
    }

    private static CardTiming packet(long clockHz, int commands, long pake, long cert, long establish) {
        return packet(1, clockHz, commands, pake, cert, establish);
    }

    private static CardTiming packet(int flags, long clockHz, int commands, long pake, long cert, long establish) {
        return CardTiming.parse(ByteBuffer.allocate(42).order(ByteOrder.BIG_ENDIAN)
                .put(new byte[]{'P', 'E', 'B', '1'}).putInt(flags).putInt((int) clockHz)
                .putInt(commands).putLong(pake).putLong(cert).putLong(establish)
                .put((byte) 0x90).put((byte) 0).array());
    }

    private static CardTiming baseline() {
        return packet(CLOCK_HZ, 0, 0, 0, 0);
    }

    private static CardTiming validSnapshot() {
        return packet(CLOCK_HZ, 3, 1_050_000, 2_100_000, 3_150_000);
    }

    private static PakeEmvSession.Result measuredResult() throws Exception {
        StageResult[] phases = phases();
        StageResult[] measured = PakeEmvSession.attachTiming(baseline(), validSnapshot(),
                phases[0], phases[1], phases[2]);
        return new PakeEmvSession.Result(measured[0], measured[1], measured[2],
                CLOCK_HZ, null, 3444, 3960);
    }

    @Test
    public void uiDisplaysActualProcessingTimesWithoutDoubleCountingCardWait() throws Exception {
        String text = PakeEmvResultText.format(measuredResult());
        assertTrue(text.startsWith("Measurement complete | Session keys match"));
        assertTrue(text.contains("Terminal protocol CPU: 60.000 ms"));
        assertTrue(text.contains("Card processing: 60.000 ms"));
        assertTrue(text.contains("Terminal active wall time: 90.000 ms"));
        assertTrue(text.contains("APDU round-trip total: 300.000 ms"));
        assertTrue(text.contains("Protocol phase wall time: 390.000 ms"));
        assertTrue(text.contains("do not add card processing time again"));
    }

    @Test
    public void frozenCpuClockIsUnavailableWithoutHidingCardWallOrTrafficResults() throws Exception {
        StageResult[] stages = {phase(3, 2, false), phase(4, 5), phase(6, 0)};
        StageResult[] measured = PakeEmvSession.attachTiming(baseline(), validSnapshot(),
                stages[0], stages[1], stages[2]);
        PakeEmvSession.Result result = new PakeEmvSession.Result(measured[0], measured[1], measured[2],
                CLOCK_HZ, null, 3444, 3960);
        String text = PakeEmvResultText.format(result);
        assertTrue(text.startsWith("Protocol complete | Session keys match"));
        assertFalse(text.startsWith("Measurement complete"));
        assertTrue(text.contains("Terminal CPU timing unavailable; other measurements retained."));
        assertTrue(text.contains("Terminal protocol CPU: Unavailable ("));
        assertTrue(text.contains("PAKE\n  Protocol CPU: Unavailable ("));
        assertFalse(text.contains("Protocol CPU: 0.000 ms"));
        assertFalse(text.contains("Terminal protocol CPU: 0.000 ms"));
        assertTrue(text.contains("Certificate authentication\n  Protocol CPU: 20.000 ms"));
        assertTrue(text.contains("Card processing: 60.000 ms"));
        assertTrue(text.contains("Protocol phase wall time: 390.000 ms"));
        assertTrue(text.contains("Application data bidirectional total: 20 B"));
        assertTrue(text.contains("APDU round-trip count: 3"));
        assertTrue(text.contains("USB-worker CPU is excluded"));
    }

    @Test
    public void resolvedSubMicrosecondCpuIsNotRoundedToZeroMilliseconds() {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        clock.wall = 10;
        clock.cpu = 1;
        StageResult tiny = stage.finish();
        PakeEmvSession.Result result = new PakeEmvSession.Result(tiny, tiny, tiny,
                0, "No card timer in fixture", 3444, 3960);
        String text = PakeEmvResultText.format(result);
        assertTrue(text.contains("Terminal protocol CPU: 3 ns"));
        assertTrue(text.contains("Protocol CPU: 1 ns"));
        assertFalse(text.contains("Terminal protocol CPU: 0.000 ms"));
    }

    @Test
    public void uiDisplaysBothTrafficDirectionsAndTheirIndependentGrossTotals() throws Exception {
        String text = PakeEmvResultText.format(measuredResult());
        assertTrue(text.contains("Application data terminal -> card: 13 B"));
        assertTrue(text.contains("Application data card -> terminal: 7 B"));
        assertTrue(text.contains("Application data bidirectional total: 20 B"));
        assertTrue(text.contains("Complete APDUs terminal -> card: 28 B"));
        assertTrue(text.contains("Complete APDUs card -> terminal: 13 B"));
        assertTrue(text.contains("Complete APDU bidirectional total: 41 B"));
        assertTrue(text.contains("APDU round-trip count: 3"));
    }

    @Test
    public void uiShowsAllThreePhasesAndTheActualCardFrequencyAndCycleTotal() throws Exception {
        String text = PakeEmvResultText.format(measuredResult());
        assertTrue(text.contains("PAKE\n  Protocol CPU: 20.000 ms\n  Card processing: 10.000 ms"));
        assertTrue(text.contains("Certificate authentication\n  Protocol CPU: 20.000 ms\n  Card processing: 20.000 ms"));
        assertTrue(text.contains("Key establishment\n  Protocol CPU: 20.000 ms\n  Card processing: 30.000 ms"));
        assertTrue(text.contains("Application data: terminal -> card 3 B, card -> terminal 2 B"));
        assertTrue(text.contains("Application data: terminal -> card 4 B, card -> terminal 5 B"));
        assertTrue(text.contains("Application data: terminal -> card 6 B, card -> terminal 0 B"));
        assertTrue(text.contains("Card clock: 105.000 MHz"));
        assertTrue(text.contains("Card timer source: DWT CYCCNT"));
        assertTrue(text.contains("Card cycle total: 6300000 cycles"));
    }

    @Test
    public void sysTickTimingShowsItsSourceAndUsesTheSameCoreCycleConversion() throws Exception {
        StageResult[] stages = phases();
        CardTiming reset = packet(3, CLOCK_HZ, 0, 0, 0, 0);
        CardTiming snapshot = packet(3, CLOCK_HZ, 3, 1_050_000, 2_100_000, 3_150_000);
        StageResult[] measured = PakeEmvSession.attachTiming(reset, snapshot, stages[0], stages[1], stages[2]);
        PakeEmvSession.Result result = new PakeEmvSession.Result(measured[0], measured[1], measured[2],
                CLOCK_HZ, TimerSource.SYSTICK_IRQ, null, 3444, 3960);
        assertTrue(result.hasCardTiming());
        String text = PakeEmvResultText.format(result);
        assertTrue(text.contains("Card timer source: SysTick IRQ"));
        assertTrue(text.contains("Card processing: 60.000 ms"));
        assertTrue(text.contains("Card cycle total: 6300000 cycles"));
        assertTrue(text.contains("Application data bidirectional total: 20 B"));
        assertTrue(text.contains("Protocol phase wall time: 390.000 ms"));
    }

    @Test
    public void changingTimerSourceInvalidatesTimingWithoutChangingTerminalMeasurements() throws Exception {
        StageResult[] stages = phases();
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PakeEmvSession.attachTiming(baseline(),
                        packet(3, CLOCK_HZ, 3, 1, 1, 1), stages[0], stages[1], stages[2]));
        assertTrue(failure.getMessage().contains("timer source changed"));
        for (StageResult stage : stages) {
            assertFalse(stage.cardTimingAvailable);
            assertEquals(20_000_000L, stage.cpuNs);
            assertEquals(130_000_000L, stage.wallNs);
        }
    }

    @Test
    public void unavailableCardTimingIsNeverRenderedAsZeroAndKeepsTerminalAndTrafficData() throws Exception {
        StageResult[] stages = phases();
        PakeEmvSession.Result result = new PakeEmvSession.Result(stages[0], stages[1], stages[2],
                0, "DWT benchmark firmware is not enabled", 3444, 3960);
        assertFalse(result.hasCardTiming());
        String text = PakeEmvResultText.format(result);
        assertTrue(text.startsWith("Protocol complete | Session keys match\nCard timing unavailable;"));
        assertFalse(text.startsWith("Measurement complete"));
        assertTrue(text.contains("Card processing: Unavailable"));
        assertFalse(text.contains("Card processing: 0.000 ms"));
        assertTrue(text.contains("Card timing unavailable: DWT benchmark firmware is not enabled"));
        assertFalse(text.contains("Card clock: "));
        assertFalse(text.contains("Card cycle total: "));
        assertTrue(text.contains("Terminal protocol CPU: 60.000 ms"));
        assertTrue(text.contains("Protocol phase wall time: 390.000 ms"));
        assertTrue(text.contains("Application data bidirectional total: 20 B"));
        assertTrue(text.contains("Complete APDU bidirectional total: 41 B"));
    }

    @Test
    public void uiUsesStableDecimalPrecisionUnderACommaDecimalLocale() throws Exception {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.GERMANY);
            String text = PakeEmvResultText.format(measuredResult());
            assertTrue(text.contains("Terminal protocol CPU: 60.000 ms"));
            assertTrue(text.contains("Card clock: 105.000 MHz"));
            assertFalse(text.contains("60,000 ms"));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    public void validTimingAttachmentPreservesEveryOriginalTerminalMeasurement() throws Exception {
        StageResult[] stages = phases();
        StageResult[] measured = PakeEmvSession.attachTiming(baseline(), validSnapshot(),
                stages[0], stages[1], stages[2]);
        assertEquals(3, measured.length);
        long[] expectedCycles = {1_050_000, 2_100_000, 3_150_000};
        for (int i = 0; i < stages.length; i++) {
            assertFalse(stages[i].cardTimingAvailable);
            assertEquals(0, stages[i].cardCycles);
            assertTrue(measured[i].cardTimingAvailable);
            assertEquals(expectedCycles[i], measured[i].cardCycles);
            long[] expected = stages[i].values(0);
            expected[9] = expectedCycles[i];
            expected[10] = (i + 1) * 10_000_000L;
            assertArrayEquals(expected, measured[i].values(CLOCK_HZ));
        }
    }

    @Test
    public void snapshotsWithWrongFrequencyOrMissingAndStaleCountsAreRejected() throws Exception {
        StageResult[] stages = phases();
        assertThrows(IllegalStateException.class, () -> PakeEmvSession.attachTiming(baseline(),
                packet(120_000_000, 3, 1, 1, 1), stages[0], stages[1], stages[2]));
        for (int commands : new int[]{0, 2, 4}) {
            assertThrows(IllegalStateException.class, () -> PakeEmvSession.attachTiming(baseline(),
                    packet(CLOCK_HZ, commands, 1, 1, 1), stages[0], stages[1], stages[2]));
        }
        for (StageResult original : stages) assertFalse(original.cardTimingAvailable);
    }

    @Test
    public void everyProtocolPhaseMustHavePositiveMeasuredCardCycles() throws Exception {
        StageResult[] stages = phases();
        for (int missing = 0; missing < 3; missing++) {
            long[] cycles = {1, 1, 1};
            cycles[missing] = 0;
            assertThrows(IllegalStateException.class, () -> PakeEmvSession.attachTiming(baseline(),
                    packet(CLOCK_HZ, 3, cycles[0], cycles[1], cycles[2]),
                    stages[0], stages[1], stages[2]));
        }
        for (StageResult original : stages) assertEquals(0, original.cardCycles);
    }

    @Test
    public void cardTimeCannotExceedTheRoundTripContainingItsHandler() throws Exception {
        StageResult[] stages = phases();
        // 10,500,001 cycles at 105 MHz is just over the measured 100 ms I/O interval.
        assertThrows(IllegalStateException.class, () -> PakeEmvSession.attachTiming(baseline(),
                packet(CLOCK_HZ, 3, 1, 1, 10_500_001), stages[0], stages[1], stages[2]));
        // Failure in the last phase must not leak partially attached state into the inputs.
        for (StageResult original : stages) {
            assertFalse(original.cardTimingAvailable);
            assertEquals(0, original.cardCycles);
        }
        StageResult[] retry = PakeEmvSession.attachTiming(baseline(), validSnapshot(),
                stages[0], stages[1], stages[2]);
        for (StageResult measured : retry) assertTrue(measured.cardTimingAvailable);
    }

    @Test
    public void cardTimeEqualToTheMeasuredIoBoundaryIsAccepted() throws Exception {
        StageResult[] stages = phases();
        StageResult[] measured = PakeEmvSession.attachTiming(baseline(),
                packet(CLOCK_HZ, 3, 10_500_000, 10_500_000, 10_500_000),
                stages[0], stages[1], stages[2]);
        for (StageResult result : measured) assertEquals(result.ioNs, result.values(CLOCK_HZ)[10]);
    }
}
