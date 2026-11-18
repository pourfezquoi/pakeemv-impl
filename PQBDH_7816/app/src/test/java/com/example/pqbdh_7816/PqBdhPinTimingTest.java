package com.example.pqbdh_7816;

import static org.junit.Assert.*;

import com.example.pqbdh_7816.benchmark.BenchmarkSupport.TimerSource;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Stage;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

/** PIN timing is an explicit extra phase, with no simulated timing reported as hardware data. */
public class PqBdhPinTimingTest {
    private static final long CLOCK = 105_000_000L;
    private static final byte[] KEY = new byte[32];

    private static final class FakeClock implements ProtocolMeasurements.Clock {
        long wall, cpu;
        @Override public long wallNs() { return wall; }
        @Override public long cpuNs() { return cpu; }
    }

    private static byte[] packet(int flags, long clock, int count, long cycles) {
        return ByteBuffer.allocate(26).order(ByteOrder.BIG_ENDIAN)
                .put(new byte[]{'P', 'Q', 'P', '1'}).putInt(flags).putInt((int) clock)
                .putInt(count).putLong(cycles).put((byte) 0x90).put((byte) 0).array();
    }

    private static PqBdhSession.Result core(boolean measured) throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchange(command -> {
            clock.wall += 10_000_000;
            clock.cpu += 1_000_000;
            return new byte[]{(byte) 0x90, 0};
        }, new byte[]{(byte) 0x80, (byte) 0xCA, 0, 0, 0}, measured ? CLOCK : 0);
        StageResult phase = stage.finish();
        if (measured) phase = phase.withCardCycles(105_000);
        return new PqBdhSession.Result(phase, phase, phase, measured ? CLOCK : 0,
                measured ? TimerSource.SYSTICK_IRQ : null, measured ? null : "Counter unavailable", 3444, 3960);
    }

    @Test
    public void successfulPinAddsOneCaseFourExchangeWithoutChangingCoreTotals() throws Exception {
        PqBdhSession.Result core = core(true);
        FakeClock clock = new FakeClock();
        List<Integer> instructions = new ArrayList<>();
        PqBdhSession.Result authenticated = PqBdhSession.verifyOfflinePin(command -> {
            instructions.add(command[1] & 255);
            if ((command[1] & 255) == 0xF7) {
                assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xF7, 4, 0, 0}, command);
                clock.wall += 99_000_000; // Excluded diagnostic round trip.
                return packet(3, CLOCK, 1, 105_000);
            }
            assertEquals(40, command.length);
            assertEquals(34, command[4] & 255);
            assertEquals(0, command[39]);
            byte[] encrypted = Arrays.copyOfRange(command, 5, 39);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"),
                    new GCMParameterSpec(128, Arrays.copyOf(encrypted, 12)));
            assertArrayEquals(new byte[]{'1', '2', '3', '4', '5', '6'},
                    cipher.doFinal(Arrays.copyOfRange(encrypted, 12, encrypted.length)));
            clock.wall += 10_000_000;
            clock.cpu += 1_000_000;
            return new byte[]{(byte) 0x90, 0};
        }, clock, core, true, true, KEY, () -> {
            clock.wall += 9_000_000_000L; // Human input is excluded.
            return "123456";
        }, ignored -> { });
        assertEquals(Arrays.asList(0x20, 0xF7), instructions);
        assertEquals(34, authenticated.pin.logicalT2c);
        assertEquals(0, authenticated.pin.logicalC2t);
        assertEquals(40, authenticated.pin.commandBytes);
        assertEquals(2, authenticated.pin.responseBytes);
        assertEquals(10_000_000, authenticated.pin.wallNs);
        assertEquals(10_000_000, authenticated.pin.ioNs);
        assertEquals(1_000_000, authenticated.pin.cpuNs);
        assertFalse(authenticated.pin.cpuTimingAvailable); // Fixture transport has no isolated I/O worker.
        assertEquals(105_000, authenticated.pin.cardCycles);
        assertEquals(core.total().apduCount, authenticated.total().apduCount);
        assertEquals(core.total().apduCount + 1, authenticated.authenticatedTotal().apduCount);
        assertEquals(core.total().commandBytes + 40, authenticated.authenticatedTotal().commandBytes);
        String report = PqBdhResultText.format(authenticated);
        assertTrue(report.contains("CORE TIMING"));
        assertTrue(report.startsWith("Protocol complete | PIN verified | Session keys match"));
        assertTrue(report.contains("Terminal protocol CPU: Unavailable ("));
        assertTrue(report.contains("Authenticated session total (three-phase core + PIN)"));
    }

    @Test
    public void wrongPinNeverProducesAnAuthenticatedResultOrQueriesThePinCounter() throws Exception {
        PqBdhSession.Result core = core(true);
        FakeClock clock = new FakeClock();
        List<Integer> instructions = new ArrayList<>();
        Exception error = assertThrows(IllegalStateException.class, () -> PqBdhSession.verifyOfflinePin(command -> {
            instructions.add(command[1] & 255);
            clock.wall += 10_000_000;
            return new byte[]{0x63, (byte) 0xC2};
        }, clock, core, true, true, KEY, () -> "123456", ignored -> { }));
        assertTrue(error.getMessage().contains("PIN verification failed; retries remaining: 2"));
        assertEquals(Arrays.asList(0x20), instructions);
        assertNull(core.pin);
    }

    @Test
    public void strictPinMeasurementRequiresAdvertisedVerifiedCoreTimingBeforePrompting() throws Exception {
        for (boolean advertised : new boolean[]{false, true}) {
            PqBdhSession.Result core = core(false);
            assertThrows(PqBdhSession.CardTimingUnavailableException.class,
                    () -> PqBdhSession.verifyOfflinePin(command -> { throw new AssertionError("Unexpected APDU"); },
                            new FakeClock(), core, advertised, true, KEY,
                            () -> { throw new AssertionError("Unexpected PIN prompt"); }, ignored -> { }));
        }
    }

    @Test
    public void optionalPinKeepsTerminalResultsWhenNoCardTimerIsAvailable() throws Exception {
        FakeClock clock = new FakeClock();
        PqBdhSession.Result result = PqBdhSession.verifyOfflinePin(command -> {
            assertEquals(0x20, command[1] & 255);
            clock.wall += 1_000_000;
            return new byte[]{(byte) 0x90, 0};
        }, clock, core(false), false, false, KEY, () -> "123456", ignored -> { });
        assertNotNull(result.pin);
        assertFalse(result.pin.cardTimingAvailable);
        assertFalse(result.authenticatedTotal().cardTimingAvailable);
        assertTrue(PqBdhResultText.format(result).contains("PIN card timing unavailable"));
    }

    @Test
    public void pinSnapshotRejectsSourceClockCountZeroCyclesAndImpossibleTiming() throws Exception {
        FakeClock clock = new FakeClock();
        Stage stage = new Stage();
        stage.start(clock);
        stage.exchangeWithLe(command -> {
            clock.wall += 10_000_000;
            return new byte[]{(byte) 0x90, 0};
        }, com.example.pqbdh_7816.apdu.ApduCodec.buildCommandApdu(0x80, 0x20, 0, 0, new byte[34]), CLOCK);
        StageResult pin = stage.finish();
        for (byte[] invalid : new byte[][]{packet(1, CLOCK, 1, 1), packet(3, CLOCK + 1, 1, 1),
                packet(3, CLOCK, 0, 1), packet(3, CLOCK, 2, 1), packet(3, CLOCK, 1, 0),
                packet(3, CLOCK, 1, 2_100_000)}) {
            assertThrows(IllegalArgumentException.class,
                    () -> PqBdhPinTiming.parse(invalid).attach(pin, CLOCK, TimerSource.SYSTICK_IRQ));
        }
    }

    @Test
    public void pinSnapshotRejectsTruncationBadStatusMagicFlagsAndUnsignedOverflow() {
        byte[] wrongMagic = packet(3, CLOCK, 1, 1); wrongMagic[1] = 'E';
        byte[] wrongStatus = packet(3, CLOCK, 1, 1); wrongStatus[24] = 0x6D;
        for (byte[] invalid : new byte[][]{null, new byte[25], new byte[27], wrongMagic, wrongStatus,
                packet(0, CLOCK, 1, 1), packet(7, CLOCK, 1, 1), packet(3, 0, 1, 1), packet(3, CLOCK, 1, -1)}) {
            assertThrows(IllegalArgumentException.class, () -> PqBdhPinTiming.parse(invalid));
        }
    }

    @Test
    public void pinQueryTransportFailureIsFatalEvenInOptionalTimingMode() throws Exception {
        FakeClock clock = new FakeClock();
        PqBdhSession.Result core = core(true);
        IOException failure = new IOException("Reader disconnected");
        assertSame(failure, assertThrows(IOException.class, () -> PqBdhSession.verifyOfflinePin(command -> {
            if ((command[1] & 255) == 0xF7) throw failure;
            clock.wall += 10_000_000;
            return new byte[]{(byte) 0x90, 0};
        }, clock, core, true, false, KEY, () -> "123456", ignored -> { })));
    }
}
