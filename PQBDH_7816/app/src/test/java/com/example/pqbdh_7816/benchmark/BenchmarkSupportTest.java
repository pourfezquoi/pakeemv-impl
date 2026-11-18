package com.example.pqbdh_7816.benchmark;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Test;

public class BenchmarkSupportTest {
    private static byte[] timingResponse() {
        return ByteBuffer.allocate(42).order(ByteOrder.BIG_ENDIAN)
                .put(new byte[]{'P', 'E', 'B', '1'})
                .putInt(1).putInt(105_000_000).putInt(0xfedcba98)
                .putLong(0x0000000102030405L)
                .putLong(0x0000010203040506L)
                .putLong(0x0010203040506070L)
                .put((byte) 0x90).put((byte) 0).array();
    }

    @Test
    public void parsesUnsignedBigEndianFieldsAndWideCycleCounts() {
        BenchmarkSupport.CardTiming timing = BenchmarkSupport.CardTiming.parse(timingResponse());
        assertEquals(105_000_000L, timing.clockHz);
        assertEquals(0xfedcba98L, timing.commandCount);
        assertEquals(0x0000000102030405L, timing.negotiateKemCycles);
        assertEquals(0x0000010203040506L, timing.certCycles);
        assertEquals(0x0010203040506070L, timing.establishCycles);
    }

    @Test
    public void permitsZeroCountersAndMaximumSupportedUnsignedFields() {
        byte[] response = timingResponse();
        ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN)
                .putInt(8, -1).putInt(12, -1)
                .putLong(16, 0).putLong(24, 0).putLong(32, Long.MAX_VALUE);
        BenchmarkSupport.CardTiming timing = BenchmarkSupport.CardTiming.parse(response);
        assertEquals(0xffffffffL, timing.clockHz);
        assertEquals(0xffffffffL, timing.commandCount);
        assertEquals(0, timing.negotiateKemCycles);
        assertEquals(0, timing.certCycles);
        assertEquals(Long.MAX_VALUE, timing.establishCycles);
    }

    @Test
    public void rejectsNullShortAndExtendedResponses() {
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.CardTiming.parse(null));
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkSupport.CardTiming.parse(Arrays.copyOf(timingResponse(), 41)));
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkSupport.CardTiming.parse(Arrays.copyOf(timingResponse(), 43)));
    }

    @Test
    public void rejectsEitherInvalidStatusByte() {
        for (int offset : new int[]{40, 41}) {
            byte[] response = timingResponse();
            response[offset] ^= 1;
            assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.CardTiming.parse(response));
        }
    }

    @Test
    public void rejectsUnknownMagicUnavailableCounterAndUnknownFlags() {
        byte[] wrongMagic = timingResponse();
        wrongMagic[3] = '2';
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.CardTiming.parse(wrongMagic));
        for (int flags : new int[]{0, 2, 4, -1}) {
            byte[] response = timingResponse();
            ByteBuffer.wrap(response).putInt(4, flags);
            assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.CardTiming.parse(response));
        }
    }

    @Test
    public void parsesSysTickAndDwtCyclesWithoutChangingTheirCoreClockUnits() {
        for (int flags : new int[]{1, 3}) {
            byte[] response = timingResponse();
            ByteBuffer.wrap(response).putInt(4, flags);
            BenchmarkSupport.CardTiming timing = BenchmarkSupport.CardTiming.parse(response);
            assertEquals(flags == 1 ? BenchmarkSupport.TimerSource.DWT : BenchmarkSupport.TimerSource.SYSTICK_IRQ,
                    timing.timerSource);
            assertEquals(105_000_000L, timing.clockHz);
            assertEquals(0x0000000102030405L, timing.negotiateKemCycles);
            assertEquals(0x0000010203040506L, timing.certCycles);
            assertEquals(0x0010203040506070L, timing.establishCycles);
        }
    }

    @Test
    public void validNotReadyPacketPreservesTheReportedClockWithoutClaimingMissingFirmware() {
        byte[] response = timingResponse();
        ByteBuffer.wrap(response).putInt(4, 0);
        BenchmarkSupport.CounterNotReadyException failure = assertThrows(
                BenchmarkSupport.CounterNotReadyException.class,
                () -> BenchmarkSupport.CardTiming.parse(response));
        assertEquals(105_000_000L, failure.clockHz);
        assertTrue(failure.getMessage().contains("timing interface is present"));
    }

    @Test
    public void rejectsZeroFrequencyAndEachUnsigned64Overflow() {
        byte[] noClock = timingResponse();
        ByteBuffer.wrap(noClock).putInt(8, 0);
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.CardTiming.parse(noClock));
        for (int offset : new int[]{16, 24, 32}) {
            byte[] response = timingResponse();
            response[offset] = (byte) 0x80;
            assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.CardTiming.parse(response));
        }
    }

    @Test
    public void acceptsOnlyTimesStrictlyBelowNinetyPercentOfCounterPeriod() {
        long limitNs = 38_654_705_664L; // 0.9 * 2^32 cycles at 100 MHz.
        BenchmarkSupport.validateRoundTrip(0, 100_000_000);
        BenchmarkSupport.validateRoundTrip(limitNs - 1, 100_000_000);
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkSupport.validateRoundTrip(limitNs, 100_000_000));
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkSupport.validateRoundTrip(Long.MAX_VALUE, 100_000_000));
    }

    @Test
    public void wrapGuardKeepsSubNanosecondBoundaryExactWithoutMultiplicationOverflow() {
        long clockHz = 105_000_000L;
        long floorNs = ((1L << 32) * 900_000_000L) / clockHz;
        // At 105 MHz the limit lies strictly between these consecutive nanoseconds.
        BenchmarkSupport.validateRoundTrip(floorNs, clockHz);
        assertThrows(IllegalArgumentException.class,
                () -> BenchmarkSupport.validateRoundTrip(floorNs + 1, clockHz));
    }

    @Test
    public void wrapGuardRejectsInvalidInputs() {
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.validateRoundTrip(-1, 105_000_000));
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.validateRoundTrip(1, 0));
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.validateRoundTrip(1, -1));
    }

    @Test
    public void summarizesOneValueWithZeroSampleDeviation() {
        BenchmarkSupport.Summary result = BenchmarkSupport.Summary.of(Collections.singletonList(7L));
        assertEquals(1, result.count);
        assertEquals(7, result.mean, 0);
        assertEquals(7, result.median, 0);
        assertEquals(0, result.sd, 0);
        assertEquals(7, result.min);
        assertEquals(7, result.max);
        assertEquals(7, result.p95);
    }

    @Test
    public void summarizesEvenValuesWithoutChangingInputAndUsesSampleDeviation() {
        List<Long> values = Arrays.asList(4L, 1L, 3L, 2L);
        BenchmarkSupport.Summary result = BenchmarkSupport.Summary.of(values);
        assertEquals(Arrays.asList(4L, 1L, 3L, 2L), values);
        assertEquals(4, result.count);
        assertEquals(2.5, result.mean, 0);
        assertEquals(2.5, result.median, 0);
        assertEquals(Math.sqrt(5.0 / 3.0), result.sd, 1e-12);
        assertEquals(1, result.min);
        assertEquals(4, result.max);
        assertEquals(4, result.p95);
    }

    @Test
    public void computesNearestRankPercentileAndOddMedian() {
        List<Long> values = new ArrayList<>();
        for (long value = 20; value >= 1; value--) values.add(value);
        assertEquals(19, BenchmarkSupport.Summary.of(values).p95);
        BenchmarkSupport.Summary odd = BenchmarkSupport.Summary.of(Arrays.asList(9L, 0L, 3L));
        assertEquals(3, odd.median, 0);
        assertEquals(4, odd.mean, 0);
        assertEquals(Math.sqrt(21), odd.sd, 1e-12);
    }

    @Test
    public void evenMedianDoesNotOverflowLongSum() {
        BenchmarkSupport.Summary result = BenchmarkSupport.Summary.of(
                Arrays.asList(Long.MAX_VALUE, Long.MAX_VALUE));
        assertEquals((double) Long.MAX_VALUE, result.mean, 0);
        assertEquals((double) Long.MAX_VALUE, result.median, 0);
        assertEquals(0, result.sd, 0);
    }

    @Test
    public void rejectsMissingEmptyNegativeAndNullStatisticalSamples() {
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.Summary.of(null));
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.Summary.of(Collections.emptyList()));
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.Summary.of(Arrays.asList(1L, -1L)));
        assertThrows(IllegalArgumentException.class, () -> BenchmarkSupport.Summary.of(Arrays.asList(1L, null)));
    }
}
