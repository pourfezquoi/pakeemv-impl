package com.example.pqbdh_7816;

import com.example.pqbdh_7816.benchmark.BenchmarkSupport.TimerSource;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Separate optional INS20 counters; the three-phase PEB1 packet stays unchanged. */
final class PqBdhPinTiming {
    final long clockHz;
    final long commandCount;
    final long cycles;
    final TimerSource timerSource;

    private PqBdhPinTiming(long clockHz, long commandCount, long cycles, TimerSource timerSource) {
        this.clockHz = clockHz;
        this.commandCount = commandCount;
        this.cycles = cycles;
        this.timerSource = timerSource;
    }

    static PqBdhPinTiming parse(byte[] response) {
        require(response != null && response.length == 26, "PIN timing requires 24 payload bytes and SW=9000");
        require(response[24] == (byte) 0x90 && response[25] == 0, "PIN timing status must be 9000");
        require(response[0] == 'P' && response[1] == 'Q' && response[2] == 'P' && response[3] == '1',
                "PIN timing magic must be PQP1");
        ByteBuffer packet = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
        int flags = packet.getInt(4);
        require(flags == 1 || flags == 3, "PIN timing counter is unavailable or has unsupported flags");
        long clock = Integer.toUnsignedLong(packet.getInt(8));
        long count = Integer.toUnsignedLong(packet.getInt(12));
        long cycles = packet.getLong(16);
        require(clock > 0 && cycles >= 0, "Invalid PIN timing clock or cycle total");
        return new PqBdhPinTiming(clock, count, cycles, flags == 1 ? TimerSource.DWT : TimerSource.SYSTICK_IRQ);
    }

    StageResult attach(StageResult pin, long expectedClockHz, TimerSource expectedSource) {
        require(clockHz == expectedClockHz, "Card clock changed during PIN verification");
        require(timerSource == expectedSource, "Card timer source changed during PIN verification");
        require(commandCount == 1 && pin.apduCount == 1 && cycles > 0,
                "PIN timing must contain exactly one successful measured exchange");
        StageResult measured = pin.withCardCycles(cycles);
        require(measured.values(clockHz)[10] <= pin.ioNs, "Card PIN handler time exceeds its APDU round trip");
        return measured;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
