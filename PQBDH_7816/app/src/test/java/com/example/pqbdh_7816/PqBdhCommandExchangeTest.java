package com.example.pqbdh_7816;

import static org.junit.Assert.*;

import com.example.pqbdh_7816.benchmark.IsolatedIoExchange;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Clock;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Stage;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;

/** Failure context must distinguish fragments from polls without exposing their contents. */
public class PqBdhCommandExchangeTest {
    @Test
    public void commandWrapperPreservesActualIoWorkerIdentityForCpuMeasurement() throws Exception {
        AtomicLong wall = new AtomicLong();
        AtomicLong cpu = new AtomicLong();
        AtomicLong actualWorkerId = new AtomicLong(-1);
        AtomicInteger calls = new AtomicInteger();
        Clock clock = new Clock() {
            @Override public long wallNs() { return wall.addAndGet(1_000); }
            @Override public long cpuNs() { return cpu.incrementAndGet(); }
        };
        long protocolThreadId = Thread.currentThread().getId();
        try (IsolatedIoExchange io = new IsolatedIoExchange(command -> {
            actualWorkerId.set(Thread.currentThread().getId());
            calls.incrementAndGet();
            return new byte[]{(byte) 0x90, 0};
        })) {
            PqBdhCommandExchange exchange = new PqBdhCommandExchange(io);
            assertTrue(exchange.isCpuIsolated());
            Stage stage = new Stage();
            stage.start(clock);
            assertArrayEquals(new byte[]{(byte) 0x90, 0}, stage.exchange(exchange,
                    new byte[]{(byte) 0x80, (byte) 0xB2, 0, 0, 0}, 0));
            StageResult result = stage.finish();
            assertTrue(result.cpuTimingError, result.cpuTimingAvailable);
            assertEquals(protocolThreadId, result.protocolThreadId);
            assertTrue(actualWorkerId.get() > 0);
            assertEquals(actualWorkerId.get(), result.ioThreadId);
            assertEquals(io.ioThreadId(), exchange.ioThreadId());
            assertNotEquals(result.protocolThreadId, result.ioThreadId);
            assertEquals(1, calls.get());
        }
        PqBdhCommandExchange inline = new PqBdhCommandExchange(
                command -> new byte[]{(byte) 0x90, 0});
        assertFalse(inline.isCpuIsolated());
        assertEquals(-1, inline.ioThreadId());
    }

    @Test
    public void rejectionIncludesPhaseOrdinalLengthAndAllFivePublicHeaderBytes() throws Exception {
        int[] calls = {0};
        PqBdhCommandExchange exchange = new PqBdhCommandExchange(command ->
                ++calls[0] < 3 ? new byte[]{(byte) 0x90, 0} : new byte[]{0x6D, 0});
        exchange.beginPhase("NegotiateKEM");
        byte[] command = new byte[225];
        command[0] = (byte) 0x80; command[1] = (byte) 0xCA;
        command[2] = 1; command[4] = (byte) 220;
        Arrays.fill(command, 5, command.length, (byte) 0xAB);
        exchange.send(command);
        exchange.send(command);
        PqBdhCommandExchange.RejectedCommandException failure = assertThrows(
                PqBdhCommandExchange.RejectedCommandException.class, () -> exchange.send(command));
        assertTrue(failure.getMessage().contains("NegotiateKEM APDU #3"));
        assertTrue(failure.getMessage().contains("header=80 CA 01 00 DC"));
        assertTrue(failure.getMessage().contains("command=225 B, data=220 B"));
        assertTrue(failure.getMessage().contains("SW=6D00"));
        assertFalse(failure.getMessage().contains("AB AB"));
        assertArrayEquals(Arrays.copyOf(command, 5), failure.header);
        command[0] = 0;
        assertEquals(0x80, failure.header[0] & 255);
    }

    @Test
    public void emptyCiphertextPollIsIdentifiedSeparatelyFromDataFragments() {
        PqBdhCommandExchange exchange = new PqBdhCommandExchange(command -> new byte[]{0x6D, 0});
        exchange.beginPhase("NegotiateKEM");
        Exception failure = assertThrows(PqBdhCommandExchange.RejectedCommandException.class,
                () -> exchange.send(new byte[]{(byte) 0x80, (byte) 0xCA, 1, 0, 0}));
        assertTrue(failure.getMessage().contains("header=80 CA 01 00 00"));
        assertTrue(failure.getMessage().contains("command=5 B, data=0 B"));
    }

    @Test
    public void successesAndAuthenticationStatusesAreReturnedUnchanged() throws Exception {
        for (byte[] response : new byte[][]{{(byte) 0x90, 0}, {0x61, 0}, {0x63, (byte) 0xCA}}) {
            PqBdhCommandExchange exchange = new PqBdhCommandExchange(command -> response);
            assertSame(response, exchange.send(new byte[]{(byte) 0x80, (byte) 0xB2, 0, 0, 0}));
        }
    }

    @Test
    public void phaseCounterResetsAndClassRejectionRetainsStatus() throws Exception {
        int[] calls = {0};
        PqBdhCommandExchange exchange = new PqBdhCommandExchange(command ->
                ++calls[0] == 1 ? new byte[]{(byte) 0x90, 0} : new byte[]{0x6E, 0});
        byte[] command = {(byte) 0x80, (byte) 0xB2, 0, 0, 0};
        exchange.beginPhase("NegotiateKEM");
        exchange.send(command);
        exchange.beginPhase("Certificates");
        Exception failure = assertThrows(PqBdhCommandExchange.RejectedCommandException.class,
                () -> exchange.send(command));
        assertTrue(failure.getMessage().contains("Certificates APDU #1"));
        assertTrue(failure.getMessage().contains("SW=6E00"));
    }

    @Test
    public void transportFailurePropagatesWithoutRetryOrDiagnosticCommands() {
        IOException expected = new IOException("Reader unavailable");
        int[] calls = {0};
        PqBdhCommandExchange exchange = new PqBdhCommandExchange(command -> {
            calls[0]++; throw expected;
        });
        assertSame(expected, assertThrows(IOException.class,
                () -> exchange.send(new byte[]{(byte) 0x80, (byte) 0xCA, 1, 0, 0})));
        assertEquals(1, calls[0]);
    }
}
