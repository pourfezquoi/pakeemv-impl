package com.example.pqbdh_7816;

import static org.junit.Assert.*;

import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Exchange;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

/** Diagnostic correctness only; no crypto, physical card, or timing data is produced. */
public class PqBdhDiagnosticsTest {
    private static final byte[] REJECTED = bytes(0x80, 0xCA, 1, 0, 0xDC);
    private static final byte[] TRACE = bytes(0x80, 0xF1, 0, 0, 0);
    private static final byte[] ECHO_A = bytes(0x80, 0xF2, 0x3A, 0xC7, 0);
    private static final byte[] ECHO_B = bytes(0x80, 0xF2, 0xA6, 0x5D, 0);
    private static final byte[] PING = bytes(0x80, 0xF0, 0, 0, 1);
    private static final byte[] PROFILE = bytes(0x80, 0xF8, 0, 0, 0);
    private static final byte[] ECHO_A_RESPONSE = bytes(0x3A, 0xC7, 0x90, 0);
    private static final byte[] ECHO_B_RESPONSE = bytes(0xA6, 0x5D, 0x90, 0);
    private static final byte[] PING_RESPONSE = bytes(1, 0x90, 0);

    @Test
    public void traceIsTheFirstRequestAndComparesTheCompletePublicHeader() throws Exception {
        Script exchange = rejectionScript(bytes(0x80, 0xCA, 1, 0, 0xDC, 0x90, 0));
        String report = PqBdhDiagnostics.traceRejectedCommand(exchange, REJECTED);
        assertCommands(exchange, TRACE, ECHO_A, ECHO_B, PING);
        assertTrue(report.contains("Expected rejected header: 80 CA 01 00 DC"));
        assertTrue(report.contains("TRACE matches the expected public header"));
        assertTrue(report.contains("ECHO delivery/freshness checks passed"));
        assertTrue(report.contains("do not authenticate the card or firmware"));
    }

    @Test
    public void nonzeroMismatchedTraceIsEvidenceWithoutAClaimAboutItsCause() throws Exception {
        String report = PqBdhDiagnostics.traceRejectedCommand(
                rejectionScript(bytes(0, 0, 5, 0x80, 0xCA, 0x90, 0)), REJECTED);
        assertTrue(report.contains("TRACE differs from the expected public header"));
        assertTrue(report.contains("reported 00 00 05 80 CA"));
        assertTrue(report.contains("without establishing its cause"));
        assertFalse(report.contains("wrong firmware"));
        assertFalse(report.contains("Rebuild and flash"));
    }

    @Test
    public void zeroTraceDoesNotProveThatTheEndpointReceivedZeros() throws Exception {
        String report = PqBdhDiagnostics.traceRejectedCommand(
                rejectionScript(bytes(0, 0, 0, 0, 0, 0x90, 0)), REJECTED);
        assertTrue(report.contains("TRACE inconclusive: an all-zero header"));
        assertTrue(report.contains("may mean the firmware does not update"));
        assertFalse(report.contains("TRACE differs"));
    }

    @Test
    public void unsupportedOrMalformedTraceRemainsInconclusiveAndChecksContinue() throws Exception {
        for (byte[] response : new byte[][]{null, bytes(), bytes(0x90), bytes(0x6D, 0),
                bytes(0x6A, 0x81), bytes(0, 0, 0, 0, 0, 0x69, 0x85), bytes(0x90, 0)}) {
            Script exchange = rejectionScript(response);
            String report = PqBdhDiagnostics.traceRejectedCommand(exchange, REJECTED);
            assertTrue(report.contains("TRACE inconclusive"));
            assertCommands(exchange, TRACE, ECHO_A, ECHO_B, PING);
        }
    }

    @Test
    public void onlyTheFirstFiveInputBytesCanAppearInTheReport() throws Exception {
        byte[] commandWithData = bytes(0x80, 0xCA, 1, 0, 0xDC, 0xDE, 0xAD, 0xBE, 0xEF);
        byte[] original = commandWithData.clone();
        String report = PqBdhDiagnostics.traceRejectedCommand(
                rejectionScript(bytes(0x80, 0xCA, 1, 0, 0xDC, 0x90, 0)), commandWithData);
        assertTrue(report.contains("80 CA 01 00 DC"));
        assertFalse(report.contains("DE AD BE EF"));
        assertArrayEquals(original, commandWithData);
    }

    @Test
    public void connectionCheckUsesDistinctEchoesThenPingTraceAndOptionalProfile() throws Exception {
        Script exchange = new Script(ECHO_A_RESPONSE, ECHO_B_RESPONSE, PING_RESPONSE,
                bytes(0x80, 0xF0, 0, 0, 1, 0x90, 0),
                bytes('P', 'Q', 'M', '1', 0, 0, 0, 2, 0, 0, 0, 15, 0x90, 0));
        String report = PqBdhDiagnostics.checkConnection(exchange);
        assertCommands(exchange, ECHO_A, ECHO_B, PING, TRACE, PROFILE);
        assertTrue(report.contains("ECHO A: expected 3A C7 90 00"));
        assertTrue(report.contains("ECHO B: expected A6 5D 90 00"));
        assertTrue(report.contains("ECHO delivery/freshness checks passed"));
        assertTrue(report.contains("PING matches the demo response"));
        assertTrue(report.contains("TRACE matches the expected public header"));
        assertTrue(report.contains("50 51 4D 31 00 00 00 02 00 00 00 0F 90 00"));
        assertTrue(report.contains("Card profile PQM1 v2"));
    }

    @Test
    public void connectionCheckLabelsTheOldCertificateProfileAsIncompatibleWithoutAnotherApdu() throws Exception {
        Script exchange = new Script(ECHO_A_RESPONSE, ECHO_B_RESPONSE, PING_RESPONSE,
                bytes(0x80, 0xF0, 0, 0, 1, 0x90, 0),
                bytes('P', 'Q', 'M', '1', 0, 0, 0, 1, 0, 0, 0, 127, 0x90, 0));
        String report = PqBdhDiagnostics.checkConnection(exchange);
        assertCommands(exchange, ECHO_A, ECHO_B, PING, TRACE, PROFILE);
        assertTrue(report.contains("Incompatible profile:"));
        assertTrue(report.contains("version=1"));
        assertTrue(report.contains("expected padded-certificate profile 2"));
        assertFalse(report.contains("Card profile PQM1 v2:"));
    }

    @Test
    public void repeatedSuccessfulEchoResponseFlagsPossibleStaleDelivery() throws Exception {
        Script exchange = new Script(bytes(0x6D, 0), ECHO_A_RESPONSE, ECHO_A_RESPONSE, PING_RESPONSE);
        String report = PqBdhDiagnostics.traceRejectedCommand(exchange, REJECTED);
        assertTrue(report.contains("ECHO freshness check failed"));
        assertTrue(report.contains("Possible stale/replayed delivery or incompatible ECHO behavior"));
        assertTrue(report.contains("cause is unconfirmed"));
        assertFalse(report.contains("checks passed"));
    }

    @Test
    public void swappedEchoRepliesCannotPassTheDeliveryCheck() throws Exception {
        Script exchange = new Script(bytes(0x6D, 0), ECHO_B_RESPONSE, ECHO_A_RESPONSE, PING_RESPONSE);
        String report = PqBdhDiagnostics.traceRejectedCommand(exchange, REJECTED);
        assertTrue(report.contains("did not match the expected replies"));
        assertFalse(report.contains("checks passed"));
    }

    @Test
    public void UnsupportedEchoStatusesAreNotMisreportedAsAReplay() throws Exception {
        Script exchange = new Script(bytes(0x6D, 0), bytes(0x6D, 0), bytes(0x6D, 0), bytes(0x6D, 0));
        String report = PqBdhDiagnostics.traceRejectedCommand(exchange, REJECTED);
        assertTrue(report.contains("inconclusive because ECHO is unsupported"));
        assertFalse(report.contains("Possible stale/replayed"));
        assertTrue(report.contains("PING did not match"));
    }

    @Test
    public void traceTransportFailurePropagatesUnchangedAndStopsAllLaterRequests() {
        IOException expected = new IOException("TRACE transport disconnected");
        List<byte[]> sent = new ArrayList<>();
        IOException actual = assertThrows(IOException.class,
                () -> PqBdhDiagnostics.traceRejectedCommand(command -> {
                    sent.add(command.clone());
                    throw expected;
                }, REJECTED));
        assertSame(expected, actual);
        assertEquals(1, sent.size());
        assertArrayEquals(TRACE, sent.get(0));
    }

    @Test
    public void transportFailureAtAnyConnectionStepStopsWithoutRetry() {
        for (int step = 0; step < 5; step++) {
            final int failAt = step;
            int[] calls = {0};
            IOException expected = new IOException("Transfer failed");
            assertSame(expected, assertThrows(IOException.class,
                    () -> PqBdhDiagnostics.checkConnection(command -> {
                        if (calls[0]++ == failAt) throw expected;
                        return bytes(0x6D, 0);
                    })));
            assertEquals(step + 1, calls[0]);
        }
    }

    @Test
    public void traceEvidenceIsPublishedBeforeAnEchoTimeoutWithoutReplacingItsException() {
        IOException expected = new IOException("ECHO timed out");
        List<String> progress = new ArrayList<>();
        List<byte[]> commands = new ArrayList<>();
        assertSame(expected, assertThrows(IOException.class,
                () -> PqBdhDiagnostics.traceRejectedCommand(command -> {
                    commands.add(command.clone());
                    if (commands.size() == 1) {
                        assertArrayEquals(TRACE, command);
                        assertEquals("Diagnostic request: 80 F1 00 00 00", progress.get(0));
                        return bytes(0x80, 0xCA, 1, 0, 0xDC, 0x90, 0);
                    }
                    assertArrayEquals(ECHO_A, command);
                    throw expected;
                }, REJECTED, progress::add)));
        assertEquals(2, commands.size());
        assertEquals(3, progress.size());
        assertTrue(progress.get(1).contains("Diagnostic response to 80 F1 00 00 00: 80 CA 01 00 DC 90 00"));
        assertTrue(progress.get(1).contains("SW=9000"));
        assertEquals("Diagnostic request: 80 F2 3A C7 00", progress.get(2));
    }

    @Test
    public void connectionProgressRetainsTheFirstEchoAndTheFailedRequestWithoutRetry() {
        IOException expected = new IOException("Second ECHO disconnected");
        List<String> progress = new ArrayList<>();
        int[] calls = {0};
        assertSame(expected, assertThrows(IOException.class,
                () -> PqBdhDiagnostics.checkConnection(command -> {
                    calls[0]++;
                    if (calls[0] == 1) {
                        assertArrayEquals(ECHO_A, command);
                        assertEquals("Diagnostic request: 80 F2 3A C7 00", progress.get(0));
                        return ECHO_A_RESPONSE;
                    }
                    assertArrayEquals(ECHO_B, command);
                    throw expected;
                }, progress::add)));
        assertEquals(2, calls[0]);
        assertEquals(3, progress.size());
        assertTrue(progress.get(1).contains("3A C7 90 00 (4 bytes, SW=9000)"));
        assertEquals("Diagnostic request: 80 F2 A6 5D 00", progress.get(2));
    }

    @Test
    public void bothReportsAreBoundedEvenForOversizedReplies() throws Exception {
        byte[] huge = new byte[100_000];
        Arrays.fill(huge, (byte) 0xAB);
        huge[huge.length - 2] = (byte) 0x90;
        huge[huge.length - 1] = 0;
        for (String report : new String[]{
                PqBdhDiagnostics.traceRejectedCommand(command -> huge, REJECTED),
                PqBdhDiagnostics.checkConnection(command -> huge)}) {
            assertTrue(report.length() <= 4000);
            assertTrue(report.contains("... (100000 bytes, SW=9000)"));
            String tooMany = String.join(" ", java.util.Collections.nCopies(49, "AB"));
            assertFalse(report.contains(tooMany));
        }
    }

    @Test
    public void unknownConnectionProfileIsExplicitlyUnconfirmedWithoutAnyTimingQuery() throws Exception {
        Script exchange = new Script(ECHO_A_RESPONSE, ECHO_B_RESPONSE, PING_RESPONSE,
                bytes(0x80, 0xF0, 0, 0, 1, 0x90, 0), bytes(0x6D, 0));
        String report = PqBdhDiagnostics.checkConnection(exchange);
        assertTrue(report.contains("Profile support is unconfirmed"));
        assertTrue(report.contains("does not identify the installed image"));
        assertCommands(exchange, ECHO_A, ECHO_B, PING, TRACE, PROFILE);
        for (byte[] command : exchange.commands) {
            assertEquals(5, command.length);
            assertFalse((command[1] & 255) == 0xF7);
            assertFalse((command[1] & 255) == 0xCA);
        }
    }

    @Test
    public void invalidArgumentsFailBeforeSendingAnything() {
        int[] calls = {0};
        Exchange exchange = command -> { calls[0]++; return bytes(0x90, 0); };
        for (byte[] header : new byte[][]{null, bytes(), bytes(0x80, 0xCA, 1, 0)}) {
            assertThrows(IllegalArgumentException.class,
                    () -> PqBdhDiagnostics.traceRejectedCommand(exchange, header));
        }
        assertThrows(IllegalArgumentException.class, () -> PqBdhDiagnostics.checkConnection(null));
        assertThrows(IllegalArgumentException.class,
                () -> PqBdhDiagnostics.traceRejectedCommand(null, REJECTED));
        assertEquals(0, calls[0]);
    }

    private static Script rejectionScript(byte[] trace) {
        return new Script(trace, ECHO_A_RESPONSE, ECHO_B_RESPONSE, PING_RESPONSE);
    }

    private static void assertCommands(Script actual, byte[]... expected) {
        assertEquals(expected.length, actual.commands.size());
        for (int i = 0; i < expected.length; i++) assertArrayEquals(expected[i], actual.commands.get(i));
    }

    private static byte[] bytes(int... values) {
        byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++) result[i] = (byte) values[i];
        return result;
    }

    private static final class Script implements Exchange {
        final List<byte[]> commands = new ArrayList<>();
        final byte[][] responses;

        Script(byte[]... responses) { this.responses = responses; }

        @Override public byte[] send(byte[] command) {
            assertTrue("Unexpected extra request", commands.size() < responses.length);
            commands.add(command.clone());
            byte[] response = responses[commands.size() - 1];
            return response == null ? null : response.clone();
        }
    }
}
