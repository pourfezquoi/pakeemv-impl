package com.example.pakebdh_7816;

import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Exchange;
import java.util.Arrays;
import java.util.function.Consumer;

/** Public, non-cryptographic delivery diagnostics, outside measured protocol phases. */
final class PakeEmvDiagnostics {
    private static final int MAX_REPLY_BYTES = 48;
    private static final int MAX_REPORT_CHARS = 4000;
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private PakeEmvDiagnostics() { }

    static String traceRejectedCommand(Exchange exchange, byte[] rejectedHeader) throws Exception {
        return traceRejectedCommand(exchange, rejectedHeader, ignored -> { });
    }

    static String traceRejectedCommand(Exchange exchange, byte[] rejectedHeader,
                                       Consumer<String> progress) throws Exception {
        exchange = withProgress(exchange, progress);
        if (rejectedHeader == null || rejectedHeader.length < 5) {
            throw new IllegalArgumentException("A five-byte public APDU header is required.");
        }
        byte[] expectedHeader = Arrays.copyOf(rejectedHeader, 5);
        StringBuilder report = new StringBuilder("Public command diagnostics, outside measured phases.\n");
        report.append("Expected rejected header: ").append(hex(expectedHeader, 5)).append('\n');
        // TRACE must be the first request: another APDU would replace the relevant header.
        appendTrace(report, expectedHeader,
                exchange.send(new byte[]{(byte) 0x80, (byte) 0xF1, 0, 0, 0}));
        appendEchoChecks(report, exchange);
        appendPing(report, exchange);
        return finish(report);
    }

    static String checkConnection(Exchange exchange) throws Exception {
        return checkConnection(exchange, ignored -> { });
    }

    static String checkConnection(Exchange exchange, Consumer<String> progress) throws Exception {
        exchange = withProgress(exchange, progress);
        StringBuilder report = new StringBuilder(
                "Connection diagnostics only; no PAKE or F7 timing query is sent.\n");
        appendEchoChecks(report, exchange);
        appendPing(report, exchange);
        appendTrace(report, new byte[]{(byte) 0x80, (byte) 0xF0, 0, 0, 1},
                exchange.send(new byte[]{(byte) 0x80, (byte) 0xF1, 0, 0, 0}));
        // The optional public profile probe is last so it cannot replace the PING trace.
        byte[] profile = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF8, 0, 0, 0});
        report.append("Optional profile F8: expected PEM1 payload and SW=9000; received ")
                .append(reply(profile)).append('.').append('\n');
        if (unsupported(profile)) {
            report.append("Profile support is unconfirmed; this result does not identify the installed image.\n");
        }
        return finish(report);
    }

    private static void appendTrace(StringBuilder report, byte[] expected, byte[] response) {
        report.append("TRACE F1: expected header ").append(hex(expected, 5))
                .append(" + 90 00; received ").append(reply(response)).append('.').append('\n');
        if (response == null || response.length != 7 || statusWord(response) != 0x9000) {
            report.append("TRACE inconclusive: the response is unsupported or does not contain a five-byte header and SW=9000.\n");
            return;
        }
        byte[] actual = Arrays.copyOf(response, 5);
        boolean allZero = true;
        for (byte value : actual) allZero &= value == 0;
        if (allZero) {
            report.append("TRACE inconclusive: an all-zero header may mean the firmware does not update this diagnostic.\n");
        } else if (Arrays.equals(expected, actual)) {
            report.append("TRACE matches the expected public header. This is reported delivery metadata.\n");
        } else {
            report.append("TRACE differs from the expected public header: reported ")
                    .append(hex(actual, 5))
                    .append(". This records a mismatch without establishing its cause.\n");
        }
    }

    private static void appendEchoChecks(StringBuilder report, Exchange exchange) throws Exception {
        byte[] firstExpected = {(byte) 0x3A, (byte) 0xC7, (byte) 0x90, 0};
        byte[] secondExpected = {(byte) 0xA6, (byte) 0x5D, (byte) 0x90, 0};
        byte[] first = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF2, 0x3A, (byte) 0xC7, 0});
        report.append("ECHO A: expected ").append(hex(firstExpected, 4))
                .append("; received ").append(reply(first)).append('.').append('\n');
        byte[] second = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF2, (byte) 0xA6, 0x5D, 0});
        report.append("ECHO B: expected ").append(hex(secondExpected, 4))
                .append("; received ").append(reply(second)).append('.').append('\n');
        if (Arrays.equals(first, firstExpected) && Arrays.equals(second, secondExpected)) {
            report.append("ECHO delivery/freshness checks passed for both distinct public parameters.\n");
        } else if (first != null && first.length == 4 && statusWord(first) == 0x9000
                && Arrays.equals(first, second)) {
            report.append("ECHO freshness check failed: identical successful replies for distinct parameters. ")
                    .append("Possible stale/replayed delivery or incompatible ECHO behavior; the cause is unconfirmed.\n");
        } else if (unsupported(first) && unsupported(second)) {
            report.append("ECHO delivery/freshness checks are inconclusive because ECHO is unsupported.\n");
        } else {
            report.append("ECHO delivery/freshness checks did not match the expected replies; the cause is unconfirmed.\n");
        }
    }

    private static void appendPing(StringBuilder report, Exchange exchange) throws Exception {
        byte[] response = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF0, 0, 0, 1});
        report.append("PING F0: expected 01 90 00; received ").append(reply(response)).append('.').append('\n');
        report.append(Arrays.equals(response, new byte[]{1, (byte) 0x90, 0})
                ? "PING matches the demo response.\n"
                : "PING did not match the demo response; this alone does not identify the endpoint.\n");
    }

    private static String reply(byte[] response) {
        if (response == null) return "missing response";
        return hex(response, MAX_REPLY_BYTES) + " (" + response.length + " bytes, SW="
                + (statusWord(response) < 0 ? "missing" : hexStatus(statusWord(response))) + ")";
    }

    private static String hex(byte[] bytes, int maximum) {
        int length = Math.min(bytes.length, maximum);
        StringBuilder text = new StringBuilder(length * 3 + 4);
        for (int i = 0; i < length; i++) {
            if (i != 0) text.append(' ');
            text.append(HEX[(bytes[i] >>> 4) & 15]).append(HEX[bytes[i] & 15]);
        }
        if (length == 0) text.append("empty");
        if (bytes.length > length) text.append(" ...");
        return text.toString();
    }

    private static String hexStatus(int status) {
        return new String(new char[]{HEX[(status >>> 12) & 15], HEX[(status >>> 8) & 15],
                HEX[(status >>> 4) & 15], HEX[status & 15]});
    }

    private static int statusWord(byte[] response) {
        if (response == null || response.length < 2) return -1;
        return ((response[response.length - 2] & 255) << 8) | (response[response.length - 1] & 255);
    }

    private static boolean unsupported(byte[] response) {
        int status = statusWord(response);
        return status == 0x6D00 || status == 0x6A81 || status == 0x6E00;
    }

    private static String finish(StringBuilder report) {
        report.append("These public delivery checks do not authenticate the card or firmware.");
        if (report.length() <= MAX_REPORT_CHARS) return report.toString();
        String suffix = "\n[Report truncated]";
        return report.substring(0, MAX_REPORT_CHARS - suffix.length()) + suffix;
    }

    private static void requireExchange(Exchange exchange) {
        if (exchange == null) throw new IllegalArgumentException("An APDU exchange is required.");
    }

    private static Exchange withProgress(Exchange exchange, Consumer<String> progress) {
        requireExchange(exchange);
        if (progress == null) throw new IllegalArgumentException("A diagnostic progress callback is required.");
        return command -> {
            String header = hex(command, 5);
            // Publish each completed response before sending another diagnostic request.
            // Earlier evidence remains visible even if a later transport call fails.
            progress.accept("Diagnostic request: " + header);
            byte[] response = exchange.send(command);
            progress.accept("Diagnostic response to " + header + ": " + reply(response));
            return response;
        };
    }
}
