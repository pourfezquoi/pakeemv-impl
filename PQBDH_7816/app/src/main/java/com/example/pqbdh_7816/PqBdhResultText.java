package com.example.pqbdh_7816;

import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.util.Locale;

/** Presentation only: all displayed quantities come from completed measured phases. */
final class PqBdhResultText {
    private PqBdhResultText() { }

    static String format(PqBdhSession.Result result) {
        boolean authenticated = result.pin != null;
        StageResult core = result.total();
        StageResult total = authenticated ? result.authenticatedTotal() : core;
        boolean completeCardTiming = result.hasCardTiming()
                && (!authenticated || result.pin.cardTimingAvailable);
        StringBuilder text = new StringBuilder();
        if (authenticated) {
            text.append(completeCardTiming && total.cpuTimingAvailable ? "Measurement complete" : "Protocol complete")
                    .append(" | PIN verified | Session keys match\n");
            if (!completeCardTiming) {
                text.append("Card timing unavailable for the complete session; terminal wall timing and traffic measured.\n");
            }
            if (!total.cpuTimingAvailable) {
                text.append("Terminal CPU timing unavailable; other measurements retained.\n");
            }
            text.append("\nAuthenticated session total (three-phase core + PIN)\n\n");
        } else {
            text.append("Handshake only | PIN not verified | Session keys match\n")
                    .append(completeCardTiming && total.cpuTimingAvailable
                            ? "Core measurement complete.\n" : "Core protocol complete.\n");
            if (!completeCardTiming) {
                text.append("Card timing unavailable; terminal wall timing and traffic measured.\n");
            }
            if (!total.cpuTimingAvailable) {
                text.append("Terminal CPU timing unavailable; other measurements retained.\n");
            }
            text.append('\n');
        }
        timing(text, authenticated ? "TIMING" : "CORE TIMING", total, result.clockHz);
        traffic(text, authenticated ? "TRAFFIC" : "CORE TRAFFIC", total);

        text.append("PER-PHASE RESULTS\n");
        phase(text, "NegotiateKEM", result.negotiateKem, result.clockHz);
        phase(text, "Certificate authentication", result.certificates, result.clockHz);
        phase(text, "Key establishment", result.establishKey, result.clockHz);
        if (authenticated) {
            phase(text, "Offline PIN verification", result.pin, result.clockHz);
            if (!result.pin.cardTimingAvailable) {
                text.append("PIN card timing unavailable: ").append(result.pinTimingError == null
                        ? "No valid PIN counter data." : result.pinTimingError).append("\n\n");
            }
            text.append("CORE SUBTOTAL (CA/B2/50, excludes PIN)\n");
            timing(text, "CORE TIMING", core, result.clockHz);
            traffic(text, "CORE TRAFFIC", core);
        }
        if (result.hasCardTiming()) {
            text.append("Card timer source: ").append(result.timerSource.label).append('\n');
            text.append("Card clock: ").append(String.format(Locale.ROOT, "%.3f", result.clockHz / 1_000_000.0))
                    .append(completeCardTiming ? " MHz\nCard cycle total: " : " MHz\nCard core cycle subtotal: ")
                    .append(completeCardTiming ? total.cardCycles : core.cardCycles).append(" cycles\n\n");
        } else {
            text.append("Core card timing unavailable: ").append(result.cardTimingError == null
                    ? "No valid counter data." : result.cardTimingError).append("\n\n");
        }
        text.append("Scope: terminal sent = card received; card sent = terminal received.\n")
                .append("Terminal protocol CPU includes computation and dispatch/wakeup bookkeeping; USB-worker CPU is excluded.\n")
                .append("APDU round trips include card processing and communication; do not add card processing time again.\n")
                .append(authenticated
                        ? "Main totals include CA/B2/50 and one successful offline PIN verification. The core subtotal excludes PIN.\n"
                        : "Core totals cover CA/B2/50 and perform no password authentication.\n")
                .append("GenerateAC, human PIN entry, connection, setup, diagnostics and display are excluded. ")
                .append("Traffic excludes T=1 / CCID / USB framing.");
        return text.toString();
    }

    private static void timing(StringBuilder text, String heading, StageResult total, long clockHz) {
        text.append(heading).append('\n')
                .append("Terminal protocol CPU: ").append(cpuTime(total)).append("\n")
                .append("Card processing: ").append(cardMs(total, clockHz)).append("\n")
                .append("Terminal active wall time: ").append(ms(total.wallNs - total.ioNs)).append(" ms\n")
                .append("APDU round-trip total: ").append(ms(total.ioNs)).append(" ms\n")
                .append("Protocol phase wall time: ").append(ms(total.wallNs)).append(" ms\n\n");
    }

    private static void traffic(StringBuilder text, String heading, StageResult total) {
        text.append(heading).append('\n')
                .append("Application data terminal -> card: ").append(total.logicalT2c).append(" B\n")
                .append("Application data card -> terminal: ").append(total.logicalC2t).append(" B\n")
                .append("Application data bidirectional total: ").append(total.logicalT2c + total.logicalC2t).append(" B\n")
                .append("Complete APDUs terminal -> card: ").append(total.commandBytes).append(" B\n")
                .append("Complete APDUs card -> terminal: ").append(total.responseBytes).append(" B\n")
                .append("Complete APDU bidirectional total: ").append(total.commandBytes + total.responseBytes).append(" B\n")
                .append("APDU round-trip count: ").append(total.apduCount).append("\n\n");
    }

    private static void phase(StringBuilder text, String name, StageResult phase, long clockHz) {
        text.append(name).append("\n")
                .append("  Protocol CPU: ").append(cpuTime(phase)).append("\n")
                .append("  Card processing: ").append(cardMs(phase, clockHz)).append("\n")
                .append("  Application data: terminal -> card ").append(phase.logicalT2c)
                .append(" B, card -> terminal ").append(phase.logicalC2t).append(" B\n")
                .append("  APDUs: terminal -> card ").append(phase.commandBytes)
                .append(" B, card -> terminal ").append(phase.responseBytes)
                .append(" B; ").append(phase.apduCount).append(" round trips\n\n");
    }

    private static String cpuTime(StageResult phase) {
        if (!phase.cpuTimingAvailable || phase.cpuNs <= 0) {
            String reason = phase.cpuTimingError;
            return "Unavailable (" + (reason == null || reason.isEmpty()
                    ? "CPU clock did not resolve this phase" : reason) + ")";
        }
        // Preserve a resolved sub-microsecond value instead of rounding it to 0.000 ms.
        return phase.cpuNs < 1_000 ? phase.cpuNs + " ns" : ms(phase.cpuNs) + " ms";
    }

    private static String cardMs(StageResult phase, long clockHz) {
        return phase.cardTimingAvailable
                ? String.format(Locale.ROOT, "%.3f ms", phase.cardCycles * 1000.0 / clockHz)
                : "Unavailable";
    }

    private static String ms(long ns) {
        return String.format(Locale.ROOT, "%.3f", ns / 1_000_000.0);
    }
}
