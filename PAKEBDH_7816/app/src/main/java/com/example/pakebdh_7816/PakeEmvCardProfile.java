package com.example.pakebdh_7816;

import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Exchange;
import java.util.Locale;
import java.util.function.Consumer;

/** Reads the public firmware compatibility profile outside measured protocol traffic. */
final class PakeEmvCardProfile {
    private static final long REQUIRED_COMMAND_CAPABILITIES = 0x07L;
    private static final long F7_CAPABILITY = 0x08L;
    private static final long COUNTER_DIAGNOSTIC_CAPABILITY = 0x10L;
    private static final long SYSTICK_CAPABILITY = 0x20L;
    private static final String FLASH_ADVICE = "Rebuild and flash the Card_pakebdh Debug target on the card; "
            + "installing the Android APK does not update card firmware.";

    static final class Profile {
        final String description;
        final boolean timingAdvertised;
        final boolean diagnosticsAdvertised;
        final boolean sysTickAdvertised;

        Profile(String description, boolean timingAdvertised, boolean diagnosticsAdvertised,
                boolean sysTickAdvertised) {
            this.description = description;
            this.timingAdvertised = timingAdvertised;
            this.diagnosticsAdvertised = diagnosticsAdvertised;
            this.sysTickAdvertised = sysTickAdvertised;
        }
    }

    private PakeEmvCardProfile() { }

    static String inspect(Exchange exchange, Consumer<String> status) throws Exception {
        return query(exchange, status).description;
    }

    static Profile query(Exchange exchange, Consumer<String> status) throws Exception {
        if (exchange == null) throw new IllegalArgumentException("An APDU exchange is required.");
        if (status == null) throw new IllegalArgumentException("A profile status callback is required.");
        // Transport errors deliberately propagate. They do not establish legacy compatibility.
        byte[] response = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF8, 0, 0, 0});
        int sw = statusWord(response);
        if (sw < 0) throw new IllegalStateException("Card profile F8 returned a missing/truncated response; SW=unavailable.");
        if (sw == 0x6D00 || sw == 0x6A81) {
            if (response.length != 2) {
                throw new IllegalStateException("Malformed unsupported-profile F8 response; SW=" + formatSw(sw) + '.');
            }
            String meaning = sw == 0x6D00 ? "instruction not supported" : "function not supported";
            String profile = "Unverified card profile: F8 returned SW=" + formatSw(sw) + " (" + meaning
                    + "). Keeping the original demo transport; requiring CHIC tag authentication; skipping F7 timing queries. "
                    + "C1/B2/50 support has not been confirmed.";
            status.accept(profile);
            return new Profile(profile, false, false, false);
        }
        if (sw != 0x9000) {
            throw new IllegalStateException("Card profile F8 failed with SW=" + formatSw(sw) + '.');
        }
        if (response.length != 14) {
            throw new IllegalStateException("Malformed card profile F8 response: expected 12 payload bytes and SW=9000.");
        }
        if (response[0] != 'P' || response[1] != 'E' || response[2] != 'M' || response[3] != '1') {
            throw new IllegalStateException("Unsupported card profile F8 magic: expected PEM1; SW=9000.");
        }
        long version = readU32(response, 4);
        if (version != 3) {
            throw new IllegalStateException("Unsupported card profile F8 version=" + version + "; expected six-message CHIC profile 3, SW=9000. ");
        }
        long capabilities = readU32(response, 8);
        if ((capabilities & REQUIRED_COMMAND_CAPABILITIES) != REQUIRED_COMMAND_CAPABILITIES) {
            throw new IllegalStateException("Incompatible card profile PEM1 v3: capabilities="
                    + formatCapabilities(capabilities) + " do not advertise every required C1/B2/50 command; SW=9000. "
                    + FLASH_ADVICE);
        }
        String profile = "Card profile PEM1 v3: capabilities=" + formatCapabilities(capabilities)
                + "; C1/B2/50 advertised; F7 timing "
                + ((capabilities & F7_CAPABILITY) != 0 ? "advertised" : "not advertised")
                + "; counter diagnostics "
                + ((capabilities & COUNTER_DIAGNOSTIC_CAPABILITY) != 0 ? "advertised" : "not advertised")
                + "; SysTick fallback "
                + ((capabilities & SYSTICK_CAPABILITY) != 0 ? "advertised." : "not advertised.");
        status.accept(profile);
        return new Profile(profile, (capabilities & F7_CAPABILITY) != 0,
                (capabilities & COUNTER_DIAGNOSTIC_CAPABILITY) != 0,
                (capabilities & SYSTICK_CAPABILITY) != 0);
    }

    static String describeCommandFailure(String operation, byte[] response, String profile) {
        String name = operation == null || operation.isEmpty() ? "APDU command" : operation;
        int sw = statusWord(response);
        String reason;
        if (sw == 0x6D00) reason = "Instruction-rejected status received.";
        else if (sw == 0x6E00) reason = "Class-rejected status received.";
        else if (sw == 0x6A81) reason = "Function-rejected status received.";
        else reason = "Check the actual command/response path.";
        return name + " returned SW=" + formatSw(sw) + ". " + reason
                + " The sent header alone does not establish what the card decoded."
                + " TRACE/ECHO evidence is needed before assigning a cause.";
    }

    private static int statusWord(byte[] response) {
        if (response == null || response.length < 2) return -1;
        return ((response[response.length - 2] & 0xff) << 8) | (response[response.length - 1] & 0xff);
    }

    private static long readU32(byte[] response, int offset) {
        long value = 0;
        for (int i = 0; i < 4; i++) value = (value << 8) | (response[offset + i] & 0xffL);
        return value;
    }

    private static String formatSw(int sw) {
        return sw < 0 ? "unavailable" : String.format(Locale.ROOT, "%04X", sw);
    }

    private static String formatCapabilities(long capabilities) {
        return String.format(Locale.ROOT, "0x%08X", capabilities);
    }
}
