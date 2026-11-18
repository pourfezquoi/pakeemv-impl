package com.example.pqbdh_7816;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.junit.Test;

public class PqBdhCardProfileTest {
    private static byte[] profile(long version, long capabilities) {
        return ByteBuffer.allocate(14).order(ByteOrder.BIG_ENDIAN)
                .put(new byte[]{'P', 'Q', 'M', '1'}).putInt((int) version)
                .putInt((int) capabilities).put((byte) 0x90).put((byte) 0).array();
    }

    private static String inspect(byte[] response, List<String> log) throws Exception {
        return PqBdhCardProfile.inspect(command -> {
            assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xF8, 0, 0, 0}, command);
            return response;
        }, log::add);
    }

    @Test
    public void sendsTheExactProfileQueryAndReportsSupportedCommandsAndF7() throws Exception {
        List<String> log = new ArrayList<>();
        String description = inspect(profile(2, 0x0f), log);
        assertTrue(description.contains("PQM1 v2"));
        assertTrue(description.contains("capabilities=0x0000000F"));
        assertTrue(description.contains("CA/B2/50 advertised"));
        assertTrue(description.contains("F7 timing advertised"));
        assertEquals(1, log.size());
        assertEquals(description, log.get(0));
    }

    @Test
    public void doesNotRequireF7ForACompatibleNormalApplication() throws Exception {
        List<String> log = new ArrayList<>();
        String description = inspect(profile(2, 7), log);
        assertTrue(description.contains("CA/B2/50 advertised"));
        assertTrue(description.contains("F7 timing not advertised"));
        assertFalse(description.contains("Unverified"));
        assertEquals(description, log.get(0));
    }

    @Test
    public void retainsUnsignedCapabilityBitsForForwardCompatibleDiagnostics() throws Exception {
        String description = inspect(profile(2, 0x8000000fL), new ArrayList<>());
        assertTrue(description.contains("0x8000000F"));
        assertTrue(description.contains("F7 timing advertised"));
    }

    @Test
    public void counterDiagnosticsRequireTheirOwnAdvertisedCapability() throws Exception {
        for (int capabilities : new int[]{7, 15, 23, 31, 39, 63, 95, 127}) {
            PqBdhCardProfile.Profile result = PqBdhCardProfile.query(
                    command -> profile(2, capabilities), ignored -> { });
            assertEquals((capabilities & 8) != 0, result.timingAdvertised);
            assertEquals((capabilities & 16) != 0, result.diagnosticsAdvertised);
            assertEquals((capabilities & 32) != 0, result.sysTickAdvertised);
            assertEquals((capabilities & 64) != 0, result.pinTimingAdvertised);
        }
        PqBdhCardProfile.Profile legacy = PqBdhCardProfile.query(
                command -> new byte[]{0x6D, 0}, ignored -> { });
        assertFalse(legacy.timingAdvertised);
        assertFalse(legacy.diagnosticsAdvertised);
        assertFalse(legacy.sysTickAdvertised);
    }

    @Test
    public void eachRequiredCoreCommandMustBeAdvertised() {
        for (long capabilities : new long[]{0, 1, 2, 3, 4, 5, 6}) {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> inspect(profile(2, capabilities), new ArrayList<>()));
            assertTrue(failure.getMessage().contains("CA/B2/50"));
            assertTrue(failure.getMessage().contains("SW=9000"));
            assertTrue(failure.getMessage().contains("Card_armcortex Debug"));
        }
    }

    @Test
    public void unsupportedInstructionOrFunctionHasAnExplicitLoggedUnverifiedLegacyProfile() throws Exception {
        for (int sw : new int[]{0x6D00, 0x6A81}) {
            List<String> log = new ArrayList<>();
            String description = inspect(new byte[]{(byte) (sw >> 8), (byte) sw}, log);
            assertTrue(description.contains("Unverified card profile"));
            assertTrue(description.contains(String.format(Locale.ROOT, "SW=%04X", sw)));
            assertTrue(description.contains("original demo transport"));
            assertTrue(description.contains("skipping F7 timing queries"));
            assertTrue(description.contains("support has not been confirmed"));
            assertEquals(description, log.get(0));
        }
    }

    @Test
    public void unknownStatusWordsCannotSilentlySelectTheLegacyPath() {
        for (int sw : new int[]{0x6E00, 0x6F00, 0x6982, 0x6300}) {
            List<String> log = new ArrayList<>();
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> inspect(new byte[]{(byte) (sw >> 8), (byte) sw}, log));
            assertTrue(failure.getMessage().contains(String.format(Locale.ROOT, "SW=%04X", sw)));
            assertTrue(log.isEmpty());
        }
    }

    @Test
    public void missingTruncatedExtendedAndStatusOnlySuccessResponsesAreRejected() {
        byte[] longer = new byte[15];
        longer[13] = (byte) 0x90;
        for (byte[] response : new byte[][]{null, new byte[0], new byte[1],
                new byte[]{(byte) 0x90, 0}, longer,
                new byte[]{0, (byte) 0x6D, 0}}) {
            assertThrows(IllegalStateException.class, () -> inspect(response, new ArrayList<>()));
        }
    }

    @Test
    public void pakeFirmwareCannotBeAcceptedAsThePqBdhProfile() {
        byte[] pakeProfile = profile(2, 63);
        pakeProfile[1] = 'E';
        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> inspect(pakeProfile, new ArrayList<>()));
        assertTrue(error.getMessage().contains("expected PQM1"));
    }

    @Test
    public void wrongMagicAndUnsupportedVersionsFailClosed() {
        byte[] wrongMagic = profile(2, 15);
        wrongMagic[2] = 'B';
        assertThrows(IllegalStateException.class, () -> inspect(wrongMagic, new ArrayList<>()));
        for (long version : new long[]{0, 1, 3, 0xffffffffL}) {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> inspect(profile(version, 15), new ArrayList<>()));
            assertTrue(failure.getMessage().contains("version=" + version));
        }
    }

    @Test
    public void advertisedVersionOneIsRejectedWithPaddedProfileAndFirmwareAdvice() {
        List<String> log = new ArrayList<>();
        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> inspect(profile(1, 127), log));
        assertTrue(error.getMessage().contains("version=1"));
        assertTrue(error.getMessage().contains("padded-certificate profile 2"));
        assertTrue(error.getMessage().contains("Rebuild and flash"));
        assertTrue(log.isEmpty());
    }

    @Test
    public void transportExceptionPropagatesUnchangedWithoutLegacyLogOrRetry() {
        IOException expected = new IOException("CCID transport disconnected");
        int[] calls = {0};
        List<String> log = new ArrayList<>();
        IOException actual = assertThrows(IOException.class, () -> PqBdhCardProfile.inspect(command -> {
            calls[0]++;
            throw expected;
        }, log::add));
        assertSame(expected, actual);
        assertEquals(1, calls[0]);
        assertTrue(log.isEmpty());
    }

    @Test
    public void commandFailurePreservesRawStatusWithoutAssigningAnUnverifiedCause() {
        for (int sw : new int[]{0x6D00, 0x6E00, 0x6A81, 0x6700}) {
            String failure = PqBdhCardProfile.describeCommandFailure("NegotiateKEM CA fragment 1",
                    new byte[]{(byte) (sw >> 8), (byte) sw}, "Unverified profile from F8");
            assertTrue(failure.contains("NegotiateKEM CA fragment 1"));
            assertTrue(failure.contains(String.format(Locale.ROOT, "SW=%04X", sw)));
            assertTrue(failure.contains("does not establish what the card decoded"));
            assertTrue(failure.contains("TRACE/ECHO evidence"));
            assertFalse(failure.contains("Rebuild and flash"));
            assertFalse(failure.contains("active card does not support"));
        }
    }

    @Test
    public void missingDiagnosticContextStillReturnsAnExplicitUsefulFailure() {
        for (byte[] response : new byte[][]{null, new byte[0], new byte[1]}) {
            String failure = PqBdhCardProfile.describeCommandFailure(null, response, null);
            assertTrue(failure.contains("APDU command"));
            assertTrue(failure.contains("SW=unavailable"));
            assertTrue(failure.contains("does not establish what the card decoded"));
        }
    }
}
