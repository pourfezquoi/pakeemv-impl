package com.example.pqbdh_7816.apdu;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Locale;
import org.junit.Test;

/** CCID reply fixtures validate parsing only; they do not measure an attached reader. */
public class CcidSlotStatusTest {
    @Test
    public void describesTheThreeReaderReportedIccStates() {
        String[] states = {"present and active", "present and inactive", "no ICC present"};
        for (int state = 0; state < states.length; state++) {
            String text = CcidSlotStatus.describe(reply(0, 1, state, 0, 0), 0, 1);
            assertTrue(text, text.contains("slot=0, seq=1, state=" + states[state]));
            assertTrue(text, text.contains(String.format(Locale.ROOT, "status=0x%02X; error=0x00", state)));
            assertTrue(text, text.contains("clock=running (0x00)"));
        }
    }

    @Test
    public void retainsReaderFailureBytesRatherThanReportingSuccessfulAbsence() {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(reply(0, 1, 0x42, 0xFE, 0), 0, 1));
        assertEquals("CCID GetSlotStatus command failed: status=0x42, error=0xFE", failure.getMessage());
    }

    @Test
    public void doesNotTreatAnExtensionOrReservedCommandStatusAsACompletedReply() {
        IllegalStateException extension = assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(reply(0, 1, 0x80, 2, 0), 0, 1));
        assertTrue(extension.getMessage().contains("time extension"));
        assertTrue(extension.getMessage().contains("status=0x80, error=0x02"));
        IllegalStateException reserved = assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(reply(0, 1, 0xC0, 0, 0), 0, 1));
        assertTrue(reserved.getMessage().contains("reserved command status"));
    }

    @Test
    public void reservedIccStateIsNotGuessedToMeanCardAbsent() {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(reply(0, 1, 3, 0, 0), 0, 1));
        assertTrue(failure.getMessage().contains("reserved ICC state"));
    }

    @Test
    public void preservesClockNamesAndRawClockValues() {
        String[] states = {"running", "stopped low", "stopped high", "unknown", "reserved"};
        for (int clock = 0; clock < states.length; clock++) {
            String text = CcidSlotStatus.describe(reply(0, 1, 1, 0, clock), 0, 1);
            assertTrue(text, text.endsWith(String.format(Locale.ROOT,
                    "clock=%s (0x%02X)", states[clock], clock)));
        }
        assertTrue(CcidSlotStatus.describe(reply(0, 1, 1, 0, 255), 0, 1)
                .endsWith("clock=reserved (0xFF)"));
    }

    @Test
    public void requiresTheMatchingResponseTypeSlotAndSequence() {
        byte[] wrongType = reply(0, 1, 1, 0, 0);
        wrongType[0] = (byte) 0x80;
        IllegalStateException type = assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(wrongType, 0, 1));
        assertTrue(type.getMessage().contains("type: 0x80; expected 0x81"));
        IllegalStateException slot = assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(reply(1, 1, 1, 0, 0), 0, 1));
        assertTrue(slot.getMessage().contains("slot mismatch"));
        IllegalStateException sequence = assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(reply(0, 2, 1, 0, 0), 0, 1));
        assertTrue(sequence.getMessage().contains("sequence mismatch"));
    }

    @Test
    public void rejectsEveryTruncatedHeaderAndNullReply() {
        assertThrows(IllegalStateException.class, () -> CcidSlotStatus.describe(null, 0, 1));
        byte[] full = reply(0, 1, 1, 0, 0);
        for (int length = 0; length < 10; length++) {
            byte[] shortReply = Arrays.copyOf(full, length);
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> CcidSlotStatus.describe(shortReply, 0, 1));
            assertTrue(failure.getMessage().contains("short response"));
        }
    }

    @Test
    public void rejectsPayloadsPaddingAndUnsignedOversizedLengthClaims() {
        byte[] withPayload = Arrays.copyOf(reply(0, 1, 1, 0, 0), 11);
        withPayload[1] = 1;
        assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(withPayload, 0, 1));
        byte[] padded = Arrays.copyOf(reply(0, 1, 1, 0, 0), 11);
        assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(padded, 0, 1));
        byte[] oversized = reply(0, 1, 1, 0, 0);
        Arrays.fill(oversized, 1, 5, (byte) 0xFF);
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> CcidSlotStatus.describe(oversized, 0, 1));
        assertTrue(failure.getMessage().contains("payload=4294967295"));
    }

    @Test
    public void handlesUnsignedBoundaryIdentifiersUnderAnyLocale() {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("ar"));
            String text = CcidSlotStatus.describe(reply(255, 255, 1, 0, 0), 255, 255);
            assertTrue(text.contains("slot=255, seq=255"));
            assertTrue(text.contains("status=0x01; error=0x00"));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    public void expectedSlotAndSequenceMustBeUnsignedBytes() {
        for (int invalid : new int[]{-1, 256}) {
            assertThrows(IllegalArgumentException.class,
                    () -> CcidSlotStatus.describe(reply(0, 1, 1, 0, 0), invalid, 1));
            assertThrows(IllegalArgumentException.class,
                    () -> CcidSlotStatus.describe(reply(0, 1, 1, 0, 0), 0, invalid));
        }
    }

    private static byte[] reply(int slot, int seq, int status, int error, int clock) {
        return new byte[]{(byte) 0x81, 0, 0, 0, 0, (byte) slot, (byte) seq,
                (byte) status, (byte) error, (byte) clock};
    }
}
