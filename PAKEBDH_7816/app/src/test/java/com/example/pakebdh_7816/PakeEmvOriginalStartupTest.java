package com.example.pakebdh_7816;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class PakeEmvOriginalStartupTest {
    @Test
    public void restoresTheOriginalFourCommandsWithoutF8OrF7() throws Exception {
        List<byte[]> sent = new ArrayList<>();
        PakeEmvSession.Preparation preparation = PakeEmvSession.prepareOriginal(command -> {
            sent.add(command.clone());
            return new byte[]{0x6D, 0}; // Original startup permits unsupported diagnostic/SELECT status.
        }, ignored -> { });
        assertEquals(4, sent.size());
        assertArrayEquals(new byte[]{0, (byte) 0x84, 0, 0, 8}, sent.get(0));
        assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xF0, 0, 0, 1}, sent.get(1));
        assertArrayEquals(new byte[]{0, (byte) 0xF0, 0, 0, 8}, sent.get(2));
        assertArrayEquals(hex("00A404000E315041592E5359532E444446303100"), sent.get(3));
        assertNull(preparation.baseline);
        assertTrue(preparation.cardTimingError.contains("no F8/F7 commands were sent"));
    }

    @Test
    public void uncertainTransportStopsTheComparisonWithoutRetry() {
        int[] calls = {0};
        IOException expected = new IOException("Reader transfer failed");
        assertSame(expected, assertThrows(IOException.class, () -> PakeEmvSession.prepareOriginal(command -> {
            calls[0]++; throw expected;
        }, ignored -> { })));
        assertEquals(1, calls[0]);
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
        }
        return result;
    }
}
