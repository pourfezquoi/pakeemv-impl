package com.example.pqbdh_7816.apdu;

import java.util.Locale;

/** Decode a completed reader GetSlotStatus reply; this does not activate a card. */
public final class CcidSlotStatus {
    private CcidSlotStatus() { }

    public static String describe(byte[] response, int expectedSlot, int expectedSeq) {
        requireByte(expectedSlot, "Slot");
        requireByte(expectedSeq, "Sequence");
        if (response == null || response.length < 10) {
            throw new IllegalStateException("CCID GetSlotStatus short response: received "
                    + (response == null ? "null" : response.length + " bytes")
                    + "; need 10 bytes");
        }
        int type = response[0] & 255;
        int slot = response[5] & 255;
        int seq = response[6] & 255;
        if (type != 0x81) {
            throw new IllegalStateException(String.format(Locale.ROOT,
                    "Unexpected CCID GetSlotStatus response type: 0x%02X; expected 0x81", type));
        }
        if (slot != expectedSlot) {
            throw new IllegalStateException("CCID GetSlotStatus slot mismatch: "
                    + slot + "; expected " + expectedSlot);
        }
        if (seq != expectedSeq) {
            throw new IllegalStateException("CCID GetSlotStatus sequence mismatch: "
                    + seq + "; expected " + expectedSeq);
        }
        long payload = (response[1] & 255L) | ((response[2] & 255L) << 8)
                | ((response[3] & 255L) << 16) | ((response[4] & 255L) << 24);
        if (payload != 0 || response.length != 10) {
            throw new IllegalStateException("CCID GetSlotStatus must have zero payload and exactly 10 bytes: "
                    + "payload=" + payload + ", received=" + response.length + " bytes");
        }
        int status = response[7] & 255;
        int error = response[8] & 255;
        String raw = String.format(Locale.ROOT, "status=0x%02X, error=0x%02X", status, error);
        int command = (status >>> 6) & 3;
        if (command == 1) {
            throw new IllegalStateException("CCID GetSlotStatus command failed: " + raw);
        }
        if (command == 2) {
            throw new IllegalStateException("CCID GetSlotStatus time extension is unsupported: " + raw);
        }
        if (command == 3) {
            throw new IllegalStateException("CCID GetSlotStatus reserved command status: " + raw);
        }
        String state;
        switch (status & 3) {
            case 0: state = "present and active"; break;
            case 1: state = "present and inactive"; break;
            case 2: state = "no ICC present"; break;
            default:
                throw new IllegalStateException("CCID GetSlotStatus reserved ICC state: " + raw);
        }
        int clock = response[9] & 255;
        String clockState;
        switch (clock) {
            case 0: clockState = "running"; break;
            case 1: clockState = "stopped low"; break;
            case 2: clockState = "stopped high"; break;
            case 3: clockState = "unknown"; break;
            default: clockState = "reserved"; break;
        }
        return String.format(Locale.ROOT,
                "CCID slot status before power-on: slot=%d, seq=%d, state=%s; "
                        + "status=0x%02X; error=0x%02X; clock=%s (0x%02X)",
                slot, seq, state, status, error, clockState, clock);
    }

    private static void requireByte(int value, String name) {
        if (value < 0 || value > 255) {
            throw new IllegalArgumentException(name + " must be an unsigned byte");
        }
    }
}
