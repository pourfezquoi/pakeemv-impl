package com.example.pqbdh_7816.apdu;

import java.util.Arrays;
import java.util.Locale;

/**
 * Unchained I-block exchanges with LRC protection for the selected card profile.
 * The default preserves this repository's original fixed-zero demo transport.
 * That intentional compatibility profile is not a complete T=1 implementation.
 */
public final class T1Channel {
    public enum SequenceMode {
        DEMO_FIXED_ZERO,
        ALTERNATING
    }

    public interface FrameExchange {
        byte[] send(byte[] frame) throws Exception;
    }

    private final SequenceMode sequenceMode;
    private int sendSequence;
    private int receiveSequence;
    private boolean usable = true;

    public T1Channel() {
        this(SequenceMode.DEMO_FIXED_ZERO);
    }

    /** Alternation requires an explicitly selected compatible card/reader profile. */
    public T1Channel(SequenceMode sequenceMode) {
        if (sequenceMode == null) throw new IllegalArgumentException("A sequence mode is required.");
        this.sequenceMode = sequenceMode;
    }

    /** Call after a card power-on/reset, never as a recovery for an uncertain live command. */
    public synchronized void reset() {
        sendSequence = 0;
        receiveSequence = 0;
        usable = true;
    }

    public synchronized byte[] exchange(byte[] command, FrameExchange transport) throws Exception {
        if (!usable) {
            throw new IllegalStateException("T=1 exchange state is uncertain; reconnect/reset the card before continuing.");
        }
        if (transport == null || command == null || command.length < 5 || command.length > 255) {
            throw new IllegalArgumentException("Expected an APDU of 5 to 255 bytes and a frame transport.");
        }
        byte[] frame = iBlock(command, sendSequence);
        try {
            byte[] payload = response(transport.send(frame), receiveSequence);
            // The original demo dispatches every PCB=00 request independently.
            // Only the explicitly selected alternating profile advances sequences.
            if (sequenceMode == SequenceMode.ALTERNATING) {
                sendSequence ^= 1;
                receiveSequence ^= 1;
            }
            return payload;
        } catch (Exception | Error failure) {
            // The command may already have changed card state. Do not silently replay it.
            usable = false;
            throw failure;
        }
    }

    private static byte[] iBlock(byte[] payload, int sequence) {
        byte[] frame = new byte[payload.length + 4];
        frame[0] = 0; // NAD
        frame[1] = (byte) (sequence << 6); // Bit 6 is N(S); bit 7 remains zero.
        frame[2] = (byte) payload.length;
        System.arraycopy(payload, 0, frame, 3, payload.length);
        frame[frame.length - 1] = lrc(frame);
        return frame;
    }

    private static byte[] response(byte[] frame, int expectedSequence) {
        if (frame == null || frame.length < 4) {
            throw new IllegalStateException("T=1 response is too short.");
        }
        int length = frame[2] & 255;
        if (frame.length != length + 4) {
            throw new IllegalStateException("T=1 response length does not match LEN.");
        }
        if (frame[0] != 0 || lrc(frame) != frame[frame.length - 1]) {
            throw new IllegalStateException("T=1 response has an invalid NAD or LRC.");
        }
        int pcb = frame[1] & 255;
        // Both PCB 0x00 and 0x40 are I-blocks. N(S)=1 is not an R-block.
        if ((pcb & 0x80) != 0) {
            throw new IllegalStateException(String.format(Locale.ROOT,
                    "Unsupported T=1 control block PCB=%02X; reconnect/reset the card.", pcb));
        }
        if ((pcb & 0x3F) != 0) {
            throw new IllegalStateException("Chained or reserved T=1 response flags are not supported.");
        }
        int receivedSequence = (pcb >>> 6) & 1;
        if (receivedSequence != expectedSequence) {
            throw new IllegalStateException("T=1 response sequence mismatch: expected N(S)="
                    + expectedSequence + ", received " + receivedSequence
                    + ". The response does not match the selected sequence profile; reconnect/reset the card.");
        }
        if (length < 2) {
            throw new IllegalStateException("T=1 response must contain APDU status bytes.");
        }
        return Arrays.copyOfRange(frame, 3, 3 + length);
    }

    private static byte lrc(byte[] frame) {
        byte result = 0;
        for (int i = 0; i < frame.length - 1; i++) result ^= frame[i];
        return result;
    }
}
