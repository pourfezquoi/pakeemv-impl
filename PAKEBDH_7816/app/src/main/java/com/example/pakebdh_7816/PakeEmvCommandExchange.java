package com.example.pakebdh_7816;

import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Exchange;
import java.util.Arrays;
import java.util.Locale;

/** Public command metadata only; success exchanges add no logging or diagnostic APDUs. */
final class PakeEmvCommandExchange implements Exchange {
    static final class RejectedCommandException extends IllegalStateException {
        final byte[] header;

        RejectedCommandException(String operation, byte[] command, byte[] response) {
            super(PakeEmvCardProfile.describeCommandFailure(operation, response, null));
            header = Arrays.copyOf(command, 5);
        }
    }

    private final Exchange transport;
    private String phase = "Protocol";
    private int ordinal;

    PakeEmvCommandExchange(Exchange transport) {
        if (transport == null) throw new IllegalArgumentException("An APDU exchange is required.");
        this.transport = transport;
    }

    void beginPhase(String phase) {
        this.phase = phase;
        ordinal = 0;
    }

    @Override public boolean isCpuIsolated() {
        return transport.isCpuIsolated();
    }

    @Override public long ioThreadId() {
        return transport.ioThreadId();
    }

    @Override public byte[] send(byte[] command) throws Exception {
        if (command == null || command.length < 5) {
            throw new IllegalArgumentException("A five-byte public command header is required.");
        }
        int number = ++ordinal;
        byte[] response;
        try {
            response = transport.send(command);
        } catch (IllegalStateException failure) {
            throw new IllegalStateException(phase + " APDU #" + number + ": " + failure.getMessage(),
                    failure);
        }
        if (response == null || response.length < 2) {
            throw new IllegalStateException(phase + " APDU #" + number + " returned a short response.");
        }
        int sw = ((response[response.length - 2] & 255) << 8) | (response[response.length - 1] & 255);
        if (sw == 0x6D00 || sw == 0x6E00) {
            String operation = String.format(Locale.ROOT,
                    "%s APDU #%d: header=%02X %02X %02X %02X %02X, command=%d B, data=%d B",
                    phase, number, command[0] & 255, command[1] & 255, command[2] & 255,
                    command[3] & 255, command[4] & 255, command.length, command.length - 5);
            throw new RejectedCommandException(operation, command, response);
        }
        return response;
    }
}
