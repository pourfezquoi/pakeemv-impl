package com.example.pakebdh_7816.protocol;

import com.example.pakebdh_7816.UsbCcidTransport;
import com.example.pakebdh_7816.apdu.ApduCodec;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.function.Consumer;

public final class NegotiateKemStep {
    // Reader transport limit is ~271 bytes total. Keep APDU command body safely below that.
    // APDU wrapper overhead in short APDU mode is 6 bytes (CLA INS P1 P2 Lc Le).
    private static final int MAX_FRAGMENT_DATA_LEN = 240;
    private static final int APDU_READ_TIMEOUT_MS_DEFAULT = 15000;
    private static final int APDU_READ_TIMEOUT_MS_FINAL_FRAGMENT = 60000;
    private static final byte[] PREFLIGHT_APDU = new byte[]{(byte) 0x80, (byte) 0xF0, 0x00, 0x00, 0x01};
    private static final byte[] TRACE_LAST_CMD_APDU = new byte[]{(byte) 0x80, (byte) 0xF1, 0x00, 0x00, 0x05};
    private static final byte[] ECHO_PROBE_APDU = new byte[]{(byte) 0x80, (byte) 0xF2, (byte) 0xA5, 0x5A, 0x00};

    private NegotiateKemStep() {
    }

    public static byte[] execute(UsbCcidTransport transport, byte[] terminalPublicKey, Consumer<String> statusLogger) {
        if (terminalPublicKey == null || terminalPublicKey.length == 0) {
            throw new IllegalArgumentException("Terminal public key is empty.");
        }
        runPreflightApdu(transport, statusLogger);
        return executeFragmented(transport, terminalPublicKey, statusLogger);
    }

    private static void runPreflightApdu(UsbCcidTransport transport, Consumer<String> statusLogger) {
        statusLogger.accept("3.9 Preflight APDU check (80 F0 00 00 01)...");
        byte[] resp;
        try {
            resp = transport.sendApdu(PREFLIGHT_APDU);
        } catch (Exception e) {
            String diag = diagnosePreflightTimeout(transport, statusLogger);
            throw new IllegalStateException("Preflight APDU transport error: " + e.getMessage() + " | " + diag, e);
        }
        if (resp == null || resp.length < 2) {
            throw new IllegalStateException("Preflight APDU empty response.");
        }
        byte sw1 = resp[resp.length - 2];
        byte sw2 = resp[resp.length - 1];
        if (sw1 != (byte) 0x90 || sw2 != (byte) 0x00) {
            throw new IllegalStateException("Preflight APDU SW=" + String.format("%02X%02X", sw1, sw2));
        }
        statusLogger.accept("3.9 Preflight APDU OK (payload=" + (resp.length - 2) + " bytes).");
    }

    private static byte[] executeFragmented(UsbCcidTransport transport, byte[] terminalPublicKey, Consumer<String> statusLogger) {

        int totalFragments = (terminalPublicKey.length + MAX_FRAGMENT_DATA_LEN - 1) / MAX_FRAGMENT_DATA_LEN;
        statusLogger.accept("4. Sending NegotiateKEM APDU... (" + totalFragments + " fragment(s), size=240)");

        int offset = 0;
        int fragmentIndex = 0;
        while (offset < terminalPublicKey.length) {
            fragmentIndex++;
            int remaining = terminalPublicKey.length - offset;
            int chunkLen = Math.min(MAX_FRAGMENT_DATA_LEN, remaining);
            boolean hasMore = (offset + chunkLen) < terminalPublicKey.length;

            byte[] fragment = Arrays.copyOfRange(terminalPublicKey, offset, offset + chunkLen);
            int cla = 0x80;
            int p1 = hasMore ? 0x01 : 0x00; // Use P1 continuation flag for compatibility with readers/cards.
            statusLogger.accept("4." + fragmentIndex + " Sending NegotiateKEM fragment " + fragmentIndex + "/" + totalFragments +
                    " (" + chunkLen + " bytes, more=" + hasMore + ")...");
            byte[] apdu = ApduCodec.buildCommandApduNoLe(cla, 0xCA, p1, 0x00, fragment);
            statusLogger.accept("4." + fragmentIndex + " APDU: " + toHex(apdu));
            byte[] response;
            try {
                int readTimeoutMs = hasMore ? APDU_READ_TIMEOUT_MS_DEFAULT : APDU_READ_TIMEOUT_MS_FINAL_FRAGMENT;
                response = sendApduWithTimeout(transport, apdu, readTimeoutMs);
            } catch (Exception transportError) {
                if (fragmentIndex == 1 || !hasMore) {
                    logCardLastCommand(transport, statusLogger);
                }
                throw new IllegalStateException("NegotiateKEM fragment " + fragmentIndex +
                        " transport error: " + transportError.getMessage(), transportError);
            }
            if (response == null || response.length < 2) {
                throw new IllegalStateException("Empty response for NegotiateKEM fragment " + fragmentIndex + ".");
            }

            byte sw1 = response[response.length - 2];
            byte sw2 = response[response.length - 1];
            boolean isSuccess = (sw1 == (byte) 0x90 && sw2 == (byte) 0x00);
            boolean hasMoreResponse = (sw1 == (byte) 0x61);
            if (!isSuccess && !hasMoreResponse) {
                throw new IllegalStateException("NegotiateKEM fragment " + fragmentIndex + " SW=" +
                        String.format("%02X%02X", sw1, sw2));
            }

            if (hasMore) {
                statusLogger.accept("4." + fragmentIndex + " Card ACK received for fragment " + fragmentIndex + ".");
                offset += chunkLen;
                continue;
            }

            return collectCiphertextFragments(transport, response, statusLogger);
        }

        throw new IllegalStateException("NegotiateKEM did not send any fragment.");
    }

    private static byte[] sendApduWithTimeout(UsbCcidTransport transport, byte[] apdu, int readTimeoutMs) throws Exception {
        try {
            Method m = UsbCcidTransport.class.getMethod("sendApdu", byte[].class, int.class);
            Object response = m.invoke(transport, apdu, readTimeoutMs);
            return (byte[]) response;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw new IllegalStateException("timeout-aware sendApdu failed", cause);
        } catch (NoSuchMethodException e) {
            // Backward-compatible fallback for branches where only sendApdu(byte[]) exists.
            return transport.sendApdu(apdu);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to invoke timeout-aware sendApdu", e);
        }
    }

    private static byte[] collectCiphertextFragments(
            UsbCcidTransport transport,
            byte[] firstResponse,
            Consumer<String> statusLogger
    ) {
        ByteArrayOutputStream ct = new ByteArrayOutputStream();
        byte[] response = firstResponse;
        int part = 1;

        while (true) {
            if (response.length < 2) {
                throw new IllegalStateException("NegotiateKEM ct fragment response too short.");
            }

            byte[] payload = Arrays.copyOf(response, response.length - 2);
            if (payload.length > 0) {
                ct.write(payload, 0, payload.length);
            }

            byte sw1 = response[response.length - 2];
            byte sw2 = response[response.length - 1];
            if (sw1 == (byte) 0x90 && sw2 == (byte) 0x00) {
                byte[] fullCt = ct.toByteArray();
                if (fullCt.length == 0) {
                    throw new IllegalStateException("Card returned empty ct payload (SW=9000).");
                }
                return fullCt;
            }
            if (sw1 != (byte) 0x61) {
                throw new IllegalStateException("Unexpected SW while receiving ct: " +
                        String.format("%02X%02X", sw1, sw2));
            }

            part++;
            statusLogger.accept("4.ct Requesting next ciphertext fragment part " + part + "...");
            byte[] ackApdu = ApduCodec.buildCommandApduNoLe(0x80, 0xCA, 0x01, 0x00, null);
            try {
                response = transport.sendApdu(ackApdu);
            } catch (Exception transportError) {
                throw new IllegalStateException("Transport error while requesting next ct fragment: "
                        + transportError.getMessage(), transportError);
            }
        }
    }

    private static void logCardLastCommand(UsbCcidTransport transport, Consumer<String> statusLogger) {
        byte[] traceResp = queryLastCommandTrace(transport);
        if (traceResp == null) {
            statusLogger.accept("diag TRACE_LAST_CMD failed: no response.");
            return;
        }
        if (traceResp.length < 7) {
            statusLogger.accept("diag TRACE_LAST_CMD unavailable (short response).");
            return;
        }
        int payloadLen = traceResp.length - 2;
        if (payloadLen < 5) {
            statusLogger.accept("diag TRACE_LAST_CMD payload too short: " + payloadLen);
            return;
        }
        String trace = String.format("%02X %02X %02X %02X %02X",
                traceResp[0] & 0xFF, traceResp[1] & 0xFF, traceResp[2] & 0xFF,
                traceResp[3] & 0xFF, traceResp[4] & 0xFF);
        statusLogger.accept("diag TRACE_LAST_CMD (CLA INS P1 P2 Lc): " + trace);
        if ((traceResp[0] & 0xFF) == 0x80 && (traceResp[1] & 0xFF) == 0xF1) {
            statusLogger.accept("diag note: last_cmd=80 F1; if repeated, card firmware may still be overwriting last_cmd during TRACE.");
        }
    }

    private static String diagnosePreflightTimeout(UsbCcidTransport transport, Consumer<String> statusLogger) {
        byte[] traceResp = queryLastCommandTrace(transport);
        if (traceResp != null && traceResp.length >= 7) {
            statusLogger.accept("diag: TRACE_LAST_CMD received.");
        } else {
            statusLogger.accept("diag: TRACE_LAST_CMD unavailable (" + summarizeDiagResponse(traceResp, 5) + ").");
        }

        byte[] echoResp = queryEchoProbe(transport);
        if (isEchoProbeSuccess(echoResp)) {
            statusLogger.accept("diag: ECHO probe round-trip OK.");
            return "diag: control APDU round-trip is healthy; likely issue is specific to preflight handling path";
        }

        if (traceResp == null || traceResp.length < 7) {
            return "diag: TRACE/ECHO unavailable -> " + summarizeUnavailableDiagnostics(traceResp, echoResp);
        }
        int lastCla = traceResp[0] & 0xFF;
        int lastIns = traceResp[1] & 0xFF;
        if (lastCla == 0x80 && lastIns == 0xF0) {
            statusLogger.accept("diag: card reports last cmd=80 F0 -> card received preflight request.");
            return "diag: likely (1) terminal did not receive response, or (2) card/reader failed while sending response";
        }
        if (lastCla == 0x80 && lastIns == 0xF2) {
            statusLogger.accept("diag: card reports last cmd=80 F2 (echo) -> request path is OK, response path unstable.");
            return "diag: likely (1) terminal read-side issue or (2) card/reader response loss";
        }
        statusLogger.accept("diag: card last cmd is not preflight (" + String.format("%02X %02X", lastCla, lastIns) + ").");
        return "diag: likely (3) card did not receive preflight request";
    }

    private static byte[] queryLastCommandTrace(UsbCcidTransport transport) {
        try {
            return transport.sendApdu(TRACE_LAST_CMD_APDU);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static byte[] queryEchoProbe(UsbCcidTransport transport) {
        try {
            return transport.sendApdu(ECHO_PROBE_APDU);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean isEchoProbeSuccess(byte[] response) {
        if (response == null || response.length != 4) {
            return false;
        }
        return (response[0] == (byte) 0xA5)
                && (response[1] == 0x5A)
                && (response[2] == (byte) 0x90)
                && (response[3] == 0x00);
    }

    private static String summarizeUnavailableDiagnostics(byte[] traceResp, byte[] echoResp) {
        return "TRACE[" + summarizeDiagResponse(traceResp, 5) + "], ECHO[" + summarizeDiagResponse(echoResp, 2) + "]";
    }

    private static String summarizeDiagResponse(byte[] response, int minPayloadLen) {
        if (response == null) {
            return "no response";
        }
        if (response.length < 2) {
            return "too short (" + response.length + "B)";
        }
        int payloadLen = response.length - 2;
        int sw1 = response[response.length - 2] & 0xFF;
        int sw2 = response[response.length - 1] & 0xFF;
        String sw = String.format("%02X%02X", sw1, sw2);

        if (payloadLen < minPayloadLen) {
            if (sw1 == 0x6D) {
                return "SW=" + sw + " (INS not supported; likely card firmware without this diagnostic INS)";
            }
            if (sw1 == 0x6E) {
                return "SW=" + sw + " (CLA not supported for vendor diagnostics)";
            }
            return "SW=" + sw + ", payload=" + payloadLen + "B";
        }
        return "SW=" + sw + ", payload=" + payloadLen + "B";
    }

    private static String toHex(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}
