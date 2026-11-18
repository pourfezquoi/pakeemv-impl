package com.example.pakebdh_7816;

import java.util.Arrays;

/** JNI adapter to the pinned authors' CHIC implementation, not a Java substitute. */
final class ChicPake {
    static final int KEY_BYTES = 32;
    static final int TAG_BYTES = 32;
    static final int FIRST_MESSAGE_BYTES = 800;
    static final int RESPONSE_BYTES = 800;
    private static final int SECRET_KEY_BYTES = 1632;

    private ChicPake() { }

    static void ensureAvailable() {
        Native.ensureLoaded();
    }

    static Pending start(byte[] password, byte[] sid) {
        requireLength(password, KEY_BYTES, "CHIC password input");
        requireLength(sid, KEY_BYTES, "CHIC SID");
        Pending pending = new Pending(sid);
        try {
            Native.initStart(pending.msg1, pending.pk, pending.sk, password, pending.sid);
            return pending;
        } catch (RuntimeException | Error failed) {
            pending.close();
            throw failed;
        }
    }

    /** Owns exactly one initStart/initEnd activation and erases it on every exit. */
    static final class Pending implements AutoCloseable {
        private final byte[] msg1 = new byte[FIRST_MESSAGE_BYTES];
        private final byte[] pk = new byte[FIRST_MESSAGE_BYTES];
        private final byte[] sk = new byte[SECRET_KEY_BYTES];
        private final byte[] sid;
        private boolean closed;

        private Pending(byte[] sid) {
            this.sid = sid.clone();
        }

        synchronized byte[] firstMessage() {
            requireOpen();
            return msg1.clone();
        }

        synchronized byte[] finish(byte[] response) {
            requireOpen();
            try {
                requireLength(response, RESPONSE_BYTES, "CHIC response (tag || ciphertext)");
                // Native initEnd returns a key only after its constant-time tag check succeeds.
                return Native.initEnd(response, msg1, pk, sk, sid);
            } finally {
                close();
            }
        }

        private void requireOpen() {
            if (closed) throw new IllegalStateException("CHIC activation has already finished or closed.");
        }

        @Override public synchronized void close() {
            Arrays.fill(msg1, (byte) 0);
            Arrays.fill(pk, (byte) 0);
            Arrays.fill(sk, (byte) 0);
            Arrays.fill(sid, (byte) 0);
            closed = true;
        }
    }

    private static void requireLength(byte[] input, int expected, String name) {
        if (input == null || input.length != expected) {
            throw new IllegalArgumentException(name + " must contain " + expected + " bytes.");
        }
    }

    // The library loads on first cryptographic activation, outside pure transport tests.
    private static final class Native {
        static { System.loadLibrary("chic-jni"); }

        static void ensureLoaded() { }

        static native void initStart(byte[] msg1, byte[] pk, byte[] sk, byte[] password, byte[] sid);
        static native byte[] initEnd(byte[] response, byte[] msg1, byte[] pk, byte[] sk, byte[] sid);
    }
}
