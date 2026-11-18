package com.example.pakebdh_7816;

import java.lang.reflect.Field;
import java.util.Arrays;

/** Actual Java -> JNI -> pinned CHIC integration; the responder exists only in this host fixture. */
public final class ChicJniIntegrationTest {
    static { System.loadLibrary("chic-test-peer"); }
    private static native byte[] respond(byte[] msg1, byte[] password, byte[] sid);
    private static int assertions;

    public static void main(String[] args) throws Exception {
        byte[] password = pattern(32, 10);
        byte[] sid = pattern(32, 90);
        checkFailure(IllegalArgumentException.class, () -> ChicPake.start(new byte[31], sid));
        checkFailure(IllegalArgumentException.class, () -> ChicPake.start(password, null));
        for (int iteration = 0; iteration < 5; iteration++) {
            try (ChicPake.Pending pending = ChicPake.start(password, sid)) {
                byte[] message = pending.firstMessage();
                byte[] peer = respond(message, password, sid);
                message[0] ^= 1; // Caller receives a copy, not the retained transcript.
                byte[] key = pending.finish(Arrays.copyOfRange(peer, 32, peer.length));
                check(Arrays.equals(key, Arrays.copyOf(peer, 32)), "Java and C keys differ");
                checkErased(pending);
                checkFailure(IllegalStateException.class, () -> pending.finish(Arrays.copyOfRange(peer, 32, peer.length)));
                checkFailure(IllegalStateException.class, pending::firstMessage);
                Arrays.fill(key, (byte) 0);
                Arrays.fill(peer, (byte) 0);
            }
        }
        for (int changed : new int[]{0, 31, 32, 799}) {
            ChicPake.Pending pending = ChicPake.start(password, sid);
            byte[] peer = respond(pending.firstMessage(), password, sid);
            byte[] response = Arrays.copyOfRange(peer, 32, peer.length);
            response[changed] ^= 1;
            checkFailure(SecurityException.class, () -> pending.finish(response));
            checkErased(pending);
        }
        for (String field : new String[]{"msg1", "pk", "sk", "sid"}) {
            ChicPake.Pending pending = ChicPake.start(password, sid);
            byte[] peer = respond(pending.firstMessage(), password, sid);
            Field state = ChicPake.Pending.class.getDeclaredField(field);
            state.setAccessible(true);
            byte[] saved = (byte[]) state.get(pending);
            saved[0] ^= 1;
            checkFailure(SecurityException.class, () -> pending.finish(Arrays.copyOfRange(peer, 32, peer.length)));
            checkErased(pending);
        }
        for (boolean wrongSid : new boolean[]{false, true}) {
            ChicPake.Pending pending = ChicPake.start(password, sid);
            byte[] otherPassword = password.clone(), otherSid = sid.clone();
            if (wrongSid) otherSid[2] ^= 1; else otherPassword[2] ^= 1;
            byte[] peer = respond(pending.firstMessage(), otherPassword, otherSid);
            checkFailure(SecurityException.class, () -> pending.finish(Arrays.copyOfRange(peer, 32, peer.length)));
            checkErased(pending);
        }
        ChicPake.Pending truncated = ChicPake.start(password, sid);
        checkFailure(IllegalArgumentException.class, () -> truncated.finish(new byte[768]));
        checkErased(truncated);
        ChicPake.Pending abandoned = ChicPake.start(password, sid);
        abandoned.close();
        abandoned.close();
        checkErased(abandoned);
        System.out.println("CHIC Java/JNI integration passed: " + assertions + " assertions.");
    }

    private static void checkErased(ChicPake.Pending pending) throws Exception {
        for (String name : new String[]{"msg1", "pk", "sk", "sid"}) {
            Field field = ChicPake.Pending.class.getDeclaredField(name);
            field.setAccessible(true);
            byte[] bytes = (byte[]) field.get(pending);
            check(Arrays.equals(bytes, new byte[bytes.length]), "Retained " + name + " was not erased");
        }
    }

    private static byte[] pattern(int size, int start) {
        byte[] value = new byte[size];
        for (int i = 0; i < size; i++) value[i] = (byte) (start + i);
        return value;
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private static void checkFailure(Class<? extends Throwable> type, Runnable operation) {
        assertions++;
        try { operation.run(); }
        catch (Throwable failure) {
            if (type.isInstance(failure)) return;
            throw new AssertionError("Expected " + type.getName(), failure);
        }
        throw new AssertionError("Expected " + type.getName());
    }
}
