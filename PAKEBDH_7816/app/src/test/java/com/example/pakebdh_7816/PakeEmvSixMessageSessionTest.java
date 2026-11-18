package com.example.pakebdh_7816;

import static org.junit.Assert.*;

import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Clock;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Exchange;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

/** Real transcript/KDF/AE primitives, with injectable CHIC/KEM/certificate boundaries. */
public class PakeEmvSixMessageSessionTest {
    private static final String PAN = PakeEmvBenchmarkConfig.EXPECTED_PAN;
    private static final String OTHER_PAN = "4502123456789013";
    private static final byte[] TK = pattern(32, 20), SS = pattern(32, 80);
    private static final byte[] PK_C = pattern(800, 2), PK_IS = pattern(1312, 4);
    private static final byte[] E_CERT = pattern(8220, 18), CT = pattern(768, 14);

    @Test public void completesInit1ToInit4WithExactSixMessagesAndNoDiagnosticProof() throws Exception {
        Fixture f = new Fixture();
        PakeEmvSession.Result result = f.handshake(PAN);
        assertTrue(result.accepted);
        assertEquals(46, result.total().apduCount);
        assertEquals(1724, result.total().logicalT2c);
        assertEquals(9052, result.total().logicalC2t);
        assertEquals(1954, result.total().commandBytes);
        assertEquals(9144, result.total().responseBytes);
        assertEquals(64, f.card.lastM3.length);
        assertEquals(828, f.card.lastM5.length);
        assertArrayEquals(f.card.finalKey, result.recordedKey.copy());
        assertEquals(0x50, f.card.instructions.get(f.card.instructions.size() - 1).intValue());
        assertFalse(f.card.instructions.contains(0xF4));
        assertEquals(1, f.backend.closedStates);
        assertTrue(f.card.preM6SecretsErased);
    }

    @Test public void referenceMismatchSendsIdenticalM5AndRetainsSameKeyUntilLocalInit4Reject() throws Exception {
        Fixture matching = new Fixture(), mismatch = new Fixture();
        PakeEmvSession.Result accepted = matching.handshake(PAN), rejected = mismatch.handshake(OTHER_PAN);
        assertTrue(accepted.accepted);
        assertFalse(rejected.accepted);
        assertArrayEquals(matching.card.lastM5, mismatch.card.lastM5);
        assertArrayEquals(accepted.recordedKey.copy(), rejected.recordedKey.copy());
        assertEquals(matching.card.instructions, mismatch.card.instructions);
        assertEquals(46, mismatch.card.instructions.size());
        assertEquals(1, mismatch.card.m6Responses);
        String report = PakeEmvResultText.format(rejected);
        assertFalse(report.contains("Session keys match"));
        assertTrue(report.contains("Reference PAN does not match"));
        assertTrue(report.contains("Final confirmation (pi3) passed"));
        assertFalse(report.contains(OTHER_PAN));
    }

    @Test public void badPi2AndBadPi3RejectAfterM5AndRetainRecordedKey() throws Exception {
        for (boolean pi2 : new boolean[]{true, false}) {
            Fixture f = new Fixture(); f.card.corruptPi2 = pi2; f.card.corruptPi3 = !pi2;
            PakeEmvSession.Result result = f.handshake(PAN);
            assertFalse(result.accepted);
            assertNotNull(result.recordedKey);
            assertEquals(32, result.recordedKey.copy().length);
            assertEquals(46, f.card.instructions.size());
            assertEquals(0x50, f.card.instructions.get(45).intValue());
            assertTrue(result.rejectionReason.contains("Reference PAN matched"));
            assertTrue(result.rejectionReason.contains(pi2
                    ? "Card rejected M5 (SW=6982)" : "Final confirmation (pi3) failed verification"));
        }
    }

    @Test public void wrongPanAndBadPi3AreBothReportedLocally() throws Exception {
        Fixture f = new Fixture();
        f.card.corruptPi3 = true;
        PakeEmvSession.Result result = f.handshake(OTHER_PAN);
        assertFalse(result.accepted);
        assertTrue(result.rejectionReason.contains("Reference PAN does not match"));
        assertTrue(result.rejectionReason.contains("Final confirmation (pi3) failed verification"));
        assertEquals(46, f.card.instructions.size());
    }

    @Test public void pi3MustBeExactly32BytesAndStatus9000() throws Exception {
        for (int length : new int[]{0, 31, 33}) {
            Fixture f = new Fixture(); f.card.pi3Length = length;
            PakeEmvSession.Result result = f.handshake(PAN);
            assertFalse(result.accepted);
            assertNotNull(result.recordedKey);
            assertEquals(46, f.card.instructions.size());
            assertTrue(result.rejectionReason.contains("Invalid M6 payload length"));
            assertTrue(result.rejectionReason.contains("received " + length));
        }
    }

    @Test public void postM5TransportFailureCarriesTheIndependentKeyRecord() throws Exception {
        Fixture f = new Fixture(); f.card.dropM6 = true;
        PakeEmvSession.FinalOutcomeException failure = assertThrows(PakeEmvSession.FinalOutcomeException.class,
                () -> f.handshake(PAN));
        assertNotNull(failure.recordedKey);
        assertArrayEquals(f.card.finalKey, failure.recordedKey.copy());
        assertEquals(46, f.card.instructions.size());
    }

    @Test public void badChicTagIsFatalWithoutM3OrPinRetry() {
        Fixture f = new Fixture(); f.backend.badChicTag = true;
        assertThrows(SecurityException.class, () -> f.transaction(PAN, false));
        assertEquals(1, f.pinRequests);
        assertEquals(1, f.card.beginTransactions);
        assertFalse(f.card.instructions.contains(0xB2));
        assertEquals(1, f.backend.closedStates);
    }

    @Test public void explicitRetryKeepsReferencePanAndBeginsTransactionOnlyOnce() throws Exception {
        Fixture f = new Fixture(); f.card.retries = 2;
        PakeEmvSession.Result result = f.transaction(OTHER_PAN, false);
        assertFalse(result.accepted);
        assertEquals(3, f.pinRequests);
        assertEquals(1, f.card.beginTransactions);
        assertEquals(3, f.card.firstMessages.size());
        assertFalse(Arrays.equals(f.card.firstMessages.get(0), f.card.firstMessages.get(1)));
        assertFalse(Arrays.equals(f.card.firstMessages.get(1), f.card.firstMessages.get(2)));
        assertFalse(Arrays.equals(f.backend.passwords.get(0), f.backend.passwords.get(1)));
        assertEquals(3, f.backend.closedStates);
        assertEquals(1, f.card.m6Responses);
    }

    @Test public void moreThanTwoRetryRequestsTerminateWithoutAFourthPin() {
        Fixture f = new Fixture(); f.card.retries = 3;
        assertThrows(IllegalStateException.class, () -> f.transaction(PAN, false));
        assertEquals(3, f.pinRequests);
        assertEquals(1, f.card.beginTransactions);
        assertEquals(0, f.card.m6Responses);
    }

    @Test public void malformedRetryAndCertificateFailureNeverRequestAnotherPinOrM5() {
        Fixture malformed = new Fixture(); malformed.card.malformedRetry = true;
        assertThrows(IllegalStateException.class, () -> malformed.transaction(PAN, false));
        assertEquals(1, malformed.pinRequests);
        assertFalse(malformed.card.instructions.contains(0x50));
        Fixture invalidCert = new Fixture(); invalidCert.backend.badCredentials = true;
        assertThrows(SecurityException.class, () -> invalidCert.transaction(PAN, false));
        assertEquals(1, invalidCert.pinRequests);
        assertFalse(invalidCert.card.instructions.contains(0x50));
    }

    @Test public void invalidExpectedPanStopsBeforeAnyPeerExchangeOrPinInput() {
        Fixture f = new Fixture();
        assertThrows(IllegalArgumentException.class, () -> f.transaction("", false));
        assertEquals(0, f.card.instructions.size());
        assertEquals(0, f.pinRequests);
    }

    @Test public void optionalMeasurementAfterClosedProtocolIsIdenticalForBothFinalOutcomes() throws Exception {
        Fixture good = new Fixture(), bad = new Fixture();
        PakeEmvSession.Result accepted = good.transaction(PAN, true);
        PakeEmvSession.Result rejected = bad.transaction(OTHER_PAN, true);
        assertTrue(accepted.accepted); assertFalse(rejected.accepted);
        assertTrue(accepted.hasCardTiming()); assertTrue(rejected.hasCardTiming());
        assertEquals(good.card.instructions, bad.card.instructions);
        assertEquals(0xF7, good.card.instructions.get(good.card.instructions.size() - 1).intValue());
        assertEquals(1, good.card.postM6Diagnostics);
        assertEquals(1, bad.card.postM6Diagnostics);
    }

    private static final class Fixture {
        final Backend backend = new Backend();
        final Card card = new Card(backend);
        final FakeClock clock = new FakeClock();
        int pinRequests;
        PakeEmvSession.Result handshake(String pan) throws Exception {
            return PakeEmvSession.runHandshake(card, "123456", pan, clock,
                    new PakeEmvSession.Preparation(null, "test", "timing excluded"), ignored -> { }, backend);
        }
        PakeEmvSession.Result transaction(String pan, boolean timing) throws Exception {
            card.advertiseTiming = timing;
            return PakeEmvSession.runTransaction(card, pan, () -> {
                pinRequests++;
                return String.format(java.util.Locale.ROOT, "%06d", 123455 + pinRequests);
            }, clock, PakeEmvSession.RunMode.OPTIONAL_TIMING, ignored -> { }, backend);
        }
    }

    private static final class FakeClock implements Clock {
        long wall, cpu;
        @Override public long wallNs() { return wall += 1_000_000; }
        @Override public long cpuNs() { return cpu += 1000; }
    }

    private static final class Backend implements PakeEmvSession.Backend {
        boolean badChicTag, badCredentials;
        int randomCounter, generation, closedStates;
        byte[] tkReference, certKeyReference, ecKeyReference, ssReference;
        final List<byte[]> passwords = new ArrayList<>();
        @Override public PakeEmvSession.PakeState start(byte[] password, byte[] sid) {
            passwords.add(password.clone());
            byte[] first = pattern(800, ++generation);
            return new PakeEmvSession.PakeState() {
                @Override public byte[] firstMessage() { return first.clone(); }
                @Override public byte[] finish(byte[] response) {
                    if (badChicTag) throw new SecurityException("CHIC tag");
                    tkReference = TK.clone(); return tkReference;
                }
                @Override public void close() { closedStates++; }
            };
        }
        @Override public PakeEmvSession.Credentials credentials(byte[] certKey, byte[] ecert) {
            certKeyReference = certKey;
            assertEquals(8220, ecert.length);
            if (badCredentials) throw new SecurityException("Certificate policy rejected");
            return new PakeEmvSession.Credentials(PK_C, PK_IS, PAN, 3374, 4032);
        }
        @Override public PakeEmvSession.Encapsulation encapsulate(byte[] publicKey) {
            assertArrayEquals(PK_C, publicKey);
            ssReference = SS.clone();
            return new PakeEmvSession.Encapsulation(CT.clone(), ssReference);
        }
        @Override public byte[] encrypt(byte[] key, byte[] plaintext) throws Exception {
            ecKeyReference = key;
            return encryptGcm(key, plaintext, random(12));
        }
        @Override public byte[] random(int length) { return pattern(length, randomCounter++ * 43); }
        boolean erased() {
            return zero(tkReference) && zero(certKeyReference) && zero(ecKeyReference) && zero(ssReference);
        }
    }

    private static final class Card implements Exchange {
        final Backend backend;
        final List<Integer> instructions = new ArrayList<>();
        final List<byte[]> firstMessages = new ArrayList<>();
        final ByteArrayOutputStream x1 = new ByteArrayOutputStream(), m5 = new ByteArrayOutputStream();
        byte[] x2 = pattern(800, 9), lastM3, lastM5, ctx3, finalKey;
        int x2Offset, certOffset, beginTransactions, retries, m6Responses, postM6Diagnostics, coreCommands;
        int pi3Length = 32;
        boolean corruptPi2, corruptPi3, dropM6, malformedRetry, advertiseTiming, completed, preM6SecretsErased;
        Card(Backend backend) { this.backend = backend; }
        @Override public byte[] send(byte[] command) throws Exception {
            int ins = command[1] & 255, p1 = command[2] & 255;
            instructions.add(ins);
            byte[] data = Arrays.copyOfRange(command, 5, command.length);
            switch (ins) {
                case 0xF8:
                    return advertiseTiming ? ByteBuffer.allocate(14).put(new byte[]{'P','E','M','1'})
                            .putInt(3).putInt(15).putShort((short) 0x9000).array() : status(0x6D00);
                case 0xF9:
                    beginTransactions++; return status(0x9000);
                case 0xF7:
                    if (p1 == 0) coreCommands = 0;
                    else if (completed) postM6Diagnostics++;
                    return ByteBuffer.allocate(42).put(new byte[]{'P','E','B','1'}).putInt(1)
                            .putInt(105_000_000).putInt(p1 == 0 ? 0 : coreCommands)
                            .putLong(p1 == 0 ? 0 : 1).putLong(p1 == 0 ? 0 : 1).putLong(p1 == 0 ? 0 : 1)
                            .putShort((short) 0x9000).array();
                case 0xC1:
                    coreCommands++;
                    if (data.length != 0) {
                        if (x2Offset == 800) { x1.reset(); x2Offset = 0; certOffset = 0; m5.reset(); }
                        x1.write(data);
                        if (p1 == 1) return status(0x9000);
                        assertEquals(832, x1.size()); firstMessages.add(x1.toByteArray());
                    }
                    byte[] part = fragment(x2, x2Offset); x2Offset += part.length - 2; return part;
                case 0xB2:
                    coreCommands++;
                    if (data.length != 0) {
                        assertEquals(64, data.length); lastM3 = data;
                        byte[] c1 = PakeEmvProtocol.ctx1(x1.toByteArray(), x2);
                        byte[] nu = Arrays.copyOf(data, 32);
                        assertArrayEquals(PakeEmvProtocol.kc1(TK, c1, nu), Arrays.copyOfRange(data, 32, 64));
                        if (malformedRetry) return withStatus(new byte[]{'R','E','T','R','Y',0});
                        if (retries-- > 0) return withStatus(new byte[]{'R','E','T','R','Y'});
                        byte[] c2 = PakeEmvProtocol.ctx2(data, c1);
                        ctx3 = PakeEmvProtocol.ctx3(E_CERT, c2);
                    }
                    byte[] cert = fragment(E_CERT, certOffset); certOffset += cert.length - 2; return cert;
                case 0x50:
                    coreCommands++;
                    m5.write(data);
                    if (p1 == 1) return status(0x9000);
                    assertEquals(828, m5.size()); lastM5 = m5.toByteArray();
                    preM6SecretsErased = backend.erased();
                    byte[] ec = Arrays.copyOf(lastM5, 796);
                    byte[] decrypted = decryptGcm(PakeEmvProtocol.ec2Key(TK, ctx3), ec);
                    assertArrayEquals(CT, decrypted);
                    byte[] c4 = PakeEmvProtocol.ctx4(ec, ctx3);
                    PakeEmvProtocol.Keys keys = PakeEmvProtocol.deriveKeys(TK, SS,
                            PakeEmvProtocol.pkh(PK_C, PK_IS), c4);
                    finalKey = keys.finalKey;
                    byte[] pi2 = Arrays.copyOfRange(lastM5, 796, 828);
                    if (corruptPi2) pi2[0] ^= 1;
                    completed = true;
                    if (!MessageDigest.isEqual(PakeEmvProtocol.kc2(keys.k2, c4), pi2)) return status(0x6982);
                    byte[] pi3 = PakeEmvProtocol.kc3(keys.k3, PakeEmvProtocol.ctx5(pi2, c4));
                    if (corruptPi3) pi3[0] ^= 1;
                    m6Responses++;
                    if (dropM6) throw new IOException("M6 transport failed");
                    return withStatus(Arrays.copyOf(pi3, pi3Length));
                default: throw new AssertionError("Unexpected extra APDU " + ins);
            }
        }
    }

    private static byte[] encryptGcm(byte[] key, byte[] plain, byte[] nonce) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return PakeEmvCrypto.concat(nonce, c.doFinal(plain));
    }
    private static byte[] decryptGcm(byte[] key, byte[] encrypted) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, Arrays.copyOf(encrypted, 12)));
        return c.doFinal(Arrays.copyOfRange(encrypted, 12, encrypted.length));
    }
    private static byte[] fragment(byte[] input, int offset) {
        int size = Math.min(240, input.length - offset), left = input.length - offset - size;
        byte[] part = Arrays.copyOfRange(input, offset, offset + size + 2);
        part[size] = (byte) (left == 0 ? 0x90 : 0x61); part[size + 1] = (byte) (left > 255 ? 0 : left);
        return part;
    }
    private static byte[] withStatus(byte[] data) { return PakeEmvCrypto.concat(data, status(0x9000)); }
    private static byte[] status(int sw) { return new byte[]{(byte) (sw >>> 8), (byte) sw}; }
    private static byte[] pattern(int length, int start) {
        byte[] data = new byte[length]; for (int i = 0; i < length; i++) data[i] = (byte) (start + i); return data;
    }
    private static boolean zero(byte[] data) {
        return data != null && Arrays.equals(data, new byte[data.length]);
    }
}
