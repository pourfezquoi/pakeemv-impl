package com.example.pakebdh_7816;

import static com.example.pakebdh_7816.PakeEmvCrypto.*;

import com.example.pakebdh_7816.apdu.ApduCodec;
import com.example.pakebdh_7816.benchmark.BenchmarkSupport.CardTiming;
import com.example.pakebdh_7816.benchmark.BenchmarkSupport.CardTimingDiagnostics;
import com.example.pakebdh_7816.benchmark.BenchmarkSupport.CounterNotReadyException;
import com.example.pakebdh_7816.benchmark.BenchmarkSupport.SysTickDiagnostics;
import com.example.pakebdh_7816.benchmark.BenchmarkSupport.TimerSource;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Clock;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Exchange;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.Stage;
import com.example.pakebdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.function.Consumer;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;

/** The same measured online handshake is used by the App and hardware benchmark. */
final class PakeEmvSession {
    private static final Consumer<String> QUIET = ignored -> { };

    enum RunMode { OPTIONAL_TIMING, REQUIRE_TIMING, ORIGINAL_FLOW }

    static final class Result {
        final StageResult pake;
        final StageResult certificates;
        final StageResult establishKey;
        final long clockHz;
        final TimerSource timerSource;
        final String cardTimingError;
        final int certCBytes;
        final int certISBytes;
        final boolean accepted;
        final String rejectionReason;
        final KeyRecord recordedKey;

        Result(StageResult pake, StageResult certificates, StageResult establishKey,
               long clockHz, String cardTimingError, int certCBytes, int certISBytes) {
            this(pake, certificates, establishKey, clockHz,
                    pake.cardTimingAvailable && certificates.cardTimingAvailable && establishKey.cardTimingAvailable
                            ? TimerSource.DWT : null, cardTimingError, certCBytes, certISBytes);
        }

        Result(StageResult pake, StageResult certificates, StageResult establishKey,
               long clockHz, TimerSource timerSource, String cardTimingError, int certCBytes, int certISBytes) {
            this(pake, certificates, establishKey, clockHz, timerSource, cardTimingError,
                    certCBytes, certISBytes, true, null, null);
        }

        Result(StageResult pake, StageResult certificates, StageResult establishKey,
               long clockHz, TimerSource timerSource, String cardTimingError, int certCBytes,
               int certISBytes, boolean accepted, String rejectionReason, KeyRecord recordedKey) {
            this.pake = pake;
            this.certificates = certificates;
            this.establishKey = establishKey;
            this.clockHz = clockHz;
            this.timerSource = timerSource;
            this.cardTimingError = cardTimingError;
            this.certCBytes = certCBytes;
            this.certISBytes = certISBytes;
            this.accepted = accepted;
            this.rejectionReason = rejectionReason;
            this.recordedKey = recordedKey;
        }

        StageResult total() {
            return ProtocolMeasurements.total(pake, certificates, establishKey);
        }

        boolean hasCardTiming() {
            return timerSource != null && clockHz > 0 && pake.cardTimingAvailable && certificates.cardTimingAvailable
                    && establishKey.cardTimingAvailable;
        }
    }

    /** A locally recorded key exists after Init3, even when Init4 rejects. Never logged or sent. */
    static final class KeyRecord implements AutoCloseable {
        private final byte[] key;
        private boolean closed;
        KeyRecord(byte[] key) { this.key = key.clone(); }
        synchronized byte[] copy() {
            if (closed) throw new IllegalStateException("Recorded key has been closed.");
            return key.clone();
        }
        @Override public synchronized void close() { wipe(key); closed = true; }
    }

    static final class FinalOutcomeException extends Exception {
        final KeyRecord recordedKey;
        FinalOutcomeException(String message, Throwable cause, KeyRecord recordedKey) {
            super(message, cause);
            this.recordedKey = recordedKey;
        }
    }

    /** Only the explicit RETRY encoding received while awaiting M4 reaches this transition. */
    private static final class RetryRequested extends Exception { }

    interface PinSupplier { String nextPin() throws Exception; }

    interface PakeState extends AutoCloseable {
        byte[] firstMessage();
        byte[] finish(byte[] response);
        @Override void close();
    }

    static final class Credentials {
        final byte[] cardKey, issuerKey;
        final String pan;
        final int certCBytes, certISBytes;
        Credentials(byte[] cardKey, byte[] issuerKey, String pan, int certCBytes, int certISBytes) {
            this.cardKey = cardKey; this.issuerKey = issuerKey; this.pan = pan;
            this.certCBytes = certCBytes; this.certISBytes = certISBytes;
        }
    }

    static final class Encapsulation {
        final byte[] ciphertext, secret;
        Encapsulation(byte[] ciphertext, byte[] secret) {
            this.ciphertext = ciphertext; this.secret = secret;
        }
    }

    /** Primitives are injectable for transcript/state tests; production always uses NativeBackend. */
    interface Backend extends AutoCloseable {
        PakeState start(byte[] password, byte[] sid) throws Exception;
        Credentials credentials(byte[] certKey, byte[] ecert) throws Exception;
        Encapsulation encapsulate(byte[] publicKey) throws Exception;
        byte[] encrypt(byte[] key, byte[] plaintext) throws Exception;
        byte[] random(int length);
        @Override default void close() { }
    }

    private static final class NativeBackend implements Backend {
        private final KeyEncapsulation kem;
        private final SecureRandom random = new SecureRandom();
        NativeBackend() {
            ensurePqcProviders();
            ChicPake.ensureAvailable();
            kem = new KeyEncapsulation("ML-KEM-512");
        }
        @Override public PakeState start(byte[] password, byte[] sid) {
            ChicPake.Pending pending = ChicPake.start(password, sid);
            return new PakeState() {
                @Override public byte[] firstMessage() { return pending.firstMessage(); }
                @Override public byte[] finish(byte[] response) { return pending.finish(response); }
                @Override public void close() { pending.close(); }
            };
        }
        @Override public Credentials credentials(byte[] certKey, byte[] ecert) throws Exception {
            CertBundle certs = decryptAndParseCertPayload(certKey, ecert);
            PakeEmvCertificates.Verified verified = PakeEmvCertificates.verify(certs.certC, certs.certIS);
            return new Credentials(verified.cardKey, verified.issuerKey, verified.pan,
                    certs.certC.length, certs.certIS.length);
        }
        @Override public Encapsulation encapsulate(byte[] publicKey) {
            Pair<byte[], byte[]> pair = kem.encap_secret(publicKey);
            return new Encapsulation(pair.getLeft(), pair.getRight());
        }
        @Override public byte[] encrypt(byte[] key, byte[] plaintext) throws Exception {
            return aesGcmEncrypt(key, plaintext);
        }
        @Override public byte[] random(int length) {
            byte[] bytes = new byte[length]; random.nextBytes(bytes); return bytes;
        }
        @Override public void close() { kem.dispose_KEM(); }
    }

    static final class CardTimingUnavailableException extends IllegalStateException {
        CardTimingUnavailableException(String message, Throwable cause) { super(message, cause); }
    }

    static final class Preparation {
        final CardTiming baseline;
        final String profile;
        final String cardTimingError;
        final boolean diagnosticsAdvertised;
        final boolean sysTickAdvertised;

        Preparation(CardTiming baseline, String profile, String cardTimingError) {
            this(baseline, profile, cardTimingError, false, false);
        }

        Preparation(CardTiming baseline, String profile, String cardTimingError,
                    boolean diagnosticsAdvertised, boolean sysTickAdvertised) {
            this.baseline = baseline;
            this.profile = profile;
            this.cardTimingError = cardTimingError;
            this.diagnosticsAdvertised = diagnosticsAdvertised;
            this.sysTickAdvertised = sysTickAdvertised;
        }
    }

    private PakeEmvSession() { }

    static Result run(Exchange exchange, String pin, String expectedPan, Clock clock,
                      boolean requireCardTiming, Consumer<String> status) throws Exception {
        return run(exchange, pin, expectedPan, clock,
                requireCardTiming ? RunMode.REQUIRE_TIMING : RunMode.OPTIONAL_TIMING, status);
    }

    /** Benchmark/single-input entry point: RETRY requires a new caller-supplied PIN, never reuse. */
    static Result run(Exchange exchange, String pin, String expectedPan, Clock clock,
                      RunMode mode, Consumer<String> status) throws Exception {
        final boolean[] supplied = {false};
        return runTransaction(exchange, expectedPan, () -> {
            if (supplied[0]) throw new IllegalStateException("The card requested RETRY; fresh PIN input is required.");
            supplied[0] = true;
            return pin;
        }, clock, mode, status);
    }

    static Result runTransaction(Exchange exchange, String expectedPan, PinSupplier pins,
                                 Clock clock, RunMode mode, Consumer<String> status) throws Exception {
        // Validate the independent transaction identity before loading providers or sending any APDU.
        String fixedPan = PakeEmvCertificates.canonicalPan(expectedPan);
        try (Backend backend = new NativeBackend()) {
            return runTransaction(exchange, fixedPan, pins, clock, mode, status, backend);
        }
    }

    static Result runTransaction(Exchange exchange, String expectedPan, PinSupplier pins, Clock clock,
                                 RunMode mode, Consumer<String> status, Backend backend) throws Exception {
        String fixedPan = PakeEmvCertificates.canonicalPan(expectedPan);
        require(mode != null && pins != null && backend != null, "Transaction inputs are required.");
        boolean requireTiming = mode == RunMode.REQUIRE_TIMING;
        Preparation preparation = mode == RunMode.ORIGINAL_FLOW
                ? prepareOriginal(exchange, status) : prepare(exchange, requireTiming, status);
        byte[] begin = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF9, 0, 0, 0});
        require(begin != null && begin.length == 2 && statusWord(begin) == 0x9000,
                "BeginTransaction F9 failed; no PIN or protocol message was sent.");
        for (int retries = 0; ; retries++) {
            String pin = pins.nextPin();
            require(pin != null && pin.matches("[0-9]{6}"), "PIN must have six ASCII digits");
            try {
                // The six-message logical protocol stops at M6 on both final outcomes.
                Result outcome = runHandshake(exchange, pin, fixedPan, clock, preparation, status, backend);
                // Explicit measurement management runs after the closed protocol, independent of acceptance.
                return collectTiming(exchange, preparation, outcome, requireTiming, status);
            } catch (RetryRequested retry) {
                require(retries < 2, "The transaction exceeded its two permitted PIN retries.");
                status.accept("The card returned RETRY. Enter a fresh PIN; the reference PAN remains fixed.");
                // F7 resets measurement counters only. F9 must never reset the transaction retry budget here.
                preparation = mode == RunMode.ORIGINAL_FLOW
                        ? new Preparation(null, preparation.profile, preparation.cardTimingError)
                        : prepare(exchange, requireTiming, status);
            }
        }
    }

    /** Init1 through Init4 only: no management or diagnostic APDU follows M6 here. */
    static Result runHandshake(Exchange exchange, String pin, String expectedPan, Clock clock,
                                Preparation preparation, Consumer<String> status, Backend backend) throws Exception {
        byte[] tk = null, pw = null, certKey = null, ecKey = null, ss = null;
        PakeEmvProtocol.Keys keys = null;
        KeyRecord recorded = null;
        final long clockHz = preparation.baseline == null ? 0 : preparation.baseline.clockHz;
        PakeEmvCommandExchange core = new PakeEmvCommandExchange(exchange);
        try {
            status.accept("1/3 PAKE: Init1 and Init2...");
            core.beginPhase("PAKE");
            Stage pake = new Stage(); pake.start(clock);
            pw = sha256(pin.getBytes(StandardCharsets.US_ASCII));
            byte[] sid = backend.random(32), x1, x2;
            try (PakeState pending = backend.start(pw, sid)) {
                wipe(pw);
                x1 = concat(sid, pending.firstMessage());
                byte[] first = PakeEmvIo.sendPakeInitFragmented(
                        command -> pake.exchange(core, command, clockHz), x1, QUIET);
                x2 = PakeEmvIo.collectPakeResponse(
                        command -> pake.exchange(core, command, clockHz), first);
                // An invalid CHIC tag terminates this transaction; it is never a PIN-retry signal.
                tk = pending.finish(x2);
            }
            byte[] ctx1 = PakeEmvProtocol.ctx1(x1, x2);
            StageResult pakeResult = pake.finish();
            require(pakeResult.logicalT2c == PakeEmvProtocol.X1_BYTES
                    && pakeResult.logicalC2t == PakeEmvProtocol.X2_BYTES, "PAKE payload accounting mismatch");

            status.accept("2/3 Certificate authentication: Init2 and Init3...");
            core.beginPhase("Certificates");
            Stage certificates = new Stage(); certificates.start(clock);
            byte[] nu = backend.random(32);
            byte[] m3 = concat(nu, PakeEmvProtocol.kc1(tk, ctx1, nu));
            byte[] ctx2 = PakeEmvProtocol.ctx2(m3, ctx1);
            byte[] firstCert = certificates.exchange(core,
                    ApduCodec.buildCommandApduNoLe(0x80, 0xB2, 0, 0, m3), clockHz);
            if (isRetry(firstCert)) throw new RetryRequested();
            byte[] ecert = PakeEmvIo.collectReadCertCiphertext(
                    command -> certificates.exchange(core, command, clockHz), firstCert);
            certKey = PakeEmvProtocol.certKey(tk, ctx2);
            Credentials credential = backend.credentials(certKey, ecert);
            wipe(certKey); certKey = null;
            boolean identityMatches = expectedPan.equals(credential.pan);
            byte[] ctx3 = PakeEmvProtocol.ctx3(ecert, ctx2);
            StageResult certResult = certificates.finish();
            require(certResult.logicalT2c == PakeEmvProtocol.M3_BYTES
                    && certResult.logicalC2t == PakeEmvProtocol.ECERT_BYTES, "Certificate payload accounting mismatch");

            status.accept("3/3 Key establishment: Init3 and Init4...");
            core.beginPhase("Establish key");
            Stage establish = new Stage(); establish.start(clock);
            Encapsulation encapsulation = backend.encapsulate(credential.cardKey);
            ss = encapsulation.secret;
            require(encapsulation.ciphertext != null && encapsulation.ciphertext.length == 768,
                    "ML-KEM-512 encapsulation ciphertext must contain 768 bytes.");
            ecKey = PakeEmvProtocol.ec2Key(tk, ctx3);
            byte[] ec = backend.encrypt(ecKey, encapsulation.ciphertext);
            wipe(ecKey); ecKey = null;
            byte[] ctx4 = PakeEmvProtocol.ctx4(ec, ctx3);
            byte[] pkh = PakeEmvProtocol.pkh(credential.cardKey, credential.issuerKey);
            keys = PakeEmvProtocol.deriveKeys(tk, ss, pkh, ctx4);
            wipe(tk); tk = null;
            wipe(ss); ss = null;
            byte[] pi2 = PakeEmvProtocol.kc2(keys.k2, ctx4);
            byte[] m5 = concat(ec, pi2);
            byte[] ctx5 = PakeEmvProtocol.ctx5(pi2, ctx4);
            // Init3 records K when it emits M5; the later PAN decision cannot undo that event.
            recorded = new KeyRecord(keys.finalKey);
            wipe(keys.finalKey); wipe(keys.k2);
            // Between Init3 and Init4 only k3, ctx5 and ok remain secret algorithm state;
            // recorded K belongs to the separate local key-output record.
            byte[] last = PakeEmvIo.sendEstablishKeyFragmented(
                    command -> establish.exchange(core, command, clockHz), m5, QUIET);
            byte[] expectedPi3 = PakeEmvProtocol.kc3(keys.k3, ctx5);
            int finalStatus = statusWord(last);
            int finalPayloadLength = last.length - 2;
            boolean confirmationMatches = finalStatus == 0x9000
                    && finalPayloadLength == PakeEmvProtocol.M6_BYTES
                    && MessageDigest.isEqual(expectedPi3, Arrays.copyOf(last, PakeEmvProtocol.M6_BYTES));
            wipe(expectedPi3);
            StageResult establishResult = establish.finish();
            require(establishResult.logicalT2c == PakeEmvProtocol.M5_BYTES,
                    "Establish-key payload accounting mismatch");
            boolean accepted = confirmationMatches & identityMatches;
            String rejectionReason = describeInit4Rejection(identityMatches, confirmationMatches,
                    finalStatus, finalPayloadLength);
            return new Result(pakeResult, certResult, establishResult, clockHz, null,
                    preparation.cardTimingError, credential.certCBytes, credential.certISBytes,
                    accepted, rejectionReason, recorded);
        } catch (Exception failure) {
            if (recorded != null) {
                throw new FinalOutcomeException("The protocol terminated after recording the Init3 key.", failure, recorded);
            }
            throw failure;
        } finally {
            wipe(tk); wipe(pw); wipe(certKey); wipe(ecKey); wipe(ss);
            if (keys != null) { wipe(keys.finalKey); wipe(keys.k2); wipe(keys.k3); }
        }
    }

    /** Local test diagnostics. The PAN decision never changes protocol traffic. */
    private static String describeInit4Rejection(boolean identityMatches, boolean confirmationMatches,
                                                  int finalStatus, int finalPayloadLength) {
        String panMismatch = "Reference PAN does not match the verified card certificate.";
        if (confirmationMatches) {
            return identityMatches ? null : panMismatch + " Final confirmation (pi3) passed.";
        }

        String confirmationFailure;
        if (finalStatus != 0x9000) {
            confirmationFailure = String.format(Locale.ROOT,
                    "Card rejected M5 (SW=%04X). Final confirmation (pi3) unavailable.", finalStatus);
        } else if (finalPayloadLength != PakeEmvProtocol.M6_BYTES) {
            confirmationFailure = "Invalid M6 payload length: expected " + PakeEmvProtocol.M6_BYTES
                    + " bytes for pi3, received " + finalPayloadLength + ".";
        } else {
            confirmationFailure = "Final confirmation (pi3) failed verification.";
        }
        return identityMatches ? confirmationFailure + " Reference PAN matched."
                : panMismatch + " " + confirmationFailure;
    }

    private static boolean isRetry(byte[] response) {
        return Arrays.equals(response, new byte[]{'R', 'E', 'T', 'R', 'Y', (byte) 0x90, 0});
    }

    private static Result collectTiming(Exchange exchange, Preparation preparation, Result outcome,
                                        boolean requireTiming, Consumer<String> status) throws Exception {
        if (preparation.baseline == null) return outcome;
        try {
            CardTiming snapshot = snapshotTiming(exchange, preparation, status);
            StageResult[] stages = attachTiming(preparation.baseline, snapshot,
                    outcome.pake, outcome.certificates, outcome.establishKey);
            return new Result(stages[0], stages[1], stages[2], outcome.clockHz,
                    preparation.baseline.timerSource, outcome.cardTimingError, outcome.certCBytes,
                    outcome.certISBytes, outcome.accepted, outcome.rejectionReason, outcome.recordedKey);
        } catch (Exception failure) {
            if (requireTiming || !(failure instanceof IllegalArgumentException || failure instanceof IllegalStateException)) {
                throw new FinalOutcomeException("Post-protocol measurement failed.", failure, outcome.recordedKey);
            }
            return new Result(outcome.pake, outcome.certificates, outcome.establishKey, outcome.clockHz,
                    null, failure.getMessage(), outcome.certCBytes, outcome.certISBytes, outcome.accepted,
                    outcome.rejectionReason, outcome.recordedKey);
        }
    }

    static StageResult[] attachTiming(CardTiming reset, CardTiming snapshot,
                                      StageResult pake, StageResult certificates, StageResult establish) {
        require(reset.clockHz == snapshot.clockHz, "Card clock changed during the session");
        require(reset.timerSource == snapshot.timerSource, "Card timer source changed during the session");
        require(snapshot.commandCount == pake.apduCount + certificates.apduCount + establish.apduCount,
                "Card/terminal measured APDU counts differ");
        require(snapshot.pakeCycles > 0 && snapshot.certCycles > 0 && snapshot.establishCycles > 0,
                "Card did not measure all protocol phases");
        StageResult[] results = {pake.withCardCycles(snapshot.pakeCycles),
                certificates.withCardCycles(snapshot.certCycles),
                establish.withCardCycles(snapshot.establishCycles)};
        for (StageResult result : results) {
            require(result.values(reset.clockHz)[10] <= result.ioNs,
                    "Card handler time exceeds APDU round trips; check clock/counters");
        }
        return results;
    }

    /** No JNI or protocol state changes: only negotiate the optional measurement interface. */
    static Preparation prepare(Exchange exchange, boolean requireCardTiming, Consumer<String> status)
            throws Exception {
        PakeEmvCardProfile.Profile profile = PakeEmvCardProfile.query(exchange, status);
        if (!profile.timingAdvertised) {
            String reason = "F7 timing was not advertised. No F7 reset/query was sent. "
                    + "Card timing requires the measurement firmware; terminal timing and traffic remain available.";
            if (requireCardTiming) throw new CardTimingUnavailableException(reason, null);
            status.accept("Card timing unavailable: " + reason);
            return new Preparation(null, profile.description, reason);
        }
        status.accept("Resetting advertised card timing: APDU 80 F7 00 00 00...");
        try {
            CardTiming baseline = timing(exchange, 0);
            if (baseline.timerSource == TimerSource.SYSTICK_IRQ) {
                if (!profile.sysTickAdvertised) {
                    throw new CardTimingUnavailableException(
                            "The reset returned SysTick IRQ timing without advertising that source in F8.", null);
                }
                status.accept("Verifying advertised SysTick timing: APDU 80 F7 03 00 00...");
                SysTickDiagnosticReply reply = sysTickDiagnostics(exchange);
                if (reply.diagnostic == null || reply.diagnostic.flags != 3
                        || reply.diagnostic.clockHz != baseline.clockHz) {
                    throw new CardTimingUnavailableException(
                            "SysTick timing reset and cached readiness/clock do not match. " + reply.evidence, null);
                }
                status.accept(reply.evidence);
            }
            require(baseline.commandCount == 0 && baseline.pakeCycles == 0
                    && baseline.certCycles == 0 && baseline.establishCycles == 0,
                    "Card benchmark counters did not reset");
            return new Preparation(baseline, profile.description, null,
                    profile.diagnosticsAdvertised, profile.sysTickAdvertised);
        } catch (CardTimingUnavailableException unavailable) {
            String reason = timingFailureReason(exchange, unavailable,
                    profile.diagnosticsAdvertised, profile.sysTickAdvertised, status);
            if (requireCardTiming) throw new CardTimingUnavailableException(reason, unavailable);
            status.accept("Card timing unavailable: " + reason
                    + " Terminal timing and traffic will still be measured.");
            return new Preparation(null, profile.description, reason,
                    profile.diagnosticsAdvertised, profile.sysTickAdvertised);
        }
    }

    static CardTiming snapshotTiming(Exchange exchange, Preparation preparation, Consumer<String> status)
            throws Exception {
        try {
            return timing(exchange, 1);
        } catch (CardTimingUnavailableException unavailable) {
            String reason = timingFailureReason(exchange, unavailable,
                    preparation.diagnosticsAdvertised, preparation.sysTickAdvertised, status);
            status.accept("Card timing unavailable after the protocol: " + reason);
            throw new CardTimingUnavailableException(reason, unavailable);
        }
    }

    private static String timingFailureReason(Exchange exchange, CardTimingUnavailableException unavailable,
                                             boolean dwtDiagnostics, boolean sysTickDiagnostics,
                                             Consumer<String> status) throws Exception {
        String reason = unavailable.getMessage();
        if (unavailable.getCause() instanceof CounterNotReadyException) {
            if (dwtDiagnostics) {
                status.accept("Reading advertised card counter diagnostics: APDU 80 F7 02 00 00...");
                reason += "\n" + timingDiagnostics(exchange);
            }
            if (sysTickDiagnostics) {
                status.accept("Reading advertised SysTick counter diagnostics: APDU 80 F7 03 00 00...");
                SysTickDiagnosticReply reply = sysTickDiagnostics(exchange);
                reason += "\n" + reply.evidence;
                if (reply.diagnostic != null && reply.diagnostic.flags == 3) {
                    reason += "\nSysTick diagnostic readiness differs from the failed timing response; card timing remains unavailable.";
                }
            }
        }
        return reason;
    }

    /** Restore the pre-benchmark startup sequence for an explicit comparison run. */
    static Preparation prepareOriginal(Exchange exchange, Consumer<String> status) throws Exception {
        byte[][] commands = {
                {0, (byte) 0x84, 0, 0, 8},
                {(byte) 0x80, (byte) 0xF0, 0, 0, 1},
                {0, (byte) 0xF0, 0, 0, 8},
                {0, (byte) 0xA4, 4, 0, 14, 0x31, 0x50, 0x41, 0x59, 0x2E,
                        0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0}
        };
        String[] labels = {"GET CHALLENGE", "Vendor PING", "ISO PING", "SELECT"};
        status.accept("Original startup comparison: F8 and F7 are disabled for this run.");
        for (int i = 0; i < commands.length; i++) {
            byte[] response = exchange.send(commands[i]);
            status.accept(String.format(Locale.ROOT, "Original startup %s: SW=%04X",
                    labels[i], statusWord(response)));
        }
        return new Preparation(null, "Original startup comparison",
                "Disabled for the original startup comparison; no F8/F7 commands were sent.");
    }

    static CardTiming timing(Exchange exchange, int p1) throws Exception {
        // Transport/framing failures must propagate; the next command may otherwise use stale state.
        byte[] response = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF7, (byte) p1, 0, 0});
        try {
            return CardTiming.parse(response);
        } catch (IllegalArgumentException invalid) {
            String sw = response == null || response.length < 2 ? "missing"
                    : String.format(Locale.ROOT, "%04X", statusWord(response));
            String advice = invalid instanceof CounterNotReadyException ? ""
                    : sw.equals("6D00") || sw.equals("6A81")
                    ? " Rebuild and flash Card_pakebdh with PAKE_EMV_BENCHMARK=1 to provide the F7 timing interface."
                    : " Check the firmware timing packet and clock/counter configuration.";
            throw new CardTimingUnavailableException("F7 timing SW=" + sw + ": "
                    + invalid.getMessage() + advice, invalid);
        }
    }

    private static String timingDiagnostics(Exchange exchange) throws Exception {
        // A transport failure must stop the session; it cannot become a diagnostic result.
        byte[] response = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF7, 2, 0, 0});
        try {
            CardTimingDiagnostics diagnostic = CardTimingDiagnostics.parse(response);
            String evidence = diagnostic.description();
            if (diagnostic.flags != 0) {
                evidence += "\nDiagnostic readiness differs from the reset response; card timing remains unavailable.";
            }
            return evidence;
        } catch (IllegalArgumentException invalid) {
            return diagnosticFailure("Card counter diagnostics unavailable: ", invalid, response);
        }
    }

    private static final class SysTickDiagnosticReply {
        final SysTickDiagnostics diagnostic;
        final String evidence;

        SysTickDiagnosticReply(SysTickDiagnostics diagnostic, String evidence) {
            this.diagnostic = diagnostic;
            this.evidence = evidence;
        }
    }

    private static SysTickDiagnosticReply sysTickDiagnostics(Exchange exchange) throws Exception {
        byte[] response = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF7, 3, 0, 0});
        try {
            SysTickDiagnostics diagnostic = SysTickDiagnostics.parse(response);
            return new SysTickDiagnosticReply(diagnostic, diagnostic.description());
        } catch (IllegalArgumentException invalid) {
            return new SysTickDiagnosticReply(null,
                    diagnosticFailure("SysTick counter diagnostics unavailable: ", invalid, response));
        }
    }

    private static String diagnosticFailure(String label, IllegalArgumentException invalid, byte[] response) {
        String sw = response == null || response.length < 2 ? "missing"
                : String.format(Locale.ROOT, "%04X", statusWord(response));
        StringBuilder evidence = new StringBuilder(label).append(invalid.getMessage()).append(" Response: ")
                .append(response == null ? 0 : response.length).append(" bytes, SW=").append(sw)
                .append(", prefix=");
        if (response == null || response.length == 0) evidence.append("none");
        else for (int i = 0; i < Math.min(response.length, 48); i++) {
            if (i != 0) evidence.append(' ');
            evidence.append(String.format(Locale.ROOT, "%02X", response[i] & 255));
        }
        return evidence.toString();
    }

    private static int statusWord(byte[] response) {
        require(response != null && response.length >= 2, "Short APDU response");
        return ((response[response.length - 2] & 255) << 8) | (response[response.length - 1] & 255);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static void wipe(byte[] bytes) {
        if (bytes != null) Arrays.fill(bytes, (byte) 0);
    }
}
