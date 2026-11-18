package com.example.pqbdh_7816;

import static com.example.pqbdh_7816.PqBdhCrypto.*;

import com.example.pqbdh_7816.apdu.ApduCodec;
import com.example.pqbdh_7816.benchmark.BenchmarkSupport.CardTiming;
import com.example.pqbdh_7816.benchmark.BenchmarkSupport.CardTimingDiagnostics;
import com.example.pqbdh_7816.benchmark.BenchmarkSupport.CounterNotReadyException;
import com.example.pqbdh_7816.benchmark.BenchmarkSupport.SysTickDiagnostics;
import com.example.pqbdh_7816.benchmark.BenchmarkSupport.TimerSource;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Clock;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Exchange;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.Stage;
import com.example.pqbdh_7816.benchmark.ProtocolMeasurements.StageResult;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.function.Consumer;
import org.bouncycastle.cert.X509CertificateHolder;
import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;

/** The same measured online handshake is used by the App and hardware benchmark. */
final class PqBdhSession {
    private static final Consumer<String> QUIET = ignored -> { };

    enum RunMode { OPTIONAL_TIMING, REQUIRE_TIMING, ORIGINAL_FLOW }

    interface PinProvider { String prompt() throws Exception; }

    static final class Result {
        final StageResult negotiateKem;
        final StageResult certificates;
        final StageResult establishKey;
        final long clockHz;
        final TimerSource timerSource;
        final String cardTimingError;
        final int certCBytes;
        final int certISBytes;
        final StageResult pin;
        final String pinTimingError;

        Result(StageResult negotiateKem, StageResult certificates, StageResult establishKey,
               long clockHz, String cardTimingError, int certCBytes, int certISBytes) {
            this(negotiateKem, certificates, establishKey, clockHz,
                    negotiateKem.cardTimingAvailable && certificates.cardTimingAvailable && establishKey.cardTimingAvailable
                            ? TimerSource.DWT : null, cardTimingError, certCBytes, certISBytes);
        }

        Result(StageResult negotiateKem, StageResult certificates, StageResult establishKey,
               long clockHz, TimerSource timerSource, String cardTimingError, int certCBytes, int certISBytes) {
            this(negotiateKem, certificates, establishKey, clockHz, timerSource, cardTimingError,
                    certCBytes, certISBytes, null, null);
        }

        private Result(StageResult negotiateKem, StageResult certificates, StageResult establishKey,
                       long clockHz, TimerSource timerSource, String cardTimingError, int certCBytes,
                       int certISBytes, StageResult pin, String pinTimingError) {
            this.negotiateKem = negotiateKem;
            this.certificates = certificates;
            this.establishKey = establishKey;
            this.clockHz = clockHz;
            this.timerSource = timerSource;
            this.cardTimingError = cardTimingError;
            this.certCBytes = certCBytes;
            this.certISBytes = certISBytes;
            this.pin = pin;
            this.pinTimingError = pinTimingError;
        }

        StageResult total() {
            return ProtocolMeasurements.total(negotiateKem, certificates, establishKey);
        }

        Result withPin(StageResult pin, String pinTimingError) {
            return new Result(negotiateKem, certificates, establishKey, clockHz, timerSource, cardTimingError,
                    certCBytes, certISBytes, pin, pinTimingError);
        }

        StageResult authenticatedTotal() {
            require(pin != null, "No successful PIN verification was measured");
            return ProtocolMeasurements.total(total(), pin);
        }

        boolean hasCardTiming() {
            return timerSource != null && clockHz > 0 && negotiateKem.cardTimingAvailable && certificates.cardTimingAvailable
                    && establishKey.cardTimingAvailable;
        }
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
        final boolean pinTimingAdvertised;

        Preparation(CardTiming baseline, String profile, String cardTimingError) {
            this(baseline, profile, cardTimingError, false, false, false);
        }

        Preparation(CardTiming baseline, String profile, String cardTimingError,
                    boolean diagnosticsAdvertised, boolean sysTickAdvertised, boolean pinTimingAdvertised) {
            this.baseline = baseline;
            this.profile = profile;
            this.cardTimingError = cardTimingError;
            this.diagnosticsAdvertised = diagnosticsAdvertised;
            this.sysTickAdvertised = sysTickAdvertised;
            this.pinTimingAdvertised = pinTimingAdvertised;
        }
    }

    private PqBdhSession() { }

    static Result run(Exchange exchange, Clock clock, boolean requireCardTiming,
                      Consumer<String> status) throws Exception {
        return run(exchange, clock,
                requireCardTiming ? RunMode.REQUIRE_TIMING : RunMode.OPTIONAL_TIMING, status);
    }

    static Result run(Exchange exchange, Clock clock, RunMode mode,
                      Consumer<String> status) throws Exception {
        return run(exchange, clock, mode, null, status);
    }

    static Result runWithPinVerification(Exchange exchange, Clock clock, boolean requireCardTiming,
                                         PinProvider pinProvider, Consumer<String> status) throws Exception {
        require(pinProvider != null, "A PIN provider is required");
        return run(exchange, clock, requireCardTiming ? RunMode.REQUIRE_TIMING : RunMode.OPTIONAL_TIMING,
                pinProvider, status);
    }

    private static Result run(Exchange exchange, Clock clock, RunMode mode,
                              PinProvider pinProvider, Consumer<String> status) throws Exception {
        require(mode != null, "A session mode is required");
        boolean requireCardTiming = mode == RunMode.REQUIRE_TIMING;
        KeyEncapsulation kem = null;
        byte[] ss1 = null, k1 = null, ss2 = null, finalKey = null;
        try {
            // Native handle/provider setup is outside the measured online protocol.
            ensurePqcProviders();
            kem = new KeyEncapsulation("ML-KEM-512");
            Preparation preparation = mode == RunMode.ORIGINAL_FLOW
                    ? prepareOriginal(exchange, status) : prepare(exchange, requireCardTiming, status);
            CardTiming baseline = preparation.baseline;
            String cardError = preparation.cardTimingError;
            TimerSource timerSource = null;
            final long clockHz = baseline == null ? 0 : baseline.clockHz;
            PqBdhCommandExchange coreExchange = new PqBdhCommandExchange(exchange);

            status.accept("1/3 NegotiateKEM: generating the ephemeral key and first session key...");
            coreExchange.beginPhase("NegotiateKEM");
            Stage negotiateKem = new Stage();
            negotiateKem.start(clock);
            byte[] publicKey = kem.generate_keypair();
            require(publicKey.length == 800, "Expected an ML-KEM-512 public key");
            byte[] init = publicKey;
            byte[] first = PqBdhIo.sendNegotiateKemFragmented(
                    command -> negotiateKem.exchange(coreExchange, command, clockHz), init, QUIET);
            byte[] ct1 = PqBdhIo.collectKemCiphertext(
                    command -> negotiateKem.exchange(coreExchange, command, clockHz), first);
            require(ct1.length == 768, "Expected an ML-KEM-512 ciphertext");
            ss1 = kem.decap_secret(ct1);
            k1 = sha256(ss1);
            StageResult negotiateKemResult = negotiateKem.finish();
            require(negotiateKemResult.logicalT2c == init.length && negotiateKemResult.logicalC2t == ct1.length,
                    "NegotiateKEM payload accounting mismatch");

            status.accept("2/3 Certificate authentication: decrypting and verifying certificates...");
            coreExchange.beginPhase("Certificates");
            Stage certificates = new Stage();
            certificates.start(clock);
            byte[] response = certificates.exchange(coreExchange,
                    ApduCodec.buildCommandApduNoLe(0x80, 0xB2, 0, 0, null), clockHz);
            byte[] encryptedCertificates = PqBdhIo.collectReadCertCiphertext(
                    command -> certificates.exchange(coreExchange, command, clockHz), response);
            CertBundle certs = decryptAndParseCertPayload(k1, encryptedCertificates);
            X509CertificateHolder issuer = new X509CertificateHolder(certs.certIS);
            X509CertificateHolder card = new X509CertificateHolder(certs.certC);
            byte[] issuerKey = extractRawPublicKey(issuer);
            // Keep the existing self-signed issuer test profile and both verifications.
            verifyCertificateSignature(certs.certIS, issuerKey);
            verifyCertificateSignature(certs.certC, issuerKey);
            byte[] cardKey = extractRawPublicKey(card);
            StageResult certResult = certificates.finish();
            require(certResult.logicalT2c == 0
                    && certResult.logicalC2t == encryptedCertificates.length,
                    "Certificate payload accounting mismatch");
            require(encryptedCertificates.length == CERT_CIPHERTEXT_BYTES,
                    "Certificate envelope length mismatch");

            status.accept("3/3 Key establishment: encapsulating and establishing the final session key...");
            coreExchange.beginPhase("Establish key");
            Stage establish = new Stage();
            establish.start(clock);
            Pair<byte[], byte[]> encapsulation = kem.encap_secret(cardKey);
            byte[] ct2 = encapsulation.getLeft();
            ss2 = encapsulation.getRight();
            byte[] encryptedCt2 = aesGcmEncrypt(k1, ct2);
            PqBdhIo.sendEstablishKeyFragmented(
                    command -> establish.exchange(coreExchange, command, clockHz), encryptedCt2, QUIET);
            finalKey = deriveFinalSessionKey(ss1, ss2);
            StageResult establishResult = establish.finish();
            require(ct2.length == 768 && encryptedCt2.length == 796
                    && establishResult.logicalT2c == encryptedCt2.length
                    && establishResult.logicalC2t == 0, "Establish-key payload accounting mismatch");

            // Snapshot and final-key proof are diagnostics, outside the three measured phases.
            if (baseline != null) {
                CardTiming snapshot = null;
                try {
                    snapshot = snapshotTiming(exchange, preparation, status);
                } catch (CardTimingUnavailableException unavailable) {
                    if (requireCardTiming) throw unavailable;
                    cardError = unavailable.getMessage();
                }
                if (snapshot != null) {
                    try {
                        StageResult[] measured = attachTiming(baseline, snapshot,
                                negotiateKemResult, certResult, establishResult);
                        negotiateKemResult = measured[0];
                        certResult = measured[1];
                        establishResult = measured[2];
                        timerSource = baseline.timerSource;
                    } catch (IllegalArgumentException | IllegalStateException invalidTiming) {
                        if (requireCardTiming) throw invalidTiming;
                        cardError = invalidTiming.getMessage();
                    }
                }
            }
            byte[] proof = exchange.send(new byte[]{(byte) 0x80, (byte) 0xF4, 0, 0, 32});
            try {
                require(proof != null && proof.length == 34 && statusWord(proof) == 0x9000,
                        "Final-key diagnostic must return the full key and status 9000");
                require(MessageDigest.isEqual(finalKey, Arrays.copyOf(proof, 32)),
                        "Terminal and card final session keys differ");
            } finally {
                wipe(proof);
            }
            Result result = new Result(negotiateKemResult, certResult, establishResult, clockHz,
                    timerSource, cardError, certs.certC.length, certs.certIS.length);
            if (pinProvider != null) {
                result = verifyOfflinePin(exchange, clock, result, preparation.pinTimingAdvertised,
                        requireCardTiming, finalKey, pinProvider, status);
            }
            return result;
        } finally {
            wipe(ss1); wipe(k1); wipe(ss2); wipe(finalKey);
            if (kem != null) kem.dispose_KEM();
        }
    }

    /** Measure one successful offline PIN attempt without changing the three-phase core totals. */
    static Result verifyOfflinePin(Exchange exchange, Clock clock, Result result, boolean pinTimingAdvertised,
                                   boolean requireCardTiming, byte[] finalKey, PinProvider pinProvider,
                                   Consumer<String> status) throws Exception {
        if (requireCardTiming && (!pinTimingAdvertised || !result.hasCardTiming())) {
            throw new CardTimingUnavailableException(
                    "The authenticated benchmark requires advertised and verified separate PIN timing.", null);
        }
        // Human input and capability queries are outside every measured phase.
        String pin = pinProvider.prompt();
        require(pin != null && pin.matches("[0-9]{6}"), "PIN must have six ASCII digits");
        status.accept("Additional phase: offline PIN verification (excluded from core totals)...");
        PqBdhCommandExchange coreExchange = new PqBdhCommandExchange(exchange);
        coreExchange.beginPhase("Offline PIN verification");
        Stage pinStage = new Stage();
        pinStage.start(clock);
        byte[] encryptedPin = aesGcmEncrypt(finalKey, pin.getBytes(StandardCharsets.US_ASCII));
        byte[] pinCommand = ApduCodec.buildCommandApdu(0x80, 0x20, 0, 0, encryptedPin);
        byte[] pinResponse = pinStage.exchangeWithLe(coreExchange, pinCommand, result.clockHz);
        StageResult pinResult = pinStage.finish();
        int sw = statusWord(pinResponse);
        require(sw == 0x9000, (sw & 0xFFF0) == 0x63C0
                ? "PIN verification failed; retries remaining: " + (sw & 15)
                : String.format(Locale.ROOT, "PIN verification failed with SW=%04X", sw));
        require(encryptedPin.length == 34 && pinCommand.length == 40
                && pinResult.logicalT2c == 34 && pinResult.logicalC2t == 0,
                "PIN payload accounting mismatch");
        String pinError = "Separate card PIN timing was not advertised or core timing was unavailable.";
        if (pinTimingAdvertised && result.hasCardTiming()) {
            try {
                PqBdhPinTiming snapshot = PqBdhPinTiming.parse(exchange.send(
                        new byte[]{(byte) 0x80, (byte) 0xF7, 4, 0, 0}));
                pinResult = snapshot.attach(pinResult, result.clockHz, result.timerSource);
                pinError = null;
            } catch (IllegalArgumentException | IllegalStateException invalidPinTiming) {
                if (requireCardTiming) throw invalidPinTiming;
                pinError = invalidPinTiming.getMessage();
            }
        }
        result = result.withPin(pinResult, pinError);
        return result;
    }

    static StageResult[] attachTiming(CardTiming reset, CardTiming snapshot,
                                      StageResult negotiateKem, StageResult certificates, StageResult establish) {
        require(reset.clockHz == snapshot.clockHz, "Card clock changed during the session");
        require(reset.timerSource == snapshot.timerSource, "Card timer source changed during the session");
        require(snapshot.commandCount == negotiateKem.apduCount + certificates.apduCount + establish.apduCount,
                "Card/terminal measured APDU counts differ");
        require(snapshot.negotiateKemCycles > 0 && snapshot.certCycles > 0 && snapshot.establishCycles > 0,
                "Card did not measure all protocol phases");
        StageResult[] results = {negotiateKem.withCardCycles(snapshot.negotiateKemCycles),
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
        PqBdhCardProfile.Profile profile = PqBdhCardProfile.query(exchange, status);
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
            require(baseline.commandCount == 0 && baseline.negotiateKemCycles == 0
                    && baseline.certCycles == 0 && baseline.establishCycles == 0,
                    "Card benchmark counters did not reset");
            return new Preparation(baseline, profile.description, null,
                    profile.diagnosticsAdvertised, profile.sysTickAdvertised, profile.pinTimingAdvertised);
        } catch (CardTimingUnavailableException unavailable) {
            String reason = timingFailureReason(exchange, unavailable,
                    profile.diagnosticsAdvertised, profile.sysTickAdvertised, status);
            if (requireCardTiming) throw new CardTimingUnavailableException(reason, unavailable);
            status.accept("Card timing unavailable: " + reason
                    + " Terminal timing and traffic will still be measured.");
            return new Preparation(null, profile.description, reason,
                    profile.diagnosticsAdvertised, profile.sysTickAdvertised, profile.pinTimingAdvertised);
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
                    ? " Rebuild and flash Card_armcortex with PAKE_EMV_BENCHMARK=1 to provide the F7 timing interface."
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
