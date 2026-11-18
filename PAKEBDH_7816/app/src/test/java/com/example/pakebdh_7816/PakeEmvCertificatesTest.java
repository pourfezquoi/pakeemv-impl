package com.example.pakebdh_7816;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

/** Real ML-DSA certificate verification; native JNI is unnecessary for these tests. */
public class PakeEmvCertificatesTest {
    private static final Provider BC = new BouncyCastleProvider();
    private static final ASN1ObjectIdentifier ML_DSA_44 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17");
    private static final ASN1ObjectIdentifier ML_KEM_512 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.1");
    private static final Date NOW = new Date(1794960000000L); // 2026-11-18, within provisioned validity.
    private static final Date BEFORE = new Date(1767225600000L); // 2026-01-01
    private static final Date AFTER = new Date(1830297600000L); // 2028-01-01
    private static final X500Name ROOT_NAME = new X500Name("CN=Unit Test Root,O=Tests,C=SG");
    private static final X500Name CARD_NAME = new X500Name("CN=4502123456789012,O=Tests,C=SG");
    private static byte[] fixtureCard, fixtureIssuer;
    private static byte[] cardKey, rootKey;
    private static KeyPair testRoot;
    private static byte[] generatedCard, generatedRoot;
    private static long serial = 100;

    @BeforeClass public static void setup() throws Exception {
        fixtureCard = fixture("certC.der");
        fixtureIssuer = fixture("certIS.der");
        cardKey = new X509CertificateHolder(fixtureCard).getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        // Fresh ephemeral signing key used only by this test process, never production.
        testRoot = KeyPairGenerator.getInstance("ML-DSA-44", BC).generateKeyPair();
        rootKey = SubjectPublicKeyInfo.getInstance(testRoot.getPublic().getEncoded()).getPublicKeyData().getBytes();
        generatedRoot = certificate(ROOT_NAME, ROOT_NAME,
                SubjectPublicKeyInfo.getInstance(testRoot.getPublic().getEncoded()), null, null);
        generatedCard = card(CARD_NAME, new AlgorithmIdentifier(ML_KEM_512), cardKey, null, null);
    }

    private static byte[] fixture(String name) throws Exception {
        try (InputStream input = PakeEmvCertificatesTest.class.getResourceAsStream("/pake-emv-certificates/" + name)) {
            if (input == null) throw new AssertionError("Missing certificate fixture " + name);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
            return output.toByteArray();
        }
    }

    private static void verifySignature(byte[] encoded, byte[] signerKey) throws Exception {
        X509CertificateHolder certificate = new X509CertificateHolder(encoded);
        SubjectPublicKeyInfo signer = new SubjectPublicKeyInfo(new AlgorithmIdentifier(ML_DSA_44), signerKey);
        if (!certificate.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signer))) {
            throw new SecurityException("Invalid test certificate signature");
        }
    }

    private static PakeEmvCertificates.Verified verifyGenerated(byte[] card, byte[] issuer) throws Exception {
        return PakeEmvCertificates.verify(card, issuer, rootKey, NOW,
                PakeEmvCertificatesTest::verifySignature);
    }

    private static byte[] certificate(X500Name issuer, X500Name subject, SubjectPublicKeyInfo key,
                                      BasicConstraints constraints, KeyUsage usage) throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer,
                BigInteger.valueOf(++serial), BEFORE, AFTER, subject, key);
        if (constraints != null) builder.addExtension(Extension.basicConstraints, true, constraints);
        if (usage != null) builder.addExtension(Extension.keyUsage, true, usage);
        return builder.build(new JcaContentSignerBuilder("ML-DSA-44").setProvider(BC)
                .build(testRoot.getPrivate())).getEncoded();
    }

    private static byte[] card(X500Name subject, AlgorithmIdentifier algorithm, byte[] key,
                                BasicConstraints constraints, KeyUsage usage) throws Exception {
        return certificate(ROOT_NAME, subject, new SubjectPublicKeyInfo(algorithm, key), constraints, usage);
    }

    @Test public void provisionedCertificatesAuthenticateUnderIndependentPin() throws Exception {
        PakeEmvCertificates.Verified result = PakeEmvCertificates.verify(fixtureCard, fixtureIssuer, NOW,
                PakeEmvCertificatesTest::verifySignature);
        X509CertificateHolder issuer = new X509CertificateHolder(fixtureIssuer);
        X509CertificateHolder card = new X509CertificateHolder(fixtureCard);
        assertEquals(new X500Name("CN=Sample Issuer CA,O=Test Org,C=ZZ"), issuer.getSubject());
        assertEquals(new X500Name("CN=4502123456789012,O=Test,C=ZZ"), card.getSubject());
        assertEquals(new BigInteger("010000000001", 16), issuer.getSerialNumber());
        assertEquals(new BigInteger("010000000002", 16), card.getSerialNumber());
        assertEquals(new Date(1577836800000L), issuer.getNotBefore());
        assertEquals(new Date(2524607999000L), issuer.getNotAfter());
        assertEquals(PakeEmvBenchmarkConfig.EXPECTED_PAN, result.pan);
        assertArrayEquals(cardKey, result.cardKey);
        assertArrayEquals(PakeEmvTrustAnchor.publicKey(), result.issuerKey);
        assertEquals(PakeEmvTrustAnchor.CERTIFICATE_SHA256,
                Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(fixtureIssuer)));
        assertEquals(PakeEmvTrustAnchor.PUBLIC_KEY_SHA256,
                Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(result.issuerKey)));
    }

    @Test public void selfSignedAttackerIssuerCannotBecomeTheTrustAnchor() {
        AtomicInteger verifierCalls = new AtomicInteger();
        assertThrows(SecurityException.class, () -> PakeEmvCertificates.verify(generatedCard, generatedRoot, NOW,
                (certificate, signer) -> verifierCalls.incrementAndGet()));
        assertEquals("Reject unconfigured root before consulting its self-signature", 0, verifierCalls.get());
    }

    @Test public void configuredIssuerPolicyValidatesRealSignaturesAndReturnsPan() throws Exception {
        PakeEmvCertificates.Verified result = verifyGenerated(generatedCard, generatedRoot);
        assertEquals("4502123456789012", result.pan);
        assertArrayEquals(rootKey, result.issuerKey);
        assertArrayEquals(cardKey, result.cardKey);
    }

    @Test public void expectedPanIsNotPartOfCertificateAcceptance() throws Exception {
        PakeEmvCertificates.Verified result = verifyGenerated(generatedCard, generatedRoot);
        assertNotEquals(PakeEmvCertificates.canonicalPan("4502123456789013"), result.pan);
        // The policy returns the certified PAN; the protocol records the mismatch
        // and performs its M5/M6 exchange before deciding local acceptance.
    }

    @Test public void referencePanRequiresAsciiDigitsWithNoSilentNormalization() {
        for (String pan : new String[]{"", "4502123456789012 ", " 4502123456789012", "4502-1234-5678-9012",
                "４５０２１２３４５６７８９０１２", "12345678901", "12345678901234567890", "450212345678901x"}) {
            assertThrows(IllegalArgumentException.class, () -> PakeEmvCertificates.canonicalPan(pan));
        }
        assertThrows(IllegalArgumentException.class, () -> PakeEmvCertificates.canonicalPan(null));
        assertEquals("001234567890", PakeEmvCertificates.canonicalPan("001234567890"));
    }

    @Test public void expiredAndNotYetValidChainsAreRejected() {
        for (Date now : new Date[]{new Date(0), new Date(2556144000000L)}) { // Beyond the fixture's 2049 expiry.
            assertThrows(SecurityException.class, () -> PakeEmvCertificates.verify(fixtureCard, fixtureIssuer, now,
                    PakeEmvCertificatesTest::verifySignature));
        }
    }

    @Test public void alteredLeafSignatureIsRejected() {
        byte[] corrupt = generatedCard.clone();
        corrupt[corrupt.length - 1] ^= 1;
        assertThrows(Exception.class, () -> verifyGenerated(corrupt, generatedRoot));
    }

    @Test public void alteredIssuerSignatureIsRejected() {
        byte[] corrupt = generatedRoot.clone();
        corrupt[corrupt.length - 1] ^= 1;
        assertThrows(Exception.class, () -> verifyGenerated(generatedCard, corrupt));
    }

    @Test public void invalidLeafPublicKeyAlgorithmOrLengthIsRejected() throws Exception {
        for (byte[] corrupt : new byte[][]{
                card(CARD_NAME, new AlgorithmIdentifier(ML_DSA_44), cardKey, null, null),
                card(CARD_NAME, new AlgorithmIdentifier(ML_KEM_512), new byte[799], null, null)}) {
            assertThrows(SecurityException.class, () -> verifyGenerated(corrupt, generatedRoot));
        }
    }

    @Test public void spuriousAlgorithmParametersAreRejected() throws Exception {
        byte[] corrupt = card(CARD_NAME, new AlgorithmIdentifier(ML_KEM_512,
                org.bouncycastle.asn1.DERNull.INSTANCE), cardKey, null, null);
        assertThrows(SecurityException.class, () -> verifyGenerated(corrupt, generatedRoot));
    }

    @Test public void mismatchedCertificateSignatureAlgorithmIsRejected() throws Exception {
        org.bouncycastle.asn1.x509.Certificate original = new X509CertificateHolder(generatedCard).toASN1Structure();
        byte[] corrupt = new DERSequence(new ASN1Encodable[]{original.getTBSCertificate(),
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")),
                new DERBitString(original.getSignature().getBytes())}).getEncoded();
        assertThrows(SecurityException.class, () -> verifyGenerated(corrupt, generatedRoot));
    }

    @Test public void chainIssuerNameMustLinkToTheConfiguredRoot() throws Exception {
        byte[] corrupt = certificate(new X500Name("CN=Different issuer"), CARD_NAME,
                new SubjectPublicKeyInfo(new AlgorithmIdentifier(ML_KEM_512), cardKey), null, null);
        assertThrows(SecurityException.class, () -> verifyGenerated(corrupt, generatedRoot));
    }

    @Test public void panBindingMustBeUniqueAsciiAndUnambiguous() throws Exception {
        for (String name : new String[]{"CN=4502123456789012,CN=4502123456789013", "O=No PAN",
                "CN=4502123456789012+OU=Ambiguous", "CN=450212345678901x", "CN=45021234567"}) {
            byte[] corrupt = card(new X500Name(name), new AlgorithmIdentifier(ML_KEM_512), cardKey, null, null);
            assertThrows(SecurityException.class, () -> verifyGenerated(corrupt, generatedRoot));
        }
    }

    @Test public void trailingObjectsAndNonDerCertificateEncodingAreRejected() throws Exception {
        byte[] trailing = Arrays.copyOf(generatedCard, generatedCard.length + 2);
        trailing[trailing.length - 2] = 5; // ASN.1 NULL
        org.bouncycastle.asn1.x509.Certificate certificate = new X509CertificateHolder(generatedCard).toASN1Structure();
        byte[] ber = new BERSequence(new ASN1Encodable[]{certificate.getTBSCertificate(),
                certificate.getSignatureAlgorithm(), certificate.getSignature()}).getEncoded();
        assertThrows(Exception.class, () -> verifyGenerated(trailing, generatedRoot));
        assertThrows(Exception.class, () -> verifyGenerated(ber, generatedRoot));
    }

    @Test public void unsupportedCriticalExtensionsAreRejected() throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(ROOT_NAME,
                BigInteger.valueOf(++serial), BEFORE, AFTER, CARD_NAME,
                new SubjectPublicKeyInfo(new AlgorithmIdentifier(ML_KEM_512), cardKey));
        builder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.55555.1"), true, new DEROctetString(new byte[]{1, 2}));
        byte[] corrupt = builder.build(new JcaContentSignerBuilder("ML-DSA-44").setProvider(BC)
                .build(testRoot.getPrivate())).getEncoded();
        assertThrows(SecurityException.class, () -> verifyGenerated(corrupt, generatedRoot));
    }

    @Test public void knownCaAndKeyUsageConstraintsAreEnforced() throws Exception {
        byte[] goodRoot = certificate(ROOT_NAME, ROOT_NAME,
                SubjectPublicKeyInfo.getInstance(testRoot.getPublic().getEncoded()), new BasicConstraints(true),
                new KeyUsage(KeyUsage.keyCertSign));
        byte[] goodCard = card(CARD_NAME, new AlgorithmIdentifier(ML_KEM_512), cardKey,
                new BasicConstraints(false), new KeyUsage(KeyUsage.keyEncipherment));
        assertArrayEquals(cardKey, verifyGenerated(goodCard, goodRoot).cardKey);
        byte[] badCard = card(CARD_NAME, new AlgorithmIdentifier(ML_KEM_512), cardKey,
                new BasicConstraints(true), new KeyUsage(KeyUsage.keyCertSign));
        assertThrows(SecurityException.class, () -> verifyGenerated(badCard, goodRoot));
        byte[] badRoot = certificate(ROOT_NAME, ROOT_NAME,
                SubjectPublicKeyInfo.getInstance(testRoot.getPublic().getEncoded()), new BasicConstraints(false), null);
        assertThrows(SecurityException.class, () -> verifyGenerated(goodCard, badRoot));
    }

    @Test public void verificationUsesStableCertificateSnapshots() throws Exception {
        byte[] mutableCard = generatedCard.clone();
        byte[] mutableIssuer = generatedRoot.clone();
        AtomicInteger calls = new AtomicInteger();
        PakeEmvCertificates.Verified result = PakeEmvCertificates.verify(mutableCard, mutableIssuer,
                rootKey, NOW, (certificate, signer) -> {
                    verifySignature(certificate, signer);
                    if (calls.incrementAndGet() == 1) {
                        Arrays.fill(mutableCard, (byte) 0);
                        Arrays.fill(mutableIssuer, (byte) 0);
                    }
                });
        assertArrayEquals(cardKey, result.cardKey);
        assertEquals(2, calls.get());
    }
}
