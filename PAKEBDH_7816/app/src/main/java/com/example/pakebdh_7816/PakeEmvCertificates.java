package com.example.pakebdh_7816;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

/** Explicit two-certificate validation policy for the provisioned laboratory suite.
 * The issuer public key is an independently installed trust anchor, never learned
 * from a received certificate. The existing pinned root predates BasicConstraints
 * and KeyUsage extensions; their absence is allowed for this fixed root profile.
 */
final class PakeEmvCertificates {
    private static final String ML_DSA_44 = "2.16.840.1.101.3.4.3.17";
    private static final String ML_KEM_512 = "2.16.840.1.101.3.4.4.1";
    private static final int ISSUER_KEY_BYTES = 1312;
    private static final int CARD_KEY_BYTES = 800;
    private static final int MAX_CERTIFICATE_BYTES = 8192;

    private PakeEmvCertificates() { }

    interface SignatureVerifier {
        void verify(byte[] certificate, byte[] signerKey) throws Exception;
    }

    /** VerifyCert(pk_CA, certs): authentication of PAN_expected is a later step. */
    static Verified verify(byte[] certC, byte[] certIS) throws Exception {
        return verify(certC, certIS, new Date(), PakeEmvCrypto::verifyCertificateSignature);
    }

    static Verified verify(byte[] certC, byte[] certIS, Date now,
                           SignatureVerifier verifier) throws Exception {
        return verify(certC, certIS, PakeEmvTrustAnchor.publicKey(), now, verifier);
    }

    /** Explicit trust input permits independently provisioned deployments and tests. */
    static Verified verify(byte[] certC, byte[] certIS, byte[] trustedCaPublicKey,
                           Date now, SignatureVerifier verifier) throws Exception {
        if (trustedCaPublicKey == null || trustedCaPublicKey.length != ISSUER_KEY_BYTES
                || now == null || verifier == null) {
            throw new IllegalArgumentException("A configured ML-DSA-44 CA key, time and verifier are required.");
        }
        byte[] cardEncoding = certC == null ? null : certC.clone();
        byte[] issuerEncoding = certIS == null ? null : certIS.clone();
        X509CertificateHolder card = parseDer(cardEncoding);
        X509CertificateHolder issuer = parseDer(issuerEncoding);
        validateCertificate(card, now);
        validateCertificate(issuer, now);
        byte[] cardKey = publicKey(card, ML_KEM_512, CARD_KEY_BYTES);
        byte[] issuerKey = publicKey(issuer, ML_DSA_44, ISSUER_KEY_BYTES);
        if (!MessageDigest.isEqual(trustedCaPublicKey, issuerKey)) {
            throw new SecurityException("The certificate issuer is not a configured trust anchor.");
        }
        if (!issuer.getIssuer().equals(issuer.getSubject())
                || !card.getIssuer().equals(issuer.getSubject())) {
            throw new SecurityException("Certificate issuer/subject chain does not match the pinned root.");
        }
        validateExtensions(issuer, true);
        validateExtensions(card, false);
        verifier.verify(issuerEncoding.clone(), trustedCaPublicKey.clone());
        verifier.verify(cardEncoding.clone(), issuerKey.clone());
        String pan = certificatePan(card);
        return new Verified(cardKey, issuerKey, pan);
    }

    /** A reference PAN is supplied before PAKE; no normalization hides a mismatch. */
    static String canonicalPan(String pan) {
        if (pan == null || !pan.matches("[0-9]{12,19}")) {
            throw new IllegalArgumentException("PAN must contain 12 to 19 ASCII digits.");
        }
        return pan;
    }

    private static X509CertificateHolder parseDer(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length == 0 || encoded.length > MAX_CERTIFICATE_BYTES) {
            throw new SecurityException("Invalid certificate length.");
        }
        try (ASN1InputStream input = new ASN1InputStream(encoded)) {
            ASN1Primitive certificate = input.readObject();
            if (certificate == null || input.readObject() != null
                    || !Arrays.equals(encoded, certificate.getEncoded(ASN1Encoding.DER))) {
                throw new SecurityException("Certificate must contain exactly one canonical DER object.");
            }
            return new X509CertificateHolder(encoded);
        } catch (IllegalArgumentException malformed) {
            throw new SecurityException("Malformed X.509 certificate.", malformed);
        }
    }

    private static void validateCertificate(X509CertificateHolder certificate, Date now) {
        if (certificate.getVersionNumber() != 3 || !certificate.isValidOn(now)
                || certificate.getSerialNumber().signum() <= 0
                || certificate.getSerialNumber().bitLength() > 160) {
            throw new SecurityException("Certificate version, validity or serial is invalid.");
        }
        requireAlgorithm(certificate.getSignatureAlgorithm(), ML_DSA_44);
        if (!certificate.getSignatureAlgorithm().equals(
                certificate.toASN1Structure().getTBSCertificate().getSignature())) {
            throw new SecurityException("Certificate signature algorithms disagree.");
        }
        if (certificate.toASN1Structure().getSignature().getPadBits() != 0
                || certificate.getSignature().length != 2420) {
            throw new SecurityException("Expected a complete ML-DSA-44 signature.");
        }
    }

    private static byte[] publicKey(X509CertificateHolder certificate, String oid, int size) {
        SubjectPublicKeyInfo info = certificate.getSubjectPublicKeyInfo();
        requireAlgorithm(info.getAlgorithm(), oid);
        byte[] raw = info.getPublicKeyData().getBytes();
        if (info.getPublicKeyData().getPadBits() != 0 || raw.length != size) {
            throw new SecurityException("Invalid certified public-key encoding or size.");
        }
        return raw;
    }

    private static void requireAlgorithm(AlgorithmIdentifier algorithm, String expected) {
        if (!expected.equals(algorithm.getAlgorithm().getId()) || algorithm.getParameters() != null) {
            throw new SecurityException("Certificate algorithm is outside the selected suite.");
        }
    }

    private static void validateExtensions(X509CertificateHolder certificate, boolean issuer) {
        Extensions extensions = certificate.getExtensions();
        if (extensions == null) return;
        for (ASN1ObjectIdentifier oid : extensions.getCriticalExtensionOIDs()) {
            if (!Extension.basicConstraints.equals(oid) && !Extension.keyUsage.equals(oid)) {
                throw new SecurityException("Unsupported critical certificate extension: " + oid.getId());
            }
        }
        BasicConstraints constraints = BasicConstraints.fromExtensions(extensions);
        if (constraints != null && constraints.isCA() != issuer) {
            throw new SecurityException("Certificate CA constraints do not match its role.");
        }
        KeyUsage usage = KeyUsage.fromExtensions(extensions);
        if (usage != null && (!usage.hasUsages(issuer ? KeyUsage.keyCertSign : KeyUsage.keyEncipherment)
                || (!issuer && usage.hasUsages(KeyUsage.keyCertSign)))) {
            throw new SecurityException("Certificate key usage does not match its role.");
        }
    }

    private static String certificatePan(X509CertificateHolder card) {
        RDN[] names = card.getSubject().getRDNs(BCStyle.CN);
        if (names.length != 1 || names[0].isMultiValued()
                || !(names[0].getFirst().getValue() instanceof ASN1String)) {
            throw new SecurityException("Card certificate must bind one unambiguous PAN common name.");
        }
        try {
            return canonicalPan(((ASN1String) names[0].getFirst().getValue()).getString());
        } catch (IllegalArgumentException malformed) {
            throw new SecurityException("Card certificate PAN is invalid.", malformed);
        }
    }

    static final class Verified {
        final byte[] cardKey;
        final byte[] issuerKey;
        final String pan;

        Verified(byte[] cardKey, byte[] issuerKey, String pan) {
            this.cardKey = cardKey.clone();
            this.issuerKey = issuerKey.clone();
            this.pan = pan;
        }
    }
}
