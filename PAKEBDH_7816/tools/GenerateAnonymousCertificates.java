import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.Locale;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/** Offline, public laboratory fixtures. The fresh issuer private key is never exported. */
public final class GenerateAnonymousCertificates {
    private static final Provider BC = new BouncyCastleProvider();
    private static final String SIGNATURE_ALGORITHM = "ML-DSA-44";
    private static final String SIGNATURE_OID = "2.16.840.1.101.3.4.3.17";
    private static final X500Name ISSUER = new X500Name("CN=Sample Issuer CA,O=Test Org,C=ZZ");
    private static final X500Name CARD = new X500Name("CN=4502123456789012,O=Test,C=ZZ");
    private static final Date NOT_BEFORE = Date.from(Instant.parse("2020-01-01T00:00:00Z"));
    private static final Date NOT_AFTER = Date.from(Instant.parse("2049-12-31T23:59:59Z"));

    private GenerateAnonymousCertificates() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: GenerateAnonymousCertificates REPOSITORY_ROOT NEW_OUTPUT_DIRECTORY");
        }
        Path repository = Path.of(args[0]).toAbsolutePath().normalize();
        Path output = Path.of(args[1]).toAbsolutePath().normalize();
        Files.createDirectories(output);
        for (String name : new String[]{"certC.der", "certIS.der", "anonymous-fixtures.json"}) {
            if (Files.exists(output.resolve(name))) {
                throw new IllegalStateException("Refusing to overwrite " + output.resolve(name));
            }
        }
        X509CertificateHolder previousCard = new X509CertificateHolder(
                Files.readAllBytes(repository.resolve("Card_pakebdh/certC.der")));
        SubjectPublicKeyInfo cardPublicKey = previousCard.getSubjectPublicKeyInfo();
        if (!"2.16.840.1.101.3.4.4.1".equals(cardPublicKey.getAlgorithm().getAlgorithm().getId())
                || cardPublicKey.getPublicKeyData().getBytes().length != 800) {
            throw new IllegalStateException("Expected the existing 800-byte ML-KEM-512 card public key.");
        }
        // Fresh OS-seeded randomness; there is no deterministic seed or private-key output.
        SecureRandom randomness = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM, BC);
        generator.initialize(new java.security.spec.NamedParameterSpec(SIGNATURE_ALGORITHM), randomness);
        KeyPair issuerKeys = generator.generateKeyPair();
        SubjectPublicKeyInfo issuerPublicKey = SubjectPublicKeyInfo.getInstance(issuerKeys.getPublic().getEncoded());
        X509CertificateHolder issuer = sign(ISSUER, issuerPublicKey, new BigInteger("010000000001", 16),
                issuerKeys, randomness);
        X509CertificateHolder card = sign(CARD, cardPublicKey, new BigInteger("010000000002", 16),
                issuerKeys, randomness);
        byte[] certC = card.getEncoded();
        byte[] certIS = issuer.getEncoded();
        if (certC.length != 3444 || certIS.length != 3960) {
            throw new IllegalStateException("Public fixture lengths changed: " + certC.length + "/" + certIS.length);
        }
        for (X509CertificateHolder certificate : new X509CertificateHolder[]{issuer, card}) {
            if (!SIGNATURE_OID.equals(certificate.getSignatureAlgorithm().getAlgorithm().getId())
                    || certificate.getSignature().length != 2420
                    || !certificate.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC)
                    .build(issuerKeys.getPublic()))) {
                throw new IllegalStateException("Generated certificate signature verification failed.");
            }
        }
        if (!Arrays.equals(previousCard.getSubjectPublicKeyInfo().getPublicKeyData().getBytes(),
                card.getSubjectPublicKeyInfo().getPublicKeyData().getBytes())) {
            throw new IllegalStateException("The card's existing KEM credential must be preserved.");
        }
        Files.write(output.resolve("certC.der"), certC);
        Files.write(output.resolve("certIS.der"), certIS);
        String manifest = String.format(Locale.ROOT,
                "{\n  \"public_test_fixture\": true,\n  \"signature_algorithm\": \"ML-DSA-44\",\n"
                + "  \"card_kem\": \"ML-KEM-512\",\n  \"issuer_subject\": \"CN=Sample Issuer CA,O=Test Org,C=ZZ\",\n"
                + "  \"card_subject\": \"CN=4502123456789012,O=Test,C=ZZ\",\n"
                + "  \"not_before\": \"2020-01-01T00:00:00Z\",\n  \"not_after\": \"2049-12-31T23:59:59Z\",\n"
                + "  \"issuer_serial_hex\": \"010000000001\",\n  \"card_serial_hex\": \"010000000002\",\n"
                + "  \"cert_c_bytes\": 3444,\n  \"cert_is_bytes\": 3960,\n"
                + "  \"cert_c_sha256\": \"%s\",\n  \"cert_is_sha256\": \"%s\",\n"
                + "  \"card_public_key_sha256\": \"%s\",\n  \"issuer_public_key_sha256\": \"%s\",\n"
                + "  \"issuer_private_key_exported\": false,\n"
                + "  \"scope\": \"Public laboratory credentials, not payment-system production credentials\"\n}\n",
                digest(certC), digest(certIS), digest(cardPublicKey.getPublicKeyData().getBytes()),
                digest(issuerPublicKey.getPublicKeyData().getBytes()));
        Files.writeString(output.resolve("anonymous-fixtures.json"), manifest);
        System.out.print(manifest);
    }

    private static X509CertificateHolder sign(X500Name subject, SubjectPublicKeyInfo publicKey,
                                              BigInteger serial, KeyPair issuerKeys,
                                              SecureRandom randomness) throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(ISSUER, serial,
                NOT_BEFORE, NOT_AFTER, subject, publicKey);
        return builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC)
                .setSecureRandom(randomness).build(issuerKeys.getPrivate()));
    }

    private static String digest(byte[] input) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
    }
}
