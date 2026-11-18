# Public certificate fixtures

The two card projects use public laboratory certificates with generic names,
fixed validity dates and fixed serial numbers. Their card public key matches the
existing laboratory ML-KEM-512 private credential. The issuer is a freshly
generated ML-DSA-44 laboratory CA; its private key is never written to a file.
These certificates are test credentials and do not represent a real issuer,
organization or payment-system certification authority.

The numeric PAN is a fixed public protocol fixture. It is not acquired from a
user account or a live payment card. The terminal still obtains its expected PAN
independently of the received certificate.

To deliberately refresh the fixtures, set `BC_CLASSPATH` to the Bouncy Castle
`bcprov`, `bcpkix` and `bcutil` JARs, then run from the repository root with a JDK
that supports `java.util.HexFormat`:

```sh
mkdir -p work/certificate-generator
javac -cp "$BC_CLASSPATH" -d work/certificate-generator \
  PAKEBDH_7816/tools/GenerateAnonymousCertificates.java
java -cp "$BC_CLASSPATH:work/certificate-generator" GenerateAnonymousCertificates \
  . work/new-public-certificates
python3 PAKEBDH_7816/tools/provision_test_trust.py \
  --install-certificates work/new-public-certificates
```

Use a new output directory for each generation. Every generation creates a new
issuer key using fresh randomness; it is intentionally not byte-reproducible.
The installation step preserves the card KEM credential, keeps the certificate
lengths at 3444 and 3960 bytes, and updates both card headers, the terminal's CA
pin, the public credential-key header and the certificate test resources.
`anonymous-fixtures.json` records public hashes and generic metadata.

Running `provision_test_trust.py` without arguments only regenerates the public
pin and key constants from the currently installed certificates. That operation
is byte-reproducible and does not generate keys or change certificates.
