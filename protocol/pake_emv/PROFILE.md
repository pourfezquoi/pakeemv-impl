# PAKE-EMV final six-message profile

This profile implements the final detailed flow supplied in Figure 12 of the
manuscript, together with the role processes in Figure 13 and the surrounding
protocol text. The terminal executes Init1 through Init4; the card executes
Resp1 through Resp3. The earlier overview figure and historical benchmark
measurements do not specify this revision's wire format.

## Concrete public configuration

The exact ASCII suite identifier, without a terminating NUL, is:

```text
PAKE-EMV-v3:CHIC-ddf94132-Kyber512:ML-KEM-512:ML-DSA-44:SHA256:HKDF-SHA256:AES256-GCM:CERT8192
```

`H` is SHA-256 with its complete 32-byte output. The figure's labels are literal
ASCII bytes. `KDF2(tk, info)` is RFC 5869 HKDF-SHA-256 with Extract salt of 32 zero
bytes, IKM `tk`, Expand info exactly `info`, and output length 32 bytes. CERT,
EC2, FINAL, CONF2 and CONF3 remain distinct domains. These are concrete choices
for the manuscript's abstract hash/KDF interfaces, not modifications to the
underlying CHIC construction or a proof of the random-oracle assumptions.

The CHIC implementation and its exact modified Kyber dependency remain pinned
and byte-for-byte preserved in `third_party/chic`. The outer PIN adapter hashes
the six ASCII digits with SHA-256. Its identity-independent, fresh 32-byte SID
is transmitted inside `X1 = SID || CHIC_msg1`. The subsequent nonce `nu` is a
different fresh 32-byte value, sampled only after receiving X2 and successfully
finishing CHIC. PAN is never an input to CHIC or the SID.

The second KEM is ML-KEM-512. Certificates use ML-DSA-44 signatures. AE is
AES-256-GCM with a fresh independent 12-byte nonce, a 16-byte authentication tag,
and empty associated data. Its encoding is `nonce || ciphertext || tag`.

All concatenations have fixed-size fields within this suite, except the
explicitly length-encoded certificate chain. No C string terminators, implicit
text encodings, truncated confirmation tags or hex encodings enter the hashes.

## Messages and local algorithms

| Message | Direction | Encoding | Bytes |
| --- | --- | --- | ---: |
| M1 = X1 | Terminal Init1 to card Resp1 | SID[32] || original CHIC msg1[800] | 832 |
| M2 = X2 | Card Resp1 to terminal Init2 | original CHIC tag[32] || ciphertext[768] | 800 |
| M3 | Terminal Init2 to card Resp2 | nu[32] || pi1[32] | 64 |
| M4 = ecert | Card Resp2 to terminal Init3 | AES-GCM envelope of padded certs[8192] | 8220 |
| M5 | Terminal Init3 to card Resp3 | ec[796] || pi2[32] | 828 |
| M6 | Card Resp3 to terminal Init4 | pi3[32] | 32 |

`ctx1 = H("PAKE-EMV" || suite || X1 || X2)` includes the complete transmitted
X1, including SID, and the complete authenticated CHIC X2. Init2 computes
`pi1 = H("KC1" || tk || ctx1 || nu)`. Both roles derive:

```text
ctx2 = H("ctx2" || M3 || ctx1)
Kcert = KDF2(tk, "CERT" || ctx2)
ctx3 = H("ctx3" || ecert || ctx2)
Kec = KDF2(tk, "EC2" || ctx3)
ctx4 = H("ctx4" || ec || ctx3)
pkh = H("pkh" || pkC[800] || pkIS[1312])
K  = KDF2(tk, ss || "FINAL" || pkh || ctx4)
k2 = KDF2(tk, ss || "CONF2" || pkh || ctx4)
k3 = KDF2(tk, ss || "CONF3" || pkh || ctx4)
pi2 = H("KC2" || k2 || ctx4)
ctx5 = H("ctx5" || pi2 || ctx4)
pi3 = H("KC3" || k3 || ctx5)
```

The card verifies pi1 before releasing ecert, and verifies pi2 before recording
K or returning pi3. An implicit-rejection ML-KEM secret is therefore checked by
pi2. The terminal verifies pi3 and its stored PAN comparison before accepting.
The old F4 diagnostic proof is not a substitute for M6 and is not part of this
profile.

## Certificate encoding, trust and reference PAN

Before encryption, the certificate plaintext is exactly 8192 bytes:

```text
lenC_u16BE || lenIS_u16BE || DER_certC || DER_certIS || 0x80 || zero padding
```

Both DER lengths must be positive, the marker must fit, and every remaining
padding byte must be zero. The maximum combined DER size is 8187 bytes. Parsing,
padding or decryption errors abort before any certificate is used. This common
fixed length does not vary by the expected or certified card identity.

The laboratory issuer's public key is provisioned as the terminal trust anchor
independently of the received M4. Verifying a received self-signature alone does
not create trust. The certificate policy validates the permitted signature and
public-key algorithms, the trusted issuer binding, signatures, validity, chain
names, critical extensions and the leaf's PAN encoding. This pinned laboratory
anchor policy is not an arbitrary Internet/X.509 trust-store policy.

The demo certificate encodes PAN as the leaf subject's single CN, restricted to
12 through 19 ASCII decimal digits. `PAN_expected` uses the same canonical
format and comes from terminal transaction configuration before M1. The lab
App and instrumentation test default to the reference provisioned for the
bundled test card. Instrumentation may override it with `benchmarkExpectedPan`.
This input is independent of the received chain and remains fixed across all permitted PIN retries. Its
acquisition is outside the modeled six-message exchange and must not be logged
or transmitted by this protocol.

After valid certificate verification, the terminal records
`ok = (PAN_cert == PAN_expected)` but always proceeds to the same Init3/M5
operations. It records K independently of final acceptance, retains that record
on both final outcomes, and waits for M6. A mismatching PAN does not change M5,
the K record or subsequent protocol traffic. Init4 accepts only if pi3 is valid
and ok is true. It sends no protocol response on either outcome. Card-side K is
recorded only after successful pi2 verification. Temporary secrets and obsolete
running state are erased separately from the retained key record.

## APDU framing, transaction initialization and retries

F8 advertises PEM1 profile version 3. BeginTransaction is the management command
`80 F9 00 00 00`, returning `9000`. It creates a fresh card-side role instance,
clears the previous transaction's key record and initializes retry count n=0.
The terminal issues it once before the first PIN/PAKE attempt of a transaction.
It is an implementation of the external session initializer, outside M1–M6 and
outside core timing/traffic. It is never issued between retries.

C1 carries fragmented M1 and returns fragmented M2; B2 carries M3 and returns
fragmented M4; 50 carries fragmented M5 and returns M6 in its final response.
Input fragments use P1=1 for more and P1=0 for the final fragment. C1/B2 response
continuations use P1=1 with no command data. P2 is zero. The card rejects invalid
lengths, unexpected phases, extra data and invalid confirmation messages.
Status words and transport framing are not inputs to the protocol hashes.

A well-formed M3 whose pi1 fails receives the distinct five-byte ASCII payload
`RETRY`, with status `9000`, when n<2. The card increments n and waits for a new
M1. The terminal then requests a new PIN and starts fresh CHIC state, SID and
nonce while keeping the same reference PAN. At most two retries, or three
attempts, are allowed per transaction. Malformed M3, wrong-phase messages,
CHIC Finish failure, AE failure, certificate failure and final confirmation
failure terminate rather than triggering this retry path. CHIC's own tag is
never bypassed to force a failed PIN into the outer RETRY path.

The retry count is a property of this transaction instance; it is not a
persistent PIN lockout across new transactions or power cycles. New C1 messages
cannot silently restart a running or halted role; a new external transaction
requires BeginTransaction.

## Measurement boundary and deployment checks

The core ends with M6 and the terminal's local Init4 result. Optional F7 timing
queries belong to a separate measurement wrapper, not a seventh protocol
message or a key-confirmation step. That wrapper performs the same cached
snapshot operation for completed accepting and rejecting final outcomes,
independently of the PAN comparison or pi3 result. The core sends no F4 proof,
acceptance response, conditional reset or conditional trace after M6.

With the current fragmentation sizes, the core uses 46 APDU exchanges: 7 for
M1/M2, 35 for M3/M4, and 4 for M5/M6. Its application payload totals 10776 bytes
and complete command/response APDUs total 11098 bytes. Setup, management,
measurement diagnostics and transport framing are excluded. Historical
measurements of earlier profiles must be collected again for this revision.

Both Android and card firmware must be updated together. Host interoperability,
negative tests and cross-compilation do not replace a Keil rebuild or physical
board validation. The preserved CHIC author's reference implementation has
documented password-dependent timing limitations; this integration does not
remove them or prove the manuscript's UC/session-model assumptions.
