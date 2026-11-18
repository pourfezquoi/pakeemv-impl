# PAKE-EMV outer-profile tests

Run `bash protocol/pake_emv/tests/run-host-tests.sh` from a checkout with a
C99 compiler, OpenSSL development headers/libraries, Python 3 and a JDK.
`JAVA_HOME` optionally selects the JDK. The managed workspace provides these
through `source /workspace/tooling/env.sh`.

`reference_vectors.py` independently specifies the concrete figure encodings
using Python's standard `hashlib` and `hmac`. Input byte `i` is
`(17*i+seed) mod 256`; seeds and lengths are recorded in that script.
`vectors.json` commits the resulting expected bytes. Both C and Java helpers
must agree with all 15 independently recomputed outputs: five contexts,
three confirmation hashes, certificate/encrypted-ciphertext keys, public-key
binding, three derived keys and the padded-certificate hash.

Tests also check transcript and key-binding changes, distinct label outputs,
strict certificate padding, fixed message sizes in Java, maximum certificate
payload, malformed lengths, and clearing C certificate views on parse errors.
The C SHA-256 callback uses OpenSSL only in the test executable. Production
card helpers remain allocation-free and use the card's streaming SHA-256 API.
