# CHIC author reference implementation

This directory compiles the complete CHIC-512 reference construction from
[mbbarbosa/pake-constructions](https://github.com/mbbarbosa/pake-constructions)
at `ddf94132d343227df0dc051664d1ad95f672a81e`, with that revision's exact
[mbbarbosa/kyber](https://github.com/mbbarbosa/kyber) submodule at
`51fbde797f32c228976777021144a69e45b5fcd8`.

Files below `upstream/` are byte-for-byte upstream copies. `UPSTREAM.json`
records each upstream repository, revision, path and Git blob SHA-1.
Run `python3 third_party/chic/verify_upstream.py` from the repository root
to verify every vendored source and notice without network access.

## Construction and interface

The application must call `chic_init_start`, `chic_respond` and
`chic_init_end` from `chic.h`. They call the author's unchanged
`initStart`, `resp` and `initEnd`; there is no replacement HIC, KEM or KDF.
The author-provided Kyber dependency is retained separately from the
application's second-stage ML-KEM. Both use 512 parameters but the PAKE
does not substitute a different KEM implementation.

The first core message is 800 bytes. The response is exactly 800 bytes,
`tag[32] || ciphertext[768]`. The original `hash_g` is SHA3-512 over
`ss || sid || pk || msg1 || ct`; its first half is the 32-byte PAKE key
and its second half is the responder tag. Finish checks this tag before
the adapter releases the PAKE key.

The adapter requires distinct correctly sized arrays. The external
`int chic_randombytes(uint8_t *, size_t)` provider must return zero only
after filling the entire request using a cryptographic random source.
No default entropy provider is linked. The bridge detects a failed
provider, initializes the upstream scratch request, and erases all public
outputs before returning failure. Android/host failure tracking uses
thread-local storage; the serialized Keil smartcard uses a single flag.
Finish erases the caller's key output before checking and again on failure.
The C adapter is stateless; the application owns session creation,
single-use state, retry limits and state erasure.

## Build adapters

The small `src/chic_ref_*.c` translation units include `namespace.h`
followed by the unchanged author files. The shim isolates every global
KEM, SHA3/SHAKE and Rijndael symbol from the card's existing ML-KEM code.
It selects `KYBER_K=2` and uses Rijndael's documented
`UINT32_TYPE=uint32_t` configuration; neither changes the algorithm or
wire format. No optional TEMPO sampling algorithm is selected.

The pinned rejection-sampling file unconditionally includes OpenSSL's
`bn.h`, although its default original sampler contains no BIGNUM calls.
The private `compat/openssl/bn.h` is an empty include adapter for that
unused dependency. It supplies no types, functions or cryptography.
Both it and the namespace shim reject every optional TEMPO sampler at
compile time. The complete original default sampling code is compiled.

The public header does not include private Kyber headers. CMake builds
`chic_ref` as a position-independent static library and uses
`-fno-strict-aliasing` for GCC/Clang because the author's Rijndael code
accesses byte buffers as 32-bit words. The Keil Arm Compiler 6 target compiles
the same translation units in C99 mode with `CHIC_SINGLE_THREADED` and
`-fno-strict-aliasing`. The reference HIC's internal Rijndael
buffers must be word-aligned by the target compiler; host sanitizer
checks cover the tested host build, and the Keil build still requires
target validation.

```sh
cmake -S third_party/chic -B work/chic-host -DBUILD_TESTING=ON
cmake --build work/chic-host
ctest --test-dir work/chic-host --output-on-failure
```

The tests check deterministic interoperability with the original entry
points, HIC inversion, wrong passwords, altered transcript fields,
responder tag/ciphertext tampering, cross-session responses, output
erasure and random-source failure.

## Upstream implementation and license notices

The preserved [upstream README](upstream/README.md) states:

> These implementations are not claimed to be fit for practical deployment.
> In particular, no attempt has been made to ensure that the implementation
> of the half-ideal-cipher is constant-time with respect to the input password.

Restoring the author construction does not remove that implementation
limitation or establish a proof for the outer APDU/SID integration.

All upstream copyright and license notices are preserved. The upstream
top-level LICENSE describes CC0/Apache-2.0, while the imported ccrypt
Rijndael file headers explicitly state GNU GPL and refer to a COPYING file
not present in the pinned repository. `LICENSE.rijndael-GPL-2` supplies
the standard GPLv2 text for reference; this provenance record does not
resolve that discrepancy or relicense the imported code.
