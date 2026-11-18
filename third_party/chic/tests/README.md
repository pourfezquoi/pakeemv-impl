The host test uses the author's unchanged CHIC entry points as an interoperability
oracle for the public adapter. It records OS entropy and replays exactly the same
bytes to compare initial state, full HIC message, responder message (`tag || ct`)
and derived key. It also checks HIC inversion, both directions of the adapter /
reference handshake, wrong passwords, altered SID, altered stored transcript,
public and secret keys, every tag byte, representative ciphertext positions and
key clearing after a previously successful Finish.

The entropy recorder in `test_chic.c` is **test-only**. It fails closed if Linux
`getrandom` fails; it must never be linked into Android or card production builds.
