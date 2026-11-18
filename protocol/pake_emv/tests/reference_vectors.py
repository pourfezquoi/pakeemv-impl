#!/usr/bin/env python3
"""Independent PAKE-EMV-v3 vectors using Python's standard hashlib/hmac."""
import hashlib
import hmac
import json
from pathlib import Path
import sys

SUITE = (b"PAKE-EMV-v3:CHIC-ddf94132-Kyber512:ML-KEM-512:ML-DSA-44:"
         b"SHA256:HKDF-SHA256:AES256-GCM:CERT8192")


def pattern(length, seed):
    return bytes((17 * i + seed) & 255 for i in range(length))


def sha(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def kdf(tk, info):
    # RFC 5869 Extract(salt=zero[32], IKM=tk), Expand(info, L=32).
    prk = hmac.new(bytes(32), tk, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def vectors():
    tk, ss = pattern(32, 1), pattern(32, 2)
    x1, x2, nu = pattern(832, 3), pattern(800, 4), pattern(32, 5)
    ecert, ec = pattern(8220, 6), pattern(796, 7)
    pk_c, pk_is = pattern(800, 8), pattern(1312, 9)
    ctx1 = sha(b"PAKE-EMV", SUITE, x1, x2)
    pi1 = sha(b"KC1", tk, ctx1, nu)
    ctx2 = sha(b"ctx2", nu, pi1, ctx1)
    kcert = kdf(tk, b"CERT" + ctx2)
    ctx3 = sha(b"ctx3", ecert, ctx2)
    kec = kdf(tk, b"EC2" + ctx3)
    ctx4 = sha(b"ctx4", ec, ctx3)
    pkh = sha(b"pkh", pk_c, pk_is)
    key = kdf(tk, ss + b"FINAL" + pkh + ctx4)
    k2 = kdf(tk, ss + b"CONF2" + pkh + ctx4)
    k3 = kdf(tk, ss + b"CONF3" + pkh + ctx4)
    pi2 = sha(b"KC2", k2, ctx4)
    ctx5 = sha(b"ctx5", pi2, ctx4)
    pi3 = sha(b"KC3", k3, ctx5)
    cert_c, cert_is = pattern(1200, 10), pattern(2400, 11)
    padded = len(cert_c).to_bytes(2, "big") + len(cert_is).to_bytes(2, "big")
    padded += cert_c + cert_is + b"\x80"
    padded += bytes(8192 - len(padded))
    values = dict(ctx1=ctx1, pi1=pi1, ctx2=ctx2, kcert=kcert, ctx3=ctx3,
                  kec=kec, ctx4=ctx4, pkh=pkh, key=key, k2=k2, k3=k3,
                  pi2=pi2, ctx5=ctx5, pi3=pi3, padded_sha256=sha(padded))
    return {name: value.hex() for name, value in values.items()}


def main():
    expected = vectors()
    if len(sys.argv) == 1:
        print(json.dumps(expected, indent=2))
        return
    for path in sys.argv[1:]:
        path = Path(path)
        if path.suffix == ".json":
            actual = json.loads(path.read_text())
        else:
            actual = dict(line.split("=", 1) for line in path.read_text().splitlines()
                          if "=" in line)
        if actual != expected:
            missing = set(expected) - set(actual)
            extra = set(actual) - set(expected)
            mismatches = [name for name in expected.keys() & actual.keys()
                          if expected[name] != actual[name]]
            raise SystemExit(f"Vector mismatch: {path}; missing={missing}, extra={extra}, "
                             f"changed={mismatches}")
        print(f"Verified {len(expected)} independent Python vectors: {path}")


if __name__ == "__main__":
    main()
