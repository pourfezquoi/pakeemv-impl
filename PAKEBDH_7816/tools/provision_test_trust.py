#!/usr/bin/env python3
"""Provision public pins/credential-key constants from the existing demo certs.

This offline maintenance tool does not generate keys, sign certificates or use
the card's private key. Review issuer authenticity before replacing a trust pin.
"""
import base64
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fields(encoded, expected_tag):
    """Read a canonical definite-length DER object and its immediate children."""
    def item(data, position):
        start = position
        tag = data[position]
        position += 1
        first = data[position]
        position += 1
        if first & 128:
            width = first & 127
            if not 1 <= width <= 4 or data[position] == 0:
                raise ValueError("Invalid DER length")
            length = int.from_bytes(data[position:position + width], 'big')
            if length < 128:
                raise ValueError("Non-canonical DER length")
            position += width
        else:
            length = first
        end = position + length
        if end > len(data):
            raise ValueError("Truncated DER")
        return tag, data[position:end], data[start:end], end
    tag, content, _, end = item(encoded, 0)
    if tag != expected_tag or end != len(encoded):
        raise ValueError("Unexpected DER object")
    result = []
    position = 0
    while position < len(content):
        tag, value, raw, position = item(content, position)
        result.append((tag, value, raw))
    return result


def raw_public_key(certificate, expected_size):
    certificate_fields = fields(certificate, 0x30)
    tbs = fields(certificate_fields[0][2], 0x30)
    spki = fields(tbs[6 if tbs[0][0] == 0xa0 else 5][2], 0x30)
    assert len(spki) == 2 and spki[1][0] == 3 and spki[1][1][0] == 0
    public_key = spki[1][1][1:]
    assert len(public_key) == expected_size
    return public_key


def digest(data):
    return hashlib.sha256(data).hexdigest()


def c_array(name, data):
    lines = [f'static const unsigned char {name}[{len(data)}] = {{']
    for offset in range(0, len(data), 12):
        lines.append('    ' + ', '.join(f'0x{x:02x}' for x in data[offset:offset+12]) + ',')
    return '\n'.join(lines + ['};', ''])


def certificate_header(cert_c, cert_is):
    text = '// Public laboratory certificates generated with an ephemeral ML-DSA-44 issuer.\n#pragma once\n\n'
    for name, data in (('certC_der', cert_c), ('certIS_der', cert_is)):
        text += f'static const unsigned int {name}_len = {len(data)};\n'
        text += f'static const unsigned char {name}[{len(data)}] = {{\n'
        for offset in range(0, len(data), 12):
            chunk = data[offset:offset + 12]
            suffix = ',' if offset + len(chunk) < len(data) else ''
            text += '    ' + ', '.join(f'0x{x:02x}' for x in chunk) + suffix + '\n'
        text += '};\n\n'
    return text.rstrip() + '\n'


def install_certificates(directory):
    cert_c = (directory / 'certC.der').read_bytes()
    cert_is = (directory / 'certIS.der').read_bytes()
    manifest = json.loads((directory / 'anonymous-fixtures.json').read_text())
    assert (len(cert_c), len(cert_is)) == (3444, 3960), 'Preserve certificate/message lengths'
    assert manifest['cert_c_sha256'] == digest(cert_c)
    assert manifest['cert_is_sha256'] == digest(cert_is)
    new_card_key = raw_public_key(cert_c, 800)
    assert manifest['card_public_key_sha256'] == digest(new_card_key)
    assert manifest['issuer_public_key_sha256'] == digest(raw_public_key(cert_is, 1312))
    for card_directory in ('Card_pakebdh', 'Card_armcortex'):
        previous = (ROOT / card_directory / 'certC.der').read_bytes()
        assert raw_public_key(previous, 800) == new_card_key, 'Preserve the existing card KEM credential'
    header = certificate_header(cert_c, cert_is)
    for card_directory in ('Card_pakebdh', 'Card_armcortex'):
        (ROOT / card_directory / 'certC.der').write_bytes(cert_c)
        (ROOT / card_directory / 'certIS.der').write_bytes(cert_is)
        (ROOT / card_directory / 'Demo/cert_blobs.h').write_text(header)
    fixtures = ROOT / 'PAKEBDH_7816/app/src/test/resources/pake-emv-certificates'
    fixtures.mkdir(parents=True, exist_ok=True)
    (fixtures / 'certC.der').write_bytes(cert_c)
    (fixtures / 'certIS.der').write_bytes(cert_is)
    (ROOT / 'PAKEBDH_7816/tools/anonymous-fixtures.json').write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install-certificates', type=Path,
                        help='Install a deliberately generated anonymous public fixture directory')
    args = parser.parse_args()
    if args.install_certificates is not None:
        install_certificates(args.install_certificates)
    cert_c = (ROOT / 'Card_pakebdh/certC.der').read_bytes()
    cert_is = (ROOT / 'Card_pakebdh/certIS.der').read_bytes()
    pk_c = raw_public_key(cert_c, 800)
    pk_is = raw_public_key(cert_is, 1312)
    text = '''package com.example.pakebdh_7816;

import org.bouncycastle.util.encoders.Base64;

/** Public laboratory CA pin installed independently of protocol messages.
 * Regenerate deliberately using PAKEBDH_7816/tools/provision_test_trust.py.
 * This trusts the existing self-signed issuer as the suite's CA anchor.
 */
final class PakeEmvTrustAnchor {
    private PakeEmvTrustAnchor() { }
'''
    text += f'    static final String CERTIFICATE_SHA256 = "{digest(cert_is)}";\n'
    text += f'    static final String PUBLIC_KEY_SHA256 = "{digest(pk_is)}";\n'
    encoded = base64.b64encode(pk_is).decode('ascii')
    text += '    private static final String PUBLIC_KEY =\n'
    text += '\n'.join('            "' + encoded[i:i+96] + '"' + (';' if i+96 >= len(encoded) else ' +')
                      for i in range(0, len(encoded), 96))
    text += '\n\n    static byte[] publicKey() { return Base64.decode(PUBLIC_KEY); }\n}\n'
    (ROOT / 'PAKEBDH_7816/app/src/main/java/com/example/pakebdh_7816/PakeEmvTrustAnchor.java').write_text(text)
    header = '/* Public keys extracted offline by PAKEBDH_7816/tools/provision_test_trust.py.\n'
    header += f' * certC DER SHA-256: {digest(cert_c)}\n'
    header += f' * certIS DER SHA-256: {digest(cert_is)}\n */\n'
    header += '#ifndef PAKE_EMV_CREDENTIAL_KEYS_H\n#define PAKE_EMV_CREDENTIAL_KEYS_H\n\n'
    header += c_array('pake_emv_card_public_key', pk_c) + '\n'
    header += c_array('pake_emv_issuer_public_key', pk_is) + '\n#endif\n'
    (ROOT / 'Card_pakebdh/Demo/pake_emv_credential_keys.h').write_text(header)
    print('Provisioned public issuer pin and card/issuer key constants.')


if __name__ == '__main__':
    main()
