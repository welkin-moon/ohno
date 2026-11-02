"""Versioned, signed update offers. This module never downloads or executes code.

The school release-signing key is separate from its HTTPS key. Only its public
key belongs in a client image; publishing and key provisioning are not enabled
by importing this module. See docs/managed-updates.md for the rollout gates.
"""
from __future__ import annotations

import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

SCHEMA = 1
PLATFORM = 'windows-x64'
MAX_SEQUENCE = 2**53 - 1
MAX_PACKAGE_SIZE = 256 * 1024 * 1024
MAX_TIMESTAMP = 253402300799  # Last second of year 9999; fits signed 64-bit.
MAX_VALIDITY = 7 * 24 * 3600
MAX_DOCUMENT_SIZE = 4096
MAX_CLOCK_SKEW = 300
FIELDS = ('schema', 'platform', 'sequence', 'version', 'min_updater',
          'issued_at', 'expires_at', 'size', 'sha256')
VERSION = re.compile(r'(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})(?:-[a-z0-9](?:[a-z0-9.-]{0,31}))?\Z')
HEX = re.compile(r'[0-9a-f]+\Z')


def _integer(value: Any, low: int, high: int) -> bool:
    # bool is an int subclass in Python, but is never a wire-protocol integer.
    return type(value) is int and low <= value <= high


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and bool(HEX.fullmatch(value))


def validate_fields(fields: dict) -> None:
    if not isinstance(fields, dict) or set(fields) != set(FIELDS):
        raise ValueError('unknown or missing update field')
    if type(fields['schema']) is not int or fields['schema'] != SCHEMA or fields['platform'] != PLATFORM:
        raise ValueError('unsupported update format or platform')
    if not _integer(fields['sequence'], 1, MAX_SEQUENCE):
        raise ValueError('invalid update sequence')
    if not isinstance(fields['version'], str) or not VERSION.fullmatch(fields['version']):
        raise ValueError('invalid release version')
    if not _integer(fields['min_updater'], 1, 65535):
        raise ValueError('invalid minimum updater version')
    if not _integer(fields['issued_at'], 1, MAX_TIMESTAMP) or not _integer(fields['expires_at'], 1, MAX_TIMESTAMP):
        raise ValueError('invalid update validity timestamps')
    if not 0 < fields['expires_at'] - fields['issued_at'] <= MAX_VALIDITY:
        raise ValueError('invalid update validity interval')
    if not _integer(fields['size'], 1024, MAX_PACKAGE_SIZE) or not _hex(fields['sha256'], 64):
        raise ValueError('invalid update package identity')


def signing_bytes(fields: dict) -> bytes:
    """Unambiguous ASCII transcript, shared with the native client.

    Field order is fixed; all variable fields reject CR, LF and separators.
    The domain separator also binds the signature algorithm/protocol version.
    """
    validate_fields(fields)
    return ('ohno-update-p256-sha256-v1\n' + '\n'.join(str(fields[x]) for x in FIELDS) + '\n').encode('ascii')


def public_key_hex(key: ec.EllipticCurvePublicKey) -> str:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError('release key must be P-256')
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()


def sign_manifest(fields: dict, key: ec.EllipticCurvePrivateKey) -> dict:
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError('release key must be P-256')
    # Windows CNG consumes fixed-width r || s, not ASN.1 DER.
    r, s = utils.decode_dss_signature(key.sign(signing_bytes(fields), ec.ECDSA(hashes.SHA256())))
    return dict(fields, signature=(r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).hex())


def parse_manifest(document: str | bytes) -> dict:
    if not isinstance(document, (str, bytes)) or len(document) > MAX_DOCUMENT_SIZE:
        raise ValueError('invalid update document size')
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('duplicate update field')
            result[name] = value
        return result
    try:
        # Decode bytes explicitly: json.loads(bytes) also accepts UTF-16/32,
        # whereas the Windows wire parser deliberately accepts UTF-8 only.
        if isinstance(document, bytes):
            document = document.decode('utf-8')
        manifest = json.loads(document, object_pairs_hook=unique)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid update JSON') from error
    if not isinstance(manifest, dict) or set(manifest) != set(FIELDS) | {'signature'}:
        raise ValueError('unknown or missing signed update field')
    validate_fields({name: manifest[name] for name in FIELDS})
    if not _hex(manifest['signature'], 128):
        raise ValueError('invalid update signature format')
    return manifest


def verify_manifest(document: str | bytes, pinned_public_key: str, *,
                    installed_sequence: int, updater_version: int, now: int) -> dict:
    """Authenticate an offer before any package download or filesystem mutation.

    installed_sequence must be a durable high-water mark, not a parsed semver.
    A rollback must not lower it: republish old payload with a higher sequence.
    The signing key must come from installation, never from the offered JSON.
    """
    if (not _integer(installed_sequence, 0, MAX_SEQUENCE) or
            not _integer(updater_version, 1, 65535) or not _integer(now, 1, MAX_TIMESTAMP)):
        raise ValueError('invalid trusted update context')
    manifest = parse_manifest(document)
    if not _hex(pinned_public_key, 130) or not pinned_public_key.startswith('04'):
        raise ValueError('invalid pinned release key')
    fields = {name: manifest[name] for name in FIELDS}
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pinned_public_key))
        signature = bytes.fromhex(manifest['signature'])
        der = utils.encode_dss_signature(int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big'))
        key.verify(der, signing_bytes(fields), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as error:
        raise ValueError('update signature not trusted') from error
    if manifest['sequence'] <= installed_sequence:
        raise ValueError('update sequence already applied or replayed')
    if manifest['min_updater'] > updater_version:
        raise ValueError('updater is too old')
    if manifest['issued_at'] > now + MAX_CLOCK_SKEW or manifest['expires_at'] <= now:
        raise ValueError('update expired or not yet valid')
    return manifest


def package_path(manifest: dict) -> str:
    """Fixed same-origin route; the manifest cannot supply a URL or command."""
    validate_fields({name: manifest[name] for name in FIELDS})
    return '/api/device/update/package/' + manifest['sha256']
