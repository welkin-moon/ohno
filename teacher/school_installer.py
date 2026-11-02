"""Build a school-specific double-click installer from a verified Ohno setup binary.

No teacher secret/password/key is included; only the HTTPS origin and public
certificate are attached. Windows setup reads the same little-endian trailer.
"""
from __future__ import annotations
import struct
import ipaddress
import re
from urllib.parse import urlsplit

MAGIC = b'OHNOBT01'
MAGIC_V2 = b'OHNOBT02'
TRAILER_V2 = struct.Struct('<III8s')
TRAILER = struct.Struct('<II8s')
MAX_ORIGIN = 1024
MAX_CERT = 16384
MAX_INSTALLER = 256 * 1024 * 1024
HOSTNAME = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def enrollment_origin(host: str, port: int) -> str:
    if not isinstance(host, str) or not host.isascii() or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('invalid teacher host or port')
    try:
        address = ipaddress.ip_address(host)
        host = '[' + str(address) + ']' if address.version == 6 else str(address)
    except ValueError:
        host = host.lower()
        if not HOSTNAME.fullmatch(host):
            raise ValueError('invalid teacher hostname')
    return 'https://' + host + ':' + str(port)


def validate_origin(server_url: str) -> None:
    # urlsplit silently removes tabs/newlines. Reject them before parsing so
    # Python and the native installer agree on the exact origin in the trailer.
    if (not isinstance(server_url, str) or len(server_url) > MAX_ORIGIN or
            not server_url.startswith('https://') or
            any(ord(c) < 33 or ord(c) > 126 for c in server_url) or
            any(c in server_url for c in '\\?#')):
        raise ValueError('invalid teacher origin')
    parts = urlsplit(server_url)
    if (not parts.hostname or parts.username is not None or parts.password is not None or
            parts.path not in ('', '/')):
        raise ValueError('teacher origin must be a standalone HTTPS origin')
    if parts.port is None:
        raise ValueError('teacher origin requires an explicit port')
    enrollment_origin(parts.hostname, parts.port)


def build_school_installer(setup_exe: bytes, server_url: str, certificate_pem: bytes, release_public_key: str | None = None) -> bytes:
    if not isinstance(setup_exe, bytes) or not (1024 <= len(setup_exe) <= MAX_INSTALLER):
        raise ValueError('invalid base installer')
    validate_origin(server_url)
    if (not isinstance(certificate_pem, bytes) or
            not (100 <= len(certificate_pem) <= MAX_CERT) or
            not certificate_pem.startswith(b'-----BEGIN CERTIFICATE-----') or
            b'-----END CERTIFICATE-----' not in certificate_pem or
            b'\0' in certificate_pem or
            b'PRIVATE KEY' in certificate_pem):
        raise ValueError('invalid public certificate')
    url_bytes = server_url.encode('ascii')
    if release_public_key is not None:
        if not isinstance(release_public_key,str) or not re.fullmatch(r'04[0-9a-f]{128}',release_public_key):
            raise ValueError('invalid pinned release public key')
        from cryptography.hazmat.primitives.asymmetric import ec
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),bytes.fromhex(release_public_key))
        key_bytes=release_public_key.encode('ascii')
        return setup_exe+url_bytes+certificate_pem+key_bytes+TRAILER_V2.pack(len(url_bytes),len(certificate_pem),len(key_bytes),MAGIC_V2)
    return setup_exe + url_bytes + certificate_pem + TRAILER.pack(len(url_bytes),len(certificate_pem),MAGIC)


def get_school_configuration(installer: bytes) -> tuple[str, bytes]:
    origin,certificate,_=get_school_trust(installer)
    return origin,certificate


def get_school_trust(installer: bytes) -> tuple[str, bytes, str | None]:
    if len(installer)>=TRAILER_V2.size and installer[-8:]==MAGIC_V2:
        url_size,cert_size,key_size,magic=TRAILER_V2.unpack(installer[-TRAILER_V2.size:])
        if not (1<=url_size<=MAX_ORIGIN and 100<=cert_size<=MAX_CERT and key_size==130):
            raise ValueError('invalid release trust trailer')
        start=len(installer)-TRAILER_V2.size-url_size-cert_size-key_size
        if start<1024:raise ValueError('truncated trusted installer')
        origin=installer[start:start+url_size].decode('ascii')
        certificate=installer[start+url_size:start+url_size+cert_size]
        key=installer[start+url_size+cert_size:-TRAILER_V2.size].decode('ascii')
        if build_school_installer(installer[:start],origin,certificate,key)!=installer:
            raise ValueError('noncanonical release trust trailer')
        return origin,certificate,key
    if len(installer) < TRAILER.size:
        raise ValueError('missing trailer')
    url_size, cert_size, magic = TRAILER.unpack(installer[-TRAILER.size:])
    if magic != MAGIC or not (1 <= url_size <= MAX_ORIGIN) or not (100 <= cert_size <= MAX_CERT):
        raise ValueError('missing enrollment data')
    start = len(installer)-TRAILER.size-url_size-cert_size
    if start < 1024: raise ValueError('truncated installer')
    url_bytes = installer[start:start+url_size]
    cert_bytes = installer[start+url_size:start+url_size+cert_size]
    if build_school_installer(installer[:start],url_bytes.decode('ascii'),cert_bytes) != installer:
        raise ValueError('noncanonical enrollment trailer')
    return url_bytes.decode('ascii'), cert_bytes, None
