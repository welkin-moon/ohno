"""Build a school-specific double-click installer from a verified Ohno setup binary.

No teacher secret/password/key is included; only the HTTPS origin and public
certificate are attached. Windows setup reads the same little-endian trailer.
"""
from __future__ import annotations
import struct
from urllib.parse import urlsplit

MAGIC = b'OHNOBT01'
TRAILER = struct.Struct('<II8s')
MAX_ORIGIN = 1024
MAX_CERT = 16384
MAX_INSTALLER = 256 * 1024 * 1024


def build_school_installer(setup_exe: bytes, server_url: str, certificate_pem: bytes) -> bytes:
    if not isinstance(setup_exe, bytes) or not (1024 <= len(setup_exe) <= MAX_INSTALLER):
        raise ValueError('invalid base installer')
    if not isinstance(server_url, str) or len(server_url.encode('utf-8')) > MAX_ORIGIN:
        raise ValueError('invalid teacher origin')
    parts = urlsplit(server_url)
    if (parts.scheme != 'https' or not parts.hostname or parts.username is not None or
            parts.password is not None or parts.path not in ('', '/') or
            parts.query or parts.fragment or not server_url.isascii() or not parts.hostname.isascii()):
        raise ValueError('teacher origin must be a standalone HTTPS origin')
    try:
        port = parts.port
        if not port or not (1 <= port <= 65535): raise ValueError()
    except ValueError as exc:
        raise ValueError('invalid teacher port') from exc
    if (not isinstance(certificate_pem, bytes) or
            not (100 <= len(certificate_pem) <= MAX_CERT) or
            not certificate_pem.startswith(b'-----BEGIN CERTIFICATE-----') or
            b'-----END CERTIFICATE-----' not in certificate_pem or
            b'PRIVATE KEY' in certificate_pem):
        raise ValueError('invalid public certificate')
    url_bytes = server_url.encode('ascii')
    return setup_exe + url_bytes + certificate_pem + TRAILER.pack(len(url_bytes),len(certificate_pem),MAGIC)


def get_school_configuration(installer: bytes) -> tuple[str, bytes]:
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
    return url_bytes.decode('ascii'), cert_bytes
