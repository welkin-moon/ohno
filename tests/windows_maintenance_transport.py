r"""Adversarial tests of the REAL native WinHTTP maintenance transport.

Run on an ephemeral Windows runner, without elevation or trust-store changes:
  cl /utf-8 /std:c++17 /EHsc /W4 /MT tests\windows_maintenance_client.cpp ^
     windows\maintenance_http.cpp /Fe:maintenance-client.exe winhttp.lib crypt32.lib
  python tests/windows_maintenance_transport.py --client maintenance-client.exe

The only Python dependency is the teacher's existing cryptography requirement.
All listeners are loopback-only, and all private keys/passwords are ephemeral.
No setup executable, service, certificate store, registry, or firewall is changed.
--self-test validates fixtures/the harness on Linux; it is NOT a native TLS test.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class Fixture:
    def __init__(self, directory, name, *, hostname=True, expired=False,
                 future=False, server_usage=True, private_key=None):
        self.key = private_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        before = now - timedelta(minutes=5)
        after = now + timedelta(hours=1)
        if expired:
            before, after = now - timedelta(hours=2), now - timedelta(hours=1)
        if future:
            before, after = now + timedelta(hours=1), now + timedelta(hours=2)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost' if hostname else 'wrong.example')])
        names = [x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))] if hostname else [x509.DNSName('wrong.example')]
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(before).not_valid_after(after)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server_usage else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(self.key, hashes.SHA256()))
        self.pem = cert.public_bytes(serialization.Encoding.PEM).decode('ascii')
        self.cert_path = directory / (name + '.pem')
        self.key_path = directory / (name + '.key')
        self.cert_path.write_text(self.pem, encoding='ascii')
        self.key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(self.cert_path), str(self.key_path))


class TestServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, fixture, mode='normal', redirect='', second_fixture=None):
        self.fixture = fixture
        self.second_fixture = second_fixture
        self.mode = mode
        self.redirect = redirect
        self.records = []
        self.lock = threading.Lock()
        self.connections = 0
        super().__init__(('127.0.0.1', 0), Handler)

    @property
    def url(self):
        return 'https://127.0.0.1:' + str(self.server_port)

    def get_request(self):
        raw, address = super().get_request()
        raw.settimeout(5)
        with self.lock:
            self.connections += 1
            index = self.connections
        fixture = self.second_fixture if index > 1 and self.second_fixture else self.fixture
        try:
            secured = fixture.context.wrap_socket(raw, server_side=True)
        except BaseException:
            raw.close()
            raise
        secured.test_connection_index = index
        return secured, address

    def handle_error(self, request, address):
        # Expected EOF/reset/timeout adversaries must not print request bodies.
        pass

    def completed_records(self):
        with self.lock:
            records = list(self.records)
        for record in records:
            if not record['done'].wait(6):
                raise AssertionError('local request handler did not finish')
        return records


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        record = {'method': 'POST', 'path': self.path, 'headers': dict(self.headers),
                  'body': b'', 'connection': self.connection.test_connection_index,
                  'done': threading.Event()}
        with self.server.lock:
            self.server.records.append(record)
        try:
            mode = self.server.mode
            if mode == 'disconnect_rotate' and record['connection'] == 1:
                # A second TLS connection would present a different certificate.
                # The client must not replay its body after the first closes.
                self.connection.shutdown(socket.SHUT_RDWR)
                self.close_connection = True
                return
            remaining = min(int(self.headers.get('Content-Length', '0')), 32768)
            while remaining:
                part = self.rfile.read1(min(remaining, 4096))
                if not part:
                    break
                record['body'] += part
                remaining -= len(part)
            if remaining or not record['body']:
                self.close_connection = True
                return
            data = json.loads(record['body'])
            now = int(time.time())
            reply = {'authorized': True, 'action': data['action'], 'nonce': data['nonce'],
                     'device_id': data.get('device_id', ''), 'authorized_at': now, 'expires_at': now + 120}
            status = 200
            extra = {}
            if mode in ('denied', 'save_failure', 'authentication', 'proxy_authentication'):
                status = {'denied': 403, 'save_failure': 503, 'authentication': 401, 'proxy_authentication': 407}[mode]
                reply = {'error': 'test rejection'}
                if mode == 'authentication':
                    extra['WWW-Authenticate'] = 'Negotiate, NTLM'
                if mode == 'proxy_authentication':
                    extra['Proxy-Authenticate'] = 'Negotiate, NTLM'
            elif mode.startswith('redirect_'):
                status = int(mode.split('_')[1])
                extra['Location'] = self.server.redirect + '/credential-trap'
            elif mode == 'wrong_nonce':
                reply['nonce'] = ('0' if data['nonce'][0] != '0' else '1') + data['nonce'][1:]
            elif mode == 'wrong_action':
                reply['action'] = 'uninstall' if data['action'] == 'install' else 'install'
            elif mode == 'wrong_device':
                reply['device_id'] = secrets.token_hex(16)
            elif mode == 'authorized_false':
                reply['authorized'] = False
            elif mode == 'authorized_number':
                reply['authorized'] = 1
            elif mode == 'nonce_number':
                reply['nonce'] = 3
            elif mode == 'expiry_string':
                reply['expires_at'] = str(now + 120)
            elif mode == 'expiry_float':
                reply['expires_at'] = float(now + 120)
            elif mode == 'issued_boolean':
                reply['authorized_at'] = True
            elif mode == 'wrong_window':
                reply['expires_at'] = now + 121
            elif mode == 'expired_response':
                reply['authorized_at'], reply['expires_at'] = now - 151, now - 31
            elif mode == 'clock_ahead':
                reply['authorized_at'], reply['expires_at'] = now + 15, now + 135
            elif mode == 'clock_behind':
                reply['authorized_at'], reply['expires_at'] = now - 130, now - 10
            elif mode == 'future_response':
                reply['authorized_at'], reply['expires_at'] = now + 3600, now + 3720
            elif mode == 'huge_timestamp':
                reply['authorized_at'], reply['expires_at'] = 10 ** 40, 10 ** 40 + 120
            elif mode == 'missing_field':
                del reply['authorized_at']
            elif mode == 'extra_field':
                reply['bearer_token'] = 'not-supported'
            payload = json.dumps(reply, separators=(',', ':')).encode('utf-8')
            if mode == 'duplicate_field':
                payload = payload[:-1] + b',"authorized":true}'
            elif mode == 'invalid_json':
                payload += b'not-json'
            elif mode == 'invalid_utf8':
                payload = payload[:-1] + b',"bad":"\xff"}'
            elif mode == 'oversized' or mode == 'chunked_oversized':
                payload += b' ' * 2049
            elif mode == 'array_response':
                payload = b'[' + payload + b']'
            if mode == 'oversized_headers':
                extra['X-Test-Padding'] = 'x' * 10000
            if mode == 'content_encoding':
                extra['Content-Encoding'] = 'gzip'
            self.send_response(status)
            if mode != 'missing_content_type':
                self.send_header('Content-Type', 'text/html' if mode == 'wrong_content_type' else 'application/json; charset=utf-8')
            if mode in ('chunked', 'chunked_oversized'):
                self.send_header('Transfer-Encoding', 'chunked')
            else:
                self.send_header('Content-Length', str(len(payload) + (5 if mode == 'truncated' else 0)))
            self.send_header('Connection', 'close')
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            if mode in ('chunked', 'chunked_oversized'):
                self.wfile.write(('%x\r\n' % len(payload)).encode('ascii') + payload + b'\r\n0\r\n\r\n')
            else:
                self.wfile.write(payload)
            self.close_connection = True
        except (OSError, ValueError, KeyError):
            self.close_connection = True
        finally:
            record['done'].set()


@contextmanager
def serve(fixture, **kwargs):
    server = TestServer(fixture, **kwargs)
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=6)
        if worker.is_alive():
            raise AssertionError('local HTTPS server failed to stop')


def request_input(server, fixture, action='install'):
    return {'server': server, 'certificate_pem': fixture.pem, 'action': action,
            'nonce': secrets.token_hex(32), 'password': 'ephemeral-' + secrets.token_hex(16),
            'device_id': secrets.token_hex(16) if action == 'uninstall' else '',
            'device_key': secrets.token_hex(32) if action == 'uninstall' else ''}


def invoke(client, data, expected):
    result = subprocess.run([str(client)], input=json.dumps(data, ensure_ascii=False).encode('utf-8'),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    expected = (expected,) if isinstance(expected, str) else expected
    names = {0: 'Authorized', 10: 'Denied', 11: 'Unavailable', 12: 'InvalidResponse'}
    if names.get(result.returncode) not in expected or result.stdout.strip() != names.get(result.returncode, '').encode('ascii'):
        raise AssertionError('native result/exit code did not match expected ' + '/'.join(expected) +
                             '; received exit code ' + str(result.returncode))
    for value in (data['password'], data['device_key']):
        if value and value.encode('utf-8') in result.stdout + result.stderr:
            raise AssertionError('native driver disclosed a secret in diagnostics')


def verify_records(records, data, *, body='full'):
    for record in records:
        headers = {key.lower(): value for key, value in record['headers'].items()}
        if any(key in headers for key in ('authorization', 'proxy-authorization', 'x-ohno-key', 'x-ohno-device', 'cookie')):
            raise AssertionError('secret/automatic credential header was transmitted')
        raw_headers = json.dumps(headers).encode('utf-8')
        for value in (data['password'], data['device_key']):
            if value and value.encode('utf-8') in raw_headers:
                raise AssertionError('secret occurred in a request header')
        if body == 'none' and record['body']:
            raise AssertionError('body bytes reached an unauthenticated TLS peer')
        if record['method'] != 'POST' or record['path'] != '/api/maintenance/authorize':
            raise AssertionError('unexpected method/path')
    if body == 'full':
        if len(records) != 1:
            raise AssertionError('expected exactly one POST without retries')
        actual = json.loads(records[0]['body'])
        wanted = {'action': data['action'], 'nonce': data['nonce'], 'maintenance_password': data['password']}
        if data['action'] == 'uninstall':
            wanted.update(device_id=data['device_id'], device_key=data['device_key'])
        if actual != wanted:
            raise AssertionError('request body did not match the maintenance wire schema')


def portable_self_test(fixtures):
    good = fixtures['good']
    with serve(good) as server:
        data = request_input(server.url, good)
        context = ssl.create_default_context(cafile=str(good.cert_path))
        conn = http.client.HTTPSConnection('127.0.0.1', server.server_port, context=context, timeout=5)
        wire = {key: data[key] for key in ('action', 'nonce')}
        wire['maintenance_password'] = data['password']
        conn.request('POST', '/api/maintenance/authorize', json.dumps(wire), {'Content-Type': 'application/json'})
        response = conn.getresponse()
        assert response.status == 200 and json.loads(response.read())['nonce'] == data['nonce']
        conn.close()
        verify_records(server.completed_records(), data)
    now = datetime.now(timezone.utc)
    for name, fixture in fixtures.items():
        cert = x509.load_pem_x509_certificate(fixture.pem.encode('ascii'))
        assert cert.public_key().key_size == 2048
        if name == 'expired':
            assert cert.not_valid_after_utc < now
        elif name == 'future':
            assert cert.not_valid_before_utc > now
        else:
            assert cert.not_valid_before_utc < now < cert.not_valid_after_utc
    assert fixtures['reissued'].key is good.key and fixtures['reissued'].pem != good.pem
    print('Portable fixture/harness self-test passed; no Windows transport was executed.')


def native_tests(client, fixtures):
    good = fixtures['good']
    count = 0

    def case(name, *, fixture=None, pin=None, mode='normal', expected='Authorized',
             body='full', action='install', changes=None, **server_options):
        nonlocal count
        with serve(fixture or good, mode=mode, **server_options) as server:
            data = request_input(server.url, pin or good, action)
            data.update(changes or {})
            invoke(client, data, expected)
            records = server.completed_records()
            verify_records(records, data, body=body)
            if mode == 'disconnect_rotate':
                # The first connection is authenticated; any later connection
                # has the wrong pin and must receive no credential body.
                verify_records([item for item in records if item['connection'] > 1], data, body='none')
        count += 1
        print('PASS ' + name)

    case('pinned self-signed install')
    case('pinned self-signed uninstall body credentials', action='uninstall')
    case('UTF-8/escaped password', changes={'password': '教室维护口令够长十二字符"\\结束'})
    case('valid chunked JSON', mode='chunked')
    case('bounded teacher clock ahead', mode='clock_ahead')
    case('bounded teacher clock behind', mode='clock_behind')
    case('password denial', mode='denied', expected='Denied')
    case('server persistence failure', mode='save_failure', expected='Unavailable')
    case('wrong certificate pin sends no body', fixture=fixtures['other'], expected='Unavailable', body='none', action='uninstall')
    case('same key reissued certificate is not the exact pin', fixture=fixtures['reissued'], expected='Unavailable', body='none')
    for name in ('hostname', 'expired', 'future', 'usage'):
        case('pinned invalid ' + name + ' sends no body', fixture=fixtures[name], pin=fixtures[name],
             expected='Unavailable', body='none', action='uninstall')
    case('OS trust rejects untrusted self-signed leaf without pin', changes={'certificate_pem': ''}, expected='Unavailable', body='none')
    case('malformed pin fails before networking', changes={'certificate_pem': 'invalid PEM'}, expected='InvalidResponse', body='none')
    case('multiple PEM certificates rejected', changes={'certificate_pem': good.pem + fixtures['other'].pem}, expected='InvalidResponse', body='none')
    case('no automatic integrated authentication', mode='authentication', expected='InvalidResponse')
    case('no proxy authentication', mode='proxy_authentication', expected='InvalidResponse')
    with serve(good) as trap:
        for status in (301, 302, 303, 307, 308):
            case('redirect ' + str(status) + ' never follows to secret trap', mode='redirect_' + str(status),
                 redirect=trap.url, expected='InvalidResponse', action='uninstall')
        if trap.connections or trap.completed_records():
            raise AssertionError('redirect target received a connection')
    case('connection-close/certificate-swap has no secret replay', mode='disconnect_rotate',
         second_fixture=fixtures['other'], expected=('Unavailable', 'InvalidResponse'), body='optional', action='uninstall')
    invalid_modes = ('wrong_nonce', 'wrong_action', 'wrong_device', 'authorized_false', 'authorized_number',
        'nonce_number', 'expiry_string', 'expiry_float', 'issued_boolean', 'wrong_window',
        'expired_response', 'future_response', 'huge_timestamp', 'missing_field', 'extra_field',
        'duplicate_field', 'invalid_json', 'invalid_utf8', 'array_response', 'oversized',
        'chunked_oversized', 'wrong_content_type', 'missing_content_type', 'content_encoding')
    for mode in invalid_modes:
        case('reject response ' + mode, mode=mode, expected='InvalidResponse')
    case('uninstall response bound to device', mode='wrong_device', action='uninstall', expected='InvalidResponse')
    case('truncated response fails closed', mode='truncated', expected=('Unavailable', 'InvalidResponse'))
    case('oversized headers fail closed', mode='oversized_headers', expected=('Unavailable', 'InvalidResponse'))
    for origin in ('http://127.0.0.1:1', 'https://teacher:secret@127.0.0.1:1',
                   'https://@127.0.0.1:1', 'https://127.0.0.1:1/path',
                   'https://127.0.0.1:1/?query', 'https://127.0.0.1:1/#fragment',
                   'https://127.0.0.1:1/%2e', 'https://127.0.0.1:1/\x00ignored'):
        case('invalid origin rejected locally', changes={'server': origin}, expected='InvalidResponse', body='none')
    for change in ({'nonce': 'F' * 64}, {'nonce': 'a' * 63}, {'action': 'upgrade'},
                   {'password': 'too short'}, {'password': 'a' * 129}, {'device_key': 'a' * 64}):
        case('invalid request rejected locally', changes=change, expected='InvalidResponse', body='none')
    case('uninstall requires device credentials', action='uninstall', changes={'device_key': ''}, expected='InvalidResponse', body='none')
    with socket.socket() as offline:
        offline.bind(('127.0.0.1', 0))  # reserved port, deliberately not listening
        invoke(client, request_input('https://127.0.0.1:' + str(offline.getsockname()[1]), good), 'Unavailable')
    count += 1
    print('PASS offline connection fails closed')
    print(str(count) + ' native maintenance transport cases passed; no OS state was modified.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, help='compiled native maintenance-client.exe')
    parser.add_argument('--self-test', action='store_true', help='portable fixture checks only, not native transport')
    args = parser.parse_args()
    if not args.self_test and (sys.platform != 'win32' or not args.client or not args.client.is_file()):
        parser.error('native tests require Windows and --client pointing to a compiled executable')
    with tempfile.TemporaryDirectory(prefix='ohno-maintenance-test-') as directory:
        root = Path(directory)
        fixtures = {'good': Fixture(root, 'good'), 'other': Fixture(root, 'other'),
            'hostname': Fixture(root, 'hostname', hostname=False),
            'expired': Fixture(root, 'expired', expired=True), 'future': Fixture(root, 'future', future=True),
            'usage': Fixture(root, 'usage', server_usage=False)}
        fixtures['reissued'] = Fixture(root, 'reissued', private_key=fixtures['good'].key)
        if args.self_test:
            portable_self_test(fixtures)
        else:
            native_tests(args.client.resolve(), fixtures)


if __name__ == '__main__':
    main()
