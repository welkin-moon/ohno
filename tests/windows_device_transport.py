"""Daily native HTTPS secret-boundary tests; loopback fixtures, never installation."""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
from windows_maintenance_transport import Fixture, TestServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_POST(self):
        record = {'path': self.path, 'headers': dict(self.headers), 'body': b'', 'done': threading.Event()}
        with self.server.lock:
            self.server.records.append(record)
        try:
            remaining = min(int(self.headers.get('Content-Length', '0')), 2048)
            while remaining:
                part = self.rfile.read1(remaining)
                if not part:
                    break
                record['body'] += part
                remaining -= len(part)
            if remaining or not record['body']:
                return
            policy = self.path == '/api/device/policy'
            payload = json.dumps({'approved': True, 'padding': 'x'*(40000 if policy else 0)}).encode()
            status = 200 if policy else 201
            if self.server.mode == 'oversized':
                payload = b' ' * (1024*1024+1 if policy else 8193)
            if self.server.mode == 'redirect':
                status = 307
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Connection', 'close')
            if status == 307:
                self.send_header('Location', self.server.redirect + '/credential-trap')
            self.end_headers()
            self.wfile.write(payload)
        except (OSError, ValueError):
            pass
        finally:
            self.close_connection = True
            record['done'].set()


@contextmanager
def serve(fixture, mode='normal', redirect=''):
    server = TestServer(fixture, mode=mode, redirect=redirect)
    server.RequestHandlerClass = Handler
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=6)
        assert not thread.is_alive(), 'fixture server failed to stop'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True)
    args = parser.parse_args()
    client = str(Path(args.client).resolve())
    count = 0
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        valid = Fixture(root, 'valid')
        other = Fixture(root, 'other')
        expired = Fixture(root, 'expired', expired=True)
        wrong_host = Fixture(root, 'wrong-host', hostname=False)
        for route in ('register', 'policy', 'request', 'unlock'):
            for mode in ('normal', 'wrong-pin', 'expired', 'wrong-host', 'redirect', 'oversized'):
                certificate = {'expired': expired, 'wrong-host': wrong_host}.get(mode, valid)
                pin = other if mode == 'wrong-pin' else certificate
                device, key = secrets.token_hex(16), secrets.token_hex(32)
                body = ({'id': device, 'key': key, 'name': 'fixture'} if route == 'register'
                        else {'device_id': device, 'device_key': key})
                if route == 'request':
                    body.update(kind='website', object='fixture.example')
                if route == 'unlock':
                    body.update(pin='2468')
                with serve(valid) as trap, serve(certificate, mode, trap.url) as server:
                    data = {'server': server.url, 'certificate_pem': pin.pem,
                            'path': '/api/device/'+route, 'body': json.dumps(body)}
                    result = subprocess.run([client], input=json.dumps(data).encode(),
                                            capture_output=True, timeout=30)
                    # Do not print stderr, serialized inputs or recorded bodies.
                    assert result.returncode == 0, (route, mode, 'native driver failed')
                    fields = result.stdout.decode('ascii').strip().split()
                    assert len(fields) == 3, (route, mode, 'invalid driver result')
                    failure, status, length = fields
                    records = server.completed_records()
                    assert len(records) <= 1, (route, mode, 'request was replayed')
                    assert not trap.completed_records() and trap.connections == 0, (route, mode, 'redirect followed')
                    for record in records:
                        headers = {name.lower(): value for name, value in record['headers'].items()}
                        assert not any(name in headers for name in ('authorization', 'cookie', 'x-ohno-device', 'x-ohno-key'))
                        assert all(key not in value for value in headers.values())
                    if mode == 'normal':
                        assert failure == 'None' and int(status) == (200 if route == 'policy' else 201)
                        assert int(length) > (8192 if route == 'policy' else 0)
                        assert len(records) == 1 and json.loads(records[0]['body']) == body
                    else:
                        assert failure != 'None', (route, mode, 'unexpected success')
                        if mode in ('wrong-pin', 'expired', 'wrong-host'):
                            assert all(not record['body'] for record in records), (route, mode, 'secret sent before trust')
                    count += 1
    print('Native daily device TLS: %d cases passed; pre-body trust, 201/large-policy, no header secrets/replay/redirect' % count)


if __name__ == '__main__':
    main()
