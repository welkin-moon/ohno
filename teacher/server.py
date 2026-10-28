#!/usr/bin/env python3
"""Ohno teacher service. No external Python packages; HTTPS is mandatory."""
import argparse
import hashlib
import hmac
import ipaddress
import html
import json
import os
import re
import secrets
import ssl
import tempfile
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

MAX_BODY = 65536
ITERATIONS = 310000
HOSTNAME = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[A-Za-z0-9_-]{16,128}\Z')
PROGRAM_NAME = re.compile(r'[a-z0-9_. -]{1,128}\.exe\Z')
DEFAULT_WEB = ['classic.minecraft.net', 'eaglercraft.com']
DEFAULT_GAMES = ['plantsvszombies.exe','plantsvszombiesoriginal.exe','slaythespire.exe','gta3.exe','gta-vc.exe','gta_sa.exe','gtaiv.exe','minecraftlauncher.exe','minecraft.windows.exe']


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), ITERATIONS).hex()


def esc(value):
    return html.escape(str(value), quote=True)


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.sessions = {}
        self.attempts = {}
        self.data = json.loads(self.path.read_text('utf-8'))
        if self.data.get('version') != 1:
            raise ValueError('Unsupported state version')

    @classmethod
    def initialize(cls, path, password):
        p = Path(path)
        if p.exists():
            raise FileExistsError('State already exists')
        if len(password) < 12:
            raise ValueError('Password must contain at least 12 characters')
        p.parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_hex(16)
        state = {'version': 1, 'salt': salt, 'password_hash': password_hash(password, salt),
                 'policy_revision': 0, 'web_domains': DEFAULT_WEB[:], 'program_hashes': [], 'program_names': DEFAULT_GAMES[:], 'block_local_files': False,
                 'devices': {}, 'requests': []}
        # Exclusive creation prevents accidental overwrite.
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False)
        return cls(p)

    def save(self):
        # Caller holds lock. Atomic replacement is in the same directory.
        fd, name = tempfile.mkstemp(prefix='.ohno-', dir=str(self.path.parent))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, separators=(',', ':'))
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def verify_password(self, password, address):
        with self.lock:
            now = time.monotonic()
            attempts = [x for x in self.attempts.get(address, []) if now - x < 300]
            if len(attempts) >= 8:
                self.attempts[address] = attempts
                return False
            if not hmac.compare_digest(password_hash(password, self.data['salt']), self.data['password_hash']):
                attempts.append(now)
                self.attempts[address] = attempts
                return False
            self.attempts.pop(address, None)
            return True

    def authenticate(self, password, address):
        if not self.verify_password(password, address):
            return None
        with self.lock:
            now = time.monotonic()
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[token] = (csrf, now + 3600)
            return token, csrf

    def session(self, token):
        with self.lock:
            now = time.monotonic()
            entry = self.sessions.get(token)
            if not entry or entry[1] <= now:
                self.sessions.pop(token, None)
                return None
            return entry[0]

    def device(self, dev_id, key, require_approved=True):
        with self.lock:
            dev = self.data['devices'].get(dev_id)
            if not dev or not isinstance(key, str) or not hmac.compare_digest(dev['key_hash'], hashlib.sha256(key.encode()).hexdigest()):
                return None
            if require_approved and not dev['approved']:
                return None
            return dev


STYLE = '''<style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#25303a}h1{color:#293c66}section{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}input,textarea,button{font:inherit;padding:.5rem;max-width:100%}textarea{width:95%;height:8rem}button{cursor:pointer}table{border-collapse:collapse;width:100%}td,th{padding:.5rem;border-bottom:1px solid #ddd;text-align:left}small{color:#555}.ok{color:#17613a}.pending{color:#9a4a00}</style>'''


class Handler(BaseHTTPRequestHandler):
    server_version = 'ohno-teacher/0.1'
    sys_version = ''

    def log_message(self, fmt, *args):
        # Never log paths, query parameters, headers, passwords, or device keys.
        pass

    @property
    def store(self):
        return self.server.store

    def reply(self, status, data, content_type='text/plain; charset=utf-8', headers=()):
        body = data.encode('utf-8') if isinstance(data, str) else data
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Referrer-Policy', 'no-referrer')
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def json_reply(self, status, value):
        self.reply(status, json.dumps(value, ensure_ascii=False), 'application/json; charset=utf-8')

    def read_body(self):
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY:
            return None
        return self.rfile.read(length)

    def cookie(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie', ''))
            return jar['ohno_session'].value if 'ohno_session' in jar else ''
        except cookies.CookieError:
            return ''

    def redirect(self, location, headers=()):
        self.reply(303, '', headers=[('Location', location), *headers])

    def page(self, title, content):
        self.reply(200, '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + esc(title) + '</title>' + STYLE + '<body>' + content + '</body></html>', 'text/html; charset=utf-8')

    def do_GET(self):
        if self.path == '/health':
            return self.json_reply(200, {'ok': True})
        if self.path == '/api/device/policy':
            dev_id, key = self.headers.get('X-Ohno-Device', ''), self.headers.get('X-Ohno-Key', '')
            with self.store.lock:
                if not self.store.device(dev_id, key):
                    return self.json_reply(403, {'error': 'not authorized or pending'})
                d = self.store.data
                grants = [dict(id=x['id'], kind=x['kind'], object=x['object'], expires=x.get('expires',0)) for x in d['requests'] if x['device_id'] == dev_id and x['state'] == 'approved' and x.get('expires',0) > time.time()]
                return self.json_reply(200, {'revision': d['policy_revision'], 'web_domains': d['web_domains'], 'program_hashes': d['program_hashes'], 'program_names': d.get('program_names', []), 'block_local_files': d.get('block_local_files', False), 'grants': grants})
        if self.path != '/':
            return self.reply(404, 'Not found')
        csrf = self.store.session(self.cookie())
        if not csrf:
            return self.page('ohno 登录', '<h1>ohno 教师端</h1><section><form method="post" action="/login"><label>管理密码 <input name="password" type="password" autocomplete="current-password" required></label> <button>登录</button></form></section>')
        with self.store.lock:
            d = self.store.data
            devices = list(d['devices'].items())
            requests = list(d['requests'])[-100:][::-1]
            domains = '\n'.join(d['web_domains'])
            hashes = '\n'.join(d['program_hashes'])
            names = '\n'.join(d.get('program_names', []))
            block_local_files = d.get('block_local_files', False)
            revision = d['policy_revision']
        hidden = '<input type="hidden" name="csrf" value="' + esc(csrf) + '">'
        rows = []
        for dev_id, dev in devices:
            action = '<form method="post" action="/device">' + hidden + '<input type="hidden" name="id" value="' + esc(dev_id) + '"><button name="approved" value="' + ('0' if dev['approved'] else '1') + '">' + ('停用' if dev['approved'] else '批准设备') + '</button></form>'
            rows.append('<tr><td>' + esc(dev['name']) + '</td><td>' + esc(dev_id[:12]) + '</td><td>' + ('已批准' if dev['approved'] else '待批准') + ' / ' + ('在线' if time.time()-dev.get('last_seen',0)<60 else '离线') + ' / TUN 进程: ' + ('运行' if dev.get('tun') is True else '不可用' if dev.get('tun') is False else '未知') + ' / WFP 引擎: ' + ('可用' if dev.get('wfp') is True else '不可用' if dev.get('wfp') is False else '未知') + '</td><td>' + action + '</td></tr>')
        req_rows = []
        for item in requests:
            action = ''
            if item['state'] == 'pending':
                action = '<form method="post" action="/request">' + hidden + '<input type="hidden" name="id" value="' + esc(item['id']) + '"><button name="action" value="approve">允许 1 小时</button> <button name="action" value="deny">拒绝</button></form>'
            req_rows.append('<tr><td>' + esc(item['device_id'][:12]) + '</td><td>' + esc(item['kind']) + '</td><td>' + esc(item.get('label') or item['object']) + (' <small>' + esc(item['object']) + '</small>' if item.get('label') else '') + '</td><td>' + esc(item['state']) + '</td><td>' + action + '</td></tr>')
        content = '<h1>ohno 教师端</h1><p>策略版本 ' + str(revision) + '</p><form method="post" action="/logout">' + hidden + '<button>退出</button></form>'
        content += '<section><h2>网站规则</h2><p><small>每行一个域名；客户端决定实际拦截方式。</small></p><form method="post" action="/policy">' + hidden + '<label>屏蔽域名<textarea name="domains">' + esc(domains) + '</textarea></label><label>屏蔽程序 SHA-256（每行一个）<textarea name="hashes">' + esc(hashes) + '</textarea></label><label>屏蔽程序文件名（每行一个）<textarea name="names">' + esc(names) + '</textarea></label><p><label><input type="checkbox" name="block_local_files" value="1"' + (' checked' if block_local_files else '') + '> 限制 Edge 打开本地文件（可能影响本地课件及 PDF，覆盖不保证）</label></p><button>保存规则</button></form></section>'
        content += '<section><h2>设备</h2><table><tr><th>名称</th><th>ID</th><th>状态</th><th>操作</th></tr>' + ''.join(rows) + '</table></section>'
        content += '<section><h2>审批请求</h2><table><tr><th>设备</th><th>类型</th><th>对象</th><th>状态</th><th>操作</th></tr>' + ''.join(req_rows) + '</table></section>'
        content += '<p><small>ohno 是自由软件：<a href="https://github.com/welkin-moon/ohno">查看源码与许可证</a></small></p>'
        return self.page('ohno 教师端', content)

    def do_POST(self):
        raw = self.read_body()
        if raw is None:
            return self.reply(413, 'Invalid request length')
        if self.path.startswith('/api/device/'):
            try:
                data = json.loads(raw)
                if not isinstance(data, dict): raise ValueError()
            except (ValueError, UnicodeError):
                return self.json_reply(400, {'error': 'invalid JSON'})
            if self.path == '/api/device/register':
                return self.register(data)
            if self.path == '/api/device/request':
                return self.submit_request(data)
            if self.path == '/api/device/unlock':
                return self.unlock_device(data)
            return self.json_reply(404, {'error': 'not found'})
        try:
            form = parse_qs(raw.decode('utf-8'), keep_blank_values=True, max_num_fields=20)
        except (ValueError, UnicodeError):
            return self.reply(400, 'Invalid form')
        one = lambda k: form.get(k, [''])[0]
        if self.path == '/login':
            result = self.store.authenticate(one('password'), self.client_address[0])
            if not result:
                return self.reply(403, 'Login failed or temporarily rate limited')
            token, _ = result
            return self.redirect('/', [('Set-Cookie', 'ohno_session=' + token + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600')])
        token = self.cookie()
        csrf = self.store.session(token)
        if not csrf or not hmac.compare_digest(csrf, one('csrf')):
            return self.reply(403, 'Invalid session or CSRF token')
        if self.path == '/logout':
            with self.store.lock:
                self.store.sessions.pop(token, None)
            return self.redirect('/', [('Set-Cookie', 'ohno_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0')])
        with self.store.lock:
            if self.path == '/policy':
                domains = sorted(set(x.strip().lower() for x in one('domains').splitlines() if x.strip()))
                hashes = sorted(set(x.strip().lower() for x in one('hashes').splitlines() if x.strip()))
                names = sorted(set(x.strip().lower() for x in one('names').splitlines() if x.strip()))
                if len(domains) > 1000 or len(hashes) > 1000 or len(names) > 1000 or any(not HOSTNAME.fullmatch(x) for x in domains) or any(not HASH.fullmatch(x) for x in hashes) or any(not PROGRAM_NAME.fullmatch(x) for x in names):
                    return self.reply(400, 'Invalid domains or SHA-256 values')
                self.store.data.update(web_domains=domains, program_hashes=hashes, program_names=names, block_local_files=(one('block_local_files') == '1'), policy_revision=self.store.data['policy_revision']+1)
            elif self.path == '/device':
                dev = self.store.data['devices'].get(one('id'))
                if not dev or one('approved') not in ('0', '1'):
                    return self.reply(400, 'Unknown device')
                dev['approved'] = one('approved') == '1'
            elif self.path == '/request':
                item = next((x for x in self.store.data['requests'] if x['id'] == one('id')), None)
                if not item or item['state'] != 'pending' or one('action') not in ('approve', 'deny'):
                    return self.reply(400, 'Invalid request')
                item['state'] = 'approved' if one('action') == 'approve' else 'denied'
                if item['state'] == 'approved': item['expires'] = int(time.time()) + 3600
            else:
                return self.reply(404, 'Not found')
            self.store.save()
        return self.redirect('/')

    def register(self, data):
        dev_id, key, name = data.get('id'), data.get('key'), data.get('name')
        tun, wfp = data.get('tun'), data.get('wfp')
        if (tun is not None and not isinstance(tun, bool)) or (wfp is not None and not isinstance(wfp, bool)): return self.json_reply(400, {'error': 'invalid status'})
        if not all(isinstance(x, str) for x in (dev_id, key, name)) or not ID.fullmatch(dev_id) or not ID.fullmatch(key) or not 1 <= len(name) <= 128:
            return self.json_reply(400, {'error': 'invalid device registration'})
        with self.store.lock:
            dev = self.store.data['devices'].get(dev_id)
            digest = hashlib.sha256(key.encode()).hexdigest()
            if dev:
                if not hmac.compare_digest(dev['key_hash'], digest):
                    return self.json_reply(403, {'error': 'device id already used'})
                dev['last_seen'] = int(time.time()); dev['tun'] = tun; dev['wfp'] = wfp
                self.store.save()
                return self.json_reply(200, {'approved': dev['approved']})
            if len(self.store.data['devices']) >= 1000:
                return self.json_reply(429, {'error': 'device capacity'})
            self.store.data['devices'][dev_id] = {'name': name, 'key_hash': digest, 'approved': False, 'last_seen': int(time.time()), 'tun': tun, 'wfp': wfp}
            self.store.save()
        return self.json_reply(201, {'approved': False})

    def unlock_device(self, data):
        dev_id, key = self.headers.get('X-Ohno-Device', ''), self.headers.get('X-Ohno-Key', '')
        password = data.get('password')
        if not isinstance(password, str) or len(password) > 512:
            return self.json_reply(400, {'error': 'invalid password'})
        if not self.store.device(dev_id, key):
            return self.json_reply(403, {'error': 'device not authorized'})
        if not self.store.verify_password(password, 'device:' + dev_id):
            return self.json_reply(403, {'error': 'invalid password or temporarily rate limited'})
        with self.store.lock:
            if not self.store.device(dev_id, key):
                return self.json_reply(403, {'error': 'device not authorized'})
            if len(self.store.data['requests']) >= 10000:
                return self.json_reply(429, {'error': 'request capacity'})
            item = {'id': secrets.token_urlsafe(18), 'device_id': dev_id, 'kind': 'pause', 'object': '*', 'state': 'approved', 'created': int(time.time()), 'expires': int(time.time()) + 3600}
            self.store.data['requests'].append(item)
            self.store.save()
        return self.json_reply(201, {'expires': item['expires']})

    def submit_request(self, data):
        dev_id, key = self.headers.get('X-Ohno-Device', ''), self.headers.get('X-Ohno-Key', '')
        kind, obj = data.get('kind'), data.get('object')
        label = data.get('label', '')
        if not isinstance(label, str) or len(label) > 128 or '/' in label or '\\' in label or any(ord(c) < 32 for c in label):
            return self.json_reply(400, {'error': 'invalid program label'})
        if not isinstance(kind, str) or kind not in ('website', 'application', 'network', 'local_html') or not isinstance(obj, str) or not 1 <= len(obj) <= 512:
            return self.json_reply(400, {'error': 'invalid request'})
        if (kind == 'website' and not HOSTNAME.fullmatch(obj)) or (kind in ('application','network') and not HASH.fullmatch(obj)):
            return self.json_reply(400, {'error': 'invalid object identity'})
        with self.store.lock:
            if not self.store.device(dev_id, key):
                return self.json_reply(403, {'error': 'device not authorized'})
            requests = self.store.data['requests']
            if len(requests) >= 10000:
                return self.json_reply(429, {'error': 'request capacity'})
            item = {'id': secrets.token_urlsafe(18), 'device_id': dev_id, 'kind': kind, 'object': obj, 'label': label, 'state': 'pending', 'created': int(time.time())}
            requests.append(item)
            self.store.save()
        return self.json_reply(201, {'id': item['id']})


def create_certificate(cert_path, key_path, host):
    """Create a school-controlled local HTTPS certificate; never overwrite keys."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    cert_path, key_path = Path(cert_path), Path(key_path)
    if cert_path.exists() or key_path.exists(): raise FileExistsError('certificate or key already exists')
    try:
        alt = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode('idna').decode('ascii').lower()
        if not HOSTNAME.fullmatch(host): raise ValueError('invalid server hostname')
        alt = x509.DNSName(host)
    private = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
            .not_valid_after(now+timedelta(days=825)).add_extension(x509.SubjectAlternativeName([alt]),critical=False)
            .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
            .sign(private,hashes.SHA256()))
    for path in (cert_path,key_path): path.parent.mkdir(parents=True,exist_ok=True)
    key_bytes=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    key_fd=os.open(str(key_path),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(key_fd,'wb') as f: f.write(key_bytes)
        cert_fd=os.open(str(cert_path),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
        with os.fdopen(cert_fd,'wb') as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    except Exception:
        key_path.unlink(missing_ok=True)
        raise


def main():
    p = argparse.ArgumentParser(description='ohno teacher HTTPS service')
    p.add_argument('--state', help='Path to private writable state file')
    p.add_argument('--init', action='store_true', help='Create state and teacher password interactively')
    p.add_argument('--generate-certificate', action='store_true', help='Generate a local HTTPS certificate')
    p.add_argument('--host', help='Hostname or IP for certificate')
    p.add_argument('--cert', help='PEM certificate')
    p.add_argument('--key', help='PEM private key')
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8443)
    args = p.parse_args()
    if args.generate_certificate:
        if not args.cert or not args.key or not args.host: p.error('--cert, --key and --host are required')
        create_certificate(args.cert, args.key, args.host)
        print('Certificate created. Protect the private key and install the certificate only on managed devices.')
        return
    if not args.state: p.error('--state is required')
    if args.init:
        import getpass
        first = getpass.getpass('Teacher password (12+ chars): ')
        second = getpass.getpass('Repeat password: ')
        if first != second: p.error('Passwords do not match')
        Store.initialize(args.state, first)
        print('State initialized.')
        return
    if not args.cert or not args.key: p.error('HTTPS certificate and private key are required')
    store = Store(args.state)
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.store = store
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print('ohno HTTPS server listening on %s:%d' % server.server_address)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    main()
