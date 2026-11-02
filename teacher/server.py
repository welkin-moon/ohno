#!/usr/bin/env python3
"""Ohno teacher service with a loopback control UI and a separate HTTPS API."""
import argparse
import hashlib
import hmac
import ipaddress
import html
import json
import os
import re
import secrets
import socket
import sys
import ssl
import webbrowser
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from school_installer import HOSTNAME, build_school_installer, enrollment_origin
from maintenance import MaintenanceGuard, create_credential, parse_authorization_request
from update_catalog import CatalogError, ReleaseCatalog
from update_manifest import MAX_PACKAGE_SIZE

MAX_BODY = 65536
MAX_REQUESTS = 10000
PIN_ITERATIONS = 160000
HASH = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[A-Za-z0-9_-]{16,128}\Z')
MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z')
PROGRAM_NAME = re.compile(r'[a-z0-9_. -]{1,128}\.exe\Z')
PIN = re.compile(r'[0-9]{4,8}\Z')
DEFAULT_WEB = ['classic.minecraft.net', 'eaglercraft.com']
DEFAULT_GAMES = ['plantsvszombies.exe','plantsvszombiesoriginal.exe','slaythespire.exe','gta3.exe','gta-vc.exe','gta_sa.exe','gtaiv.exe','minecraftlauncher.exe','minecraft.windows.exe']


def pin_hash(pin, salt):
    return hashlib.pbkdf2_hmac('sha256', pin.encode('ascii'), bytes.fromhex(salt), PIN_ITERATIONS).hex()


def esc(value):
    return html.escape(str(value), quote=True)


def valid_text(value, limit, allow_empty=False):
    if (not isinstance(value, str) or not (0 if allow_empty else 1) <= len(value) <= limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        return False
    try:
        value.encode('utf-8')
    except UnicodeError:
        return False
    return True


def valid_mac(value):
    # Canonical, nonzero unicast MAC; not a proof of device ownership.
    if not isinstance(value, str) or not MAC.fullmatch(value): return False
    return not (int(value[:2], 16) & 1) and value != '00:00:00:00:00:00'


def mac_bound(dev):
    # The device key still authenticates the client; MAC changes require teacher review.
    bound = dev.get('bound_mac', '')
    return bool(bound and bound in dev.get('macs', []))


class StateSaveError(RuntimeError):
    pass


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.attempts = {}
        self.maintenance_guard = MaintenanceGuard()
        self.release_directory = self.path.with_name(self.path.stem + '.releases')
        self.release_catalog = None
        self.release_error = False
        self.release_download_slots = threading.BoundedSemaphore(2)
        if self.release_directory.exists():
            try:
                self.release_catalog = ReleaseCatalog(self.release_directory)
            except (OSError, ValueError, CatalogError):
                # Never replace lost/corrupt school signing identity automatically.
                self.release_error = True
        self._committed = self.path.read_text('utf-8')
        self.data = json.loads(self._committed)
        if self.data.get('version') != 1:
            raise ValueError('Unsupported state version')
        # alpha.3 used one heavyweight password for both local management and
        # student-side unlock. Local management is now loopback-only and has no
        # login; keep only an optional short classroom unlock PIN.
        migrated = 'salt' in self.data or 'password_hash' in self.data
        self.data.pop('salt', None)
        self.data.pop('password_hash', None)
        if 'unlock_pin_salt' not in self.data:
            self.data['unlock_pin_salt'] = None
            migrated = True
        if 'unlock_pin_hash' not in self.data:
            self.data['unlock_pin_hash'] = None
            migrated = True
        # Older clients created another pending row on every retry. Keep the
        # newest copy so upgrading also recovers queues already filled by this.
        seen = set()
        requests = []
        for item in reversed(self.data['requests']):
            identity = (item['device_id'], item['kind'], item['object'])
            if item['state'] == 'pending':
                if identity in seen:
                    migrated = True
                    continue
                seen.add(identity)
            requests.append(item)
        self.data['requests'] = requests[::-1]
        if migrated:
            self.save()

    @classmethod
    def initialize(cls, path):
        p = Path(path)
        if p.exists():
            raise FileExistsError('State already exists')
        p.parent.mkdir(parents=True, exist_ok=True)
        state = {'version': 1, 'unlock_pin_salt': None, 'unlock_pin_hash': None,
                 'policy_revision': 0, 'web_domains': DEFAULT_WEB[:], 'program_hashes': [],
                 'program_names': DEFAULT_GAMES[:], 'block_local_files': False,
                 'devices': {}, 'requests': []}
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            json.dump(state, file, ensure_ascii=False)
        return cls(p)

    def save(self):
        with self.lock:
            name = None
            try:
                encoded = json.dumps(self.data, ensure_ascii=False, separators=(',', ':'))
                fd, name = tempfile.mkstemp(prefix='.ohno-', dir=str(self.path.parent))
                with os.fdopen(fd, 'w', encoding='utf-8') as file:
                    file.write(encoded)
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(name, self.path)
            except (OSError, ValueError, TypeError) as error:
                # A failed write must not make an uncommitted policy, approval
                # or PIN visible to subsequent requests in this process.
                self.data = json.loads(self._committed)
                raise StateSaveError('Cannot save teacher state') from error
            else:
                self._committed = encoded
            finally:
                if name and os.path.exists(name):
                    try:
                        os.unlink(name)
                    except OSError:
                        pass

    def initialize_releases(self):
        with self.lock:
            if self.release_catalog is not None or self.release_directory.exists():
                raise CatalogError('release trust already exists; restore rather than regenerate')
            self.release_catalog = ReleaseCatalog.initialize(self.release_directory)
            self.release_error = False

    def close(self):
        if self.release_catalog is not None:
            self.release_catalog.close()

    def set_unlock_pin(self, pin):
        with self.lock:
            if pin is None:
                self.data['unlock_pin_salt'] = None
                self.data['unlock_pin_hash'] = None
            else:
                if not isinstance(pin, str) or not PIN.fullmatch(pin):
                    raise ValueError('Unlock PIN must be 4-8 digits')
                salt = secrets.token_hex(16)
                self.data['unlock_pin_salt'] = salt
                self.data['unlock_pin_hash'] = pin_hash(pin, salt)
            self.attempts.clear()
            self.save()

    def verify_unlock_pin(self, pin, address):
        if not isinstance(pin, str) or not PIN.fullmatch(pin):
            return False
        with self.lock:
            salt = self.data.get('unlock_pin_salt')
            expected = self.data.get('unlock_pin_hash')
            if not salt or not expected:
                return False
            now = time.monotonic()
            attempts = [x for x in self.attempts.get(address, []) if now - x < 300]
            if len(attempts) >= 8:
                self.attempts[address] = attempts
                return False
            if not hmac.compare_digest(pin_hash(pin, salt), expected):
                attempts.append(now)
                self.attempts[address] = attempts
                return False
            self.attempts.pop(address, None)
            return True

    def set_maintenance_password(self, password):
        # Expensive hashing is outside the policy/state lock. Only this salted
        # server-side record is persisted; never copy it into a client image.
        credential = create_credential(password) if password is not None else None
        with self.lock:
            self.data['maintenance_credential'] = credential
            self.save()

    def authorize_maintenance(self, password, source, action, nonce, dev_id='', key=''):
        if action not in ('install', 'uninstall') or not isinstance(nonce, str) or not HASH.fullmatch(nonce):
            return None
        with self.lock:
            credential = self.data.get('maintenance_credential')
            credential = dict(credential) if isinstance(credential, dict) else None
            if action == 'uninstall' and not self.device(dev_id, key, require_approved=False):
                return None
        if not self.maintenance_guard.verify(password, credential, source):
            return None
        with self.lock:
            # Rotation/disable during a slow hash must invalidate that result.
            if self.data.get('maintenance_credential') != credential:
                return None
            if action == 'uninstall' and not self.device(dev_id, key, require_approved=False):
                return None
            now = int(time.time())
            event = {'action': action, 'nonce': nonce, 'device_id': dev_id if action == 'uninstall' else '',
                     'authorized_at': now, 'expires_at': now + 120}
            self.data['maintenance_events'] = (self.data.get('maintenance_events', []) + [event])[-100:]
            # No authorization is returned if its audit record cannot persist.
            self.save()
            return dict(event)

    def device(self, dev_id, key, require_approved=True):
        with self.lock:
            dev = self.data['devices'].get(dev_id)
            if not dev or not isinstance(key, str) or not hmac.compare_digest(dev['key_hash'], hashlib.sha256(key.encode()).hexdigest()):
                return None
            if require_approved and (not dev['approved'] or not mac_bound(dev)):
                return None
            return dev

    def add_request(self, dev_id, kind, obj, label='', approved=False):
        """Coalesce retries and reclaim finished history before rejecting new work."""
        with self.lock:
            now = int(time.time())
            requests = self.data['requests']
            for item in requests:
                if (item['device_id'] == dev_id and item['kind'] == kind and item['object'] == obj
                        and (item['state'] == 'pending' or
                             (item['state'] == 'approved' and item.get('expires', 0) > now))):
                    if approved:
                        item.update(state='approved', expires=now + 3600)
                        self.save()
                    return item
            if len(requests) >= MAX_REQUESTS:
                finished = next((i for i, item in enumerate(requests)
                    if item['state'] != 'pending' and
                    (item['state'] != 'approved' or item.get('expires', 0) <= now)), None)
                if finished is None:
                    return None
                del requests[finished]
            item = {'id': secrets.token_urlsafe(18), 'device_id': dev_id, 'kind': kind,
                    'object': obj, 'label': label, 'state': 'approved' if approved else 'pending',
                    'created': now}
            if approved:
                item['expires'] = now + 3600
            requests.append(item)
            self.save()
            return item


class TeacherHTTPServer(ThreadingHTTPServer):
    """Bound connection work; TLS handshakes must never block the accept loop."""
    allow_reuse_address = os.name != 'nt'
    request_queue_size = 64
    request_timeout = 10

    def __init__(self, address, handler, *, ssl_context=None, max_workers=64):
        self.ssl_context = ssl_context
        self.workers = threading.BoundedSemaphore(max_workers)
        if ':' in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)

    def server_bind(self):
        if os.name == 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def process_request(self, request, client_address):
        request.settimeout(self.request_timeout)
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            if self.ssl_context:
                request = self.ssl_context.wrap_socket(request, server_side=True)
            self.finish_request(request, client_address)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            pass
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            self.workers.release()


STYLE = '''<style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#25303a}h1{color:#293c66}section{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}input,textarea,button{font:inherit;padding:.5rem;max-width:100%}textarea{width:95%;height:8rem}button{cursor:pointer}table{border-collapse:collapse;width:100%}td,th{padding:.5rem;border-bottom:1px solid #ddd;text-align:left}small{color:#555}.ok{color:#17613a}.pending{color:#9a4a00}</style>'''


class Handler(BaseHTTPRequestHandler):
    server_version = 'ohno-teacher/0.2'
    sys_version = ''

    def log_message(self, fmt, *args):
        # Device keys, maintenance passwords, PINs and policy contents must never enter logs.
        pass

    @property
    def store(self):
        return self.server.store

    def is_control(self):
        if not getattr(self.server, 'control', False):
            return False
        try:
            if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                return False
        except ValueError:
            return False
        host = self.headers.get('Host', '').split(':', 1)[0].lower()
        return host in ('127.0.0.1', 'localhost')

    def reply(self, status, data, content_type='text/plain; charset=utf-8', headers=()):
        body = data.encode('utf-8') if isinstance(data, str) else data
        binary = content_type == 'application/octet-stream'
        # A single sendall(large_package) applies the socket timeout to the
        # entire transfer. Bound each chunk instead, plus an aggregate deadline;
        # slow receivers still cannot occupy a download slot indefinitely.
        deadline = time.monotonic() + 300 if binary else None
        try:
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header('Referrer-Policy', 'no-referrer')
            for key, value in headers:
                self.send_header(key, value)
            if binary:
                self.send_header('Connection', 'close')
                self.close_connection = True
            self.end_headers()
            if binary:
                view = memoryview(body)
                for offset in range(0, len(view), 65536):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return
                    self.connection.settimeout(min(self.server.request_timeout, remaining))
                    self.wfile.write(view[offset:offset+65536])
            else:
                self.wfile.write(body)
        except OSError:
            # Headers or a body prefix may already be on the wire. Never append
            # a second HTTP 503/JSON response into an incomplete binary package.
            self.close_connection = True

    def json_reply(self, status, value):
        self.reply(status, json.dumps(value, ensure_ascii=False), 'application/json; charset=utf-8')

    def read_body(self, limit=MAX_BODY):
        if self.headers.get('Transfer-Encoding') is not None or len(self.headers.get_all('Content-Length', [])) != 1:
            return None
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            return None
        if length < 0 or length > limit:
            return None
        body = self.rfile.read(length)
        return body if len(body) == length else None

    def redirect(self, location):
        self.reply(303, '', headers=[('Location', location)])

    def page(self, title, content):
        self.reply(200, '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + esc(title) + '</title>' + STYLE + '<body>' + content + '</body></html>', 'text/html; charset=utf-8')

    def device_credentials(self, data=None):
        # Current native clients send secrets only in the authenticated TLS
        # request body. Keep old header clients compatible, but never combine
        # two authentication sources or accept duplicate/partial credentials.
        names = ('X-Ohno-Device', 'X-Ohno-Key')
        if 'Authorization' in self.headers:
            return '', ''
        present = data is not None and ('device_id' in data or 'device_key' in data)
        if present:
            if any(name in self.headers for name in names):
                return '', ''
            dev_id, key = data.get('device_id'), data.get('device_key')
        else:
            if any(len(self.headers.get_all(name, [])) != 1 for name in names):
                return '', ''
            dev_id, key = (self.headers.get(name, '') for name in names)
        if not all(isinstance(value, str) and ID.fullmatch(value) for value in (dev_id, key)):
            return '', ''
        return dev_id, key

    def device_policy(self, data=None):
        if data is not None and set(data) != {'device_id', 'device_key'}:
            return self.json_reply(400, {'error': 'invalid policy request'})
        dev_id, key = self.device_credentials(data)
        with self.store.lock:
            if not self.store.device(dev_id, key):
                return self.json_reply(403, {'error': 'not authorized or pending'})
            policy = self.store.data
            grants = [dict(id=x['id'], kind=x['kind'], object=x['object'], expires=x.get('expires', 0))
                      for x in policy['requests'] if x['device_id'] == dev_id and x['state'] == 'approved' and x.get('expires', 0) > time.time()]
            return self.json_reply(200, {'revision': policy['policy_revision'], 'web_domains': policy['web_domains'],
                'program_hashes': policy['program_hashes'], 'program_names': policy.get('program_names', []),
                'block_local_files': policy.get('block_local_files', False), 'grants': grants})

    def do_GET(self):
        if self.path == '/health':
            return self.json_reply(200, {'ok': True, 'control': bool(getattr(self.server, 'control', False))})
        if self.path == '/api/device/policy':
            if getattr(self.server, 'control', False):
                return self.reply(404, 'Not found')
            return self.device_policy()
        if not self.is_control():
            return self.reply(404, 'Not found')
        if self.path == '/updates.js':
            return self.reply(200, (Path(__file__).with_name('update_ui.js')).read_bytes(), 'application/javascript; charset=utf-8')
        if self.path == '/school-installer':
            setup_exe = getattr(self.server, 'school_installer_exe', None)
            origin = getattr(self.server, 'enrollment_origin', None)
            cert_pem = getattr(self.server, 'public_certificate', None)
            if not setup_exe or not origin or not cert_pem:
                return self.reply(503, 'School installer is not available')
            try:
                with self.store.lock:
                    public_key = self.store.release_catalog.public_key if self.store.release_catalog else None
                packaged = build_school_installer(Path(setup_exe).read_bytes(), origin, cert_pem, public_key)
            except (OSError, ValueError):
                return self.reply(503, 'Cannot prepare school installer')
            return self.reply(200, packaged, 'application/octet-stream',
                              [('Content-Disposition', 'attachment; filename="Ohno-School-Setup.exe"')])
        if self.path != '/':
            return self.reply(404, 'Not found')
        csrf = self.server.control_csrf
        with self.store.lock:
            data = self.store.data
            devices = list(data['devices'].items())
            requests = list(data['requests'])[-100:][::-1]
            domains = '\n'.join(data['web_domains'])
            hashes = '\n'.join(data['program_hashes'])
            names = '\n'.join(data.get('program_names', []))
            block_local_files = data.get('block_local_files', False)
            revision = data['policy_revision']
            pin_enabled = bool(data.get('unlock_pin_hash'))
            maintenance_enabled = bool(data.get('maintenance_credential'))
        hidden = '<input type="hidden" name="csrf" value="' + esc(csrf) + '">'
        rows = []
        for dev_id, dev in devices:
            active = dev['approved'] and mac_bound(dev)
            macs = dev.get('macs', [])
            bound = dev.get('bound_mac', '')
            collision = any(other_id != dev_id and other.get('approved') and
                            other.get('bound_mac') in macs for other_id, other in devices)
            if active: status = '已批准'
            elif dev['approved']: status = 'MAC 变更，需核验并重新绑定'
            else: status = '待批准'
            if collision: status += ' / MAC 冲突'
            commands = ''
            if dev.get('primary_mac') and not active:
                commands += '<button name="approved" value="1">' + ('重新绑定' if dev['approved'] else '批准并绑定 MAC') + '</button> '
            if dev['approved']: commands += '<button name="approved" value="0">停用</button>'
            if not dev.get('primary_mac'): commands += '<small>没有可绑定的 MAC，检查网卡</small>'
            action = '<form method="post" action="/device">' + hidden + '<input type="hidden" name="id" value="' + esc(dev_id) + '">' + commands + '</form>'
            mac_text = '<strong>' + esc(bound or '未绑定') + '</strong><small> 当前: ' + esc(dev.get('primary_mac') or '未知') + '</small>'
            if len(macs) > 1: mac_text += '<small> 其他: ' + esc(', '.join(macs[1:])) + '</small>'
            rows.append('<tr><td>' + esc(dev['name']) + '</td><td>' + esc(dev_id[:12]) +
                        '</td><td>' + mac_text + '</td><td>' + esc(dev.get('last_ip') or '未知') +
                        '</td><td>' + status + ' / ' +
                        ('在线' if time.time()-dev.get('last_seen',0)<60 else '离线') +
                        ' / TUN: ' + ('运行' if dev.get('tun') is True else '不可用' if dev.get('tun') is False else '未知') +
                        ' / WFP: ' + ('可用' if dev.get('wfp') is True else '不可用' if dev.get('wfp') is False else '未知') +
                        '</td><td>' + action + '</td></tr>')
        req_rows = []
        for item in requests:
            action = ''
            if item['state'] == 'pending':
                action = '<form method="post" action="/request">' + hidden + '<input type="hidden" name="id" value="' + esc(item['id']) + '"><button name="action" value="approve">允许 1 小时</button> <button name="action" value="deny">拒绝</button></form>'
            req_rows.append('<tr><td>' + esc(item['device_id'][:12]) + '</td><td>' + esc(item['kind']) + '</td><td>' + esc(item.get('label') or item['object']) + (' <small>' + esc(item['object']) + '</small>' if item.get('label') else '') + '</td><td>' + esc(item['state']) + '</td><td>' + action + '</td></tr>')
        content = '<h1>ohno 教师端</h1><p>仅本机可管理 · 策略版本 ' + str(revision) + '</p>'
        content += '<section><h2>教师维护密码（安装 / 卸载）</h2><p>仅用于新增安装 / 卸载授权，不是后台登录或课堂 PIN。镜像分发后的启动不重复输入。支持一句话式长口令，不要求大小写或符号组合。当前：<strong>' + ('已设置' if maintenance_enabled else '未设置，维护授权拒绝') + '</strong></p><p><small>配套新版安装器在安装 / 卸载时在线验证此密码；已发布的 alpha.6 旧安装器不具备此保护。系统管理员仍可进行标准 Windows 恢复。</small></p><form method="post" action="/maintenance-password">' + hidden + '<input name="maintenance_password" type="password" aria-label="教师维护密码" minlength="12" maxlength="128" autocomplete="new-password" placeholder="12–128 字符的维护密码"> <button name="action" value="set">设置 / 更新</button> <button name="action" value="clear" formnovalidate>停用维护授权</button></form></section>'
        with self.store.lock:
            catalog = self.store.release_catalog
            release_error = self.store.release_error
            try:
                offer = catalog.offer() if catalog else None
            except (OSError, ValueError, CatalogError):
                release_error = True
                offer = None
        content += '<section><h2>客户端升级（开发预览）</h2><p>只下发教师明确批准的本地构建，不自动信任 GitHub latest。日常批准不重复输入维护密码。须使用配套托管客户端；已发布 alpha.6 不具备自动升级。</p>'
        if release_error:
            content += '<p>发布状态或签名密钥不可用；升级拒绝。请恢复原状态，勿生成新身份冒充旧学校。</p>'
        elif catalog is None:
            content += '<p>尚未初始化独立发布签名身份。私钥仅留在教师机，公开验证钥可进入学校镜像。</p><form method="post" action="/updates/initialize">' + hidden + '<button>初始化本校发布信任</button></form>'
        else:
            content += '<p>当前：' + (esc(offer['version']) + ' / 序号 ' + str(offer['sequence']) if offer else '暂停或无有效批准') + '</p><p><small>公开验证钥：' + esc(catalog.public_key) + '</small></p>'
            content += '<form id="update-approval">' + hidden + '<input type="file" accept=".ohno" aria-label="本地 OHNO 更新包" required> <button type="submit">验证并批准此包</button> <button type="button" id="cancel-update-upload" disabled>取消请求</button></form><p id="update-upload-status" role="status"></p><script src="/updates.js" defer></script>'
            content += '<form method="post" action="/updates/pause">' + hidden + '<button>暂停下发与执行授权</button></form>'
        content += '</section>'
        content += '<section><h2>课堂解锁 PIN</h2><p>可选，只用于学生机现场暂停限制 1 小时；后台管理仅在教师机本地开放并免登录。当前：<strong>' + ('已启用' if pin_enabled else '关闭') + '</strong></p><form method="post" action="/unlock-pin">' + hidden + '<input name="pin" type="password" inputmode="numeric" pattern="[0-9]{4,8}" maxlength="8" placeholder="4–8 位数字"> <button name="action" value="set">设置 / 更新</button> <button name="action" value="clear">关闭 PIN 解锁</button></form></section>'
        content += '<section><h2>网站与程序规则</h2><form method="post" action="/policy">' + hidden + '<label>屏蔽域名<textarea name="domains">' + esc(domains) + '</textarea></label><label>屏蔽程序 SHA-256<textarea name="hashes">' + esc(hashes) + '</textarea></label><label>屏蔽程序文件名<textarea name="names">' + esc(names) + '</textarea></label><p><label><input type="checkbox" name="block_local_files" value="1"' + (' checked' if block_local_files else '') + '> 限制 Edge 打开本地文件</label></p><button>保存规则</button></form></section>'
        if getattr(self.server, 'school_installer_exe', None) and getattr(self.server, 'enrollment_origin', None):
            content += '<section><h2>学生机一键安装</h2><p><a href="/school-installer">下载 Ohno-School-Setup.exe</a>；复制到模板机双击、允许 UAC，再输入教师维护密码。镜像分发后不重复输入。</p><small>包内只有教师 API 地址、公开证书及已初始化的发布验证公钥，没有教师 PIN、密码或私钥。</small></section>'
        content += '<section><h2>设备</h2><p><small>MAC 用于设备关联；DHCP IP 仅显示最近地址。真正认证仍使用每机独立密钥。</small></p><table><tr><th>名称</th><th>ID</th><th>MAC</th><th>最近 IP</th><th>状态</th><th>操作</th></tr>' + ''.join(rows) + '</table></section>'
        content += '<section><h2>审批请求</h2><table><tr><th>设备</th><th>类型</th><th>对象</th><th>状态</th><th>操作</th></tr>' + ''.join(req_rows) + '</table></section>'
        return self.page('ohno 教师端', content)

    def do_POST(self):
        try:
            return self._do_post()
        except (StateSaveError, CatalogError, OSError):
            if self.path.startswith('/api/'):
                return self.json_reply(503, {'error': 'state unavailable; retry later'})
            return self.reply(503, '保存失败，修改未生效。请检查磁盘和文件权限后重试。')

    def _do_post(self):
        if self.path == '/updates/approve':
            if not self.is_control():
                return self.reply(404, 'Not found')
            token = self.headers.get('X-Ohno-CSRF', '')
            if not hmac.compare_digest(self.server.control_csrf.encode('utf-8'), token.encode('utf-8')):
                return self.reply(403, 'Invalid CSRF token')
            if self.headers.get('Content-Type') != 'application/octet-stream':
                return self.reply(400, 'Expected binary update package')
            # Check control/CSRF before accepting the potentially large body.
            raw = self.read_body(MAX_PACKAGE_SIZE)
            if raw is None:
                return self.reply(413, 'Invalid update length')
            with self.store.lock:
                if self.store.release_catalog is None:
                    return self.reply(409, 'Initialize release trust first')
                try:
                    approved = self.store.release_catalog.approve(raw)
                except ValueError:
                    return self.reply(400, 'Invalid x64 update package')
            return self.json_reply(200, {'approved': True, 'sequence': approved['sequence'], 'sha256': approved['sha256']})
        raw = self.read_body(2048 if self.path.startswith('/api/device/update/') else MAX_BODY)
        if raw is None:
            return self.reply(413, 'Invalid request length')
        if self.path.startswith('/api/device/') or self.path == '/api/maintenance/authorize':
            if getattr(self.server, 'control', False):
                return self.reply(404, 'Not found')
            try:
                def unique_fields(pairs):
                    value = {}
                    for key, item in pairs:
                        if key in value:
                            raise ValueError('duplicate request field')
                        value[key] = item
                    return value
                data = (parse_authorization_request(raw) if self.path == '/api/maintenance/authorize'
                        else json.loads(raw.decode('utf-8'), object_pairs_hook=unique_fields))
                if not isinstance(data, dict): raise ValueError()
            except (ValueError, UnicodeError, RecursionError):
                return self.json_reply(400, {'error': 'invalid JSON'})
            if self.path == '/api/maintenance/authorize':
                return self.maintenance_authorization(data)
            if self.path.startswith('/api/device/update/'):
                return self.device_update(data)
            if self.path == '/api/device/register':
                return self.register(data)
            if self.path == '/api/device/policy':
                return self.device_policy(data)
            if self.path == '/api/device/request':
                return self.submit_request(data)
            if self.path == '/api/device/unlock':
                return self.unlock_device(data)
            return self.json_reply(404, {'error': 'not found'})
        if not self.is_control():
            return self.reply(404, 'Not found')
        try:
            form = parse_qs(raw.decode('utf-8'), keep_blank_values=True, max_num_fields=20)
        except (ValueError, UnicodeError):
            return self.reply(400, 'Invalid form')
        one = lambda key: form.get(key, [''])[0]
        if not hmac.compare_digest(self.server.control_csrf.encode('utf-8'), one('csrf').encode('utf-8')):
            return self.reply(403, 'Invalid CSRF token')
        if self.path == '/updates/initialize':
            self.store.initialize_releases()
            return self.redirect('/')
        if self.path == '/updates/pause':
            with self.store.lock:
                if self.store.release_catalog is None:
                    return self.reply(409, 'No release trust')
                self.store.release_catalog.pause()
            return self.redirect('/')
        if self.path == '/maintenance-password':
            if one('action') not in ('set', 'clear'):
                return self.reply(400, 'Invalid maintenance action')
            try:
                self.store.set_maintenance_password(one('maintenance_password') if one('action') == 'set' else None)
            except ValueError:
                return self.reply(400, 'Maintenance password must be 12-128 printable characters')
            return self.redirect('/')
        if self.path == '/unlock-pin':
            action = one('action')
            if action == 'clear':
                self.store.set_unlock_pin(None)
            elif action == 'set':
                try:
                    self.store.set_unlock_pin(one('pin'))
                except ValueError:
                    return self.reply(400, 'PIN must be 4-8 digits')
            else:
                return self.reply(400, 'Invalid PIN action')
            return self.redirect('/')
        with self.store.lock:
            if self.path == '/policy':
                domains = sorted(set(x.strip().lower() for x in one('domains').splitlines() if x.strip()))
                hashes = sorted(set(x.strip().lower() for x in one('hashes').splitlines() if x.strip()))
                names = sorted(set(x.strip().lower() for x in one('names').splitlines() if x.strip()))
                if len(domains) + (1 if one('block_local_files') == '1' else 0) > 1000 or len(hashes) > 1000 or len(names) > 1000 or any(not HOSTNAME.fullmatch(x) for x in domains) or any(not HASH.fullmatch(x) for x in hashes) or any(not PROGRAM_NAME.fullmatch(x) for x in names):
                    return self.reply(400, 'Invalid domains or SHA-256 values')
                self.store.data.update(web_domains=domains, program_hashes=hashes, program_names=names,
                                       block_local_files=(one('block_local_files') == '1'),
                                       policy_revision=self.store.data['policy_revision']+1)
            elif self.path == '/device':
                dev = self.store.data['devices'].get(one('id'))
                if not dev or one('approved') not in ('0', '1'):
                    return self.reply(400, 'Unknown device')
                if one('approved') == '1':
                    primary = dev.get('primary_mac', '')
                    if not valid_mac(primary) or primary not in dev.get('macs', []):
                        return self.reply(400, 'No valid hardware MAC to bind')
                    for other_id, other in self.store.data['devices'].items():
                        if other_id != one('id') and other.get('approved') and other.get('bound_mac') in dev.get('macs', []):
                            return self.reply(409, 'MAC already bound to another approved device')
                    dev['bound_mac'] = primary
                    dev['approved'] = True
                else:
                    dev['approved'] = False
            elif self.path == '/request':
                item = next((x for x in self.store.data['requests'] if x['id'] == one('id')), None)
                if not item or item['state'] != 'pending' or one('action') not in ('approve', 'deny'):
                    return self.reply(400, 'Invalid request')
                item['state'] = 'approved' if one('action') == 'approve' else 'denied'
                if item['state'] == 'approved':
                    item['expires'] = int(time.time()) + 3600
            else:
                return self.reply(404, 'Not found')
            self.store.save()
        return self.redirect('/')

    def device_update(self, data):
        # Native callers put credentials in this POST body only after validating
        # the actual TLS connection. No device secrets in URLs or redirects.
        fields = {'device_id', 'device_key', 'nonce'}
        execute = self.path == '/api/device/update/authorize'
        if execute:
            fields |= {'sequence', 'sha256'}
        if (set(data) != fields or not all(isinstance(data.get(x), str) for x in ('device_id', 'device_key', 'nonce')) or
                not ID.fullmatch(data['device_id']) or not ID.fullmatch(data['device_key']) or not HASH.fullmatch(data['nonce'])):
            return self.json_reply(400, {'error': 'invalid update request'})
        with self.store.lock:
            if not self.store.device(data['device_id'], data['device_key']):
                return self.json_reply(403, {'error': 'device not approved or MAC changed'})
            catalog = self.store.release_catalog
            if catalog is None:
                return self.json_reply(503, {'error': 'release trust unavailable'})
            offer = catalog.offer()
            if offer is None:
                return self.json_reply(404, {'error': 'no currently approved release'})
            if self.path == '/api/device/update/offer':
                return self.json_reply(200, offer)
            if execute:
                if type(data['sequence']) is not int or data['sequence'] != offer['sequence'] or data['sha256'] != offer['sha256']:
                    return self.json_reply(403, {'error': 'release approval changed'})
                now = int(time.time())
                return self.json_reply(200, {'authorized': True, 'nonce': data['nonce'], 'device_id': data['device_id'],
                    'sequence': offer['sequence'], 'sha256': offer['sha256'], 'authorized_at': now, 'expires_at': now+120})
            if self.path != '/api/device/update/package/' + offer['sha256']:
                return self.json_reply(404, {'error': 'unknown update path'})
        # Bounded large transfers do not hold the policy/teacher control lock.
        # Recheck revocation after disk verification and before starting output.
        if not self.store.release_download_slots.acquire(blocking=False):
            return self.json_reply(503, {'error': 'download capacity; retry later'})
        try:
            payload = catalog.package(offer['sha256'])
            with self.store.lock:
                if not self.store.device(data['device_id'], data['device_key']):
                    return self.json_reply(403, {'error': 'device authorization changed'})
                current = catalog.offer()
                if payload is None or current is None or current['sequence'] != offer['sequence']:
                    return self.json_reply(404, {'error': 'release no longer approved'})
            return self.reply(200, payload, 'application/octet-stream')
        finally:
            self.store.release_download_slots.release()

    def maintenance_authorization(self, data):
        # This response is a nonce-bound online decision, not a bearer token.
        # New installers must verify TLS, compare action/nonce/device/expiry and
        # use it immediately; legacy alpha.6 clients do not call this endpoint.
        # parse_authorization_request has already enforced fields and types.
        # New native callers keep ALL secrets in the body, written only after
        # certificate verification on the same WinHTTP request. Header support
        # remains for older API callers; mixed forms are rejected, not guessed.
        dev_id, key = self.headers.get('X-Ohno-Device', ''), self.headers.get('X-Ohno-Key', '')
        if 'device_id' in data:
            if dev_id or key:
                return self.json_reply(400, {'error': 'ambiguous maintenance device credentials'})
            dev_id, key = data['device_id'], data['device_key']
        event = self.store.authorize_maintenance(data['maintenance_password'], self.client_address[0],
            data['action'], data['nonce'], dev_id, key)
        if event is None:
            return self.json_reply(403, {'error': 'maintenance authorization denied or temporarily unavailable'})
        return self.json_reply(200, dict(event, authorized=True))

    def register(self, data):
        if any(name in self.headers for name in ('Authorization', 'X-Ohno-Device', 'X-Ohno-Key')) or 'device_id' in data or 'device_key' in data:
            return self.json_reply(400, {'error': 'ambiguous registration credentials'})
        dev_id, key, name = data.get('id'), data.get('key'), data.get('name')
        tun, wfp = data.get('tun'), data.get('wfp')
        macs, primary = data.get('macs', []), data.get('primary_mac', '')
        if (tun is not None and not isinstance(tun, bool)) or (wfp is not None and not isinstance(wfp, bool)):
            return self.json_reply(400, {'error': 'invalid status'})
        if not all(isinstance(x, str) for x in (dev_id, key)) or not ID.fullmatch(dev_id) or not ID.fullmatch(key) or not valid_text(name, 128):
            return self.json_reply(400, {'error': 'invalid device registration'})
        if (not isinstance(macs, list) or len(macs) > 16 or
                any(not valid_mac(x) for x in macs) or len(set(macs)) != len(macs) or
                not isinstance(primary, str) or primary != (macs[0] if macs else '')):
            return self.json_reply(400, {'error': 'invalid MAC inventory'})
        with self.store.lock:
            dev = self.store.data['devices'].get(dev_id)
            digest = hashlib.sha256(key.encode()).hexdigest()
            now = int(time.time())
            if dev:
                if not hmac.compare_digest(dev['key_hash'], digest):
                    return self.json_reply(403, {'error': 'device id already used'})
                dev.update(name=name, macs=macs, primary_mac=primary,
                           last_ip=self.client_address[0], last_seen=now, tun=tun, wfp=wfp)
                self.store.save()
                return self.json_reply(200, {'approved': bool(self.store.device(dev_id, key))})
            if len(self.store.data['devices']) >= 1000:
                return self.json_reply(429, {'error': 'device capacity'})
            self.store.data['devices'][dev_id] = {
                'name': name, 'key_hash': digest, 'approved': False, 'bound_mac': '',
                'macs': macs, 'primary_mac': primary, 'last_ip': self.client_address[0],
                'last_seen': now, 'tun': tun, 'wfp': wfp
            }
            self.store.save()
        return self.json_reply(201, {'approved': False})

    def unlock_device(self, data):
        dev_id, key = self.device_credentials(data)
        # Accept alpha.3's field name for a transition period, but the value is
        # now a dedicated short classroom PIN rather than a management password.
        pin = data.get('pin', data.get('password'))
        if not isinstance(pin, str) or not PIN.fullmatch(pin):
            return self.json_reply(400, {'error': 'invalid unlock PIN'})
        if not self.store.device(dev_id, key):
            return self.json_reply(403, {'error': 'device not authorized'})
        if not self.store.verify_unlock_pin(pin, 'device:' + dev_id):
            return self.json_reply(403, {'error': 'unlock disabled, invalid PIN, or temporarily rate limited'})
        with self.store.lock:
            if not self.store.device(dev_id, key):
                return self.json_reply(403, {'error': 'device not authorized'})
            item = self.store.add_request(dev_id, 'pause', '*', approved=True)
            if item is None:
                return self.json_reply(429, {'error': 'request capacity'})
        return self.json_reply(201, {'expires': item['expires']})

    def submit_request(self, data):
        dev_id, key = self.device_credentials(data)
        kind, obj = data.get('kind'), data.get('object')
        label = data.get('label', '')
        if not valid_text(label, 128, allow_empty=True) or '/' in label or '\\' in label:
            return self.json_reply(400, {'error': 'invalid program label'})
        if not isinstance(kind, str) or kind not in ('website', 'application', 'network', 'local_html') or not valid_text(obj, 512):
            return self.json_reply(400, {'error': 'invalid request'})
        if (kind == 'website' and not HOSTNAME.fullmatch(obj)) or (kind in ('application','network') and not HASH.fullmatch(obj)):
            return self.json_reply(400, {'error': 'invalid object identity'})
        with self.store.lock:
            if not self.store.device(dev_id, key):
                return self.json_reply(403, {'error': 'device not authorized'})
            item = self.store.add_request(dev_id, kind, obj, label)
            if item is None:
                return self.json_reply(429, {'error': 'request capacity'})
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
            .not_valid_after(now+timedelta(days=825)).add_extension(x509.SubjectAlternativeName([alt, x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
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


def locate_base_installer():
    """Locate the client binary embedded by PyInstaller, or beside teacher.exe."""
    roots = []
    if getattr(sys, '_MEIPASS', None): roots.append(Path(sys._MEIPASS))
    roots.append(Path(sys.executable).resolve().parent)
    roots.append(Path.cwd())
    for root in roots:
        candidate = root / 'ohno-setup.exe'
        if candidate.is_file(): return candidate
    return None


def serve_teacher(state, cert, key, bind, port, enrollment_host=None, open_browser=False, control_port=8765):
    store = Store(state)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)

    # Context managers also release the first port if the second bind fails.
    with TeacherHTTPServer((bind, port), Handler, ssl_context=context) as api, \
            TeacherHTTPServer(('127.0.0.1', control_port), Handler) as control:
        api.store = control.store = store
        api.control = False
        control.control = True
        control.control_csrf = secrets.token_urlsafe(32)
        control.school_installer_exe = locate_base_installer()
        if enrollment_host and control.school_installer_exe:
            control.enrollment_origin = enrollment_origin(enrollment_host, api.server_port)
            control.public_certificate = Path(cert).read_bytes()

        api_thread = threading.Thread(target=api.serve_forever, daemon=True)
        api_thread.start()
        try:
            print('ohno student API listening on https://%s:%d' % api.server_address[:2])
            print('ohno teacher control listening on http://127.0.0.1:%d' % control.server_port)
            if open_browser:
                webbrowser.open('http://127.0.0.1:' + str(control.server_port) + '/', new=2)
            control.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            api.shutdown()
            api_thread.join(timeout=5)
            store.close()


def easy_start():
    """Double-click teacher app: initialize local state and open local control UI."""
    home = Path(os.environ.get('LOCALAPPDATA') or Path.home()) / 'OhnoTeacher'
    home.mkdir(parents=True, exist_ok=True)
    state, cert, key = home/'state.json', home/'teacher-cert.pem', home/'teacher-key.pem'
    hostname = socket.gethostname().split('.')[0].lower()
    if not HOSTNAME.fullmatch(hostname):
        raise ValueError('Computer hostname is not suitable for teacher HTTPS certificate')
    if not cert.exists() and not key.exists():
        create_certificate(cert, key, hostname)
    elif not (cert.exists() and key.exists()):
        raise RuntimeError('Incomplete teacher certificate files. Restore the matching cert/key pair.')
    if not state.exists():
        Store.initialize(state)
    serve_teacher(str(state),str(cert),str(key),'0.0.0.0',8443,hostname,open_browser=True)


def main():
    if len(sys.argv) == 1:
        easy_start()
        return
    p = argparse.ArgumentParser(description='ohno teacher HTTPS service')
    p.add_argument('--state', help='Path to private writable state file')
    p.add_argument('--control-port', type=int, default=8765, help='Loopback-only teacher UI port')
    p.add_argument('--init', action='store_true', help='Create empty teacher state')
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
        Store.initialize(args.state)
        print('State initialized. Teacher management is loopback-only and has no login password.')
        return
    if not args.cert or not args.key: p.error('HTTPS certificate and private key are required')
    serve_teacher(args.state,args.cert,args.key,args.bind,args.port,args.host,control_port=args.control_port)

if __name__ == '__main__':
    main()
