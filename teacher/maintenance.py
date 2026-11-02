"""Teacher maintenance-password verification; no client secrets or bearer tokens.

Only the teacher server stores this salted verifier. Keep it separate from the
optional classroom PIN and never include it in installers or golden images.
"""
from collections import deque
import hashlib
import hmac
import json
import re
import secrets
import threading
import time

ITERATIONS = 600_000
WINDOW = 300
PER_SOURCE = 8
GLOBAL_LIMIT = 32
SALT = re.compile(r'[0-9a-f]{32}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def parse_authorization_request(raw):
    if not isinstance(raw, bytes) or len(raw) > 2048:
        raise ValueError('Maintenance request too large')
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('Duplicate maintenance field')
            result[name] = value
        return result
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Invalid maintenance JSON') from error
    basic = {'action', 'nonce', 'maintenance_password'}
    device_fields = {'device_id', 'device_key'}
    if (not isinstance(data, dict) or data.get('action') not in ('install', 'uninstall') or
            set(data) not in (basic, basic | device_fields) or
            (set(data) != basic and data['action'] != 'uninstall') or
            not isinstance(data.get('nonce'), str) or not DIGEST.fullmatch(data['nonce']) or
            not isinstance(data.get('maintenance_password'), str)):
        raise ValueError('Invalid maintenance request')
    if set(data) != basic and any(not isinstance(data[name], str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', data[name]) for name in device_fields):
        raise ValueError('Invalid maintenance device identity')
    return data


def password_bytes(password):
    if (not isinstance(password, str) or not 12 <= len(password) <= 128 or
            any(ord(c) < 32 or ord(c) == 127 for c in password)):
        raise ValueError('Maintenance password must be 12-128 printable characters')
    try:
        encoded = password.encode('utf-8')
    except UnicodeError as error:
        raise ValueError('Invalid maintenance password encoding') from error
    if len(encoded) > 512:
        raise ValueError('Maintenance password is too long')
    return encoded


def create_credential(password):
    encoded = password_bytes(password)
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', encoded, bytes.fromhex(salt), ITERATIONS).hex()
    return {'algorithm': 'pbkdf2-sha256', 'iterations': ITERATIONS, 'salt': salt, 'digest': digest}


def valid_credential(credential):
    return (isinstance(credential, dict) and
            set(credential) == {'algorithm', 'iterations', 'salt', 'digest'} and
            credential['algorithm'] == 'pbkdf2-sha256' and
            type(credential['iterations']) is int and credential['iterations'] == ITERATIONS and
            isinstance(credential['salt'], str) and SALT.fullmatch(credential['salt']) and
            isinstance(credential['digest'], str) and DIGEST.fullmatch(credential['digest']))


class MaintenanceGuard:
    """Bound CPU, retained sources, and aggregate attempts, including successes.

    Global throttling means a LAN flood can temporarily deny maintenance, but
    cannot occupy all device-policy workers doing expensive password hashing.
    Standard OS-administrator recovery remains available outside this endpoint.
    """
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.attempts = deque()
        self.workers = threading.BoundedSemaphore(2)

    def verify(self, password, credential, source):
        try:
            encoded = password_bytes(password)
        except ValueError:
            return False
        if not valid_credential(credential) or not isinstance(source, str) or len(source) > 128:
            return False
        with self.lock:
            now = self.clock()
            while self.attempts and now - self.attempts[0][0] >= WINDOW:
                self.attempts.popleft()
            if (len(self.attempts) >= GLOBAL_LIMIT or
                    sum(address == source for _, address in self.attempts) >= PER_SOURCE):
                return False
            if not self.workers.acquire(blocking=False):
                return False
            self.attempts.append((now, source))
        try:
            actual = hashlib.pbkdf2_hmac('sha256', encoded, bytes.fromhex(credential['salt']), ITERATIONS).hex()
            return hmac.compare_digest(actual, credential['digest'])
        finally:
            self.workers.release()
