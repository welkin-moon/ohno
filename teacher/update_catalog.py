"""Explicit teacher-approved immutable releases; no automatic upstream fetching.

Private release key is separate from TLS and never leaves the teacher state
folder. Importing this module creates nothing. initialize() is an explicit local
setup action; tests call it only in disposable directories.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from update_manifest import MAX_PACKAGE_SIZE, MAX_SEQUENCE, public_key_hex, sign_manifest, verify_manifest
from update_package import parse_package
from private_directory import create_private_directory


class CatalogError(RuntimeError):pass


def _regular(path: Path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise CatalogError('release file is not a private regular file')


def _replace(source: Path,target: Path):
    if os.name=='nt':
        import ctypes
        move=ctypes.WinDLL('kernel32',use_last_error=True).MoveFileExW
        move.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_ulong];move.restype=ctypes.c_int
        if not move(str(source),str(target),1|8):raise OSError(ctypes.get_last_error(),'durable release rename failed')
    else:
        os.replace(source,target)
        fd=os.open(str(target.parent),os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)


def _atomic(path: Path,data: bytes):
    temporary=None
    try:
        fd,name=tempfile.mkstemp(prefix='.ohno-release-',dir=path.parent);temporary=Path(name)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        _replace(temporary,path)
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise CatalogError('duplicate catalog field')
        result[key]=value
    return result


class ReleaseCatalog:
    def __init__(self,directory: Path):
        self.root=Path(directory).absolute();self.lock=threading.RLock();self._poisoned=False
        if self.root.is_symlink() or not self.root.is_dir():raise CatalogError('missing trusted release directory')
        self.state_path=self.root/'catalog.json';self.key_path=self.root/'release-key.pem'
        self._lock_file=None
        try:
            lock_path=self.root/'catalog.lock'
            flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)
            fd=os.open(str(lock_path),flags,0o600);self._lock_file=os.fdopen(fd,'r+b',buffering=0)
            _regular(lock_path)
            if os.name=='nt':
                import msvcrt
                if os.fstat(fd).st_size==0:self._lock_file.write(b'0');self._lock_file.seek(0)
                msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            _regular(self.key_path);_regular(self.state_path)
            if self.key_path.stat().st_size>4096 or self.state_path.stat().st_size>8192:
                raise CatalogError('release trust file too large')
            raw=self.key_path.read_bytes()
            self.key=serialization.load_pem_private_key(raw,password=None)
            self.public_key=public_key_hex(self.key.public_key())
            self.data=self._parse(self.state_path.read_bytes())
        except Exception:
            self.close();raise

    def close(self):
        if self._lock_file is not None:self._lock_file.close();self._lock_file=None

    def __enter__(self):return self
    def __exit__(self,*args):self.close()

    @classmethod
    def initialize(cls,directory: Path):
        """One explicit teacher action; never repair/overwrite a missing key."""
        root=Path(directory).absolute()
        create_private_directory(root) # fails if ANY prior directory exists
        try:
            key=ec.generate_private_key(ec.SECP256R1())
            payload=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            with os.fdopen(os.open(root/'release-key.pem',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as stream:
                stream.write(payload);stream.flush();os.fsync(stream.fileno())
            _atomic(root/'catalog.json',b'{"schema":1,"high_water":0,"current":null}')
        except Exception:
            # Preserve partial evidence. Do not auto-generate a different school
            # key after an uncertain write; administrator recovery is explicit.
            raise
        return cls(root)

    def _parse(self,document: bytes):
        if len(document)>8192:raise CatalogError('catalog too large')
        try:data=json.loads(document.decode('utf-8'),object_pairs_hook=_unique)
        except (ValueError,UnicodeError,RecursionError) as error:raise CatalogError('invalid catalog') from error
        if (not isinstance(data,dict) or set(data)!={'schema','high_water','current'} or
                type(data['schema']) is not int or data['schema']!=1 or
                type(data['high_water']) is not int or not 0<=data['high_water']<=MAX_SEQUENCE):
            raise CatalogError('invalid catalog fields')
        if data['current'] is not None:
            current=data['current']
            try:
                manifest=verify_manifest(json.dumps(current),self.public_key,installed_sequence=0,
                    updater_version=65535,now=current['issued_at'])
            except (ValueError,KeyError,TypeError) as error:raise CatalogError('catalog signature not trusted') from error
            if manifest['sequence']!=data['high_water']:raise CatalogError('catalog replay floor mismatch')
        return data

    def _ready(self):
        if self._poisoned or self._lock_file is None:raise CatalogError('catalog unavailable; reopen and verify storage')

    def _save(self,next_state):
        self._ready();encoded=json.dumps(next_state,separators=(',',':')).encode('ascii');self._parse(encoded)
        try:_atomic(self.state_path,encoded)
        except OSError as error:
            # Rename/fsync failures can be ambiguous. Poison this instance so
            # memory cannot expose an uncommitted decision or reset a sequence.
            self._poisoned=True;raise CatalogError('catalog write failed; restart and inspect') from error
        self.data=next_state

    def approve(self,package: bytes,*,now=None,lifetime=86400,min_updater=1):
        parsed=parse_package(package)
        digest=hashlib.sha256(package).hexdigest()
        now=int(time.time()) if now is None else now
        with self.lock:
            self._ready()
            sequence=self.data['high_water']+1
            fields={'schema':1,'platform':'windows-x64','sequence':sequence,'version':parsed.version,
                    'min_updater':min_updater,'issued_at':now,'expires_at':now+lifetime,
                    'size':len(package),'sha256':digest}
            manifest=sign_manifest(fields,self.key)
            path=self.root/(digest+'.ohno')
            if path.exists():
                _regular(path)
                if path.stat().st_size!=len(package) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                    raise CatalogError('immutable package was changed')
            else:
                try:_atomic(path,package)
                except OSError as error:raise CatalogError('package persistence failed') from error
            # Package is durable BEFORE the signed approval becomes visible.
            self._save({'schema':1,'high_water':sequence,'current':manifest})
            return copy.deepcopy(manifest)

    def pause(self):
        with self.lock:
            self._ready();self._save(dict(self.data,current=None))

    def offer(self,*,now=None):
        now=int(time.time()) if now is None else now
        with self.lock:
            self._ready();current=self.data['current']
            if current is None:return None
            try:
                result=verify_manifest(json.dumps(current),self.public_key,installed_sequence=0,updater_version=65535,now=now)
            except ValueError:return None
            return copy.deepcopy(result)

    def package(self,digest: str,*,now=None):
        """Current approved bytes only; caller separately authenticates device."""
        with self.lock:
            current=self.offer(now=now)
            if current is None or digest!=current['sha256']:return None
            path=self.root/(current['sha256']+'.ohno');_regular(path)
            if path.stat().st_size!=current['size']:raise CatalogError('approved package size changed')
            data=path.read_bytes()
            if len(data)>MAX_PACKAGE_SIZE or hashlib.sha256(data).hexdigest()!=current['sha256']:
                raise CatalogError('approved package integrity changed')
            return data
