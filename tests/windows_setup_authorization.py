"""Ephemeral Windows CI only: rejected/canceled setup must make zero OS changes.

No certificate is installed by this harness; all keys are temporary fixtures.
The successful install/remove lifecycle is covered by windows_end_to_end.py.
"""
import ctypes
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import winreg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'teacher'))
from server import create_certificate

PASSWORD='CI fixture classroom maintenance passphrase'
SETUP=Path.cwd()/'ohno-setup.exe'


def clean():
    if subprocess.run(['sc.exe','query','OhnoPrototype'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=1060:
        raise AssertionError('unexpected existing/mutated service; abort without cleanup')
    for path in [r'SOFTWARE\Ohno',r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OhnoPrototype']:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,path):
                raise AssertionError('unexpected existing/mutated registry state; abort without cleanup')
        except FileNotFoundError:pass
    if (Path(os.environ['ProgramFiles'])/'OhnoPrototype').exists():
        raise AssertionError('unexpected existing/mutated program directory; abort without cleanup')


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        body=b''
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<=length<=2048:return
            body=self.rfile.read(length)
            if not body:return
            request=json.loads(body)
            now=int(time.time())
            result={'authorized':True,'action':request['action'],'nonce':request['nonce'],
                    'device_id':'','authorized_at':now,'expires_at':now+120}
            if self.server.mode=='nonce':
                result['nonce']=('1' if result['nonce'][0]=='0' else '0')+result['nonce'][1:]
            status=403 if self.server.mode=='revoked' else 200
            output=json.dumps(result).encode()
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(output)));self.end_headers();self.wfile.write(output)
        except (OSError,ValueError,KeyError):pass
        finally:self.server.bodies.append(body)


def attempt(origin,cert):
    clean()
    result=subprocess.run([str(SETUP),'--install',origin,'--certificate',str(cert),'--password-stdin'],
                          input=PASSWORD+'\n',text=True,timeout=35)
    if result.returncode==0:raise AssertionError('negative setup unexpectedly succeeded')
    clean()


def main():
    clean()
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        create_certificate(root/'good.pem',root/'good.key','localhost')
        create_certificate(root/'other.pem',root/'other.key','localhost')
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/'good.pem',root/'good.key')
        with ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
            server.socket=context.wrap_socket(server.socket,server_side=True)
            server.mode='nonce';server.bodies=[]
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            origin='https://localhost:'+str(server.server_port)
            try:
                attempt(origin,root/'other.pem')
                time.sleep(.1)
                if any(server.bodies):raise AssertionError('wrong pinned cert received secret body')
                attempt(origin,root/'good.pem')
                server.mode='revoked'
                attempt(origin,root/'good.pem')
                deadline=time.monotonic()+5
                while sum(bool(body) for body in server.bodies)<2 and time.monotonic()<deadline:time.sleep(.05)
                if sum(bool(body) for body in server.bodies)!=2:raise AssertionError('negative authenticated requests did not complete')
                # Close the real native password prompt: cancel is not an error
                # popup or a partial install, and sends no request at all.
                before=len(server.bodies)
                process=subprocess.Popen([str(SETUP),'--install',origin,'--certificate',str(root/'good.pem')])
                user32=ctypes.WinDLL('user32',use_last_error=True)
                user32.FindWindowW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p]
                user32.FindWindowW.restype=ctypes.c_void_p
                user32.PostMessageW.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_size_t,ctypes.c_ssize_t]
                deadline=time.monotonic()+10;window=None
                try:
                    while time.monotonic()<deadline and process.poll() is None:
                        window=user32.FindWindowW('OhnoMaintenancePasswordV1',None)
                        if window:break
                        time.sleep(.1)
                    if not window:raise AssertionError('native maintenance password prompt did not appear')
                    user32.PostMessageW(window,0x0010,0,0)  # WM_CLOSE
                    if process.wait(timeout=10)!=2:raise AssertionError('cancel did not return cancellation status')
                finally:
                    if process.poll() is None:process.kill();process.wait(timeout=5)
                clean()
                if len(server.bodies)!=before:raise AssertionError('cancel contacted teacher server')
                # Reopen, enter through the real password edit, and double-submit.
                # The authenticated server deliberately gives a mismatched nonce.
                server.mode='nonce'
                process=subprocess.Popen([str(SETUP),'--install',origin,'--certificate',str(root/'good.pem')])
                try:
                    deadline=time.monotonic()+10;window=None
                    while time.monotonic()<deadline and process.poll() is None:
                        window=user32.FindWindowW('OhnoMaintenancePasswordV1',None)
                        if window:break
                        time.sleep(.1)
                    if not window:raise AssertionError('repeated password prompt did not appear')
                    user32.GetDlgItem.argtypes=[ctypes.c_void_p,ctypes.c_int];user32.GetDlgItem.restype=ctypes.c_void_p
                    user32.SetWindowTextW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p]
                    edit=user32.GetDlgItem(window,201)
                    if not edit or not user32.SetWindowTextW(edit,PASSWORD):raise AssertionError('password edit unavailable')
                    user32.PostMessageW(window,0x0111,1,0);user32.PostMessageW(window,0x0111,1,0)  # WM_COMMAND/IDOK
                    if process.wait(timeout=35)!=1:raise AssertionError('mismatched nonce was not rejected after UI submission')
                finally:
                    if process.poll() is None:process.kill();process.wait(timeout=5)
                clean()

            finally:
                server.shutdown();thread.join(timeout=5)
        with socket.socket() as unused:
            unused.bind(('127.0.0.1',0));offline=unused.getsockname()[1]
        attempt('https://localhost:'+str(offline),root/'good.pem')
        for path in [root/'good.pem',root/'other.pem']:
            thumb=hashlib.sha1(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest().upper()
            if subprocess.run(['certutil','-store','Root',thumb],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
                raise AssertionError('rejected setup installed a machine trust root')
    print('Native setup refusal/cancel/offline/certificate/nonce/revocation tests passed; no OS mutations')


if __name__=='__main__':main()
