"""Native update pull/stage tests: temporary dirs/keys, no candidate execution."""
import argparse
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'teacher'))
from cryptography.hazmat.primitives.asymmetric import ec
from server import create_certificate
from test_update_package import fixture_package
from update_package import FILES
from update_manifest import public_key_hex, sign_manifest

DEVICE='a'*32;KEY='b'*64


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        try:
            length=int(self.headers.get('Content-Length','-1'))
            if not 0<=length<=2048:return
            data=self.rfile.read(length)
            if not data:return
            value=json.loads(data);self.server.requests.append((self.path,value))
            if self.headers.get('X-Ohno-Key') or self.headers.get('X-Ohno-Device'):raise AssertionError('secret header')
            if value['device_id']!=DEVICE or value['device_key']!=KEY:return self.send(403,b'{}')
            if self.path.endswith('/offer'):
                if self.server.mode=='no_offer':return self.send(404,b'{}')
                offer=copy.deepcopy(self.server.offer)
                if self.server.mode=='bad_signature':offer['signature']='0'*128
                if self.server.mode=='wrong_platform':offer['platform']='windows-arm64'
                return self.send(200,json.dumps(offer).encode())
            if '/package/' in self.path:
                if self.server.mode=='redirect':return self.send(307,b'{}',extra=[('Location',self.server.origin+'/trap')])
                data=self.server.package
                if self.server.mode=='tampered':data=data[:-1]+bytes([data[-1]^1])
                if self.server.mode=='oversized':data+=b'x'
                if self.server.mode=='short':data=data[:-1]
                if self.server.mode=='slow':time.sleep(.3)
                return self.send(200,data,content='application/octet-stream')
            if self.path.endswith('/authorize'):
                if self.server.mode=='revoked':return self.send(403,b'{}')
                now=int(time.time());result={'authorized':True,'nonce':value['nonce'],'device_id':DEVICE,
                    'sequence':self.server.offer['sequence'],'sha256':self.server.offer['sha256'],'authorized_at':now,'expires_at':now+120}
                if self.server.mode=='wrong_nonce':result['nonce']='0'*64
                if self.server.mode=='wrong_hash':result['sha256']='0'*64
                if self.server.mode=='wrong_device':result['device_id']='c'*32
                if self.server.mode=='wrong_sequence':result['sequence']+=1
                if self.server.mode=='expired':result['authorized_at']=now-151;result['expires_at']=now-31
                return self.send(200,json.dumps(result).encode())
            raise AssertionError('unexpected path')
        except (OSError,ValueError,KeyError):pass
    def send(self,status,data,content='application/json',extra=()):
        self.send_response(status);self.send_header('Content-Type',content);self.send_header('Content-Length',str(len(data)))
        for name,value in extra:self.send_header(name,value)
        self.end_headers();self.wfile.write(data)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--client',required=True);args=parser.parse_args();client=str(Path(args.client).resolve())
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp).resolve();create_certificate(root/'cert.pem',root/'key.pem','localhost')
        create_certificate(root/'other.pem',root/'other.key','localhost')
        release=ec.generate_private_key(ec.SECP256R1());public=public_key_hex(release.public_key());now=int(time.time())
        payload=fixture_package();package_file=root/'source.ohno';package_file.write_bytes(payload)
        manifest=sign_manifest({'schema':1,'platform':'windows-x64','sequence':7,'version':'0.2.0','min_updater':1,
            'issued_at':now,'expires_at':now+3600,'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest()},release)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'cert.pem',root/'key.pem')
        with ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
            server.socket=context.wrap_socket(server.socket,server_side=True);server.origin='https://127.0.0.1:'+str(server.server_port)
            server.offer=manifest;server.package=payload;server.mode='normal';server.requests=[]
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            def invoke(directory,mode='fetch',expected=0,initialize=True,**overrides):
                directory.mkdir(exist_ok=True)
                config={'mode':mode,'root':str(directory),'initialize':initialize,'server':server.origin,
                    'certificate':(root/'cert.pem').read_text(),'public_key':public,'device_id':DEVICE,'device_key':KEY,
                    'document':json.dumps(manifest),'package':str(package_file)}
                config.update(overrides)
                result=subprocess.run([client],input=json.dumps(config),capture_output=True,text=True,timeout=30)
                if result.returncode!=expected:raise AssertionError(f'{directory.name}: {result.returncode} expected {expected}: {result.stderr}')
                return json.loads(result.stdout) if result.stdout else None
            try:
                for mode in ['normal','revoked','wrong_nonce','wrong_hash','wrong_device','wrong_sequence','expired']:
                    server.mode=mode;directory=root/mode;result=invoke(directory)
                    if not result['staged'] or result['authorized']!=(mode=='normal'):raise AssertionError('execution decision binding failed: '+mode)
                    state=json.loads((directory/'update-state.json').read_text())
                    if state['high_water']!=0 or state['phase']!='stable':raise AssertionError('staging changed active selector')
                    staged=directory/'versions'/('7-'+manifest['sha256'])
                    if any(not (staged/name).is_file() for name in FILES):raise AssertionError('fixed payload missing')
                    if list(directory.glob('download-*.tmp')):raise AssertionError('download buffer not cleaned')
                for mode in ['bad_signature','wrong_platform','tampered','oversized','short','redirect']:
                    server.mode=mode;directory=root/mode;before=len(server.requests);invoke(directory,expected=1)
                    if (directory/'versions').exists():raise AssertionError('invalid package reached extraction')
                    if mode in ['bad_signature','wrong_platform'] and len(server.requests)!=before+1:raise AssertionError('download preceded manifest authentication')
                    if any(path.endswith('/trap') for path,_ in server.requests):raise AssertionError('redirect followed')
                    if list(directory.glob('download-*.tmp')):raise AssertionError('failed download left temporary file')
                server.mode='normal';before=len(server.requests)
                invoke(root/'wrong-pin',expected=1,certificate=(root/'other.pem').read_text())
                if len(server.requests)!=before:raise AssertionError('wrong TLS pin received credentials')
                invoke(root/'wrong-release-key',expected=1,public_key=public_key_hex(ec.generate_private_key(ec.SECP256R1()).public_key()))
                invoke(root/'replay',expected=1,floor=7)
                before=len(server.requests);invoke(root/'canceled-before',expected=1,cancel_before=True)
                if len(server.requests)!=before:raise AssertionError('canceled operation contacted teacher')
                server.mode='slow';invoke(root/'canceled-download',expected=1,cancel_ms=50);server.mode='normal'
                server.mode='no_offer';selfless=invoke(root/'no-offer');server.mode='normal'
                if selfless!={'staged':False}:raise AssertionError('missing offer staged a candidate')
                # Revalidation catches mutations even when outer archive stays intact.
                staged=root/'normal'/'versions'/('7-'+manifest['sha256'])
                target=staged/FILES[0];saved=target.read_bytes();target.write_bytes(saved[:-1]+b'x')
                invoke(root/'normal',mode='verify',expected=1,initialize=False);target.write_bytes(saved)
                invoke(root/'normal',mode='verify',initialize=False)
                # Archive hardlinks cannot be used as verified staging input.
                linked=root/'source-link.ohno';os.link(package_file,linked)
                invoke(root/'hardlink',mode='stage',expected=1);linked.unlink()
                blocked=root/'blocked-directory';blocked.mkdir();(blocked/'versions').write_bytes(b'fixture obstacle')
                invoke(blocked,mode='stage',expected=1)
                if (blocked/'versions').read_bytes()!=b'fixture obstacle':raise AssertionError('failed staging overwrote preexisting file')
                # Kill at every extraction/archive/metadata/rename boundary.
                for point in range(1,11):
                    directory=root/f'crash-{point}'
                    invoke(directory,mode='stage',fault=point,expected=100+point)
                    state=json.loads((directory/'update-state.json').read_text())
                    if state['phase']!='stable' or state['high_water']!=0:raise AssertionError('partial payload selected')
                    invoke(directory,mode='stage',initialize=False)
                    if list((directory/'versions').glob('.stage-*')):raise AssertionError('owned interrupted staging directory not reclaimed')
                # Initial payload establishes an unsigned baseline only through
                # explicit installer-owned resource path, not a remote offer.
                initial=invoke(root/'initial',mode='initial',initialize=False)
                if initial['active']['sequence']!=0:raise AssertionError('baseline sequence wrong')
            finally:server.shutdown();thread.join(timeout=5)
    print('Native signed pull/stage, TLS-before-secret, revocation/nonce, tamper, replay, cancel, baseline and 10 staging-crash tests passed; no executable ran')


if __name__=='__main__':main()
