"""Ephemeral GitHub Windows runner only. Installs a test root and service, then removes both."""
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import winreg
from pathlib import Path
from urllib.parse import urlencode

root=Path.cwd()
sys.path.insert(0,str(root/'teacher'))
from server import Store
from school_installer import build_school_installer
setup=root/'ohno-setup.exe'
target=root/'test-target.exe'
ctx=None
pin='2468'
maintenance_password='CI fixture classroom maintenance passphrase'


def call(method,path,body=None,headers=None):
    conn=http.client.HTTPSConnection('localhost',8443,context=ctx,timeout=5)
    conn.request(method,path,body,headers or {});r=conn.getresponse();result=(r.status,dict(r.getheaders()),r.read().decode());conn.close();return result


def control_call(method,path,body=None,headers=None):
    conn=http.client.HTTPConnection('127.0.0.1',8765,timeout=5)
    hdrs=dict(headers or {});hdrs.setdefault('Host','127.0.0.1')
    conn.request(method,path,body,hdrs);r=conn.getresponse();result=(r.status,dict(r.getheaders()),r.read().decode());conn.close();return result


def waitfor(fn,seconds=90):
    deadline=time.monotonic()+seconds;last=None
    while time.monotonic()<deadline:
        try:
            value=fn()
            if value:return value
        except (OSError,ValueError,KeyError) as e:last=e
        time.sleep(1)
    raise RuntimeError('timed out: '+str(last))


def form(path,values):
    status,_,text=control_call('POST',path,urlencode(values))
    if status!=303:raise RuntimeError('request rejected: '+str(status)+' '+text)


def assert_removed(thumb):
    for path in [r'SOFTWARE\Ohno',r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OhnoPrototype']:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,path):
                raise RuntimeError('installer registry state remains after removal')
        except FileNotFoundError:pass
    if subprocess.run(['sc.exe','query','OhnoPrototype'],stdout=subprocess.DEVNULL).returncode!=1060:
        raise RuntimeError('service remains after removal')
    if (Path(os.environ['ProgramFiles'])/'OhnoPrototype').exists():
        raise RuntimeError('installer program directory remains after removal')
    if subprocess.run(['certutil','-store','Root',thumb],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
        raise RuntimeError('fixture root remains after removal')


def main():
    global ctx
    server=None;child=None;listener=None;stream=None;installed=False;root_installed=False
    with tempfile.TemporaryDirectory() as temp:
        state=Path(temp)/'state.json'
        cert=Path(temp)/'test-cert.pem';key=Path(temp)/'test-key.pem'
        openssl=shutil.which('openssl') or r'C:\Program Files\Git\usr\bin\openssl.exe'
        subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        thumb=hashlib.sha1(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest().upper()
        ctx=ssl.create_default_context(cafile=str(cert))
        prepared=Store.initialize(state)
        prepared.set_maintenance_password(maintenance_password)
        prepared.initialize_releases()
        release_public_key=prepared.release_catalog.public_key
        prepared.close()
        try:
            server=subprocess.Popen([sys.executable,str(root/'teacher/server.py'),'--state',str(state),'--cert',str(cert),'--key',str(key),'--bind','127.0.0.1','--port','8443'])
            waitfor(lambda:call('GET','/health')[0]==200,15)
            # Exercise the same embedded school configuration used by a double-click,
            # without a message box on the headless CI runner.
            school_setup=Path(temp)/'Ohno-School-Setup.exe'
            school_setup.write_bytes(build_school_installer(setup.read_bytes(),'https://localhost:8443',cert.read_bytes(),release_public_key))
            rejected=subprocess.run([str(school_setup),'--install-bundled','--password-stdin'],
                                    input='wrong classroom maintenance passphrase\n',text=True,timeout=30)
            if rejected.returncode==0:raise RuntimeError('incorrect password installed service')
            if subprocess.run(['sc.exe','query','OhnoPrototype'],stdout=subprocess.DEVNULL).returncode!=1060:raise RuntimeError('denied install changed service state')
            subprocess.run([str(school_setup),'--install-bundled','--password-stdin'],
                           input=maintenance_password+'\n',text=True,check=True,timeout=30);installed=True;root_installed=True
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Ohno') as config:
                if winreg.QueryValueEx(config,'ReleasePublicKey')[0]!=release_public_key:raise RuntimeError('school release public key was not pinned at install')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OhnoPrototype') as uninstall:
                command=winreg.QueryValueEx(uninstall,'UninstallString')[0]
                if 'ohno-maintenance.exe' not in command or not command.endswith(' --remove'):raise RuntimeError('normal Windows uninstall entry missing')
            def read():return json.loads(state.read_text('utf-8'))
            device=waitfor(lambda:next(iter(read()['devices']),None),90)
            waitfor(lambda:read()['devices'][device].get('tun') is True,90)
            first_mac=waitfor(lambda:read()['devices'][device].get('primary_mac'),45)
            if first_mac not in read()['devices'][device]['macs']: raise RuntimeError('inconsistent MAC inventory')
            adapter=subprocess.run(['powershell','-NoProfile','-Command',"if (Get-NetAdapter -Name 'ohno-tun' -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"])
            if adapter.returncode:raise RuntimeError('TUN adapter not found')
            status,_,page=control_call('GET','/');assert status==200
            if 'action="/login"' in page or 'name="password"' in page: raise RuntimeError('teacher control unexpectedly exposes a login form')
            csrf=re.search(r'name="csrf" value="([^"]+)',page).group(1)
            form('/unlock-pin',{'csrf':csrf,'action':'set','pin':pin})
            form('/device',{'csrf':csrf,'id':device,'approved':'1'})
            if read()['devices'][device]['bound_mac']!=first_mac: raise RuntimeError('device MAC was not bound')
            file_hash=hashlib.sha256(target.read_bytes()).hexdigest()
            form('/policy',{'csrf':csrf,'domains':'game.example','hashes':file_hash,'names':''})
            child=subprocess.Popen([str(target)])
            waitfor(lambda:child.poll() is not None,120)
            request=waitfor(lambda:next((x for x in read()['requests'] if x['object']==file_hash),None),90)
            form('/request',{'csrf':csrf,'id':request['id'],'action':'approve'})
            time.sleep(25) # allow the service to fetch the temporary grant
            child=subprocess.Popen([str(target)])
            time.sleep(20)
            if child.poll() is not None:raise RuntimeError('approved target was stopped')
            child.terminate();child.wait(timeout=5);child=None
            subprocess.run([str(root/'pipe-client.exe'),'W:game.example'],check=True)
            website=waitfor(lambda:next((x for x in read()['requests'] if x['kind']=='website' and x['object']=='game.example'),None),90)
            form('/request',{'csrf':csrf,'id':website['id'],'action':'approve'})
            def allowed_site():
                path=r'SOFTWARE\Policies\Microsoft\Edge\URLAllowlist'
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,path,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as registry:
                    count=winreg.QueryInfoKey(registry)[1]
                    return any(winreg.EnumValue(registry,i)[1]=='.game.example' for i in range(count))
            waitfor(allowed_site,90)
            # Mark a dedicated test executable as downloaded before launching it.
            network_target=root/'network-target.exe';net_hash=hashlib.sha256(network_target.read_bytes()).hexdigest()
            stream=str(network_target)+':Zone.Identifier'
            Path(stream).write_text('[ZoneTransfer]\r\nZoneId=3\r\n',encoding='ascii')
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(8);port=str(listener.getsockname()[1])
            child=subprocess.Popen([str(network_target),port,'60000'])
            net_request=waitfor(lambda:next((x for x in read()['requests'] if x['kind']=='network' and x['object']==net_hash),None),80)
            if child.wait(timeout=75)==0:raise RuntimeError('untrusted executable connected despite WFP rule')
            child=None
            form('/request',{'csrf':csrf,'id':net_request['id'],'action':'approve'})
            def allowed_connect():
                result=subprocess.run([str(network_target),port],timeout=8)
                return result.returncode==0
            waitfor(allowed_connect,90)
            subprocess.run([str(root/'pipe-client.exe'),'U:'+pin],check=True)
            waitfor(lambda:any(x['kind']=='pause' and x['device_id']==device for x in read()['requests']),30)
            # The next policy refresh removes the managed domain block while paused.
            def website_unblocked():
                path=r'SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,path,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as registry:
                    return all(winreg.EnumValue(registry,i)[1]!='game.example' for i in range(winreg.QueryInfoKey(registry)[1]))
            waitfor(website_unblocked,90)
            # Revoked maintenance authority must not stop or remove the service.
            form('/maintenance-password',{'csrf':csrf,'action':'clear'})
            denied=subprocess.run([str(setup),'--remove','--password-stdin'],
                                  input=maintenance_password+'\n',text=True,timeout=30)
            if denied.returncode==0:raise RuntimeError('disabled maintenance password removed service')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Services\OhnoPrototype'):
                pass
            form('/maintenance-password',{'csrf':csrf,'action':'set','maintenance_password':maintenance_password})
            # Device revocation is not a trap preventing authorized removal.
            form('/device',{'csrf':csrf,'id':device,'approved':'0'})
            # Exercise normal removal on a revoked device, then a fresh install
            # and explicit offline OS-administrator recovery. All fixture state
            # belongs to this ephemeral runner; no production instance is used.
            subprocess.run([str(setup),'--remove','--password-stdin'],
                           input=maintenance_password+'\n',text=True,check=True,timeout=35)
            installed=False
            assert_removed(thumb)
            previous_devices=set(read()['devices'])
            subprocess.run([str(school_setup),'--install-bundled','--password-stdin'],
                           input=maintenance_password+'\n',text=True,check=True,timeout=35)
            installed=True
            waitfor(lambda:set(read()['devices'])-previous_devices,90)
            server.terminate();server.wait(timeout=10);server=None
            offline=subprocess.run([str(setup),'--remove','--password-stdin'],
                                   input=maintenance_password+'\n',text=True,timeout=35)
            if offline.returncode==0:raise RuntimeError('offline normal removal unexpectedly authorized')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Services\OhnoPrototype'):
                pass
            subprocess.run([str(setup),'--admin-recovery-remove'],check=True,timeout=35)
            installed=False
            assert_removed(thumb)
            print('Windows authorized setup/removal, offline admin recovery, service, rules, PIN and revocation tests passed')
        finally:
            cleanup_failed=False
            if child and child.poll() is None:child.terminate();child.wait(timeout=5)
            if listener:listener.close()
            if stream:
                try:Path(stream).unlink()
                except FileNotFoundError:pass
            if installed:
                result=subprocess.run([str(setup),'--remove','--password-stdin'],
                                      input=maintenance_password+'\n',text=True,timeout=35)
                if result.returncode:
                    cleanup_failed=True
                    # Explicit OS-admin recovery cleans the ephemeral runner only;
                    # never hide the failed normal removal assertion.
                    subprocess.run([str(setup),'--admin-recovery-remove'],timeout=35)
                for path in [r'SOFTWARE\Ohno',r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OhnoPrototype']:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,path):cleanup_failed=True
                    except FileNotFoundError:pass
                if subprocess.run(['certutil','-store','Root',thumb],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:cleanup_failed=True
            if server:
                server.terminate();server.wait(timeout=10)
            if root_installed:subprocess.run(['certutil','-delstore','Root',thumb],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if cleanup_failed:raise RuntimeError('service or imported root cleanup failed')

if __name__=='__main__':main()
