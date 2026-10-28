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
setup=root/'ohno-setup.exe'
target=root/'test-target.exe'
ctx=ssl._create_unverified_context()
password='ci-test-password-only'


def call(method,path,body=None,headers=None):
    conn=http.client.HTTPSConnection('localhost',8443,context=ctx,timeout=5)
    conn.request(method,path,body,headers or {});r=conn.getresponse();result=(r.status,dict(r.getheaders()),r.read().decode());conn.close();return result


def waitfor(fn,seconds=90):
    deadline=time.monotonic()+seconds;last=None
    while time.monotonic()<deadline:
        try:
            value=fn()
            if value:return value
        except (OSError,ValueError,KeyError) as e:last=e
        time.sleep(1)
    raise RuntimeError('timed out: '+str(last))


def form(path,values,cookie):
    status,_,text=call('POST',path,urlencode(values),{'Cookie':cookie})
    if status!=303:raise RuntimeError('request rejected: '+str(status)+' '+text)


def main():
    server=None;child=None;listener=None;stream=None;installed=False;root_installed=False
    with tempfile.TemporaryDirectory() as temp:
        state=Path(temp)/'state.json'
        cert=Path(temp)/'test-cert.pem';key=Path(temp)/'test-key.pem'
        openssl=shutil.which('openssl') or r'C:\Program Files\Git\usr\bin\openssl.exe'
        subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        thumb=hashlib.sha1(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest().upper()
        Store.initialize(state,password)
        try:
            server=subprocess.Popen([sys.executable,str(root/'teacher/server.py'),'--state',str(state),'--cert',str(cert),'--key',str(key),'--bind','127.0.0.1','--port','8443'])
            waitfor(lambda:call('GET','/health')[0]==200,15)
            subprocess.run([str(setup),'--install','https://localhost:8443','--certificate',str(cert)],check=True);installed=True;root_installed=True
            def read():return json.loads(state.read_text('utf-8'))
            device=waitfor(lambda:next(iter(read()['devices']),None),90)
            waitfor(lambda:read()['devices'][device].get('tun') is True,90)
            first_mac=waitfor(lambda:read()['devices'][device].get('primary_mac'),45)
            if first_mac not in read()['devices'][device]['macs']: raise RuntimeError('inconsistent MAC inventory')
            adapter=subprocess.run(['powershell','-NoProfile','-Command',"if (Get-NetAdapter -Name 'ohno-tun' -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"])
            if adapter.returncode:raise RuntimeError('TUN adapter not found')
            status,headers,_=call('POST','/login',urlencode({'password':password}));assert status==303
            cookie=headers['Set-Cookie'].split(';')[0]
            status,_,page=call('GET','/',headers={'Cookie':cookie});assert status==200
            csrf=re.search(r'name="csrf" value="([^"]+)',page).group(1)
            form('/device',{'csrf':csrf,'id':device,'approved':'1'},cookie)
            if read()['devices'][device]['bound_mac']!=first_mac: raise RuntimeError('device MAC was not bound')
            file_hash=hashlib.sha256(target.read_bytes()).hexdigest()
            form('/policy',{'csrf':csrf,'domains':'game.example','hashes':file_hash,'names':''},cookie)
            child=subprocess.Popen([str(target)])
            waitfor(lambda:child.poll() is not None,120)
            request=waitfor(lambda:next((x for x in read()['requests'] if x['object']==file_hash),None),90)
            form('/request',{'csrf':csrf,'id':request['id'],'action':'approve'},cookie)
            time.sleep(25) # allow the service to fetch the temporary grant
            child=subprocess.Popen([str(target)])
            time.sleep(20)
            if child.poll() is not None:raise RuntimeError('approved target was stopped')
            child.terminate();child.wait(timeout=5);child=None
            subprocess.run([str(root/'pipe-client.exe'),'W:game.example'],check=True)
            website=waitfor(lambda:next((x for x in read()['requests'] if x['kind']=='website' and x['object']=='game.example'),None),90)
            form('/request',{'csrf':csrf,'id':website['id'],'action':'approve'},cookie)
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
            form('/request',{'csrf':csrf,'id':net_request['id'],'action':'approve'},cookie)
            def allowed_connect():
                result=subprocess.run([str(network_target),port],timeout=8)
                return result.returncode==0
            waitfor(allowed_connect,90)
            subprocess.run([str(root/'pipe-client.exe'),'U:'+password],check=True)
            waitfor(lambda:any(x['kind']=='pause' and x['device_id']==device for x in read()['requests']),30)
            # The next policy refresh removes the managed domain block while paused.
            def website_unblocked():
                path=r'SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,path,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as registry:
                    return all(winreg.EnumValue(registry,i)[1]!='game.example' for i in range(winreg.QueryInfoKey(registry)[1]))
            waitfor(website_unblocked,90)
            print('Windows service-to-teacher application, website, network and password-unlock tests passed')
        finally:
            cleanup_failed=False
            if child and child.poll() is None:child.terminate();child.wait(timeout=5)
            if listener:listener.close()
            if stream:
                try:Path(stream).unlink()
                except FileNotFoundError:pass
            if installed:
                result=subprocess.run([str(setup),'--remove'])
                if result.returncode:cleanup_failed=True
                if subprocess.run(['certutil','-store','Root',thumb],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:cleanup_failed=True
            if server:
                server.terminate();server.wait(timeout=10)
            if root_installed:subprocess.run(['certutil','-delstore','Root',thumb],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if cleanup_failed:raise RuntimeError('service or imported root cleanup failed')

if __name__=='__main__':main()
