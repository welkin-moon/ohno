"""Ephemeral GitHub Windows runner only. Installs a test root and service, then removes both."""
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
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
    server=None;child=None;installed=False;root_installed=False
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
            status,headers,_=call('POST','/login',urlencode({'password':password}));assert status==303
            cookie=headers['Set-Cookie'].split(';')[0]
            status,_,page=call('GET','/',headers={'Cookie':cookie});assert status==200
            csrf=re.search(r'name="csrf" value="([^"]+)',page).group(1)
            form('/device',{'csrf':csrf,'id':device,'approved':'1'},cookie)
            file_hash=hashlib.sha256(target.read_bytes()).hexdigest()
            form('/policy',{'csrf':csrf,'domains':'','hashes':file_hash,'names':''},cookie)
            child=subprocess.Popen([str(target)])
            waitfor(lambda:child.poll() is not None,120)
            request=waitfor(lambda:next((x for x in read()['requests'] if x['object']==file_hash),None),90)
            form('/request',{'csrf':csrf,'id':request['id'],'action':'approve'},cookie)
            time.sleep(25) # allow the service to fetch the temporary grant
            child=subprocess.Popen([str(target)])
            time.sleep(20)
            if child.poll() is not None:raise RuntimeError('approved target was stopped')
            child.terminate();child.wait(timeout=5);child=None
            print('Windows service-to-teacher approval test passed')
        finally:
            cleanup_failed=False
            if child and child.poll() is None:child.terminate();child.wait(timeout=5)
            if installed:
                result=subprocess.run([str(setup),'--remove'])
                if result.returncode:cleanup_failed=True
                if subprocess.run(['certutil','-store','Root',thumb],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:cleanup_failed=True
            if server:
                server.terminate();server.wait(timeout=10)
            if root_installed:subprocess.run(['certutil','-delstore','Root',thumb],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if cleanup_failed:raise RuntimeError('service or imported root cleanup failed')

if __name__=='__main__':main()
