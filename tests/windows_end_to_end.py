"""Ephemeral runner: new service needs no root import; simulate/clean one legacy fixture root."""
import ctypes
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
from update_package import FILES, build_package
setup=root/'ohno-setup.exe'
target=root/'test-target.exe'
ctx=None
pin='2468'
maintenance_password='CI fixture classroom maintenance passphrase'


def call(method,path,body=None,headers=None):
    conn=http.client.HTTPSConnection('localhost',8443,context=ctx,timeout=5)
    conn.request(method,path,body,headers or {});r=conn.getresponse();result=(r.status,dict(r.getheaders()),r.read().decode());conn.close();return result


def control_call(method,path,body=None,headers=None,timeout=5):
    conn=http.client.HTTPConnection('127.0.0.1',8765,timeout=timeout)
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


def configured_recovery_flag():
    api=ctypes.WinDLL('advapi32',use_last_error=True)
    api.OpenSCManagerW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32];api.OpenSCManagerW.restype=ctypes.c_void_p
    api.OpenServiceW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_uint32];api.OpenServiceW.restype=ctypes.c_void_p
    api.QueryServiceConfig2W.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)]
    api.CloseServiceHandle.argtypes=[ctypes.c_void_p]
    manager=api.OpenSCManagerW(None,None,1);service=api.OpenServiceW(manager,'OhnoPrototype',1) if manager else None
    try:
        flag=ctypes.c_int32();needed=ctypes.c_uint32()
        if not service or not api.QueryServiceConfig2W(service,4,ctypes.byref(flag),ctypes.sizeof(flag),ctypes.byref(needed)):raise ctypes.WinError(ctypes.get_last_error())
        return bool(flag.value)
    finally:
        if service:api.CloseServiceHandle(service)
        if manager:api.CloseServiceHandle(manager)


def host_pid():
    result=subprocess.run(['sc.exe','queryex','OhnoPrototype'],capture_output=True,text=True,check=True)
    match=re.search(r'PID\s*:\s*(\d+)',result.stdout)
    return int(match.group(1)) if match else 0



def request_window(expected):
    """Open the fixed launcher and close only its verified versioned GUI."""
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    ui=ctypes.WinDLL('user32',use_last_error=True)
    ui.FindWindowW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p];ui.FindWindowW.restype=ctypes.c_void_p
    ui.GetWindowThreadProcessId.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)]
    ui.PostMessageW.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_size_t,ctypes.c_ssize_t]
    api.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32];api.OpenProcess.restype=ctypes.c_void_p
    api.QueryFullProcessImageNameW.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_uint32)]
    api.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint32]
    api.TerminateProcess.argtypes=[ctypes.c_void_p,ctypes.c_uint32];api.CloseHandle.argtypes=[ctypes.c_void_p]
    assert not ui.FindWindowW('OhnoRequestWindow',None),'unexpected pre-existing request window'
    launcher=subprocess.Popen([str(Path(os.environ['ProgramFiles'])/'OhnoPrototype'/'ohno-request.exe')])
    process=None;owned=False
    try:
        window=waitfor(lambda:ui.FindWindowW('OhnoRequestWindow',None),20)
        pid=ctypes.c_uint32();ui.GetWindowThreadProcessId(window,ctypes.byref(pid))
        process=api.OpenProcess(0x101001,False,pid.value)
        name=ctypes.create_unicode_buffer(32768);size=ctypes.c_uint32(len(name))
        if not process or not api.QueryFullProcessImageNameW(process,0,name,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        assert Path(name.value)==expected,'launcher did not select expected last-good request GUI'
        owned=True
        assert ui.PostMessageW(window,0x0010,0,0) # normal WM_CLOSE, not forced shutdown
        assert api.WaitForSingleObject(process,10000)==0,'request GUI did not close normally'
        assert launcher.wait(timeout=5)==0
    finally:
        # Cleanup only processes created by this fixture and whose executable
        # identity was checked. This is never used to make the normal test pass.
        if owned and api.WaitForSingleObject(process,0)==258:api.TerminateProcess(process,1)
        if process:api.CloseHandle(process)
        if launcher.poll() is None:launcher.kill();launcher.wait(timeout=5)


def install_fixture(installer):
    """One attempt, bounded separately from TLS authorization; never replay."""
    command=[str(installer),'--install-bundled','--password-stdin']
    started=time.monotonic()
    process=subprocess.Popen(command,stdin=subprocess.PIPE,text=True)
    try:
        try:
            process.communicate(maintenance_password+'\n',timeout=30)
        except subprocess.TimeoutExpired:
            # The 20-second TLS budget is not a whole-install budget: baseline
            # archive/extracted bytes plus fixed recovery entry exceed 200 MB.
            # Observe the same process, without retrying an uncertain install.
            installation=Path(os.environ['ProgramFiles'])/'OhnoPrototype'
            print('SLOW FIXTURE INSTALL FILES',[(str(path.relative_to(installation)),path.stat().st_size)
                  for path in installation.rglob('*') if path.is_file()],flush=True)
            print(subprocess.run(['sc.exe','query','OhnoPrototype'],capture_output=True,text=True).stdout,flush=True)
            process.communicate(timeout=max(1,120-(time.monotonic()-started)))
        if process.returncode:
            raise RuntimeError('fixture install failed: '+str(process.returncode))
        print('FIXTURE INSTALL SECONDS',round(time.monotonic()-started,2),flush=True)
    finally:
        if process.poll() is None:
            process.kill();process.wait(timeout=5)


def assert_no_root_import(thumb):
    # Read-only checks: the installer must rely on its own public PEM pin,
    # not turn the school certificate into trust for every application.
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Ohno') as config:
        try:winreg.QueryValueEx(config,'ImportedRootSha1')
        except FileNotFoundError:pass
        else:raise RuntimeError('new installer recorded a system root import')
    if subprocess.run(['certutil','-store','Root',thumb],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
        raise RuntimeError('new installer added machine-wide certificate trust')

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
    server=None;child=None;listener=None;stream=None;installed=False;certificate_cleanup_needed=False
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
            server=subprocess.Popen([sys.executable,str(root/'tests/windows_e2e_teacher.py'),'--state',str(state),'--cert',str(cert),'--key',str(key),'--bind','127.0.0.1','--port','8443'])
            waitfor(lambda:call('GET','/health')[0]==200,15)
            # Exercise the same embedded school configuration used by a double-click,
            # without a message box on the headless CI runner.
            school_setup=Path(temp)/'Ohno-School-Setup.exe'
            school_setup.write_bytes(build_school_installer(setup.read_bytes(),'https://localhost:8443',cert.read_bytes(),release_public_key))
            rejected=subprocess.run([str(school_setup),'--install-bundled','--password-stdin'],
                                    input='wrong classroom maintenance passphrase\n',text=True,timeout=30)
            if rejected.returncode==0:raise RuntimeError('incorrect password installed service')
            if subprocess.run(['sc.exe','query','OhnoPrototype'],stdout=subprocess.DEVNULL).returncode!=1060:raise RuntimeError('denied install changed service state')
            # Cleanup covers even a partial/timeout authorized attempt.
            installed=True;certificate_cleanup_needed=True
            install_fixture(school_setup)
            assert_no_root_import(thumb)
            assert configured_recovery_flag()
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Ohno') as config:
                if winreg.QueryValueEx(config,'ReleasePublicKey')[0]!=release_public_key:raise RuntimeError('school release public key was not pinned at install')
                if winreg.QueryValueEx(config,'PayloadLayout')[0]!=1:raise RuntimeError('managed layout missing')
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
            # Actual stable service host, production worker and teacher catalog:
            # immutable packages, normal commit, then unhealthy candidate rollback.
            installation=Path(os.environ['ProgramFiles'])/'OhnoPrototype'
            def journal():return json.loads((installation/'update-state.json').read_text())
            def update_diagnostics():
                # Public package/journal metadata only, never device registry
                # credentials, teacher state, passwords or command-line secrets.
                print('UPDATE JOURNAL',json.dumps(journal()),flush=True)
                print('UPDATE FILES',[(str(path.relative_to(installation)),path.stat().st_size) for path in installation.rglob('*') if path.is_file()],flush=True)
                try:
                    print(subprocess.run(['powershell','-NoProfile','-Command',
                        "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like '*\\OhnoPrototype\\*' } | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath | ConvertTo-Json -Compress"],capture_output=True,text=True,timeout=10).stdout,flush=True)
                except subprocess.TimeoutExpired:
                    print('UPDATE PROCESS DIAGNOSTIC TIMED OUT',flush=True)
            def wait_update(predicate,seconds):
                try:return waitfor(predicate,seconds)
                except Exception:
                    update_diagnostics();raise

            baseline=journal()['active'];assert baseline['sequence']==0
            def request_exe(revision):return installation/'versions'/(str(revision['sequence'])+'-'+revision['sha256'])/'ohno-request.exe'
            request_window(request_exe(baseline))
            def publish(version,worker_name='ohno-worker.exe'):
                files={name:(root/(worker_name if name=='ohno-worker.exe' else name)).read_bytes() for name in FILES}
                package=build_package(version,files)
                # Real packages include the TUN engine, unlike tiny parser fixtures.
                # A slow runner committed an 83 MB package just after the old
                # 60-second response cutoff. Bound this one attempt at 120s;
                # never repeat an uncertain approval or weaken native deadlines.
                approval_started=time.monotonic()
                print('FIXTURE APPROVAL BEGIN',version,len(package),flush=True)
                try:
                    status,_,body=control_call('POST','/updates/approve',package,{'Content-Type':'application/octet-stream','X-Ohno-CSRF':csrf},timeout=120)
                except Exception:
                    update_diagnostics();raise
                if status!=200:raise RuntimeError('fixture release approval failed: '+str(status)+' '+body)
                print('Fixture package approved',version,len(package),body,'seconds',round(time.monotonic()-approval_started,2),flush=True)
                return json.loads(body)
            publish('0.2.0')
            # Exercise the actual registry loader and native pinned offer path
            # independently of host scheduling, without selector/file mutation.
            probe=subprocess.run([str(root/'installed-update-probe.exe')],timeout=30)
            if probe.returncode:
                update_diagnostics();raise RuntimeError('installed native offer probe failed')
            good=wait_update(lambda:journal() if journal()['phase']=='stable' and journal()['active']['sequence']==1 else None,180)
            assert good['active']['version']=='0.2.0' and good['high_water']==1
            request_window(request_exe(good['active']))
            assert device in read()['devices'] and read()['devices'][device]['bound_mac']==first_mac
            publish('0.2.1-nohealth-open','worker-fixture.exe')
            rolled=wait_update(lambda:journal() if journal()['phase']=='stable' and journal()['high_water']==2 else None,180)
            assert rolled['active']==good['active'] and rolled['last_good']==good['active']
            # This adversarial test worker writes its own public event trace.
            # Confirm it actually ran and drained, then remove only this known
            # fixture file; production cleanup must retain unknown root files.
            fixture_log=installation/'worker-events.log'
            fixture_events=fixture_log.read_text().splitlines()
            assert any(' start 2 0.2.1-nohealth-open' in line for line in fixture_events)
            assert any(' stop 0.2.1-nohealth-open' in line for line in fixture_events)
            silence=[int(line.split()[-1]) for line in fixture_events if ' silent-ms ' in line]
            assert len(silence)==1 and 88000<=silence[0]<=105000,('actual 90-second health timeout',silence)
            fixture_log.unlink()
            request_window(request_exe(rolled['last_good']))
            # Ensure failed sequence does not retry and production pipe returned.
            waitfor(lambda:subprocess.run([str(root/'pipe-client.exe'),'W:after-update.example'],stdout=subprocess.DEVNULL).returncode==0,90)
            before=journal()['generation'];time.sleep(65);assert journal()['generation']==before
            # Standard STOP remains stopped despite keepalive and configured SCM
            # recovery; explicit restart runs committed last-good offline-capable.
            subprocess.run(['sc.exe','stop','OhnoPrototype'],check=True)
            def service_stopped():
                output=subprocess.run(['sc.exe','query','OhnoPrototype'],capture_output=True,text=True).stdout
                return 'STOPPED' in output
            waitfor(service_stopped,25);time.sleep(12);assert service_stopped()
            subprocess.run(['sc.exe','start','OhnoPrototype'],check=True)
            waitfor(lambda:subprocess.run([str(root/'pipe-client.exe'),'W:after-restart.example'],stdout=subprocess.DEVNULL).returncode==0,90)
            assert journal()['active']==good['active'] and journal()['high_water']==2
            # Standard SCM crash recovery works without a reboot. The stored
            # non-crash flag is verified above; Microsoft's documented activation
            # is after system restart, which this ephemeral CI job does not fake.
            previous_host=host_pid();assert previous_host
            subprocess.run(['taskkill','/PID',str(previous_host),'/F'],check=True)
            waitfor(lambda:host_pid() if host_pid() not in (0,previous_host) else None,40)
            waitfor(lambda:subprocess.run([str(root/'pipe-client.exe'),'W:after-recovery.example'],stdout=subprocess.DEVNULL).returncode==0,60)
            assert journal()['active']==good['active'] and journal()['high_water']==2
            # Revoked maintenance authority must not stop or remove the service.
            form('/maintenance-password',{'csrf':csrf,'action':'clear'})
            denied=subprocess.run([str(setup),'--remove','--password-stdin'],
                                  input=maintenance_password+'\n',text=True,timeout=30)
            if denied.returncode==0:raise RuntimeError('disabled maintenance password removed service')
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Services\OhnoPrototype'):
                pass

            # Simulate an OEM image's copied registry identity on a new hardware
            # anchor. Do not change the runner's OS UUID/MAC or use an installer.
            # Maintenance authority is disabled for this entire clone boot.
            before_clone=journal()
            subprocess.run(['sc.exe','stop','OhnoPrototype'],check=True)
            waitfor(service_stopped,25)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Ohno\Identity',0,winreg.KEY_READ|winreg.KEY_SET_VALUE) as identity:
                copied=winreg.QueryValueEx(identity,'Credentials')[0]
                _,old_id,old_key=copied.rsplit(':',2)
                assert old_id==device
                winreg.QueryValueEx(identity,'Policy') # a cached policy really exists
                winreg.SetValueEx(identity,'Credentials',0,winreg.REG_SZ,'fixture-source-machine:'+old_id+':'+old_key)
            # A single physical runner retains its MAC. Revoke the source's
            # fixture enrollment so that the new ID is not a duplicate approval.
            form('/device',{'csrf':csrf,'id':device,'approved':'0'})
            known=set(read()['devices'])
            subprocess.run(['sc.exe','start','OhnoPrototype'],check=True)
            clone_device=waitfor(lambda:next(iter(set(read()['devices'])-known),None),90)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Ohno\Identity') as identity:
                _,new_id,new_key=winreg.QueryValueEx(identity,'Credentials')[0].rsplit(':',2)
                assert new_id==clone_device and new_id!=old_id and new_key!=old_key
                try:winreg.QueryValueEx(identity,'Policy')
                except FileNotFoundError:pass
                else:raise RuntimeError('cloned identity retained cached policy/grants')
            assert journal()==before_clone and not read()['devices'][clone_device]['approved']
            form('/device',{'csrf':csrf,'id':clone_device,'approved':'1'})
            status,_,policy=call('GET','/api/device/policy',headers={'X-Ohno-Device':new_id,'X-Ohno-Key':new_key})
            assert status==200 and not json.loads(policy)['grants'],'copied device inherited temporary grants'
            device=clone_device
            waitfor(lambda:subprocess.run([str(root/'pipe-client.exe'),'W:after-clone.example'],stdout=subprocess.DEVNULL).returncode==0,90)
            form('/maintenance-password',{'csrf':csrf,'action':'set','maintenance_password':maintenance_password})
            # Device revocation is not a trap preventing authorized removal.
            form('/device',{'csrf':csrf,'id':device,'approved':'0'})
            # Compatibility fixture: only now simulate an old install's recorded
            # self-signed root. All actual runtime/update traffic above already
            # succeeded without machine-wide trust. This fresh key belongs only
            # to the disposable runner and must be removed by legacy cleanup.
            subprocess.run(['certutil','-addstore','Root',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Ohno',0,winreg.KEY_SET_VALUE) as config:
                winreg.SetValueEx(config,'ImportedRootSha1',0,winreg.REG_BINARY,bytes.fromhex(thumb))
            # Exercise normal removal on a revoked device, then a fresh install
            # and explicit offline OS-administrator recovery. All fixture state
            # belongs to this ephemeral runner; no production instance is used.
            subprocess.run([str(setup),'--remove','--password-stdin'],
                           input=maintenance_password+'\n',text=True,check=True,timeout=35)
            installed=False
            assert_removed(thumb)
            previous_devices=set(read()['devices'])
            installed=True
            install_fixture(school_setup)
            assert_no_root_import(thumb)
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
            if certificate_cleanup_needed:subprocess.run(['certutil','-delstore','Root',thumb],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if cleanup_failed:raise RuntimeError('service or imported root cleanup failed')

if __name__=='__main__':main()
