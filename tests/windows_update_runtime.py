"""Execute only compiled test workers in isolated temporary NTFS directories.

Same production runtime, actual TLS/catalog protocol, private handles, processes,
job ownership and durable selectors. No service installation or production key.
"""
import argparse
import ctypes
import hashlib
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
from windows_update_staging import Handler, DEVICE, KEY
from cryptography.hazmat.primitives.asymmetric import ec
from server import create_certificate
from test_update_package import fixture_exe
from update_package import FILES, build_package
from update_manifest import public_key_hex, sign_manifest


def alive(pid):
    api=ctypes.windll.kernel32
    api.OpenProcess.restype=ctypes.c_void_p
    handle=api.OpenProcess(0x100000,False,pid)
    if not handle:return False
    try:return api.WaitForSingleObject(ctypes.c_void_p(handle),0)==258
    finally:api.CloseHandle(ctypes.c_void_p(handle))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--client',required=True);parser.add_argument('--worker',required=True)
    args=parser.parse_args();client=str(Path(args.client).resolve());worker=Path(args.worker).read_bytes()
    def package(version):
        files={name:fixture_exe() if i<4 else b'fixture license\n' for i,name in enumerate(FILES)}
        files['ohno-worker.exe']=worker
        return build_package(version,files)
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp).resolve();create_certificate(root/'cert.pem',root/'tls.key','localhost')
        create_certificate(root/'other.pem',root/'other.key','localhost')
        release=ec.generate_private_key(ec.SECP256R1());public=public_key_hex(release.public_key())
        baseline=root/'baseline.ohno';baseline.write_bytes(package('0.1.0'))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'cert.pem',root/'tls.key')
        with ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
            server.socket=context.wrap_socket(server.socket,server_side=True);server.origin='https://127.0.0.1:'+str(server.server_port)
            server.requests=[];server.mode='normal';thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            def offer(version='0.2.0',seq=7,mode='normal'):
                payload=package(version);now=int(time.time());server.mode=mode;server.package=payload
                server.offer=sign_manifest({'schema':1,'platform':'windows-x64','sequence':seq,'version':version,'min_updater':1,
                    'issued_at':now,'expires_at':now+3600,'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest()},release)
            def config(directory,initialize=True,**overrides):
                directory.mkdir(exist_ok=True)
                value={'root':str(directory),'initialize':initialize,'baseline':str(baseline),'server':server.origin,
                    'certificate':(root/'cert.pem').read_text(),'public_key':public,'device_id':DEVICE,'device_key':KEY,
                    'stop_ms':20000,'crash':0,'stop_at':0,'fail_drain':False,'fail_start':False,'fail_drain_on_start':False,'stop_after_poll':True,'stop_after_rollback':False}
                value.update(overrides);return value
            def run(directory,expected=0,**overrides):
                result=subprocess.run([client],input=json.dumps(config(directory,**overrides)),text=True,capture_output=True,timeout=30)
                assert result.returncode==expected,(directory.name,result.returncode,result.stderr,events(directory),server.requests[-3:])
                return json.loads((directory/'update-state.json').read_text())
            def events(directory):
                path=directory/'worker-events.log';return path.read_text().splitlines() if path.exists() else []
            def stopped(directory):
                pids={int(line.split()[0]) for line in events(directory)}
                deadline=time.monotonic()+5
                while any(alive(pid) for pid in pids) and time.monotonic()<deadline:time.sleep(.05)
                assert not any(alive(pid) for pid in pids),(directory.name,'orphan process',pids)
            def state_is(value,sequence,floor):
                assert value['phase']=='stable' and value['active']['sequence']==sequence and value['high_water']==floor,(value,server.requests[-3:])
            offer();directory=root/'success';state_is(run(directory),7,7)
            assert sum(' start 7 ' in line for line in events(directory))==1;stopped(directory)
            # Restart executes committed bytes offline, without an expired offer
            # or maintenance password. No additional enrollment/settings path.
            server.mode='no_offer';state_is(run(directory,initialize=False,stop_ms=20000),7,7);stopped(directory)
            for mode in ['revoked','wrong_nonce','wrong_hash','wrong_device','wrong_sequence','expired','bad_signature','tampered']:
                offer(mode=mode);directory=root/mode;state_is(run(directory,stop_ms=20000),0,0)
                assert not any(' start 7 ' in line for line in events(directory));stopped(directory)
            offer();directory=root/'wrong-cert';state_is(run(directory,certificate=(root/'other.pem').read_text(),stop_ms=20000),0,0);stopped(directory)
            for bad in ['exit','nohealth','nohealth-open','nonce','revision','zero','malformed','oversize']:
                offer('0.2.0-'+bad);directory=root/('bad-'+bad);state_is(run(directory,stop_ms=20000,stop_after_poll=False,stop_after_rollback=True),0,7)
                log=events(directory);assert sum(' start 7 ' in line for line in log)==1,log
                assert sum(' start 0 ' in line for line in log)>=2,log;stopped(directory)
                if bad=='nohealth-open':
                    silence=[int(line.split()[-1]) for line in log if ' silent-ms ' in line]
                    assert len(silence)==1 and 2800<=silence[0]<=6000,('bounded silent health timeout',silence)
            for point in [4,5,6,7,10,11,12]:
                offer();directory=root/('stop-'+str(point));state_is(run(directory,stop_at=point),0,7)
                assert sum(' start 0 ' in line for line in events(directory))==1;stopped(directory)
            for point in [4,5,6,7,8,9,10,11,12]:
                offer('0.2.0-nohealth' if point==9 else '0.2.0-descendant');directory=root/('crash-'+str(point))
                run(directory,expected=100+point,crash=point,stop_ms=20000);stopped(directory)
                server.mode='no_offer';state_is(run(directory,initialize=False,stop_ms=20000),7 if point==8 else 0,7);stopped(directory)
            offer();directory=root/'drain-unconfirmed';value=run(directory,expected=1,fail_drain=True,stop_after_poll=False)
            assert value['phase']=='prepared' and value['high_water']==7,value
            assert not any(' start 7 ' in line for line in events(directory));stopped(directory)
            offer();directory=root/'start-failed';value=run(directory,fail_start=True,stop_after_poll=False,stop_after_rollback=True)
            state_is(value,0,7);assert sum(' start 0 ' in line for line in events(directory))==2;stopped(directory)
            # Inject uncertain drain specifically after a child was created but
            # never resumed. It must not be misclassified as ordinary rollback.
            offer();directory=root/'start-drain-unconfirmed';value=run(directory,expected=1,fail_start=True,fail_drain_on_start=True)
            assert value['phase']=='probation',value
            assert sum(' start 0 ' in line for line in events(directory))==1;stopped(directory)
            # Journal corruption never resets identity/floor or launches fallback.
            offer();directory=root/'corrupt';state_is(run(directory),7,7);before=len(events(directory))
            (directory/'update-state.json').write_text('{truncated')
            result=subprocess.run([client],input=json.dumps(config(directory,initialize=False)),text=True,capture_output=True,timeout=20)
            assert result.returncode==1 and len(events(directory))==before
            # Standard keepalive restarts only its own worker, no teacher prompt.
            baseline.write_bytes(package('0.1.0-restart'));offer(mode='no_offer');directory=root/'keepalive';state_is(run(directory,stop_ms=20000),0,0)
            assert sum(' start 0 ' in line for line in events(directory))==2;stopped(directory)
            # Kill the console host while its worker and grandchild are alive:
            # closing the job through process death must reap both, not persist.
            baseline.write_bytes(package('0.1.0-descendant'));directory=root/'host-killed';value=config(directory,stop_ms=20000,stop_after_poll=False)
            process=subprocess.Popen([client],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            process.stdin.write(json.dumps(value)+'\n');process.stdin.flush();process.stdin.close()
            deadline=time.monotonic()+8
            while not any(' descendant' in line for line in events(directory)) and time.monotonic()<deadline:time.sleep(.03)
            assert any(' descendant' in line for line in events(directory)),events(directory)
            process.kill();process.wait(timeout=5);stopped(directory)
            # Missing journal isn't treated as a fresh install.
            directory=root/'missing';value=config(directory,initialize=False)
            result=subprocess.run([client],input=json.dumps(value),text=True,capture_output=True,timeout=20)
            assert result.returncode==1 and not events(directory)
            server.shutdown();thread.join()
    print('Native runtime: healthy update, private proof refusals, rollback/replay, STOP, 9 crashes, offline restart, keepalive and job cleanup passed')


if __name__=='__main__':main()
