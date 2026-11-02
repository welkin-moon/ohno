"""Read-only selector and conservative removal in temporary owned directories."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'teacher'))
from test_update_package import fixture_package


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--client',required=True);args=parser.parse_args();client=str(Path(args.client).resolve())
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp).resolve();package=root/'fixture.ohno';package.write_bytes(fixture_package())
        def call(directory,action,expected=0):
            result=subprocess.run([client,str(directory),action]+([str(package)] if action=='init' else []),timeout=20)
            assert result.returncode==expected,(directory.name,action,result.returncode)
        def install(name):
            directory=root/name;directory.mkdir();call(directory,'init');return directory,next((directory/'versions').iterdir())
        directory,version=install('normal');call(directory,'view')
        (directory/('download-'+'a'*64+'.tmp')).write_bytes(b'partial')
        call(directory,'remove');assert not list(directory.iterdir())
        directory,version=install('tamper');(version/'ohno-request.exe').write_bytes(b'changed');call(directory,'view',1);call(directory,'remove')
        directory,version=install('unknown');unknown=version/'school-note.txt';unknown.write_text('do not delete')
        call(directory,'remove',1);assert unknown.read_text()=='do not delete'
        directory,version=install('hardlink');outside=root/'outside.txt';outside.write_bytes(b'leave outside')
        target=version/'ohno-request.exe';target.unlink();os.link(outside,target);call(directory,'view',1);call(directory,'remove',1);assert outside.read_bytes()==b'leave outside' and target.exists()
        directory,version=install('bad-state');(directory/'update-state.json').write_text('{bad')
        call(directory,'view',1);call(directory,'remove') # explicit OS-admin recovery doesn't need journal
        directory,version=install('reparse');link=root/'junction'
        subprocess.run(['cmd','/c','mklink','/J',str(link),str(directory)],check=True,stdout=subprocess.DEVNULL)
        call(link,'view',1);call(link,'remove',1);assert (version/'ohno-worker.exe').exists();link.rmdir()
        directory,version=install('unknown-root');unknown=directory/'school-note.txt';unknown.write_text('retained')
        call(directory,'remove');assert list(directory.iterdir())==[unknown]
    print('Read-only selection under writer lock, payload integrity, link refusal and conservative removal passed')


if __name__=='__main__':main()
