"""Native NTFS journal interruption tests; temporary files only, no service/keys."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--client',required=True);args=parser.parse_args()
    client=str(Path(args.client).resolve())
    def call(root,action,fault=None,expected=0):
        result=subprocess.run([client,str(root),action]+([] if fault is None else [str(fault)]),
                              capture_output=True,text=True,timeout=10)
        if result.returncode!=expected:
            raise AssertionError(f'{action}/{fault}: status {result.returncode}, expected {expected}: {result.stderr}')
        return result.stdout
    with tempfile.TemporaryDirectory() as temp:
        base=Path(temp).resolve();cases=0
        # Every transition is killed at each actual write/flush/rename boundary.
        for action,prior in [('prepare',[]),('activate',['prepare']),('commit',['prepare','activate']),
                             ('rollback',['prepare']),('rollback',['prepare','activate'])]:
            for point in range(1,8):
                root=base/f'case-{cases}';root.mkdir();call(root,'init')
                for step in prior:call(root,step)
                before=json.loads(call(root,'read'))
                call(root,action,point,100+point)
                landed=json.loads(call(root,'read'))
                if point<=5 and landed!=before:raise AssertionError('pre-rename crash altered committed state')
                if point>=6 and landed['generation']!=before['generation']+1:raise AssertionError('post-rename crash lost atomic record')
                call(root,'recover');after=json.loads(call(root,'read'))
                if after['phase']!='stable' or after['high_water']<before['high_water']:
                    raise AssertionError('recovery lost replay floor or stayed pending')
                expected_hash='b'*64 if action=='commit' and point>=6 else 'a'*64
                if after['active']['sha256']!=expected_hash:raise AssertionError('unhealthy candidate ran after recovery')
                if after['high_water']>=7:call(root,'prepare',expected=1)
                call(root,'recover') # idempotent restart
                cases+=1
        root=base/'normal';root.mkdir();call(root,'init')
        call(root,'init',expected=1) # never replace a prior installation floor
        hold=subprocess.Popen([client,str(root),'hold'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            if hold.stdout.readline().strip()!='locked':raise AssertionError('journal lock not acquired')
            call(root,'read',expected=1)
        finally:hold.communicate('\n',timeout=10)
        # A partial pending file is untrusted debris, not a recovery authority.
        (root/'update-state.next').write_bytes(b'{incomplete')
        call(root,'prepare');call(root,'activate');call(root,'commit')
        if json.loads(call(root,'read'))['active']['sequence']!=7:raise AssertionError('normal commit did not persist')
        good=(root/'update-state.json').read_bytes()
        for bad in [b'',b'{truncated',b' '*4097]:
            (root/'update-state.json').write_bytes(bad);call(root,'read',expected=1);call(root,'recover',expected=1)
            if (root/'update-state.json').read_bytes()!=bad:raise AssertionError('corruption silently reconstructed')
        (root/'update-state.json').write_bytes(good)
        # A hard-linked journal/pending/lock must never be followed or replaced.
        for name in ['update-state.json','update-state.next','update.lock']:
            location=base/('links-'+name);location.mkdir();call(location,'init')
            target=location/name
            if target.exists():target.unlink()
            outside=base/('outside-'+name);outside.write_bytes(good)
            os.link(outside,target)
            call(location,'prepare',expected=1)
            if outside.read_bytes()!=good:raise AssertionError('hardlink target modified')
        # Read-only selector makes rename fail; existing valid state is retained.
        readonly=base/'readonly';readonly.mkdir();call(readonly,'init')
        record=readonly/'update-state.json';record.chmod(0o444)
        try:
            call(readonly,'prepare',expected=1)
            if json.loads(call(readonly,'read'))['high_water']!=0:raise AssertionError('failed rename changed selector')
        finally:record.chmod(0o666)
    print(f'{cases} native process-crash cases plus corruption, locking, hardlink and read-only tests passed; temp files only')


if __name__=='__main__':main()
