"""Collect licenses for the self-contained Windows teacher executable."""
import importlib.metadata
import shutil
import sys
import urllib.request
from pathlib import Path
out=Path('dist/licenses');out.mkdir(parents=True,exist_ok=True)
for package in ('cryptography','pyinstaller'):
    dist=importlib.metadata.distribution(package);found=0
    for entry in dist.files or ():
        path=str(entry).replace('\\','/')
        if ('.dist-info/licenses/' in path or '.dist-info/LICENSE' in path) and Path(path).name.upper().startswith(('LICENSE','COPYING')):
            src=Path(dist.locate_file(entry));target=out/(package+'-'+Path(path).name)
            if src.is_file():shutil.copy2(src,target);found+=1
    if not found:raise RuntimeError('Missing license for '+package)
version='.'.join(map(str,sys.version_info[:3]))
url='https://raw.githubusercontent.com/python/cpython/v'+version+'/LICENSE'
with urllib.request.urlopen(url,timeout=30) as r:(out/'python-LICENSE.txt').write_bytes(r.read())
print('Bundled runtime licenses collected')
