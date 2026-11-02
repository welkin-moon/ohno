"""Bounded, uncompressed native payload container; never executes file content.

Fixed file order/names deliberately excludes paths, commands, symlinks, archive
compression and a replaceable service host. Host protocol compatibility is
signed by update_manifest.py. All executables must be Windows x64 PE32+.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
from pathlib import Path
import struct

from update_manifest import MAX_PACKAGE_SIZE, VERSION

MAGIC=b'OHNOPK01'
FILES=('ohno-worker.exe','ohno-request.exe','ohno-maintenance.exe','ohno-tun.exe',
       'sing-box-LICENSE.txt','wintun-LICENSE.txt')
HEADER=struct.Struct('<8sHH6Q')


@dataclass(frozen=True)
class Package:
    version: str
    offsets: tuple[tuple[int,int], ...]


def x64_executable(data: bytes | memoryview) -> bool:
    if len(data)<1024 or bytes(data[:2])!=b'MZ':return False
    offset=struct.unpack_from('<I',data,0x3c)[0]
    if offset<0x40 or offset>len(data)-26:return False
    return (bytes(data[offset:offset+4])==b'PE\0\0' and
            struct.unpack_from('<H',data,offset+4)[0]==0x8664 and
            struct.unpack_from('<H',data,offset+20)[0]>=2 and
            struct.unpack_from('<H',data,offset+24)[0]==0x20b)


def parse_package(data: bytes) -> Package:
    if not isinstance(data,bytes) or not 1024<=len(data)<=MAX_PACKAGE_SIZE:
        raise ValueError('invalid package size')
    magic,version_size,count,*sizes=HEADER.unpack_from(data)
    if magic!=MAGIC or count!=len(FILES) or not 5<=version_size<=53:
        raise ValueError('invalid package header')
    start=HEADER.size+version_size
    try:version=data[HEADER.size:start].decode('ascii')
    except UnicodeError as error:raise ValueError('invalid package version') from error
    if not VERSION.fullmatch(version):raise ValueError('invalid package version')
    if any(not 1<=size<=MAX_PACKAGE_SIZE for size in sizes) or start+sum(sizes)!=len(data):
        raise ValueError('invalid package lengths or trailing bytes')
    offsets=[];view=memoryview(data)
    for index,size in enumerate(sizes):
        if index<4 and not x64_executable(view[start:start+size]):raise ValueError('payload executable is not x64 PE32+')
        if index>=4 and size>1024*1024:raise ValueError('license file too large')
        offsets.append((start,size));start+=size
    return Package(version,tuple(offsets))


def build_package(version: str, files: dict[str,bytes]) -> bytes:
    if not isinstance(version,str) or not VERSION.fullmatch(version) or set(files)!=set(FILES):
        raise ValueError('invalid package version or fixed file set')
    if any(not isinstance(files[name],bytes) for name in FILES):raise ValueError('file data must be bytes')
    ver=version.encode('ascii')
    size=HEADER.size+len(ver)+sum(len(files[name]) for name in FILES)
    if size>MAX_PACKAGE_SIZE:raise ValueError('package too large')
    result=HEADER.pack(MAGIC,len(ver),len(FILES),*(len(files[name]) for name in FILES))+ver+b''.join(files[name] for name in FILES)
    parse_package(result);return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Build an unsigned fixed-layout OHNO update payload (teacher approval signs it later)')
    parser.add_argument('--version',required=True);parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    result=build_package(args.version,{name:(args.directory/name).read_bytes() for name in FILES})
    with args.output.open('xb') as output:output.write(result)
