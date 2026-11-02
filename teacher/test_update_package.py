import struct
import unittest
from update_package import FILES, HEADER, build_package, parse_package


def fixture_exe():
    data=bytearray(1024);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0';struct.pack_into('<H',data,0x84,0x8664)
    struct.pack_into('<H',data,0x94,2);struct.pack_into('<H',data,0x98,0x20b)
    return bytes(data)


def fixture_package(version='0.2.0'):
    return build_package(version,{name:fixture_exe() if i<4 else b'fixture license\n' for i,name in enumerate(FILES)})


class PackageTests(unittest.TestCase):
    def test_roundtrip_fixed_names_and_architecture(self):
        data=fixture_package();package=parse_package(data)
        self.assertEqual(package.version,'0.2.0');self.assertEqual(len(package.offsets),6)
        for offset,size in package.offsets[:4]:self.assertEqual(data[offset:offset+size],fixture_exe())
        for bad in [data+b'x',data[:-1],b'x'*1024,data[:8]+b'\xff\xff'+data[10:],data[:10]+b'\x05\0'+data[12:]]:
            with self.assertRaises(ValueError):parse_package(bad)

    def test_length_overflows_and_every_truncation(self):
        data=fixture_package()
        for end in range(len(data)):
            with self.assertRaises(ValueError):parse_package(data[:end])
        for index in range(6):
            for size in [0,2**64-1,2**32,268435457]:
                bad=bytearray(data);struct.pack_into('<Q',bad,12+index*8,size)
                with self.assertRaises(ValueError):parse_package(bytes(bad))

    def test_no_paths_missing_files_or_unsupported_pe(self):
        files={name:fixture_exe() if i<4 else b'license' for i,name in enumerate(FILES)}
        for name in FILES:
            missing=dict(files);del missing[name]
            with self.assertRaises(ValueError):build_package('0.2.0',missing)
        bad=dict(files);bad['../escape.exe']=bad.pop(FILES[0])
        with self.assertRaises(ValueError):build_package('0.2.0',bad)
        for offset,change in [(0,b'NO'),(0x3c,struct.pack('<I',0xffffffff)),(0x84,b'\x4c\x01'),(0x98,b'\x0b\x01')]:
            payload=bytearray(fixture_exe());payload[offset:offset+len(change)]=change;bad=dict(files);bad[FILES[0]]=bytes(payload)
            with self.assertRaises(ValueError):build_package('0.2.0',bad)
        for version in ['0.2.0/../','01.2.3','0.2.0\n','中文','0.2.0-'+('x'*33)]:
            with self.assertRaises(ValueError):build_package(version,files)

if __name__=='__main__':unittest.main()
