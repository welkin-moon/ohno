import json
import os
import stat
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from update_catalog import CatalogError, ReleaseCatalog
from update_manifest import verify_manifest
from test_update_package import fixture_package


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'releases'
        self.catalog=ReleaseCatalog.initialize(self.root)
    def tearDown(self):self.catalog.close();self.temp.cleanup()
    def test_private_directory_creation_and_no_permission_rewrite(self):
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((self.root/'release-key.pem').stat().st_mode),0o600)
        else:
            import ctypes
            from ctypes import wintypes as w
            security=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            descriptor=ctypes.c_void_p();text=ctypes.c_void_p()
            security.GetNamedSecurityInfoW.argtypes=[w.LPWSTR,ctypes.c_int,w.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]
            security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[ctypes.c_void_p,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
            kernel.LocalFree.argtypes=[ctypes.c_void_p]
            try:
                self.assertEqual(security.GetNamedSecurityInfoW(str(self.root),1,4,None,None,None,None,ctypes.byref(descriptor)),0)
                self.assertTrue(security.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,1,4,ctypes.byref(text),None))
                sddl=ctypes.wstring_at(text)
                self.assertIn('D:P',sddl)
                for broad in (';;;WD)', ';;;BU)', ';;;AU)'):self.assertNotIn(broad,sddl)
                self.assertIn(';;;SY)',sddl);self.assertIn(';;;BA)',sddl)
            finally:
                if text:kernel.LocalFree(text)
                if descriptor:kernel.LocalFree(descriptor)
        original=(self.root/'release-key.pem').read_bytes()
        with self.assertRaises(FileExistsError):ReleaseCatalog.initialize(self.root)
        self.assertEqual((self.root/'release-key.pem').read_bytes(),original)

    def test_explicit_approval_pause_and_higher_sequence(self):
        self.assertIsNone(self.catalog.offer(now=1000));payload=fixture_package()
        offer=self.catalog.approve(payload,now=1000)
        self.assertEqual(verify_manifest(json.dumps(offer),self.catalog.public_key,installed_sequence=0,updater_version=1,now=1000),offer)
        self.assertEqual(self.catalog.package(offer['sha256'],now=1000),payload)
        self.assertIsNone(self.catalog.package('../release-key.pem',now=1000))
        self.assertIsNone(self.catalog.offer(now=offer['expires_at']))
        offer['version']='tampered';self.assertEqual(self.catalog.offer(now=1000)['version'],'0.2.0')
        self.catalog.pause();self.assertIsNone(self.catalog.offer(now=1000));self.assertEqual(self.catalog.data['high_water'],1)
        second=self.catalog.approve(payload,now=1001);self.assertEqual(second['sequence'],2)
        key=self.catalog.public_key;self.catalog.close();self.catalog=ReleaseCatalog(self.root)
        self.assertEqual(self.catalog.public_key,key);self.assertEqual(self.catalog.offer(now=1001),second)
    def test_key_and_catalog_never_regenerated(self):
        with self.assertRaises(FileExistsError):ReleaseCatalog.initialize(self.root)
        with self.assertRaises((OSError,CatalogError)):ReleaseCatalog(self.root)
        self.catalog.close();key=self.root/'release-key.pem';key.unlink()
        with self.assertRaises(FileNotFoundError):ReleaseCatalog(self.root)
        self.assertFalse(key.exists())
    def test_persist_failure_never_exposes_authorization(self):
        payload=fixture_package();first=self.catalog.approve(payload,now=1000)
        with mock.patch('update_catalog._replace',side_effect=OSError('fixture disk failure')):
            with self.assertRaises(CatalogError):self.catalog.approve(payload,now=1001)
        with self.assertRaises(CatalogError):self.catalog.offer(now=1001)
        self.catalog.close();self.catalog=ReleaseCatalog(self.root)
        self.assertEqual(self.catalog.offer(now=1001),first)
        self.assertEqual(self.catalog.approve(payload,now=1002)['sequence'],2)
    def test_ambiguous_landed_write_preserves_higher_sequence_on_reopen(self):
        import update_catalog
        payload=fixture_package();self.catalog.approve(payload,now=1000)
        real=update_catalog._replace
        def landed_then_failed(source,target):
            real(source,target)
            raise OSError('fixture failure after rename')
        with mock.patch('update_catalog._replace',side_effect=landed_then_failed):
            with self.assertRaises(CatalogError):self.catalog.approve(payload,now=1001)
        with self.assertRaises(CatalogError):self.catalog.offer(now=1001)
        self.catalog.close();self.catalog=ReleaseCatalog(self.root)
        self.assertEqual(self.catalog.offer(now=1001)['sequence'],2)
        self.assertEqual(self.catalog.approve(payload,now=1002)['sequence'],3)

    def test_changed_package_and_corrupt_catalog_fail_closed(self):
        offer=self.catalog.approve(fixture_package(),now=1000)
        (self.root/(offer['sha256']+'.ohno')).write_bytes(b'tampered')
        with self.assertRaises(CatalogError):self.catalog.package(offer['sha256'],now=1000)
        with self.assertRaises(CatalogError):self.catalog.approve(fixture_package(),now=1000)
        self.catalog.close();(self.root/'catalog.json').write_bytes(b'{truncated')
        with self.assertRaises(CatalogError):ReleaseCatalog(self.root)
    def test_invalid_payload_or_approval_does_not_advance(self):
        for payload in [b'',b'MZ'+b'x'*1024]:
            with self.assertRaises(ValueError):self.catalog.approve(payload,now=1000)
        for kwargs in [{'lifetime':0},{'lifetime':604801},{'min_updater':0},{'now':True}]:
            with self.assertRaises(ValueError):self.catalog.approve(fixture_package(),**kwargs)
        self.assertEqual(self.catalog.data['high_water'],0)

if __name__=='__main__':unittest.main()
