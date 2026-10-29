import unittest

from school_installer import (
    MAGIC, TRAILER, build_school_installer, get_school_configuration
)


class SchoolInstallerTests(unittest.TestCase):
    def setUp(self):
        self.base = b'MZ' + bytes(4096)
        self.cert = b'-----BEGIN CERTIFICATE-----\n' + b'A'*160 + b'\n-----END CERTIFICATE-----\n'

    def test_school_installer_round_trip(self):
        packaged=build_school_installer(self.base,'https://teacher-pc:8443',self.cert)
        self.assertEqual(get_school_configuration(packaged),('https://teacher-pc:8443',self.cert))
        self.assertTrue(packaged.endswith(TRAILER.pack(23,len(self.cert),MAGIC)))
        self.assertEqual(packaged[:len(self.base)],self.base)

    def test_reject_insecure_or_broken_configuration(self):
        for origin in ('http://teacher-pc:8443','https://teacher-pc:8443/path',
                       'https://user:pw@teacher:8443','https://teacher-pc:8443?x=1',
                       'https://teacher-pc', 'https://teacher-pc:abc'):
            with self.subTest(origin=origin):
                with self.assertRaises(ValueError):
                    build_school_installer(self.base,origin,self.cert)
        for cert in (b'', b'not a certificate', b'-----BEGIN PRIVATE KEY-----' + b'A'*256):
            with self.subTest(cert=cert[:15]):
                with self.assertRaises(ValueError):
                    build_school_installer(self.base,'https://teacher-pc:8443',cert)
        with self.assertRaises(ValueError):
            get_school_configuration(self.base)
        blob=build_school_installer(self.base,'https://teacher-pc:8443',self.cert)
        with self.assertRaises(ValueError):
            get_school_configuration(blob[:-1])


if __name__ == '__main__': unittest.main()
