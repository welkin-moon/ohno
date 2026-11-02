import unittest

from school_installer import (
    MAGIC, TRAILER, build_school_installer, enrollment_origin, get_school_configuration, get_school_trust
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

    def test_v2_binds_public_release_key_without_private_material(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from update_manifest import public_key_hex
        key=public_key_hex(ec.generate_private_key(ec.SECP256R1()).public_key())
        packaged=build_school_installer(self.base,'https://teacher-pc:8443',self.cert,key)
        self.assertEqual(get_school_trust(packaged),('https://teacher-pc:8443',self.cert,key))
        self.assertEqual(get_school_configuration(packaged),('https://teacher-pc:8443',self.cert))
        self.assertNotIn(b'PRIVATE KEY',packaged)
        for invalid in ['',key.upper(),'04'+'0'*128,key[:-1],key+'0']:
            with self.assertRaises(ValueError):build_school_installer(self.base,'https://teacher-pc:8443',self.cert,invalid)
        malformed=packaged[:-12]+bytes(4)+packaged[-8:]
        with self.assertRaises(ValueError):get_school_trust(malformed)

    def test_reject_insecure_or_broken_configuration(self):
        for origin in ('http://teacher-pc:8443','https://teacher-pc:8443/path',
                       'https://user:pw@teacher:8443','https://teacher-pc:8443?x=1',
                       'https://teacher-pc', 'https://teacher-pc:abc',
                       'https://tea\ncher:8443', 'https://tea\tcher:8443',
                       'https://bad host:8443', 'https://teacher:8443?',
                       'https://teacher:8443#', 'https://teacher:0',
                       'https://teacher:65536', 'https://teacher:8443\\',
                       'https://teacher:8443/\0'):
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

    def test_ipv6_origin_is_bracketed(self):
        origin = enrollment_origin('2001:db8::1', 8443)
        self.assertEqual(origin, 'https://[2001:db8::1]:8443')
        self.assertEqual(get_school_configuration(build_school_installer(
            self.base, origin, self.cert))[0], origin)


if __name__ == '__main__': unittest.main()
