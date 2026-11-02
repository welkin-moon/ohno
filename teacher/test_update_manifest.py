import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from update_manifest import (FIELDS, MAX_SEQUENCE, MAX_TIMESTAMP, MAX_VALIDITY,
    package_path, parse_manifest, public_key_hex, sign_manifest, signing_bytes, verify_manifest)


FIXTURE = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures' / 'update-manifest-v1.json'


class UpdateManifestTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public = public_key_hex(self.key.public_key())
        self.fields = dict(schema=1, platform='windows-x64', sequence=12,
            version='0.2.0-alpha.1', min_updater=1, issued_at=1793610000,
            expires_at=1793613600, size=4096, sha256='a'*64)
        self.context = dict(installed_sequence=11, updater_version=1, now=1793610000)

    def signed(self, fields=None):
        return sign_manifest(fields or self.fields, self.key)

    def verify(self, manifest, **context):
        return verify_manifest(json.dumps(manifest), self.public, **dict(self.context, **context))

    def test_shared_windows_signature_vector(self):
        vector = json.loads(FIXTURE.read_text())
        manifest = verify_manifest(json.dumps(vector['manifest']), vector['public_key'],
            installed_sequence=11, updater_version=1, now=1793610000)
        fields = {name: manifest[name] for name in FIELDS}
        self.assertEqual(signing_bytes(fields).decode(), vector['signing_bytes'])

    def test_sign_roundtrip_and_fixed_package_path(self):
        manifest = self.verify(self.signed())
        self.assertEqual(package_path(manifest), '/api/device/update/package/'+'a'*64)
        self.assertNotIn('public_key', manifest)
        self.assertNotIn('url', manifest)

    def test_wrong_key_and_invalid_point_rejected(self):
        document = json.dumps(self.signed())
        other = public_key_hex(ec.generate_private_key(ec.SECP256R1()).public_key())
        for public in [other, '04'+'0'*128, self.public.upper(), '02'+'a'*64, '', '04'+'z'*128]:
            with self.subTest(public=public[:8]), self.assertRaises(ValueError):
                verify_manifest(document, public, **self.context)

    def test_each_authenticated_field_is_bound_to_signature(self):
        valid = self.signed()
        for name, value in dict(sequence=13, version='0.2.0-alpha.2', min_updater=2,
                issued_at=self.fields['issued_at']-1, expires_at=self.fields['expires_at']+1,
                size=4097, sha256='b'*64).items():
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.verify(dict(valid, **{name: value}))
        for signature in ['0'*128, valid['signature'][:-1]+'g', valid['signature'][:-2], 7]:
            with self.subTest(signature=signature), self.assertRaises(ValueError):
                self.verify(dict(valid, signature=signature))

    def test_schema_platform_and_unknown_fields_rejected(self):
        valid = self.signed()
        for fields in [dict(valid, schema=2), dict(valid, platform='windows-arm64'),
                dict(valid, url='https://evil.example/setup.exe'),
                dict(valid, command='--remove'), dict(valid, public_key=self.public)]:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.verify(fields)
        for field in valid:
            incomplete = dict(valid)
            del incomplete[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.verify(incomplete)

    def test_exact_integer_types_and_bounds(self):
        valid = self.signed()
        for field in ('schema', 'sequence', 'min_updater', 'issued_at', 'expires_at', 'size'):
            for value in (True, False, '1', 1.0, -1, 0, 2**65, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.verify(dict(valid, **{field: value}))
        for field, value in [('sequence', MAX_SEQUENCE+1), ('min_updater', 65536),
                ('size', 1023), ('size', 256*1024*1024+1), ('issued_at', MAX_TIMESTAMP+1)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(dict(valid, **{field: value}))

    def test_invalid_versions_hashes_and_validity(self):
        valid = self.signed()
        for version in ['1', 'v1.2.3', '01.2.3', '1.2.3\n', '1.2.3/../',
                '1000000.0.0', '1.2.3-', '1.2.3-'+('a'*33), '1.2.3-中文', '1.2.3+build']:
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.verify(dict(valid, version=version))
        for digest in ['a'*63, 'A'*64, '../'+'a'*61, 'a'*63+'\n']:
            with self.assertRaises(ValueError):
                self.verify(dict(valid, sha256=digest))
        for expires in [self.fields['issued_at'], self.fields['issued_at']-1,
                        self.fields['issued_at']+MAX_VALIDITY+1]:
            with self.assertRaises(ValueError):
                self.verify(dict(valid, expires_at=expires))

    def test_replay_and_clock_policy(self):
        manifest = self.signed()
        for sequence in [12, 13, MAX_SEQUENCE]:
            with self.assertRaises(ValueError):
                self.verify(manifest, installed_sequence=sequence)
        for now in [self.fields['issued_at']-301, self.fields['expires_at'], self.fields['expires_at']+1]:
            with self.assertRaises(ValueError):
                self.verify(manifest, now=now)
        self.verify(manifest, now=self.fields['issued_at']-300)
        self.verify(manifest, now=self.fields['expires_at']-1)
        with self.assertRaises(ValueError):
            self.verify(self.signed(dict(self.fields, min_updater=2)))

    def test_invalid_trusted_context_rejected(self):
        for name, values in dict(installed_sequence=[-1, True, MAX_SEQUENCE+1],
                updater_version=[0, True, 65536], now=[0, True, MAX_TIMESTAMP+1]).items():
            for value in values:
                with self.subTest(field=name), self.assertRaises(ValueError):
                    self.verify(self.signed(), **{name: value})

    def test_malformed_duplicate_deep_and_oversize_json(self):
        valid = json.dumps(self.signed())
        for document in ['[]', 'null', valid[:-1], valid[:-1]+',"sequence":12}',
                valid[:-1]+',"\\u0073equence":12}', '['*2000+'0'+']'*2000,
                valid + ' '*4096, valid.encode('utf-16'), b'\xff']:
            with self.subTest(document=str(document)[:40]), self.assertRaises(ValueError):
                parse_manifest(document)

    def test_signing_rejects_non_p256_key(self):
        with self.assertRaises(ValueError):
            sign_manifest(self.fields, ec.generate_private_key(ec.SECP384R1()))
        with self.assertRaises(ValueError):
            public_key_hex(ec.generate_private_key(ec.SECP384R1()).public_key())


if __name__ == '__main__':
    unittest.main()
