import threading
import unittest
from unittest.mock import patch

from maintenance import (GLOBAL_LIMIT, ITERATIONS, MaintenanceGuard, PER_SOURCE, WINDOW,
                         create_credential, password_bytes)

PASSWORD = 'A classroom maintenance phrase!'


class MaintenanceGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.credential = create_credential(PASSWORD)

    def test_salted_slow_hash_and_unicode_password(self):
        first = create_credential('教师维护密码只用于安装和卸载')
        second = create_credential('教师维护密码只用于安装和卸载')
        self.assertNotEqual(first['salt'], second['salt'])
        self.assertNotEqual(first['digest'], second['digest'])
        self.assertEqual(first['iterations'], ITERATIONS)
        self.assertTrue(MaintenanceGuard().verify('教师维护密码只用于安装和卸载', first, 'test'))
        self.assertNotIn(PASSWORD, str(self.credential))

    def test_password_boundaries(self):
        for password in ['', 'short', 'a'*129, 'a'*11+'\n', 'a'*11+'\0', 'a'*11+'\ud800', None, 123]:
            with self.subTest(password=repr(password)), self.assertRaises(ValueError):
                password_bytes(password)
        self.assertEqual(password_bytes('a'*12), b'a'*12)
        self.assertEqual(len(password_bytes('😀'*128)), 512)

    def test_disabled_malformed_wrong_and_right_passwords(self):
        guard = MaintenanceGuard()
        for credential in [None, {}, dict(self.credential, iterations=True), dict(self.credential, iterations=10**10),
                dict(self.credential, salt='z'*32), dict(self.credential, digest='a'*63),
                dict(self.credential, algorithm='sha256'), dict(self.credential, extra=True)]:
            with self.subTest(credential=credential), patch('maintenance.hashlib.pbkdf2_hmac') as derive:
                self.assertFalse(guard.verify(PASSWORD, credential, 'test'))
                derive.assert_not_called()
        self.assertFalse(guard.verify('Wrong classroom maintenance phrase!', self.credential, 'test'))
        self.assertTrue(guard.verify(PASSWORD, self.credential, 'test'))

    def test_per_source_global_and_retained_history_are_bounded(self):
        now = [0.0]
        guard = MaintenanceGuard(clock=lambda: now[0])
        with patch('maintenance.hashlib.pbkdf2_hmac', return_value=bytes.fromhex(self.credential['digest'])) as derive:
            for _ in range(PER_SOURCE):
                self.assertTrue(guard.verify(PASSWORD, self.credential, 'one'))
            self.assertFalse(guard.verify(PASSWORD, self.credential, 'one'))
            for i in range(GLOBAL_LIMIT - PER_SOURCE):
                self.assertTrue(guard.verify(PASSWORD, self.credential, str(i)))
            for i in range(1000):
                self.assertFalse(guard.verify(PASSWORD, self.credential, 'new-'+str(i)))
            self.assertEqual(derive.call_count, GLOBAL_LIMIT)
            self.assertEqual(len(guard.attempts), GLOBAL_LIMIT)
            now[0] = WINDOW
            self.assertTrue(guard.verify(PASSWORD, self.credential, 'one'))
            self.assertEqual(len(guard.attempts), 1)

    def test_only_two_expensive_hashes_can_run_concurrently(self):
        guard = MaintenanceGuard()
        ready = threading.Barrier(3)
        release = threading.Event()
        results = []
        def derive(*args):
            ready.wait(timeout=5)
            release.wait(timeout=5)
            return bytes.fromhex(self.credential['digest'])
        with patch('maintenance.hashlib.pbkdf2_hmac', side_effect=derive):
            workers = [threading.Thread(target=lambda: results.append(guard.verify(PASSWORD, self.credential, 'test'))) for _ in range(2)]
            for worker in workers: worker.start()
            try:
                ready.wait(timeout=5)
                self.assertFalse(guard.verify(PASSWORD, self.credential, 'third'))
            finally:
                release.set()
                for worker in workers: worker.join(timeout=5)
            self.assertEqual(results, [True, True])


if __name__ == '__main__':
    unittest.main()
