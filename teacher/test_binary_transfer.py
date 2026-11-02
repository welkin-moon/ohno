"""Bound binary replies without real sleeps, services, or signing credentials."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from server import Handler


class BinaryTransferTests(unittest.TestCase):
    def handler(self, *, advance=0, fail_after=None):
        value = Handler.__new__(Handler)
        value.server = SimpleNamespace(request_timeout=10)
        value.path = '/api/device/update/package/' + 'a' * 64
        value.connection = Mock()
        value.close_connection = False
        value.send_response = Mock()
        value.send_header = Mock()
        value.end_headers = Mock()
        value.clock = 0
        value.chunks = []
        def write(data):
            if fail_after is not None and len(value.chunks) == fail_after:
                raise BrokenPipeError('fixture receiver closed')
            value.chunks.append(bytes(data))
            value.clock += advance
        value.wfile = SimpleNamespace(write=write)
        return value

    def reply(self, value, data, content_type='application/octet-stream'):
        # Use the actual POST exception boundary, which used to append a 503.
        value._do_post = lambda: value.reply(200, data, content_type)
        with patch('server.time.monotonic', side_effect=lambda: value.clock):
            value.do_POST()

    def test_continuous_progress_can_exceed_ten_seconds(self):
        value = self.handler(advance=3)
        data = b'x' * (20 * 65536 + 7)
        self.reply(value, data)
        self.assertGreater(value.clock, 10)
        self.assertEqual(b''.join(value.chunks), data)
        self.assertEqual(max(map(len, value.chunks)), 65536)
        value.send_response.assert_called_once_with(200)
        self.assertTrue(all(call.args == (10,) for call in value.connection.settimeout.call_args_list))

    def test_total_deadline_and_remaining_io_budget(self):
        value = self.handler(advance=295)
        self.reply(value, b'x' * (3 * 65536))
        self.assertEqual(len(value.chunks), 2)
        self.assertEqual([call.args[0] for call in value.connection.settimeout.call_args_list], [10, 5])
        value.send_response.assert_called_once_with(200)
        self.assertTrue(value.close_connection)

    def test_disconnect_never_appends_a_second_response(self):
        value = self.handler(fail_after=1)
        self.reply(value, b'x' * (3 * 65536))
        self.assertEqual(len(value.chunks), 1)
        value.send_response.assert_called_once_with(200)
        self.assertTrue(value.close_connection)

    def test_header_failure_does_not_start_a_second_response(self):
        value = self.handler()
        value.end_headers.side_effect = TimeoutError('fixture header write timeout')
        self.reply(value, b'x' * 65536)
        self.assertEqual(value.chunks, [])
        value.send_response.assert_called_once_with(200)
        self.assertTrue(value.close_connection)

    def test_ordinary_json_reply_is_unchanged(self):
        value = self.handler()
        self.reply(value, '{"ok":true}', 'application/json')
        self.assertEqual(value.chunks, [b'{"ok":true}'])
        value.connection.settimeout.assert_not_called()
        self.assertFalse(value.close_connection)


if __name__ == '__main__':
    unittest.main()
