"""Disposable E2E teacher: trace only public updater route/status metadata."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'teacher'))
import server


def log_update_response(self, code='-', size='-'):
    # No headers, bodies, query strings, device identifiers or secrets.
    if self.path in ('/api/device/update/offer', '/api/device/update/authorize', '/api/maintenance/authorize'):
        print('FIXTURE UPDATE HTTP', self.path, code, flush=True)
    elif self.path.startswith('/api/device/update/package/'):
        print('FIXTURE UPDATE HTTP package', code, flush=True)


server.Handler.log_request = log_update_response
if __name__ == '__main__':
    server.main()
