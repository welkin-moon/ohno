"""Check the same cmd guard used by CI, including signed NTSTATUS exits."""
import os
from pathlib import Path
import subprocess
import tempfile

GUARD = 'if errorlevel 1 exit /b 1\nif not errorlevel 0 exit /b 1'


def main():
    assert os.name == 'nt', 'native cmd regression requires Windows'
    workflow = (Path(__file__).resolve().parents[1]/'.github/workflows/prototype.yml').read_text()
    lines = [line.strip() for line in workflow.splitlines()]
    assert lines.count('if errorlevel 1 exit /b 1') > 20
    for index, line in enumerate(lines):
        if line == 'if errorlevel 1 exit /b 1':
            assert lines[index+1] == 'if not errorlevel 0 exit /b 1', 'CI can swallow a negative crash exit'
    with tempfile.TemporaryDirectory() as temp:
        script = Path(temp)/'native-gate.cmd'
        script.write_text('@echo off\ncmd /d /c exit /b %1\n'+GUARD+'\nexit /b 0\n', encoding='ascii')
        for code in (0, 1, 2, -1, -1073740791, -1073741819):
            result = subprocess.run(['cmd', '/d', '/c', str(script), str(code)], capture_output=True, timeout=10)
            assert result.returncode == (0 if code == 0 else 1), ('exit gate', code, result.returncode)
    print('Native command gate rejects positive errors and negative abort/access-violation statuses')


if __name__ == '__main__':
    main()
