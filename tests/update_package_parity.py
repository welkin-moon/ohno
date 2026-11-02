"""Python/native parser agreement; deterministic fixture mutation, no real keys."""
import argparse
from pathlib import Path
import random
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'teacher'))
from test_update_package import fixture_package
from update_package import parse_package

parser=argparse.ArgumentParser();parser.add_argument('--client',required=True);args=parser.parse_args()
client=str(Path(args.client).resolve());original=fixture_package();randomizer=random.Random(891)
cases=[original,original[:-1],original+b'extra']
for position in list(range(65))+[65+x for x in (0,1,0x3c,0x3d,0x3e,0x3f,0x80,0x81,0x82,0x83,0x84,0x85,0x94,0x98,0x99)]:
    for byte in [0,1,255]:
        data=bytearray(original);data[position]=byte;cases.append(bytes(data))
for _ in range(100):
    data=bytearray(original);data[randomizer.randrange(len(data))]=randomizer.randrange(256);cases.append(bytes(data))
with tempfile.TemporaryDirectory() as temp:
    path=Path(temp)/'package.ohno'
    for index,data in enumerate(cases):
        try:parse_package(data);expected=True
        except ValueError:expected=False
        path.write_bytes(data)
        result=subprocess.run([client,str(path)],capture_output=True,timeout=10)
        if (result.returncode==0)!=expected:raise AssertionError(f'parser disagreement on mutation {index}')
print(f'{len(cases)} Python/native package parser cases agree')
