"""Rebuild small, deterministic fuzz seeds with Python's independent codecs."""

import gzip
import io
import json
from pathlib import Path
import sys
import tarfile
import zlib


ROOT = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parent / "corpus"


def put(target, name, payload):
    directory = ROOT / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(payload)


manifest = b'{"name":"seed","version":"1","scripts":{"install":"echo seed"}}'
lock = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "seed", "version": "1", "dependencies": {"seed": "1"}},
        "node_modules/seed": {
            "name": "seed", "version": "1", "hasInstallScript": True,
            "resolved": "https://registry.npmjs.org/seed/-/seed-1.tgz",
            "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        },
    },
}
for name, value in {
    "empty": b"",
    "nested": b'{"a":[true,null,1.25,"\\u2603"]}',
    "malformed-plus": b'"\\u+041"',
    "lock": json.dumps(lock, separators=(",", ":")).encode(),
}.items():
    put("json", name, value)

for name, value in {
    "empty": b"",
    "manifest": manifest,
    "repeated": b"abc" * 10000,
}.items():
    put("gzip", name, gzip.compress(value, mtime=0))
    compressor = zlib.compressobj(wbits=-15)
    put("deflate", name, compressor.compress(value) + compressor.flush())

with io.BytesIO() as stream:
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in [
            ("package/package.json", manifest),
            ("package/binding.gyp", b"{\n  'targets': []\n}\n"),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(body))
    tar_bytes = stream.getvalue()
put("tar", "ordinary", tar_bytes)
put("tar", "repair-checksum", b"\x01" + tar_bytes)
put("artifact", "ordinary", gzip.compress(tar_bytes, mtime=0))
put("artifact", "repair-tar-and-repack", b"\x01" + tar_bytes)

put("lockfiles", "npm-v3", json.dumps(lock, separators=(",", ":")).encode())
put("lockfiles", "pnpm-v9", b"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\nsnapshots: {}\n")
put("lockfiles", "yarn-v1", b"# yarn lockfile v1\n\nseed@1:\n  version \"1\"\n")
put("ffi", "one-node", b"\x00")
put("ffi", "four-nodes", b"\x03\x00\x01\x02\x03")
for selector, name in enumerate(["lock", "manifest", "index", "approvals"]):
    put("review", name, bytes([selector]) + b"{}")
