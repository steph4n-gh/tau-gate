"""Collector compatibility checks independent of the Rust archive parser."""

import base64
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import npm_evidence


MANIFEST = b'{"name":"pkg","version":"1"}'


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return output.getvalue()


def check(raw):
    zipped = gzip.compress(raw, mtime=0)
    sri = "sha512-" + base64.b64encode(hashlib.sha512(zipped).digest()).decode()
    return npm_evidence.archive_facts(zipped, sri)


def checksum(header):
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode()


class CollectorCompatibility(unittest.TestCase):
    def test_single_nonpackage_root_and_printable_paths(self):
        raw = archive([
            ("node v24.12/package.json", MANIFEST),
            ("node v24.12/binding.gyp", b"native"),
            ("node v24.12/array/#/README.md~", b"other"),
        ])
        manifest_bytes, manifest, native, binding = check(raw)
        self.assertEqual(manifest_bytes, MANIFEST)
        self.assertEqual(manifest, {"name": "pkg", "version": "1"})
        self.assertTrue(native)
        self.assertEqual(binding, hashlib.sha256(b"native").hexdigest())

    def test_measured_timestamp_tail(self):
        raw = bytearray(archive([("cacheable-request/package.json", MANIFEST)]))
        raw[476:488] = b"14332753065\0"
        raw[488:500] = b"14332753065\0"
        checksum(memoryview(raw)[:512])
        self.assertEqual(check(raw)[0], MANIFEST)
        for offset in (345, 346, 475, 476):
            changed = raw.copy()
            changed[offset] = b"x"[0]
            checksum(memoryview(changed)[:512])
            with self.assertRaises(npm_evidence.EvidenceError):
                check(changed)

    def test_mixed_roots_and_lifecycle_aliases_fail(self):
        for entries in [
            [("json5/package.json", MANIFEST), ("other/readme", b"text")],
            [("json5/package.json", MANIFEST), ("JSON5/readme", b"text")],
            [("json5/Package.json", MANIFEST)],
            [("json5", MANIFEST)],
        ]:
            with self.subTest(entries=entries):
                with self.assertRaises(npm_evidence.EvidenceError):
                    check(archive(entries))

    def test_integrity_duplicates_parent_conflicts_and_padding_fail(self):
        for entries in [
            [("package/package.json", MANIFEST), ("package/package.json", MANIFEST)],
            [("package/package.json", MANIFEST), ("package/a", b"file"),
             ("package/a/b", b"child")],
        ]:
            with self.subTest(entries=entries):
                with self.assertRaises(npm_evidence.EvidenceError):
                    check(archive(entries))

        raw = bytearray(archive([("package/package.json", MANIFEST)]))
        raw[512 + len(MANIFEST)] = 1
        with self.assertRaises(npm_evidence.EvidenceError):
            check(raw)
        zipped = gzip.compress(archive([("package/package.json", MANIFEST)]), mtime=0)
        with self.assertRaises(npm_evidence.EvidenceError):
            npm_evidence.archive_facts(zipped, "sha512-" + base64.b64encode(bytes(64)).decode())


if __name__ == "__main__":
    unittest.main()
