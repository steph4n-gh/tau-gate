"""Collector compatibility checks independent of the Rust archive parser."""

import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
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
        corrupt = bytearray(zipped)
        corrupt[-8] ^= 1
        with self.assertRaises(npm_evidence.EvidenceError):
            npm_evidence.archive_facts(
                corrupt,
                "sha512-" + base64.b64encode(hashlib.sha512(corrupt).digest()).decode(),
            )

    def test_failed_and_repeated_reads_and_archive_work_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source"
            path.write_bytes(b"12345")
            budget = npm_evidence.WorkBudget(read=10)
            self.assertEqual(npm_evidence.read_limited(path, 5, budget=budget), b"12345")
            with self.assertRaisesRegex(npm_evidence.EvidenceError, "file exceeds"):
                npm_evidence.read_limited(path, 4, budget=budget)
            self.assertEqual(budget.read_remaining, 0)
            with self.assertRaisesRegex(npm_evidence.EvidenceError, "snapshot evidence reads"):
                npm_evidence.read_limited(path, 5, budget=budget)
            self.assertEqual(path.read_bytes(), b"12345")

        raw = archive([("package/package.json", MANIFEST)])
        zipped = gzip.compress(raw, mtime=0)
        sri = "sha512-" + base64.b64encode(hashlib.sha512(zipped).digest()).decode()
        budget = npm_evidence.WorkBudget(expanded=len(raw), headers=1)
        self.assertEqual(npm_evidence.archive_facts(zipped, sri, budget=budget)[0], MANIFEST)
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "snapshot expanded evidence"):
            npm_evidence.archive_facts(zipped, sri, budget=budget)
        budget = npm_evidence.WorkBudget(headers=1)
        two = archive([("package/package.json", MANIFEST), ("package/readme", b"text")])
        zipped = gzip.compress(two, mtime=0)
        sri = "sha512-" + base64.b64encode(hashlib.sha512(zipped).digest()).decode()
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "snapshot tar processing"):
            npm_evidence.archive_facts(zipped, sri, budget=budget)
        bad_crc = bytearray(zipped)
        bad_crc[-8] ^= 1
        bad_sri = "sha512-" + base64.b64encode(hashlib.sha512(bad_crc).digest()).decode()
        budget = npm_evidence.WorkBudget(expanded=npm_evidence.MAX_FILE)
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "snapshot expanded evidence"):
            npm_evidence.archive_facts(bad_crc, bad_sri, budget=budget)
        self.assertEqual(budget.expanded_remaining, 0)

    def test_lock_counts_stop_before_evidence_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "package-lock.json"
            packages = {"": {}}
            packages.update({f"node_modules/p{n}": {} for n in range(10_000)})
            path.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
            with self.assertRaisesRegex(npm_evidence.EvidenceError, "10000 package records"):
                npm_evidence.load_lock(path)
            root = {"dependencies": {f"p{n}": "1" for n in range(50_001)}}
            path.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": root}}))
            with self.assertRaisesRegex(npm_evidence.EvidenceError, "50000 dependency references"):
                npm_evidence.load_lock(path)


if __name__ == "__main__":
    unittest.main()
