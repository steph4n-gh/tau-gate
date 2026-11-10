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
    return check_zipped(zipped)


def check_zipped(zipped, *, budget=None):
    sri = "sha512-" + base64.b64encode(hashlib.sha512(zipped).digest()).decode()
    return npm_evidence.archive_facts(zipped, sri, budget=budget)


def large_archive(*, extra=(), expanded_size=None, payload_name="package/blob.bin",
                  payload_size=65 * 1024 ** 2, alias_name=None, alias_last_byte=b"\0"):
    output = io.BytesIO()
    expanded = 0
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as zipped:
        def write(data):
            nonlocal expanded
            zipped.write(data)
            expanded += len(data)

        def entry(name, size):
            info = tarfile.TarInfo(name)
            info.size = size
            write(info.tobuf(format=tarfile.USTAR_FORMAT))

        entry("package/package.json", len(MANIFEST))
        write(MANIFEST + bytes(-len(MANIFEST) % 512))
        for name in [payload_name] + ([alias_name] if alias_name is not None else []):
            entry(name, payload_size)
            for offset in range(0, payload_size, 64 * 1024):
                size = min(64 * 1024, payload_size - offset)
                final = alias_last_byte if name == alias_name and offset + size == payload_size else b"\0"
                write(bytes(size - 1) + final)
            write(bytes(-payload_size % 512))
        for name, data in extra:
            entry(name, len(data))
            write(data + bytes(-len(data) % 512))
        write(bytes(1024))
        if expanded_size is not None:
            while expanded < expanded_size:
                write(bytes(min(64 * 1024, expanded_size - expanded)))
    return output.getvalue(), expanded


def checksum(header):
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode()


class CollectorCompatibility(unittest.TestCase):
    def test_zero_tar_tail_must_be_block_aligned(self):
        raw = archive([("package/package.json", MANIFEST)])
        self.assertEqual(check(raw + bytes(512))[0], MANIFEST)
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "block aligned"):
            check(raw + b"\0")

    def test_large_dot_alias_requires_complete_file_identity(self):
        for first, second in [("package/./blob.bin", "package/blob.bin"),
                              ("package/blob.bin", "package/./blob.bin")]:
            zipped, _ = large_archive(payload_name=first, payload_size=33 * 1024 ** 2,
                                      alias_name=second)
            self.assertEqual(check_zipped(zipped)[0], MANIFEST)
        zipped, _ = large_archive(payload_name="package/./blob.bin", payload_size=33 * 1024 ** 2,
                                  alias_name="package/blob.bin", alias_last_byte=b"x")
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "conflicting dot-alias"):
            check_zipped(zipped)

    def test_large_archive_and_exact_expanded_limit_qualify(self):
        zipped, expanded = large_archive(extra=[("package/binding.gyp", b"native")])
        budget = npm_evidence.WorkBudget(expanded=expanded, headers=3)
        manifest_bytes, manifest, native, binding = check_zipped(zipped, budget=budget)
        self.assertEqual(manifest_bytes, MANIFEST)
        self.assertEqual(manifest, {"name": "pkg", "version": "1"})
        self.assertTrue(native)
        self.assertEqual(binding, hashlib.sha256(b"native").hexdigest())
        self.assertEqual(budget.expanded_remaining, 0)
        self.assertEqual(budget.headers_remaining, 0)
        zipped, _ = large_archive(expanded_size=128 * 1024 ** 2)
        self.assertEqual(check_zipped(zipped)[0], MANIFEST)
        zipped, _ = large_archive(payload_name="package/binding.gyp", payload_size=64 * 1024 ** 2)
        self.assertEqual(check_zipped(zipped)[2:], (True, hashlib.sha256(bytes(64 * 1024 ** 2)).hexdigest()))

    def test_large_archive_tail_and_work_limits_remain_fail_closed(self):
        zipped, expanded = large_archive()
        bad_crc = bytearray(zipped)
        bad_crc[-8] ^= 1
        bad_size = bytearray(zipped)
        bad_size[-4] ^= 1
        malformed = [bad_crc, bad_size, zipped[:-1], zipped + b"x",
                     zipped + gzip.compress(b"", mtime=0),
                     large_archive(extra=[("package/package.json", MANIFEST)])[0]]
        for data in malformed:
            with self.subTest(tail=hashlib.sha256(data).hexdigest()):
                with self.assertRaises(npm_evidence.EvidenceError):
                    check_zipped(data)
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "snapshot expanded evidence"):
            check_zipped(zipped, budget=npm_evidence.WorkBudget(expanded=expanded - 1))
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "snapshot tar processing"):
            check_zipped(zipped, budget=npm_evidence.WorkBudget(headers=1))
        oversized, _ = large_archive(expanded_size=128 * 1024 ** 2 + 512)
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "decompressed limit"):
            check_zipped(oversized)
        binding, _ = large_archive(payload_name="package/binding.gyp")
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "binding.gyp"):
            check_zipped(binding)

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

    def test_identical_nonlifecycle_dot_alias_requires_exact_partner(self):
        for first, second in (("package/./dist/index.js", "package/dist/index.js"),
                              ("package/dist/index.js", "package/./dist/index.js")):
            with self.subTest(first=first):
                raw = archive([("package/package.json", MANIFEST), (first, b"same"), (second, b"same")])
                self.assertEqual(check(raw)[0], MANIFEST)
        for entries in (
            [("package/package.json", MANIFEST), ("package/./dist/index.js", b"first"),
             ("package/dist/index.js", b"later")],
            [("package/package.json", MANIFEST), ("package/./dist/index.js", b"same")],
            [("package/./package.json", MANIFEST), ("package/package.json", MANIFEST)],
            [("package/package.json", MANIFEST), ("package/./Dist/index.js", b"same"),
             ("package/dist/index.js", b"same")],
        ):
            with self.subTest(entries=entries):
                with self.assertRaises(npm_evidence.EvidenceError):
                    check(archive(entries))
        changed = bytearray(archive([("package/package.json", MANIFEST),
                                     ("package/./dist/index.js", b"same"),
                                     ("package/dist/index.js", b"same")]))
        changed[2048 + 100:2048 + 108] = b"0000755\0"
        checksum(memoryview(changed)[2048:2560])
        with self.assertRaisesRegex(npm_evidence.EvidenceError, "conflicting dot-alias"):
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
