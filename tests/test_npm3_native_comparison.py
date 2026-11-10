"""Behavioral checks for the independent native-comparison observer."""

import gzip
import io
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from npm3_native_comparison import CASES, fixture


class NativeComparisonObserverTests(unittest.TestCase):
    def test_expected_manifest_bytes_are_original_archive_bytes(self):
        for case in CASES:
            with self.subTest(case=case.name):
                package = fixture(case)
                with tarfile.open(fileobj=io.BytesIO(gzip.decompress(package["archive"]))) as archive:
                    actual = archive.extractfile("package/package.json").read()
                self.assertEqual(package["manifest_bytes"], actual)


if __name__ == "__main__":
    unittest.main()
