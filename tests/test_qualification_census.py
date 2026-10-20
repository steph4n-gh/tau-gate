import gzip
import io
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import qualification_census as census


class CensusTests(unittest.TestCase):
    def setUp(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo("package/package.json")
            member.size = 2
            archive.addfile(member, io.BytesIO(b"{}"))
        self.tar = stream.getvalue()
        self.gzip = gzip.compress(self.tar, mtime=0)

    def test_independent_expansion_and_member_counts(self):
        result = census.archive(self.gzip)
        self.assertEqual(result["gzip_status"], "valid")
        self.assertEqual(result["produced_bytes"], len(gzip.decompress(self.gzip)))
        self.assertEqual(result["compressed_bytes"], len(self.gzip))
        self.assertEqual(result["raw_tar_headers"], 1)
        self.assertEqual(result["logical_tar_members"], 1)

    def test_failed_crc_still_charges_produced_bytes(self):
        changed = bytearray(self.gzip)
        changed[-8] ^= 1
        result = census.archive(changed)
        self.assertEqual(result["gzip_status"], "invalid")
        self.assertEqual(result["produced_bytes"], len(self.tar))
        self.assertTrue(result["produced_bytes_exact"])

    def test_expansion_bound_is_a_lower_bound(self):
        with patch.object(census, "LIMIT", 1024):
            result = census.archive(gzip.compress(b"x" * 2048, mtime=0))
        self.assertEqual(result["produced_bytes"], 1025)
        self.assertFalse(result["produced_bytes_exact"])
        self.assertEqual(result["gzip_status"], "invalid")
        self.assertFalse(result["raw_tar_headers_exact"])

    def test_truncation_is_not_a_valid_archive(self):
        result = census.archive(self.gzip[:-12])
        self.assertEqual(result["gzip_status"], "invalid")


if __name__ == "__main__":
    unittest.main()
