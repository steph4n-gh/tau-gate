"""Scientific helper regressions; run in the external math-reference environment."""
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
AVAILABLE = all(importlib.util.find_spec(name) for name in ['numpy', 'scipy', 'yaml'])
if AVAILABLE:
    from math_full_comparison import canonical_partition


@unittest.skipUnless(AVAILABLE, 'requires the optional external math-reference dependencies')
class PartitionChanges(unittest.TestCase):
    def test_added_record_in_either_half_changes_the_partition(self):
        before = canonical_partition({'a', 'b'}, {'a'})
        self.assertNotEqual(before, canonical_partition({'a', 'b', 'c'}, {'a'}))
        self.assertNotEqual(before, canonical_partition({'a', 'b', 'c'}, {'a', 'c'}))

    def test_relabelled_record_in_other_half_is_not_discarded(self):
        self.assertNotEqual(canonical_partition({'a', 'b'}, {'a'}),
                            canonical_partition({'a', 'c'}, {'a'}))

    def test_side_complement_flip_does_not_create_an_alert(self):
        self.assertEqual(canonical_partition({'a', 'b', 'c'}, {'a'}),
                         canonical_partition({'a', 'b', 'c'}, {'b', 'c'}))


if __name__ == '__main__':
    unittest.main()
