"""Locked identity and actual root source version are independent observations."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import qualification as q


class SourceVersionComparison(unittest.TestCase):
    def compare(self, actual):
        facts = {'base': {'packages': {'': {'status': 'known', 'scope': 'root',
                    'version': '1.0.0', 'scripts': {}, 'source_manifest_version': '2.0.0'}}}}
        report = {'base': {'execution_evidence': [{'path': '', 'state': 'qualified',
                    'facts': {'version': actual, 'lifecycle': {}}}]}}
        return q.compare_facts(facts, report)

    def test_actual_manifest_version_is_checked_separately_from_locked_version(self):
        self.assertEqual(self.compare('2.0.0'), [])
        mismatches = self.compare('1.0.0')
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0]['field'], 'source_manifest_version')
        self.assertEqual(mismatches[0]['expected'], '2.0.0')
        self.assertEqual(mismatches[0]['actual'], '1.0.0')


if __name__ == '__main__':
    unittest.main()
