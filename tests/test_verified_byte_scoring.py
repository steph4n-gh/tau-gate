"""Byte observations count as reported changes without becoming execution facts."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import qualification as q


class VerifiedByteScoring(unittest.TestCase):
    def event(self):
        return {'path':'node_modules/pkg','kind':'artifact_changed',
                'before':'a'*128,'after':'b'*128,'obligation':'package_change',
                'approval_relevant':False}

    def report(self):
        return {'status':'incomplete','execution_evidence_changes':[{
            'path':'node_modules/pkg',
            'before':{'state':'unsupported','facts':None,'approval_fingerprint':None,
                      'verified_artifact_sha512':'a'*128},
            'after':{'state':'unsupported','facts':None,'approval_fingerprint':None,
                     'verified_artifact_sha512':'b'*128}}]}

    def test_verified_changed_bytes_are_visible_but_comparison_stays_partial(self):
        result=q.compare_events([self.event()],self.report(),'partial')
        self.assertEqual(result['misses'],0)
        self.assertEqual(result['status'],'partial')

    def test_missing_or_wrong_observation_does_not_match(self):
        for value in [None,'c'*128]:
            report=self.report()
            report['execution_evidence_changes'][0]['after']['verified_artifact_sha512']=value
            self.assertEqual(q.compare_events([self.event()],report,'partial')['misses'],1)

    def test_observation_cannot_override_conflicting_qualified_facts(self):
        report=self.report()
        report['execution_evidence_changes'][0]['after']['facts']={'artifact_sha512':'c'*128}
        self.assertEqual(q.compare_events([self.event()],report,'partial')['misses'],1)


if __name__=='__main__':
    unittest.main()
