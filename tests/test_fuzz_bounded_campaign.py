import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import fuzz_bounded_campaign as campaign


class BoundedCampaignTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.seeds = self.root / 'seeds'
        self.seeds.mkdir()
        (self.seeds / 'original').write_bytes(b'original')
        self.binary = self.root / 'fake-target'

    def target(self, body):
        self.binary.write_text('#!' + sys.executable + '\n' + body)
        self.binary.chmod(0o755)

    def test_windows_keep_limits_corpus_and_real_work_observation(self):
        self.target('''import os,sys
from pathlib import Path
assert os.environ['ASAN_OPTIONS']=='detect_odr_violation=0'
assert all(flag in sys.argv for flag in ['-max_len=65536','-timeout=2','-rss_limit_mb=512','-max_total_time=5'])
corpus=Path(sys.argv[-1])
state=corpus/'visited'
count=int(state.read_text())+1 if state.exists() else 1
state.write_text(str(count))
print('#1 INITED cov:1',file=sys.stderr)
print('stat::number_of_executed_units: 3',file=sys.stderr)
''')
        output = self.root / 'output'
        receipt = campaign.run(self.binary, self.seeds, output)
        self.assertEqual(receipt['status'], 'passed_bounded_windows')
        self.assertEqual(len(receipt['windows']), 12)
        self.assertEqual(receipt['total_mutation_units_after_initialization'], 24)
        self.assertEqual((output / 'corpus/visited').read_text(), '12')
        self.assertEqual((self.seeds / 'original').read_bytes(), b'original')
        self.assertEqual(len(list(self.seeds.iterdir())), 1)

    def test_failed_child_stops_and_retains_its_artifact(self):
        self.target('''import sys
from pathlib import Path
folder=next(v.split('=',1)[1] for v in sys.argv if v.startswith('-artifact_prefix='))
Path(folder,'oom-input').write_bytes(b'bad input')
print('#1 INITED cov:1',file=sys.stderr)
print('stat::number_of_executed_units: 3',file=sys.stderr)
sys.exit(71)
''')
        output = self.root / 'output'
        receipt = campaign.run(self.binary, self.seeds, output)
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(len(receipt['windows']), 1)
        self.assertEqual(receipt['windows'][0]['process']['exit_code'], 71)
        self.assertEqual(receipt['windows'][0]['artifact_sha256'],
                         {'oom-input': hashlib.sha256(b'bad input').hexdigest()})
        self.assertFalse((output / 'window-02').exists())
        self.assertEqual(json.loads((output / 'receipt.json').read_bytes())['status'], 'failed')

    def test_successful_exit_without_work_is_not_a_pass(self):
        self.target('pass\n')
        receipt = campaign.run(self.binary, self.seeds, self.root / 'output')
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(len(receipt['windows']), 1)


if __name__ == '__main__':
    unittest.main()
