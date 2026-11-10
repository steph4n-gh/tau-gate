"""Root version metadata is distinct from registry/workspace package identity."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import npm_evidence as collector
import qualification_oracle as oracle
from pr_review import summary


class RootSourceMetadata(unittest.TestCase):
    def test_markdown_keeps_qualified_source_disagreement_visible(self):
        report = {"outcome": "advisory", "base": None, "head": None, "policy": None, "errors": [],
                  "core": {"base": {"execution_evidence": [{"state": "qualified", "path": "", "reason": 'source version "2" differs from locked version "1" <tag>'}]}}}
        text = summary(report)
        self.assertIn('Note base evidence', text)
        self.assertIn('source version "2" differs from locked version "1" &lt;tag&gt;', text)
        self.assertNotIn("Incomplete input reasons", text)

    def test_root_source_version_may_differ_without_changing_locked_identity_events(self):
        record = {"name": "app", "version": "1"}
        manifest = {"name": "app", "version": "2", "scripts": {"install": "echo observed"}}
        collector.check_identity("", record, manifest)
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            facts = []
            for locked in ("1", "2"):
                lock = {"lockfileVersion": 3, "packages": {"": {**record, "version": locked}}}
                lock_bytes = json.dumps(lock).encode()
                (directory / "lock.json").write_bytes(lock_bytes)
                (directory / "package.json").write_bytes(json.dumps(manifest).encode())
                index = {"schema_version": 1, "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
                         "packages": [{"path": "", "project_manifest": "package.json"}]}
                (directory / "index.json").write_bytes(json.dumps(index).encode())
                facts.append(oracle.snapshot_facts(directory / "lock.json", directory / "index.json", directory / "package.json"))
            self.assertEqual(facts[0]["status"], "complete")
            self.assertEqual(facts[0]["packages"][""]["version"], "1")
            self.assertEqual(facts[0]["packages"][""]["source_manifest_version"], "2")
            self.assertIn("root_version_metadata_disagreement", facts[0]["packages"][""]["profile_conditions"])
            changed = [e for e in oracle.events(*facts) if e["kind"] == "version_changed"]
            self.assertEqual([(e["before"], e["after"]) for e in changed], [("1", "2")])

    def test_only_nonempty_root_version_strings_have_this_distinction(self):
        record = {"name": "app", "version": "1"}
        invalid = [{"name": "other", "version": "2"}, {"name": "app"}]
        invalid += [{"name": "app", "version": version} for version in ("", None, 2, True)]
        for manifest in invalid:
            with self.subTest(manifest=manifest):
                with self.assertRaises(collector.EvidenceError):
                    collector.check_identity("", record, manifest)
                with self.assertRaises(oracle.OracleError):
                    oracle._manifest(json.dumps(manifest).encode(), None, "root", record, "")
        for path, scope in [("packages/local", "workspace"), ("node_modules/app", "archive")]:
            with self.assertRaises(collector.EvidenceError):
                collector.check_identity(path, record, {"name": "app", "version": "2"})
            with self.assertRaises(oracle.OracleError):
                oracle._manifest(b'{"name":"app","version":"2"}', None, scope, record, path)
        for locked in ("", None, 1, True):
            with self.assertRaises(collector.EvidenceError):
                collector.check_identity("", {"name": "app", "version": locked}, {"name": "app", "version": "2"})
            with self.assertRaises(oracle.OracleError):
                oracle._manifest(b'{"name":"app","version":"2"}', None, "root", {"name": "app", "version": locked}, "")

    def test_root_dependency_maps_remain_strict(self):
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            manifest = {"name": "app", "version": "2", field: {"dep": "2"}}
            record = {"name": "app", "version": "1", field: {"dep": "1"}}
            with self.assertRaises(collector.EvidenceError):
                collector.check_identity("", record, manifest)
            with self.assertRaises(oracle.OracleError):
                oracle._manifest(json.dumps(manifest).encode(), None, "root", record, "")


if __name__ == "__main__":
    unittest.main()
