import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import qualification as q


def archive(script):
    raw = json.dumps({"name": "example", "version": "1.0.0", "scripts": {"install": script}}).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
    return stream.getvalue()


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def fixture(self):
        files = {}
        archives = {}
        for commit, script in (("a" * 40, "echo before"), ("b" * 40, "echo after")):
            payload = archive(script)
            url = "https://registry.npmjs.org/example/-/example-" + commit[0] + ".tgz"
            archives[url] = payload
            integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
            lock = {"name": "project", "version": "1.0.0", "lockfileVersion": 3,
                    "packages": {"": {"name": "project", "version": "1.0.0", "dependencies": {"example": "1.0.0"}},
                                 "node_modules/example": {"version": "1.0.0", "resolved": url, "integrity": integrity, "hasInstallScript": True}}}
            directory = self.root / "discovery/owner/project" / commit
            directory.mkdir(parents=True)
            files[commit] = []
            for name, data in (("package-lock.json", lock), ("package.json", {"name": "project", "version": "1.0.0", "dependencies": {"example": "1.0.0"}})):
                raw = json.dumps(data).encode()
                (directory / name).write_bytes(raw)
                files[commit].append({"path": name, "sha256": q.digest(raw), "bytes": len(raw), "url": q.raw_url("owner/project", commit, name)})
        pair = {"id": "controlled", "repository": "owner/project", "base": "a" * 40, "head": "b" * 40, "files": files, "split": "development"}
        selection = {"projectCount": 1, "pairCount": 1, "pairs": [pair]}
        path = self.root / "corpus.json"
        q.save(path, selection)
        return path, pair, archives

    def acquire(self, fail=False):
        selection, pair, archives = self.fixture()
        args = argparse.Namespace(corpus=selection, sources=self.root / "sources", archive_cache=self.root / "archives",
                                  discovery_cache=self.root / "discovery", workers=2, max_bytes=1024 * 1024)
        def fetch(url):
            if fail:
                raise ValueError("declared unavailable artifact")
            return archives[url]
        with patch.object(q, "raw_source", return_value=None), patch.object(q.npm_evidence, "fetch_archive", side_effect=fetch):
            q.acquire(args)
        return args, pair

    def test_original_archive_is_preserved_and_verified_again_on_replay(self):
        args, pair = self.acquire()
        root = q.snapshot_path(args.sources, pair["repository"], pair["base"])
        receipt, hashes = q.verify_snapshot(root, pair["repository"], pair["base"], pair["files"][pair["base"]])
        self.assertEqual(receipt["status"], "complete")
        self.assertTrue(any(key.endswith(".tgz") for key in hashes))
        index = q.load(root / "evidence/index.json")
        artifact = next(item for item in index["packages"] if "artifact" in item)
        (root / "evidence" / artifact["artifact"]).write_bytes(b"substituted cached content")
        with self.assertRaisesRegex(ValueError, "SHA512 mismatch"):
            q.verify_snapshot(root, pair["repository"], pair["base"], pair["files"][pair["base"]])

    def test_unavailable_artifact_stays_missing_without_erasing_source_truth(self):
        args, pair = self.acquire(fail=True)
        root = q.snapshot_path(args.sources, pair["repository"], pair["base"])
        receipt, _ = q.verify_snapshot(root, pair["repository"], pair["base"], pair["files"][pair["base"]])
        self.assertEqual(receipt["status"], "partial")
        self.assertEqual(receipt["packages"]["node_modules/example"]["status"], "unavailable")
        self.assertEqual([item["path"] for item in q.load(root / "evidence/index.json")["packages"]], [""])

    def test_incomplete_core_still_exposes_defined_known_miss(self):
        expected = [{"path": "node_modules/example", "kind": "lifecycle_changed", "before": {"event": "install", "body": "echo before"}, "after": {"event": "install", "body": "echo after"}, "obligation": "execution_change", "approval_relevant": True}]
        comparison = q.compare_events(expected, {"status": "incomplete"}, "complete")
        self.assertEqual(comparison["status"], "partial")
        self.assertEqual(comparison["approval_relevant_misses"], 1)

    def test_unknown_truth_never_becomes_a_pass(self):
        result = q.compare_events([{"path": "node_modules/example", "kind": "unknown", "obligation": "execution_change"}], {"status": "complete"}, "partial")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["unknown"]), 1)
        self.assertEqual(result["misses"], 0)

    def test_source_change_without_install_script_requires_package_visibility(self):
        expected = [{"path": "node_modules/example", "kind": "source_changed", "before": "old", "after": "new", "obligation": "package_change", "approval_relevant": False}]
        result = q.compare_events(expected, {"status": "complete", "package_changes": [{"path": "node_modules/example", "changed_fields": ["source"], "before": {"source": "old"}, "after": {"source": "new"}}]}, "complete")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["matched"]), 1)

    def test_link_alias_does_not_duplicate_target_execution_facts(self):
        facts = {"head": {"packages": {"node_modules/workspace": {"status": "known", "scope": "link", "scripts": {}, "implicit_native": False},
                                           "workspace": {"status": "known", "scope": "workspace", "scripts": {"prepare": "echo ready"}, "implicit_native": False}}}}
        core_facts = {"lifecycle": {"prepare": q.script_hash("echo ready")}, "implicit_node_gyp": False}
        report = {"head": {"execution_evidence": [{"path": "node_modules/workspace", "facts": core_facts}, {"path": "workspace", "facts": core_facts}]}}
        self.assertEqual(q.compare_facts(facts, report), [])

    def test_reported_lifecycle_body_must_match_independent_event(self):
        event = {"path": "node_modules/example", "kind": "lifecycle_changed", "before": {"event": "install", "body": "before"},
                 "after": {"event": "install", "body": "after"}, "obligation": "execution_change", "approval_relevant": True}
        report = {"status": "complete", "execution_evidence_changes": [{"path": event["path"],
                  "before": {"facts": {"lifecycle": {"install": q.script_hash("before")}}},
                  "after": {"facts": {"lifecycle": {"install": q.script_hash("wrong")}}}}]}
        self.assertEqual(q.compare_events([event], report, "complete")["misses"], 1)
        report["execution_evidence_changes"][0]["after"]["facts"]["lifecycle"]["install"] = q.script_hash("after")
        self.assertEqual(q.compare_events([event], report, "complete")["misses"], 0)

    def test_complete_or_qualified_report_cannot_omit_known_facts(self):
        facts = {"head": {"packages": {"node_modules/example": {"status": "known", "scope": "archive", "scripts": {"install": "echo ready"}}}}}
        for report in ({"status": "complete"}, {"status": "incomplete", "head": {"status": "complete"}}, {"status": "incomplete", "head": {"execution_evidence": [{"path": "node_modules/example", "state": "qualified", "facts": None}]}}):
            with self.subTest(report=report):
                mismatch = q.compare_facts(facts, report)
                self.assertEqual(len(mismatch), 1)
                self.assertEqual(mismatch[0]["field"], "facts")
                self.assertIsNone(mismatch[0]["actual"])

    def test_unsupported_or_unknown_facts_remain_unassessed(self):
        facts = {"head": {"packages": {"node_modules/example": {"status": "known", "scope": "archive", "scripts": {"install": "echo ready"}}}}}
        report = {"status": "incomplete", "head": {"execution_evidence": [{"path": "node_modules/example", "state": "unsupported", "facts": None}]}}
        self.assertEqual(q.compare_facts(facts, report), [])
        facts["head"]["packages"]["node_modules/example"]["status"] = "unknown"
        self.assertEqual(q.compare_facts(facts, {"status": "complete"}), [])

    def test_added_and_removed_events_require_available_package_identity(self):
        identity = {"name": "example", "version": "1.0.0", "source": "https://registry.npmjs.org/example.tgz", "integrity": "sha512-reviewed"}
        for kind, side in (("added", "after"), ("removed", "before")):
            event = {"path": "node_modules/example", "kind": kind, "before": None, "after": None, "obligation": "package_change", "approval_relevant": True}
            event[side] = {"status": "known", "scope": "archive", **identity}
            for field in identity:
                with self.subTest(kind=kind, field=field):
                    wrong = {**identity, field: "wrong"}
                    report = {"status": "complete", "package_changes": [{"path": event["path"], "change": kind, side: wrong}]}
                    self.assertEqual(q.compare_events([event], report, "complete")["misses"], 1)
            report = {"status": "complete", "package_changes": [{"path": event["path"], "change": kind, side: identity}]}
            self.assertEqual(q.compare_events([event], report, "complete")["misses"], 0)

    def test_unknown_identity_fields_are_not_empty_string_requirements(self):
        event = {"path": "node_modules/example", "kind": "added", "before": None, "after": {"status": "unknown", "name": None, "version": "1.0.0", "source": None, "integrity": None}, "obligation": "package_change", "approval_relevant": False}
        report = {"status": "incomplete", "package_changes": [{"path": event["path"], "change": "added", "after": {"name": "example", "version": "1.0.0", "source": "", "integrity": ""}}]}
        result = q.compare_events([event], report, "partial")
        self.assertEqual(result["misses"], 0)
        self.assertEqual(result["status"], "partial")

    def test_subprocess_deadline_covers_descendant_streams_after_parent_exit(self):
        marker = self.root / "orphan-finished"
        child = f"import pathlib,time; time.sleep(2); pathlib.Path({str(marker)!r}).write_text('orphan')"
        parent = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {child!r}])"
        started = time.monotonic()
        result = q.run_bounded([sys.executable, "-c", parent], self.root / "descendant", 0.05)
        self.assertEqual(result["termination"], "timeout")
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertFalse(marker.exists())
        self.assertEqual(set(result["output_sha256"]), {"stdout", "stderr"})
        time.sleep(2.1)
        self.assertFalse(marker.exists())

    def test_subprocess_deadline_covers_descendants_without_inherited_streams(self):
        child = "import time; time.sleep(2)"
        parent = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {child!r}], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
        result = q.run_bounded([sys.executable, "-c", parent], self.root / "closed-streams", 0.05)
        self.assertEqual(result["termination"], "timeout")
        self.assertLess(result["elapsed_seconds"], 1.0)

    def test_output_limit_kills_descendants_and_preserves_bounded_bytes(self):
        marker = self.root / "output-orphan-finished"
        child = f"import pathlib,time; time.sleep(0.5); pathlib.Path({str(marker)!r}).write_text('orphan')"
        parent = f"import subprocess,sys; subprocess.Popen([sys.executable, '-c', {child!r}]); sys.stdout.write('x' * 131072); sys.stdout.flush()"
        with patch.object(q, "MAX_OUTPUT", 1024):
            result = q.run_bounded([sys.executable, "-c", parent], self.root / "excess", 2)
        self.assertEqual(result["termination"], "output_limit")
        self.assertEqual(result["output_bytes"]["stdout"], 1024)
        self.assertEqual((self.root / "excess/stdout.bin").read_bytes(), b"x" * 1024)
        time.sleep(0.6)
        self.assertFalse(marker.exists())

    def test_subprocess_memory_metric_is_separate_from_raw_output(self):
        result = q.run_bounded([sys.executable, "-c", "print('complete')"], self.root / "memory", 2)
        self.assertEqual(result["termination"], "exited")
        self.assertEqual((self.root / "memory/stdout.bin").read_text(), "complete\n")
        if result["peak_rss_measurement"] is not None:
            self.assertGreater(result["peak_rss_bytes"], 0)
            self.assertTrue((self.root / "memory/process-metrics.txt").exists())

    def test_summary_keeps_absent_receipts_in_denominator(self):
        data = {"pairs": [{"id": "present"}, {"id": "missing"}]}
        q.save(self.root / "cases/present/receipt.json", {"case_id": "present", "core": {"status": "complete"}, "comparison": {"status": "complete", "misses": 0}})
        counts = q.summarize_data(data, self.root)["counts"]
        self.assertEqual(counts["frozen_pairs"], 2)
        self.assertEqual(counts["receipts"], 1)
        self.assertEqual(counts["core_complete_pairs"], 1)
        self.assertEqual(counts["complete_pairs"], 0)
        self.assertEqual(counts["unknown_comparison_pairs"], 1)

    def test_subprocess_timeout_is_a_resource_outcome(self):
        started = time.monotonic()
        result = q.run_bounded([sys.executable, "-c", "import time; time.sleep(2)"], self.root / "run", 0.02)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(result["termination"], "timeout")
        self.assertEqual(result["program_argv"][0], sys.executable)
        self.assertTrue((self.root / "run/stdout.bin").exists())

    def test_frozen_source_mismatch_is_rejected_before_use(self):
        selection, pair, _ = self.fixture()
        lock = self.root / "discovery/owner/project" / pair["base"] / "package-lock.json"
        lock.write_bytes(b"{}")
        budget = q.Budget(1024 * 1024)
        with patch.object(q, "raw_source", return_value=None):
            _, _, source = q.capture_revision(pair["repository"], pair["base"], pair["files"][pair["base"]], self.root / "sources", self.root / "discovery", budget)
        self.assertEqual(source["status"], "partial")
        self.assertTrue(any("hash mismatch" in item["reason"] for item in source["issues"]))


if __name__ == "__main__":
    unittest.main()
