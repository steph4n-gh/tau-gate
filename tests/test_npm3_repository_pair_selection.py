"""The qualification selector must not count one repository repeatedly."""

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import npm3_sprint_pairs as pairs
import qualification as q


class RepositoryPairSelection(unittest.TestCase):
    def test_one_eligible_pair_per_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cohort = root / "cohort.json"
            snapshots = root / "snapshots.json"
            q.save(cohort, {"repositories": [
                {"rank": rank, "resolution": {"repository": repo, "host": "github.com"}}
                for rank, repo in enumerate(("owner/first", "owner/second"), 1)]})
            q.save(snapshots, {"snapshots": [
                {"repository": repo, "commit": "snapshot", "lockfiles": ["package-lock.json"]}
                for repo in ("owner/first", "owner/second")]})

            def history(repository, commit, lockfile, receipt):
                return [{"sha": f"{repository[-5:]}-head-{index}",
                         "parents": [{"sha": f"{repository[-5:]}-base-{index}"}],
                         "commit": {"committer": {"date": f"2026-01-0{index}T00:00:00Z"}}}
                        for index in (2, 1)]

            def source_file(repository, commit, repository_path, destination, budget):
                destination.parent.mkdir(parents=True, exist_ok=True)
                value = ({"lockfileVersion": 3, "packages": {"": {
                    "name": "root", "version": "2" if "head" in commit else "1"}}}
                         if repository_path.endswith("package-lock.json") else {"name": "root"})
                raw = json.dumps(value).encode()
                destination.write_bytes(raw)
                return {"status": "captured", "bytes": len(raw)}

            with patch.object(pairs, "history", history), patch.object(pairs, "source_file", source_file):
                output = root / "unique"
                pairs.freeze(SimpleNamespace(output=output, cohort=cohort, snapshots=snapshots,
                                             count=2, one_pair_per_repository=True))
            selected = q.load(output / "selection.json")
            self.assertEqual([row["repository"] for row in selected["pairs"]],
                             ["owner/first", "owner/second"])
            self.assertEqual(selected["projectCount"], 2)
            self.assertEqual(q.load(output / "protocol.json"), pairs.REPOSITORY_PROTOCOL)

    def test_conditional_completion_counts_only_oracle_valid_pairs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            q.save(output / "protocol.json", pairs.REPOSITORY_PROTOCOL)
            q.save(output / "selection.json", {"pairs": [{"id": "valid", "repository": "a/b"},
                                                         {"id": "unknown", "repository": "c/d"}],
                                                "attempts": [], "target_eligible_pairs": 2})
            q.save(output / "labels.json", {"cases": [{"id": "valid", "status": "complete",
                                                         "unknown_packages": {"base": 0, "head": 0}},
                                                        {"id": "unknown", "status": "partial",
                                                         "unknown_packages": {"base": 1, "head": 1}}]})
            receipts = []
            for case_id, processing_complete in (("valid", False), ("unknown", True)):
                receipts.append({"id": case_id, "processing_complete": processing_complete,
                                 "report_status": "incomplete", "policy_outcome": "incomplete",
                                 "unexpected_allowed_outcome": 0,
                                 "run": {"elapsed_seconds": 1, "peak_rss_bytes": 1,
                                         "output_sha256": {"stdout": case_id}},
                                 "comparison": {"matched": [], "misses": 0,
                                                "approval_relevant_misses": 0, "fact_mismatches": []}})
            with patch.object(pairs, "render_html"):
                pairs.summarize(output, q.load(output / "selection.json"),
                                q.load(output / "labels.json"), receipts)
            summary = q.load(output / "summary.json")
            self.assertEqual(summary["independent_labels_complete"], 1)
            self.assertEqual(summary["conditional_complete"], 0)
            self.assertEqual(summary["conditional_completion_fraction"], 0)
            self.assertFalse(summary["conditional_completion_floor_met"])


if __name__ == "__main__":
    unittest.main()
