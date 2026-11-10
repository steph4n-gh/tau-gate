import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "docs/examples/npm-pr-review.yml"


def review_step():
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index("      - name: Review exact snapshots and trusted maintainer comments")
    start = lines.index("        run: |", start) + 1
    end = lines.index("      - name: Preserve review reports", start)
    return textwrap.dedent("\n".join(lines[start:end])) + "\n"


class GitHubWorkflowTests(unittest.TestCase):
    def run_review(self, approved):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            scripts = temp / "npm-review-repository/tools"
            scripts.mkdir(parents=True)
            (scripts / "pr_review.py").write_text(textwrap.dedent("""\
                import json
                from pathlib import Path
                import sys

                args = sys.argv
                output = Path(args[args.index('--output') + 1])
                output.mkdir()
                allowed = output.name == 'npm-review-report'
                (output / 'report.json').write_text(json.dumps({
                    'outcome': 'allowed' if allowed else 'blocked',
                    'approval_request': None if allowed else {'subject_sha256': 'a' * 64},
                }))
                (output / 'summary.md').write_text('allowed' if allowed else 'blocked')
                print('{}')
                sys.exit(0 if allowed or '--approve-subject' in args else 1)
                """))
            (scripts / "github_pr_approval.py").write_text(textwrap.dedent("""\
                import os
                import sys

                sys.exit(0 if os.environ['TEST_APPROVED'] == '1' else 1)
                """))
            step = temp / "review-step.sh"
            step.write_text(review_step())
            summary = temp / "step-summary.md"
            summary.touch()
            environment = {**os.environ, "RUNNER_TEMP": str(temp),
                           "GITHUB_STEP_SUMMARY": str(summary), "BASE_COMMIT": "b" * 40,
                           "HEAD_COMMIT": "c" * 40, "REPOSITORY": "example/project",
                           "PR_NUMBER": "7", "TEST_APPROVED": "1" if approved else "0"}
            result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(step)],
                                    env=environment, capture_output=True, text=True, check=False)
            report = json.loads((temp / "npm-review-report/report.json").read_text())
            expected = "allowed" if approved else "blocked"
            self.assertEqual(result.returncode, 0 if approved else 1, result.stderr)
            self.assertEqual(report["outcome"], expected)
            self.assertEqual(summary.read_text(), expected)

    def test_expected_block_preserves_report_under_bash_errexit(self):
        self.run_review(False)

    def test_approval_completes_under_bash_errexit(self):
        self.run_review(True)


if __name__ == "__main__":
    unittest.main()
