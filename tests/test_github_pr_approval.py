import unittest

from tools.github_pr_approval import ApprovalError, approval_comment, rerun_target


SUBJECT = "a" * 64
BASE = "b" * 40
HEAD = "c" * 40
REPO = "example/project"


class FakeGitHub:
    def __init__(self):
        self.pr = {
            "state": "open", "base": {"sha": BASE, "repo": {"full_name": REPO}},
            "head": {"sha": HEAD}, "user": {"id": 1},
        }
        self.comments = []
        self.permissions = {}
        self.runs = []

    def request(self, path, method="GET", allow_404=False):
        if path == f"repos/{REPO}/pulls/7":
            return self.pr
        if path.startswith(f"repos/{REPO}/collaborators/"):
            return self.permissions.get(path.split("/")[4])
        if path.startswith(f"repos/{REPO}/actions/workflows/"):
            return {"workflow_runs": self.runs}
        raise AssertionError(path)

    def pages(self, path):
        assert path == f"repos/{REPO}/issues/7/comments"
        yield from self.comments


def report():
    return {"outcome": "blocked", "errors": [], "approval_request": {
        "subject_sha256": SUBJECT, "base_commit": BASE, "head_commit": HEAD,
    }}


def comment(user_id, login, body=None):
    return {"id": 11, "user": {"id": user_id, "login": login, "type": "User"},
            "body": body if body is not None else f"tau-gate approve {SUBJECT}"}


def event(action="created", body=None):
    return {"action": action, "repository": {"full_name": REPO},
            "issue": {"number": 7, "pull_request": {"url": "https://api.github.com/pulls/7"}},
            "comment": comment(2, "reviewer", body)}


class GitHubApprovalTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHub()
        self.api.permissions["reviewer"] = {"permission": "write", "user": {"id": 2}}

    def test_exact_comment_from_different_writer_approves_current_head(self):
        self.api.comments = [comment(1, "author"), comment(3, "outsider"), comment(2, "reviewer")]
        self.api.permissions["author"] = {"permission": "admin", "user": {"id": 1}}
        self.api.permissions["outsider"] = None
        self.assertEqual(approval_comment(self.api, REPO, 7, report()), 11)

    def test_old_head_and_incomplete_report_cannot_approve(self):
        self.api.comments = [comment(2, "reviewer")]
        self.api.pr["head"]["sha"] = "d" * 40
        with self.assertRaises(ApprovalError):
            approval_comment(self.api, REPO, 7, report())
        self.api.pr["head"]["sha"] = HEAD
        old = report()
        old["outcome"] = "incomplete"
        with self.assertRaises(ApprovalError):
            approval_comment(self.api, REPO, 7, old)

    def test_quoted_wrong_subject_and_read_only_comment_do_not_approve(self):
        self.api.comments = [comment(2, "reviewer", f"> tau-gate approve {SUBJECT}"),
                             comment(3, "outsider"), comment(2, "reviewer", "tau-gate approve " + "d" * 64)]
        self.api.permissions["outsider"] = {"permission": "read", "user": {"id": 3}}
        self.assertIsNone(approval_comment(self.api, REPO, 7, report()))

    def test_bot_with_write_access_does_not_approve(self):
        bot = comment(2, "reviewer")
        bot["user"]["type"] = "Bot"
        self.api.comments = [bot]
        self.assertIsNone(approval_comment(self.api, REPO, 7, report()))

    def test_comment_change_reruns_only_exact_current_pr_check(self):
        self.api.runs = [{"id": 99, "event": "pull_request_target", "status": "completed", "head_sha": HEAD,
                          "pull_requests": [{"number": 7, "head": {"sha": HEAD}, "base": {"sha": BASE}}]}]
        self.assertEqual(rerun_target(self.api, event(), REPO), 99)
        edited = event("edited", "I revoke approval")
        edited["changes"] = {"body": {"from": f"tau-gate approve {SUBJECT}"}}
        self.assertEqual(rerun_target(self.api, edited, REPO), 99)
        self.assertEqual(rerun_target(self.api, event("deleted", ""), REPO), 99)

    def test_author_or_stale_run_cannot_rerun_as_approval(self):
        self.api.runs = [{"id": 99, "event": "pull_request_target", "status": "completed", "head_sha": HEAD,
                          "pull_requests": [{"number": 7, "head": {"sha": HEAD}, "base": {"sha": "d" * 40}}]}]
        own = event()
        own["comment"]["user"] = {"id": 1, "login": "author", "type": "User"}
        self.assertIsNone(rerun_target(self.api, own, REPO))
        with self.assertRaises(ApprovalError):
            rerun_target(self.api, event(), REPO)


if __name__ == "__main__":
    unittest.main()
