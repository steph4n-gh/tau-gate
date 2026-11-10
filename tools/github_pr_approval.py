#!/usr/bin/env python3
"""Read exact Tau-Gate approval comments and rerun their trusted PR check."""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


SUBJECT = re.compile(r"[0-9a-f]{64}\Z")
APPROVAL = re.compile(r"tau-gate approve ([0-9a-f]{64})\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
MAX_PAGES = 10
MAX_RESPONSE = 4 * 1024 * 1024


class ApprovalError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class GitHub:
    def __init__(self, token):
        if not token:
            raise ApprovalError("GITHUB_TOKEN is required")
        self.token = token

    def request(self, path, method="GET", allow_404=False):
        request = urllib.request.Request(
            "https://api.github.com/" + path,
            data=b"" if method == "POST" else None,
            method=method,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
                data = response.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise ApprovalError("GitHub response exceeded 4 MiB")
                if not data:
                    return None
                return json.loads(data)
        except urllib.error.HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            raise ApprovalError(f"GitHub API returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, ValueError) as exc:
            raise ApprovalError("GitHub API response was unavailable or invalid") from exc

    def pages(self, path):
        for page in range(1, MAX_PAGES + 1):
            values = self.request(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
            if not isinstance(values, list):
                raise ApprovalError("GitHub API list response was invalid")
            yield from values
            if len(values) < 100:
                return
        raise ApprovalError("GitHub API list exceeded 1,000 records")


def repository_name(value):
    if not REPOSITORY.fullmatch(value) or ".." in value.split("/"):
        raise ApprovalError("repository must be owner/name")
    return value


def exact_pr(api, repository, number, base, head):
    pr = api.request(f"repos/{repository}/pulls/{number}")
    if (not isinstance(pr, dict) or pr.get("state") != "open"
            or pr.get("base", {}).get("sha") != base
            or pr.get("head", {}).get("sha") != head
            or pr.get("base", {}).get("repo", {}).get("full_name", "").lower() != repository.lower()):
        raise ApprovalError("pull request is not open at the reviewed base and head")
    return pr


def writer(api, repository, user):
    login = user.get("login") if isinstance(user, dict) else None
    if (not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9-]+", login)
            or user.get("type") != "User" or type(user.get("id")) is not int):
        return False
    permission = api.request(f"repos/{repository}/collaborators/{login}/permission", allow_404=True)
    return (isinstance(permission, dict)
            and permission.get("user", {}).get("id") == user.get("id")
            and permission.get("permission") in ("write", "maintain", "admin"))


def approval_comment(api, repository, number, report):
    request = report.get("approval_request") or {}
    subject = request.get("subject_sha256")
    if (report.get("outcome") != "blocked" or not isinstance(subject, str)
            or not SUBJECT.fullmatch(subject) or report.get("errors")):
        raise ApprovalError("review has no complete blocked approval request")
    pr = exact_pr(api, repository, number, request.get("base_commit"), request.get("head_commit"))
    author_id = pr.get("user", {}).get("id")
    if type(author_id) is not int:
        raise ApprovalError("pull request author is invalid")
    for comment in api.pages(f"repos/{repository}/issues/{number}/comments"):
        user = comment.get("user") if isinstance(comment, dict) else None
        if (isinstance(comment, dict) and (comment.get("body") or "").strip() == f"tau-gate approve {subject}"
                and isinstance(user, dict) and user.get("id") != author_id
                and writer(api, repository, user)):
            if type(comment.get("id")) is not int:
                raise ApprovalError("trusted approval comment ID is invalid")
            return comment["id"]
    return None


def rerun_target(api, event, repository):
    if (event.get("action") not in ("created", "edited", "deleted")
            or event.get("repository", {}).get("full_name", "").lower() != repository.lower()
            or not event.get("issue", {}).get("pull_request")):
        return None
    comment = event.get("comment") or {}
    body = comment.get("body") or ""
    old_body = event.get("changes", {}).get("body", {}).get("from") or ""
    if (event["action"] == "created" and not APPROVAL.fullmatch(body.strip())
            or event["action"] == "edited" and not (APPROVAL.fullmatch(body.strip()) or APPROVAL.fullmatch(old_body.strip()))):
        return None
    number = event["issue"].get("number")
    if type(number) is not int or number <= 0:
        raise ApprovalError("issue comment has no valid pull request number")
    pr = api.request(f"repos/{repository}/pulls/{number}")
    if not isinstance(pr, dict) or pr.get("state") != "open":
        return None
    if (comment.get("user", {}).get("id") == pr.get("user", {}).get("id")
            or not writer(api, repository, comment.get("user", {}))):
        return None
    head = pr.get("head", {}).get("sha")
    base = pr.get("base", {}).get("sha")
    if not isinstance(head, str) or not isinstance(base, str):
        raise ApprovalError("pull request revisions are invalid")
    runs = api.request(f"repos/{repository}/actions/workflows/npm-pr-review.yml/runs?event=pull_request_target&head_sha={head}&per_page=100")
    if not isinstance(runs, dict) or not isinstance(runs.get("workflow_runs"), list):
        raise ApprovalError("PR workflow runs response was invalid")
    for run in runs["workflow_runs"]:
        if (run.get("event") == "pull_request_target" and run.get("head_sha") == head
                and run.get("status") == "completed"
                and any(item.get("number") == number and item.get("head", {}).get("sha") == head
                        and item.get("base", {}).get("sha") == base
                        for item in run.get("pull_requests", []))):
            if type(run.get("id")) is not int:
                raise ApprovalError("trusted PR workflow run ID is invalid")
            return run["id"]
    raise ApprovalError("no completed trusted PR check matches the current base and head")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="find a trusted exact approval comment")
    check.add_argument("--report", type=Path, required=True)
    check.add_argument("--repository", required=True)
    check.add_argument("--pr-number", type=int, required=True)
    rerun = sub.add_parser("rerun", help="rerun the trusted PR check after an approval comment changes")
    rerun.add_argument("--event", type=Path, required=True)
    rerun.add_argument("--repository", required=True)
    args = parser.parse_args(argv)
    try:
        repository = repository_name(args.repository)
        api = GitHub(os.environ.get("GITHUB_TOKEN"))
        if args.command == "check":
            report = json.loads(args.report.read_bytes())
            if args.pr_number <= 0:
                raise ApprovalError("pull request number must be positive")
            comment_id = approval_comment(api, repository, args.pr_number, report)
            print(json.dumps({"approved": comment_id is not None, "comment_id": comment_id}, sort_keys=True))
            return 0 if comment_id is not None else 1
        event = json.loads(args.event.read_bytes())
        run_id = rerun_target(api, event, repository)
        if run_id is None:
            print(json.dumps({"rerun": False}, sort_keys=True))
            return 0
        api.request(f"repos/{repository}/actions/runs/{run_id}/rerun", method="POST")
        print(json.dumps({"rerun": True, "run_id": run_id}, sort_keys=True))
        return 0
    except (ApprovalError, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
