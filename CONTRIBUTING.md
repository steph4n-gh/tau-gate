# Contributing to Tau-Gate

Use [GitHub Issues](https://github.com/steph4n-gh/tau-gate/issues) for ordinary bugs and enhancement proposals. For a bug, include the Tau-Gate version or commit, the command and input format, the expected and actual result, and a small reproducer when possible. Do not post undisclosed vulnerabilities there; follow [SECURITY.md](SECURITY.md) instead.

Propose changes with a pull request against `main`. Describe the behavior that changes, its supported input scope, and any known limits. The maintainer evaluates the change and its CI results in the pull request before deciding whether to merge it. Small fixes do not require an issue first, but discuss substantial scope changes in an issue before implementing them.

Add automated tests when introducing major functionality. For a bug fix, add a focused regression test when the behavior can be exercised; parser and evidence-rule changes should also test a nearby ambiguous or rejected input. Update user documentation when the interface or supported scope changes. The [technical contributor guidance](GEMINI.md) explains the Rust core's constraints and points to the broader qualification checks.

Before submitting, run the checks relevant to your change. The [CI workflow](.github/workflows/ci.yml) runs additional checks; these are the usual local commands:

```sh
cargo test --release --offline --all-targets
cargo fmt -- --check
cargo clippy --offline --all-targets -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_pr_review.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_qualification*.py' -v
```

If a check cannot run locally, note that in the pull request. CI also exercises the fuzz seeds, read-only end-to-end path, and C interface smoke test. These checks do not establish that a dependency is safe; keep claims within the [documented review contract](docs/review.md).
