#!/usr/bin/env python3

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import npm_evidence

MAX_FILE = 64 * 1024 * 1024
MAX_OUTPUT = 64 * 1024 * 1024


def digest(data, algorithm="sha256"):
    return hashlib.new(algorithm, data).hexdigest()


def load(path):
    return json.loads(Path(path).read_bytes())


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("invalid relative source path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("invalid relative source path")
    return value


def read(path, maximum=MAX_FILE):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing regular file: {path}")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError(f"input exceeds {maximum} bytes: {path}")
    return data


def corpus(path):
    data = load(path)
    pairs = data["pairs"]
    ids = set()
    revisions = {}
    for pair in pairs:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", pair["id"]) or pair["id"] in ids:
            raise ValueError("invalid or duplicate case ID")
        ids.add(pair["id"])
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pair["repository"]):
            raise ValueError("invalid repository")
        if pair["split"] not in ("development", "holdout"):
            raise ValueError("invalid split")
        for side in ("base", "head"):
            commit = pair[side]
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ValueError("revision must be an exact commit")
            files = pair["files"][commit]
            for item in files:
                relative(item["path"])
                if not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
                    raise ValueError("invalid frozen file digest")
                expected = raw_url(pair["repository"], commit, item["path"])
                if item["url"] != expected:
                    raise ValueError("frozen source URL differs from revision")
            key = pair["repository"], commit
            if key in revisions and revisions[key] != files:
                raise ValueError("conflicting frozen revision files")
            revisions[key] = files
    if len(pairs) != data["pairCount"] or len({p["repository"] for p in pairs}) != data["projectCount"]:
        raise ValueError("frozen corpus counts differ")
    return data, revisions


def raw_url(repository, commit, path):
    return f"https://raw.githubusercontent.com/{repository}/{commit}/{relative(path)}"


def snapshot_path(sources, repository, commit):
    return Path(sources) / repository.replace("/", "__") / commit


class Budget:
    def __init__(self, limit):
        self.limit = limit
        self.used = 0
        self.lock = threading.Lock()

    def account(self, size):
        with self.lock:
            if self.used + size > self.limit:
                raise ValueError("declared aggregate byte budget exhausted")
            self.used += size


def raw_source(url):
    request = urllib.request.Request(url, headers={"User-Agent": "tau-gate-qualification/1", "Accept-Encoding": "identity"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), npm_evidence.NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200:
                raise ValueError("source response must have status 200")
            data = response.read(MAX_FILE + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    if len(data) > MAX_FILE:
        raise ValueError("source exceeds 64 MiB")
    return data


def capture_revision(repository, commit, frozen, sources, discovery, budget):
    root = snapshot_path(sources, repository, commit)
    project = root / "project"
    files = {}
    absent = []
    issues = []
    frozen_by_path = {item["path"]: item for item in frozen}

    def capture(path, optional=False):
        relative(path)
        destination = project / path
        spec = frozen_by_path.get(path)
        url = raw_url(repository, commit, path)
        cached = Path(discovery) / repository / commit / path if discovery else None
        prior = root / "source.json"
        previous = load(prior).get("files", {}).get(path) if prior.exists() else None
        if spec and cached and cached.is_file():
            data = read(cached)
        elif destination.exists() and (spec or previous):
            data = read(destination)
        else:
            data = raw_source(url)
        if data is None:
            if not optional:
                raise ValueError(f"required source returned 404: {path}")
            absent.append({"path": path, "url": url, "status": "http_404", "trust": "caller-trusted raw GitHub response"})
            return
        expected = spec["sha256"] if spec else previous["sha256"] if previous else None
        if expected and digest(data) != expected:
            raise ValueError(f"source hash mismatch: {path}")
        if spec and len(data) != spec["bytes"]:
            raise ValueError(f"source size mismatch: {path}")
        budget.account(len(data))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        files[path] = {"sha256": digest(data), "bytes": len(data), "url": url,
                       "identity": "frozen_manifest" if spec else "captured_raw_commit_url"}

    for item in frozen:
        try:
            capture(item["path"])
        except (OSError, ValueError) as exc:
            issues.append({"path": item["path"], "reason": str(exc)})
    lock = {}
    try:
        lock = json.loads(read(project / "package-lock.json"))
        for path, record in sorted(lock["packages"].items()):
            if record.get("link") or npm_evidence.is_registry_path(path):
                continue
            prefix = path + "/" if path else ""
            for name, optional in (("package.json", False), ("binding.gyp", True)):
                name = prefix + name
                if name in files:
                    continue
                try:
                    capture(name, optional)
                except (OSError, ValueError) as exc:
                    issues.append({"path": name, "reason": str(exc)})
    except (OSError, ValueError, KeyError, TypeError) as exc:
        issues.append({"path": "package-lock.json", "reason": str(exc)})
    receipt = {"repository": repository, "commit": commit,
               "trust": "caller-trusted exact raw GitHub commit URL; not Git object capture",
               "status": "complete" if not issues else "partial", "files": files,
               "absent": absent, "issues": issues}
    save(root / "source.json", receipt)
    return root, lock, receipt


def archive_identity(record):
    integrity = record.get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise ValueError("canonical SHA512 SRI required for acquisition")
    raw = base64.b64decode(integrity[7:], validate=True)
    if len(raw) != 64 or "sha512-" + base64.b64encode(raw).decode() != integrity:
        raise ValueError("canonical SHA512 SRI required for acquisition")
    return raw.hex()


def acquire(args):
    data, revisions = corpus(args.corpus)
    budget = Budget(args.max_bytes)
    archives = Path(args.archive_cache).resolve()
    archives.mkdir(parents=True, exist_ok=True)
    snapshots = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(capture_revision, repo, commit, files, args.sources,
                               args.discovery_cache, budget)
                   for (repo, commit), files in sorted(revisions.items())]
        snapshots = [future.result() for future in futures]
    requests = {}
    for _, lock, _ in snapshots:
        for path, record in lock.get("packages", {}).items():
            if record.get("link") or not npm_evidence.is_registry_path(path):
                continue
            try:
                key = archive_identity(record)
            except (ValueError, TypeError):
                continue
            requests.setdefault(key, record.get("resolved"))

    def fetch(item):
        key, url = item
        destination = archives / (key + ".tgz")
        try:
            raw = read(destination) if destination.exists() else npm_evidence.fetch_archive(url)
            if digest(raw, "sha512") != key:
                raise ValueError("archive SHA512 mismatch")
            budget.account(len(raw))
            if not destination.exists():
                temporary = destination.with_suffix(".tmp")
                temporary.write_bytes(raw)
                temporary.replace(destination)
            return key, {"status": "available", "sha256": digest(raw), "sha512": key, "bytes": len(raw), "url": url}
        except (OSError, ValueError, TypeError) as exc:
            return key, {"status": "unavailable", "url": url, "reason": str(exc)}

    results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for number, (key, receipt) in enumerate(pool.map(fetch, sorted(requests.items())), 1):
            results[key] = receipt
            if number % 100 == 0:
                print(f"Acquired {number}/{len(requests)} archive identities", flush=True)
    for root, lock, source in snapshots:
        evidence = root / "evidence"
        entries = []
        packages = {}
        for path, record in sorted(lock.get("packages", {}).items()):
            if record.get("link"):
                continue
            if npm_evidence.is_registry_path(path):
                try:
                    key = archive_identity(record)
                    receipt = results[key]
                except (ValueError, TypeError, KeyError) as exc:
                    receipt = {"status": "unavailable", "reason": str(exc)}
                packages[path] = receipt
                if receipt["status"] == "available":
                    relative_path = "artifacts/" + key + ".tgz"
                    destination = evidence / relative_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if destination.exists():
                        if digest(read(destination), "sha512") != key:
                            raise ValueError("existing snapshot artifact hash mismatch")
                    else:
                        try:
                            os.link(archives / (key + ".tgz"), destination)
                        except OSError:
                            shutil.copyfile(archives / (key + ".tgz"), destination)
                    entries.append({"path": path, "artifact": relative_path})
            else:
                source_path = (path + "/" if path else "") + "package.json"
                found = source_path in source["files"]
                binding_path = (path + "/" if path else "") + "binding.gyp"
                binding_known = binding_path in source["files"] or any(item["path"] == binding_path for item in source["absent"])
                packages[path] = {"status": "available" if found and binding_known else "unavailable",
                                  "reason": None if found and binding_known else "source manifest or binding.gyp presence unknown"}
                if found and binding_known:
                    relative_path = "projects/" + source_path
                    destination = evidence / relative_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(root / "project" / source_path, destination)
                    if binding_path in source["files"]:
                        shutil.copyfile(root / "project" / binding_path, destination.parent / "binding.gyp")
                    entries.append({"path": path, "project_manifest": relative_path})
        lock_path = root / "project/package-lock.json"
        lock_hash = digest(read(lock_path)) if lock_path.exists() else None
        save(evidence / "index.json", {"schema_version": 1, "lock_sha256": lock_hash, "packages": entries})
        save(root / "acquisition.json", {"status": "complete" if source["status"] == "complete" and all(p["status"] == "available" for p in packages.values()) else "partial",
                                          "packages": packages, "source_sha256": digest(read(root / "source.json"))})
    receipt = {"schema_version": 1, "corpus_sha256": digest(read(args.corpus)),
               "snapshots": len(snapshots), "archive_identities": len(results),
               "available_archives": sum(item["status"] == "available" for item in results.values()),
               "accounted_input_bytes": budget.used, "byte_budget": budget.limit,
               "workers": args.workers, "artifact_max_bytes": MAX_FILE,
               "download_overshoot_bound": args.workers * MAX_FILE,
               "archives": results}
    save(Path(args.sources) / "acquisition-run.json", receipt)
    print(json.dumps({key: value for key, value in receipt.items() if key != "archives"}, sort_keys=True))



def run_bounded(argv, output, timeout):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    program_argv = [str(arg) for arg in argv]
    metric_path = output / "process-metrics.txt"
    execution_argv = program_argv
    metric_platform = None
    if Path("/usr/bin/time").is_file() and sys.platform == "darwin":
        execution_argv = ["/usr/bin/time", "-l", "-o", str(metric_path), *program_argv]
        metric_platform = "Darwin maximum resident set size in bytes"
    elif Path("/usr/bin/time").is_file() and sys.platform.startswith("linux"):
        execution_argv = ["/usr/bin/time", "-f", "%M", "-o", str(metric_path), *program_argv]
        metric_platform = "GNU time maximum resident set size in KiB, converted to bytes"
    process = subprocess.Popen(execution_argv, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, env={**os.environ, "NO_COLOR": "1"})

    def terminate():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def group_alive():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False

    deadline = started + timeout
    termination = "exited"
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    destinations = {name: (output / (name + ".bin")).open("wb") for name in streams}
    hashers = {name: hashlib.sha256() for name in streams}
    counts = {name: 0 for name in streams}
    with selectors.DefaultSelector() as selector:
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        try:
            while True:
                leader_running = process.poll() is None
                if not leader_running and not selector.get_map() and not group_alive():
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if termination != "exited":
                        break
                    termination = "timeout"
                    terminate()
                    deadline = time.monotonic() + 0.2
                    continue
                for key, _ in selector.select(min(remaining, 0.02)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    kept = chunk[:max(MAX_OUTPUT - counts[name], 0)]
                    destinations[name].write(kept)
                    hashers[name].update(kept)
                    counts[name] += len(kept)
                    if len(kept) != len(chunk) and termination != "output_limit":
                        termination = "output_limit"
                        terminate()
                        deadline = time.monotonic() + 0.2
        finally:
            for stream in streams.values():
                stream.close()
            for destination in destinations.values():
                destination.close()
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        terminate()
        process.wait(timeout=0.2)
    hashes = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    peak_rss = None
    metric_hash = None
    if metric_path.exists():
        metric_raw = read(metric_path)
        metric_hash = digest(metric_raw)
        metric_text = metric_raw.decode("utf-8", "replace")
        if sys.platform == "darwin":
            match = re.search(r"^\s*(\d+)\s+maximum resident set size\s*$", metric_text, re.MULTILINE)
            peak_rss = int(match[1]) if match else None
        elif sys.platform.startswith("linux"):
            match = re.search(r"^([0-9]+)$", metric_text, re.MULTILINE)
            peak_rss = int(match[1]) * 1024 if match else None
    return {"argv": execution_argv, "program_argv": program_argv, "exit_code": process.returncode,
            "termination": termination, "elapsed_seconds": time.monotonic() - started,
            "timeout_seconds": timeout, "output_limit_per_stream": MAX_OUTPUT,
            "peak_rss_bytes": peak_rss, "peak_rss_measurement": metric_platform,
            "metrics_sha256": metric_hash,
            "output_sha256": hashes, "output_bytes": counts}


def verify_snapshot(root, repository, commit, frozen):
    source = load(root / "source.json")
    acquisition = load(root / "acquisition.json")
    if source["repository"] != repository or source["commit"] != commit:
        raise ValueError("source receipt revision mismatch")
    if digest(read(root / "source.json")) != acquisition["source_sha256"]:
        raise ValueError("source receipt changed after acquisition")
    hashes = {}
    for item in frozen:
        raw = read(root / "project" / relative(item["path"]))
        if digest(raw) != item["sha256"] or len(raw) != item["bytes"]:
            raise ValueError("frozen source hash mismatch: " + item["path"])
    for path, item in source["files"].items():
        raw = read(root / "project" / relative(path))
        if digest(raw) != item["sha256"]:
            raise ValueError("captured source hash mismatch: " + path)
        hashes["project/" + path] = digest(raw)
    for item in source["absent"]:
        if (root / "project" / relative(item["path"])).exists():
            raise ValueError("source absence receipt contradicted: " + item["path"])
    lock_path = root / "project/package-lock.json"
    lock = load(lock_path)
    index = load(root / "evidence/index.json")
    if index["lock_sha256"] != digest(read(lock_path)):
        raise ValueError("diagnostic index lock hash mismatch")
    seen = set()
    for item in index["packages"]:
        path = item["path"]
        if path in seen or path not in lock["packages"]:
            raise ValueError("duplicate or unknown diagnostic locator")
        seen.add(path)
        key = "artifact" if "artifact" in item else "project_manifest"
        raw = read(root / "evidence" / relative(item[key]))
        hashes["evidence/" + item[key]] = digest(raw)
        if key == "artifact":
            expected = archive_identity(lock["packages"][path])
            if digest(raw, "sha512") != expected:
                raise ValueError("archive SHA512 mismatch during replay: " + path)
            if digest(raw) != acquisition["packages"][path]["sha256"]:
                raise ValueError("archive receipt hash mismatch: " + path)
        else:
            project_path = (path + "/" if path else "") + "package.json"
            if digest(raw) != source["files"][project_path]["sha256"]:
                raise ValueError("diagnostic source differs from captured manifest")
            binding = (path + "/" if path else "") + "binding.gyp"
            evidence_binding = (root / "evidence" / item[key]).parent / "binding.gyp"
            if binding in source["files"]:
                binding_raw = read(evidence_binding)
                if digest(binding_raw) != source["files"][binding]["sha256"]:
                    raise ValueError("diagnostic binding.gyp hash mismatch")
                hashes["evidence/" + str(evidence_binding.relative_to(root / "evidence"))] = digest(binding_raw)
            elif evidence_binding.exists():
                raise ValueError("unexpected diagnostic binding.gyp")
    hashes["evidence/index.json"] = digest(read(root / "evidence/index.json"))
    hashes["source.json"] = digest(read(root / "source.json"))
    hashes["acquisition.json"] = digest(read(root / "acquisition.json"))
    return acquisition, hashes


def script_hash(body):
    return digest(body.encode()) if body is not None else None


def compare_events(expected, report, oracle_status):
    package_changes = {item["path"]: item for item in report.get("package_changes", [])}
    execution_changes = {item["path"]: item for item in report.get("execution_evidence_changes", [])}
    matched = []
    missed = []
    unknown = []
    package_fields = {"source_changed": "source", "integrity_changed": "integrity",
                      "version_changed": "version", "name_changed": "name"}
    execution_fields = {"manifest_changed": "manifest_sha256", "artifact_changed": "artifact_sha512",
                        "lifecycle_added": "lifecycle", "lifecycle_removed": "lifecycle",
                        "lifecycle_changed": "lifecycle", "implicit_native_changed": "implicit_node_gyp", "binding_changed": "binding_gyp_sha256"}
    for event in expected:
        path = event["path"]
        kind = event["kind"]
        if event.get("status") == "unknown" or kind == "unknown":
            unknown.append(event)
            continue
        if event["obligation"] == "package_change" and kind not in execution_fields:
            change = package_changes.get(path)
            if kind in ("added", "removed"):
                side = "after" if kind == "added" else "before"
                identity = event[side]
                actual = (change or {}).get(side) or {}
                observed = bool(change and change.get("change") == kind and isinstance(change.get(side), dict) and
                                all(actual.get(field) == value for field, value in identity.items()
                                    if field in ("name", "version", "source", "integrity") and value is not None))
            elif kind in package_fields:
                field = package_fields[kind]
                observed = bool(change and field in change.get("changed_fields", []) and
                                (change.get("before") or {}).get(field) == event["before"] and
                                (change.get("after") or {}).get(field) == event["after"])
            else:
                unknown.append({**event, "comparison_reason": "unknown package event kind"})
                continue
        else:
            change = execution_changes.get(path)
            if kind in ("added", "removed"):
                side = "after" if kind == "added" else "before"
                observed = bool(change and (change.get(side) or {}).get("facts"))
            elif kind in execution_fields:
                before = ((change or {}).get("before") or {}).get("facts") or {}
                after = ((change or {}).get("after") or {}).get("facts") or {}
                field = execution_fields[kind]
                observed = field in before or field in after
                observed = observed and before.get(field) != after.get(field)
                if kind.startswith("lifecycle_"):
                    hook = event["after"]["event"]
                    observed = observed and before.get(field, {}).get(hook) == script_hash(event["before"]["body"]) and after.get(field, {}).get(hook) == script_hash(event["after"]["body"])
                elif kind != "artifact_changed":
                    observed = observed and before.get(field) == event["before"] and after.get(field) == event["after"]
            else:
                unknown.append({**event, "comparison_reason": "unknown execution event kind"})
                continue
        (matched if observed else missed).append(event)
    status = "complete" if oracle_status == "complete" and not unknown and report.get("status") == "complete" else "partial"
    return {"status": status, "matched": matched, "missed": missed, "unknown": unknown,
            "misses": len(missed), "approval_relevant_misses": sum(bool(e.get("approval_relevant")) for e in missed)}



def compare_facts(facts, report):
    mismatches = []
    fields = {"manifest_sha256": "manifest_sha256", "artifact_sha512": "artifact_sha512",
              "scripts": "lifecycle", "implicit_native": "implicit_node_gyp", "binding_sha256": "binding_gyp_sha256"}
    for side, independent in facts.items():
        observed = {item["path"]: item for item in report.get(side, {}).get("execution_evidence") or []}
        for path, expected in independent["packages"].items():
            item = observed.get(path, {})
            actual = item.get("facts")
            if expected.get("scope") == "link" or expected.get("status") != "known":
                continue
            if not actual:
                if report.get("status") == "complete" or report.get(side, {}).get("status") == "complete" or item.get("state") == "qualified":
                    mismatches.append({"side": side, "path": path, "field": "facts",
                                       "expected": "known package facts", "actual": actual})
                continue
            for source, target in fields.items():
                value = {event: script_hash(body) for event, body in expected[source].items()} if source == "scripts" else expected.get(source)
                if source in expected and value != actual.get(target):
                    mismatches.append({"side": side, "path": path, "field": source,
                                       "expected": value, "actual": actual.get(target)})
    return mismatches

def replay_case(pair, args, output):
    import qualification_oracle
    destination = output / "cases" / pair["id"]
    destination.mkdir(parents=True)
    receipt = {"case_id": pair["id"], "repository": pair["repository"], "split": pair["split"],
               "capture": {}, "acquisition": {}, "collector": {}, "oracle": {},
               "core": {"status": "not_run"}, "comparison": {"status": "unavailable"}}
    snapshots = {}
    facts = {}
    for side in ("base", "head"):
        root = snapshot_path(args.sources, pair["repository"], pair[side]).resolve()
        snapshots[side] = root
        source_status = None
        source_issues = []
        acquired_status = None
        try:
            source_receipt = load(root / "source.json")
            source_status = source_receipt.get("status")
            source_issues = source_receipt.get("issues", [])
            acquired_status = load(root / "acquisition.json").get("status")
            acquired, hashes = verify_snapshot(root, pair["repository"], pair[side], pair["files"][pair[side]])
            receipt["capture"][side] = {"status": "verified", "input_sha256": hashes,
                                         "trust": "caller-trusted raw GitHub commit capture", "source_status": source_status, "source_issues": source_issues}
            receipt["acquisition"][side] = acquired
        except (OSError, ValueError, KeyError, TypeError) as exc:
            receipt["capture"][side] = {"status": "invalid_or_unavailable", "reason": str(exc), "source_status": source_status, "source_issues": source_issues}
            receipt["acquisition"][side] = {"status": "unverified", "claimed_status": acquired_status}
            receipt["oracle"][side] = {"status": "unavailable", "reason": "input verification failed"}
            continue
        collector_argv = [sys.executable, str(Path(__file__).with_name("npm_evidence.py").resolve()), "validate",
                          "--lock", root / "project/package-lock.json", "--index", root / "evidence/index.json",
                          "--manifest", root / "project/package.json"]
        collector = run_bounded(collector_argv, destination / (side + "-collector"), args.timeout)
        collector["status"] = "complete" if collector["termination"] == "exited" and collector["exit_code"] == 0 else "incomplete"
        try:
            collector["result"] = load(destination / (side + "-collector") / "stdout.bin")
        except (OSError, ValueError):
            collector["result"] = None
        if collector["termination"] == "exited" and collector["exit_code"] == 0 and not (isinstance(collector["result"], dict) and collector["result"].get("status") == "validated"):
            collector["status"] = "protocol_error"
        receipt["collector"][side] = collector
        try:
            result = qualification_oracle.snapshot_facts(root / "project/package-lock.json", root / "evidence/index.json", root / "project/package.json")
            save(destination / (side + "-oracle.json"), result)
            facts[side] = result
            receipt["oracle"][side] = {"status": result["status"], "packages_known": sum(p["status"] == "known" for p in result["packages"].values()),
                                         "packages_total": len(result["packages"]), "facts_sha256": digest(read(destination / (side + "-oracle.json")))}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            receipt["oracle"][side] = {"status": "unavailable", "reason": str(exc)}
    if all(receipt["capture"][side]["status"] == "verified" for side in ("base", "head")):
        argv = [str(args.binary), "review", "--json"]
        for side, root in snapshots.items():
            argv.extend(["--" + side, str(root / "project/package-lock.json"), "--" + side + "-manifest", str(root / "project/package.json"),
                         "--" + side + "-evidence", str(root / "evidence/index.json")])
        core = run_bounded(argv, destination / "core", args.timeout)
        report = {}
        try:
            report = load(destination / "core/stdout.bin")
            save(destination / "core.json", report)
        except (OSError, ValueError):
            pass
        core["status"] = report.get("status", "invalid_output") if core["termination"] == "exited" else core["termination"]
        if core["termination"] == "exited" and ((core["status"] == "complete" and core["exit_code"] != 0) or (core["status"] == "incomplete" and core["exit_code"] != 2)):
            core["reported_status"] = core["status"]
            core["status"] = "protocol_error"
        core["policy_outcome"] = report.get("policy", {}).get("outcome")
        core["package_states"] = {}
        for side in ("base", "head"):
            states = {}
            for item in report.get(side, {}).get("execution_evidence") or []:
                state = item.get("state", "unknown")
                states[state] = states.get(state, 0) + 1
            core["package_states"][side] = states
        core["package_changes"] = len(report.get("package_changes", []))
        core["execution_evidence_changes"] = len(report.get("execution_evidence_changes", []))
        core["review_decision_count_proxy"] = len({item["path"] for item in report.get("execution_evidence_changes", [])})
        receipt["core"] = core
        if set(facts) == {"base", "head"}:
            expected = qualification_oracle.events(facts["base"], facts["head"])
            save(destination / "expected.json", expected)
            oracle_status = "complete" if all(value["status"] == "complete" for value in facts.values()) else "partial"
            receipt["comparison"] = compare_events(expected, report, oracle_status)
            receipt["comparison"]["fact_mismatches"] = compare_facts(facts, report)
            if receipt["comparison"]["fact_mismatches"]:
                receipt["comparison"]["status"] = "partial"
            receipt["simple_diff_baseline"] = {"known_changed_instances": len({item["path"] for item in expected if item.get("kind") != "unknown"}),
                                                "expected_events": len(expected), "human_review_minutes": None}
    save(destination / "receipt.json", receipt)
    return receipt


def replay(args):
    data, _ = corpus(args.corpus)
    binary = read(args.binary)
    actual = digest(binary)
    expected = args.expected_binary_sha256 or data.get("baseline", {}).get("binary_sha256")
    if actual != expected:
        raise ValueError("binary hash mismatch; supply the explicit candidate digest for a candidate replay")
    args.binary = args.binary.resolve()
    if args.timeout < 120:
        raise ValueError("corpus replay requires at least 120 seconds per core invocation")
    if args.output.exists():
        raise ValueError("replay output must be fresh")
    args.output.mkdir(parents=True)
    helpers = {path.name: digest(read(path)) for path in [Path(__file__), Path(__file__).with_name("qualification_oracle.py"), Path(__file__).with_name("npm_evidence.py")]}
    verification = run_bounded([args.binary, "--verify"], args.output / "binary-verify", args.timeout)
    save(args.output / "implementation.json", {"binary_sha256": actual, "binary_verification": verification,
                                                "helper_sha256": helpers, "corpus_sha256": digest(read(args.corpus)),
                                                "python": sys.version, "split": args.split, "offline": True,
                                                "jobs": args.jobs, "timeout_seconds": args.timeout})
    selected_ids = set(getattr(args, "case", None) or [])
    if selected_ids - {pair["id"] for pair in data["pairs"]}:
        raise ValueError("unknown selected case ID")
    pairs = [pair for pair in data["pairs"] if (args.split == "all" or pair["split"] == args.split) and (not selected_ids or pair["id"] in selected_ids)]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for receipt in pool.map(lambda pair: replay_case(pair, args, args.output), pairs):
            print(f"Replayed {receipt['case_id']}: {receipt['core']['status']}", flush=True)
    current_helpers = {path.name: digest(read(path)) for path in [Path(__file__), Path(__file__).with_name("qualification_oracle.py"), Path(__file__).with_name("npm_evidence.py")]}
    implementation_unchanged = digest(read(args.binary)) == actual and current_helpers == helpers
    save(args.output / "implementation-after.json", {"binary_sha256": digest(read(args.binary)), "helper_sha256": current_helpers,
                                                      "implementation_unchanged": implementation_unchanged})
    save(args.output / "summary.json", summarize_data(data, args.output))
    if not implementation_unchanged:
        raise ValueError("implementation bytes changed during replay; receipts are not a single implementation qualification")


def summarize_data(data, receipts):
    cases = []
    for pair in data["pairs"]:
        path = Path(receipts) / "cases" / pair["id"] / "receipt.json"
        if path.exists():
            item = load(path)
            if item.get("case_id") != pair["id"]:
                raise ValueError("receipt case identity mismatch")
            cases.append(item)
        else:
            cases.append({"case_id": pair["id"], "core": {"status": "not_run"}, "comparison": {"status": "unavailable"}})
    statuses = {}
    for item in cases:
        status = item["core"]["status"]
        statuses[status] = statuses.get(status, 0) + 1
    package_states = {}
    for item in cases:
        for side in item["core"].get("package_states", {}).values():
            for state, count in side.items():
                package_states[state] = package_states.get(state, 0) + count
    peak_rss_values = [item["core"]["peak_rss_bytes"] for item in cases if item["core"].get("peak_rss_bytes") is not None]
    counts = {"core_peak_rss_measured_cases": len(peak_rss_values), "core_max_peak_rss_bytes": max(peak_rss_values) if peak_rss_values else None,
              "core_package_states": package_states, "frozen_pairs": len(data["pairs"]), "receipts": sum((Path(receipts) / "cases" / p["id"] / "receipt.json").exists() for p in data["pairs"]),
              "core_statuses": statuses, "core_complete_pairs": statuses.get("complete", 0),
              "complete_pairs": sum(item["core"]["status"] == "complete" and all(item.get(stage, {}).get(side, {}).get("status") == expected for stage, expected in (("capture", "verified"), ("acquisition", "complete"), ("collector", "complete"), ("oracle", "complete")) for side in ("base", "head")) for item in cases),
              "comparison_complete_pairs": sum(item["comparison"]["status"] == "complete" for item in cases),
              "known_misses": sum(item["comparison"].get("misses", 0) for item in cases),
              "approval_relevant_misses": sum(item["comparison"].get("approval_relevant_misses", 0) for item in cases),
              "unknown_comparison_pairs": sum(item["comparison"]["status"] != "complete" for item in cases),
              "oracle_packages_known": sum(side.get("packages_known", 0) for item in cases for side in item.get("oracle", {}).values()),
              "oracle_package_snapshot_records": sum(side.get("packages_total", 0) for item in cases for side in item.get("oracle", {}).values()),
              "fact_mismatches": sum(len(item["comparison"].get("fact_mismatches", [])) for item in cases),
              "package_denominator_complete": all(set(item.get("oracle", {})) == {"base", "head"} and all("packages_total" in side for side in item["oracle"].values()) for item in cases),
              "human_review_minutes": None}
    return {"schema_version": 1, "counts": counts,
            "denominator_note": "Every frozen pair remains counted. Package counts are pair-side records, including reused snapshots.",
            "claims": {"real_world_coverage": "historical cohort only", "malware_detection": False,
                       "maintainer_time_measured": False, "independent_npm_install_observation": False},
            "cases": [{"case_id": item["case_id"], "core_status": item["core"]["status"],
                       "comparison_status": item["comparison"]["status"], "misses": item["comparison"].get("misses")} for item in cases]}


def summarize(args):
    data, _ = corpus(args.corpus)
    if args.output.exists():
        raise ValueError("summary output must be fresh")
    save(args.output, summarize_data(data, args.receipts))

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    acquire_parser = commands.add_parser("acquire", help="explicit network acquisition; executes no project code")
    acquire_parser.add_argument("--corpus", type=Path, required=True)
    acquire_parser.add_argument("--sources", type=Path, required=True)
    acquire_parser.add_argument("--archive-cache", type=Path, required=True)
    acquire_parser.add_argument("--discovery-cache", type=Path)
    acquire_parser.add_argument("--workers", type=int, choices=range(1, 5), default=4)
    acquire_parser.add_argument("--max-bytes", type=int, default=16 * 1024 ** 3)
    replay_parser = commands.add_parser("replay", help="offline advisory replay into fresh receipts")
    replay_parser.add_argument("--corpus", type=Path, required=True)
    replay_parser.add_argument("--sources", type=Path, required=True)
    replay_parser.add_argument("--binary", type=Path, required=True)
    replay_parser.add_argument("--expected-binary-sha256")
    replay_parser.add_argument("--output", type=Path, required=True)
    replay_parser.add_argument("--split", choices=("all", "development", "holdout"), default="all")
    replay_parser.add_argument("--case", action="append", help="replay only this frozen case ID; repeatable")
    replay_parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    replay_parser.add_argument("--timeout", type=float, default=120.0)
    summary_parser = commands.add_parser("summarize", help="account for all frozen cases")
    summary_parser.add_argument("--corpus", type=Path, required=True)
    summary_parser.add_argument("--receipts", type=Path, required=True)
    summary_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        {"acquire": acquire, "replay": replay, "summarize": summarize}[args.command](args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"qualification: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
