# npm v3 archive and byte-reporting repair

The repair increases completed reviews from **13/30 to 22/30**, removes all ten known byte-change reporting omissions, and preserves previously qualified facts and approval fingerprints on this corpus. It still fails the unchanged **80% completion floor**.

The same 30 historical update pairs across 11 repositories and their original bytes are retained. This is a repair regression on known cases, not a fresh holdout. The original [sprint scorecard](npm3-sprint-scorecard.md) remains the baseline.

| Measure | Baseline | Repair |
| --- | ---: | ---: |
| Completed reviews | 13/30 (43.3%) | 22/30 (73.3%) |
| Incomplete reviews retained | 17 | 8 |
| Unknown package-side records | 89 | 11 |
| Previously omitted byte-change events | 10 | 0 |
| Original 4,301 assessable events matched | 4,291 | 4,301 |
| Events assessable under the declared profile | 4,301 | 4,311, all matched |
| 80% completion floor | Fail | Fail |

Each pair runs five times: all 150 executions have valid protocol outcomes, zero fact mismatches, and zero unexpected allowed outcomes. Each pair's stdout is byte-identical across its five runs. Ten additional manifest-change events become assessable after full inspection of the larger archives. These event counts are correlated facts from 30 updates, not thousands of independent security tests. Both observed lifecycle-body changes still match.

Final production source: `8b094716e4abf6de079c998630561fda7d6e43bc`. Frozen macOS executable SHA256: `85bf265bd9e3e316a7bda23727386dc302d14ad62277fd6f4b203e35c7e81911`. The [compact evidence receipt](evidence/npm3-archive-repair-20261109.json) records source identities, controls, comparisons, timings, and all replay output hashes.

## Changes and approval boundary

The Rust core now inspects archive expansion through a 32 KiB DEFLATE history buffer and a 512-byte tar block. It retains at most 1 MiB of manifest content and bounded metadata plus an incremental SHA256 per entry. Dot-alias comparison uses complete content hashes and metadata without retaining file payloads. `binding.gyp` is hashed incrementally and retains its 64 MiB limit. The expanded admission ceiling rises explicitly from 64 to 128 MiB. Compressed and external-file size, manifest size, entry count, and aggregate read/expansion/header limits remain unchanged.

Facts and fingerprints still require complete successful gzip and tar inspection, original compressed-byte integrity verification, and manifest/lock identity checks. CRC, ISIZE, single-member, trailing-data, path, type, duplicate, parent-conflict, padding, and terminator checks remain enforced. A valid early manifest cannot authorize an invalid archive tail.

`verified_artifact_sha512` separately reports original bytes matching canonical locked SHA512. A later unsupported-content or content-work-limit error retains that observation but supplies no facts or approval fingerprint. Missing or invalid integrity, unsafe or failed reads, and reads after exhausted snapshot budgets supply no verified digest. Existing fingerprints are unchanged for unchanged qualified evidence. This field makes otherwise identical unsupported records distinguishable during review; it does not classify their installation behavior.

The Python collector uses bounded zlib chunks with the same expanded ceiling and full EOF verification. The independent label oracle uses Python's gzip/tarfile implementations at the explicit 128 MiB expanded ceiling. A pre-existing collector/core mismatch was tightened: an additional zero byte after an otherwise valid tar is rejected, while a full zero block remains valid. This does not widen the core's accepted profile.

## Verification

The final binary passes 97 Rust unit tests and 51 integration tests, 320 evidence/archive controls, 20 trusted Git-wrapper controls, and all 17 npm comparison cases with npm 12.2.2 and Node 26.9.0. The initial combined build passed 92 Python tests. The new focused budget test fails before removal of blanket proof clearing and passes afterward for both expansion and header exhaustion; subsequent reads remain blocked. Clippy and formatting pass. These are same-operator local checks, not independent user or release qualification.

The collector checked all 2,704 original unique archives: the 23 above the old expansion ceiling now qualify, and the 2,681 previously valid manifests and native-build facts remain identical. Original SHA512 identities are unchanged. The largest observed expansion is 113,925,632 bytes.

All 21,196 previously qualified package-side records retain their facts, fingerprints, state, and candidate flag. The repair qualifies 78 additional records; the remaining 11 have null facts and fingerprint. These are repeated project snapshot records, not 21,285 independent package versions or security tests. The final collector validates 49 of the 60 original snapshots and retains the 11 known incomplete snapshot sides.

Five archive-inspection memory probes at exactly 128 MiB expansion each completed. Peak requested heap was 522,819 bytes, including compressed input and digest work. Median process peak RSS was 2,441,216 bytes, range 2,424,832–2,441,216. These two-entry fixtures demonstrate streaming behavior; they do not bound memory for every 10,000-entry archive or the complete review pipeline. Fixture generation is outside the measurement.

The bounded ASan campaign is **not all-pass**. Gzip, DEFLATE, and full-artifact targets each complete their 60-second mutation budget under the unchanged 512 MiB process cap. Tar reaches 584 MiB and fails that cap after 576,595 units. Its saved 12,656-byte input succeeds alone under the same settings at 41,566,208 bytes peak RSS. The failure log records about 25.9 MB live heap and 264.3 MB quarantined allocations; most live allocation is attributed to libFuzzer's corpus. Retention and harness accumulation are plausible contributors, not a proven sole cause. The primary failure is retained. Standard-library code was not rebuilt with sanitizer instrumentation. A final bookkeeping assertion also flags the generated untracked corpus symlink; separate validation confirms tracked sources, locks, and seeds are unchanged.

## Processing cost

The formerly missed-byte case, `fb55/domhandler r051-cf32167f6bca`, has five alternating runs of each executable:

| Result | Baseline | Candidate |
| --- | ---: | ---: |
| Report status | Incomplete | Complete, advisory |
| Wall time median | 16.250 s | 32.082 s |
| Wall time range | 16.214–16.351 s | 31.707–33.645 s |
| Median process peak RSS | 565,084,160 bytes | 434,601,984 bytes |
| Process peak RSS range | 563,593,216–568,393,728 bytes | 376,242,176–434,896,896 bytes |

The candidate completes additional archive validation that the baseline rejected and hashes streamed file contents for alias comparison. The complete result takes more time and less peak memory in this case. This is not an equal-completed-work speed comparison or a global performance claim. All ten stdout hashes match their respective ordinary replay outputs. Downloads are excluded; the OS cache is not flushed. Replay and collector validation run concurrently on the same 12-CPU host; initial load averages are 4.99, 4.51, and 4.42.

A separate three-second profile on `r019-2b245254e40e` produces the same report as its ordinary run. The sample is dominated by DEFLATE/Huffman work, with incremental SHA256 also visible. The profiled run is excluded from timing measurements.

## Remaining incomplete inputs

Independent labels retain 11 unknown package-side records across eight pairs:

| Input gap | Records | Affected cases |
| --- | ---: | --- |
| SHA1-only `is-extglob@2.1.1` locks; canonical SHA512 acquisition is required | 6 | Three `microsoft/node-jsonc-parser` pairs, both sides |
| SHA1-only, HTTP-resolved `lodash@3.9.3`; no accepted archive evidence | 1 | Base side of `jhchen/fast-diff` |
| Root manifest/lock version mismatch | 3 | `stream-utils/raw-body` and two `webpack/loader-runner` pairs |
| Root manifest/lock development-dependency mismatch | 1 | `paulmillr/readdirp` |

No evidence is invented and no identity or approval rule is relaxed to complete these inputs. The frozen 80% completion floor remains unchanged.

## Reproduction and evidence limits

Local raw evidence is under `ecosystem_audit/npm3-archive-repair-20261109`. It includes both source freezes, failed-before cases, original archive compatibility, exact final-binary controls, independent labels, stdout/stderr, resource receipts, and the append-only decision log. The original sprint directory is preserved. Full reproduction needs that ignored local corpus; the committed receipt is not a replacement for the archive bytes.

```sh
python3 tools/npm3_archive_repair.py prepare \
  --original ecosystem_audit/npm3-sprint-20261109/pair-qualification \
  --output /absolute/path/to/new-repair-pairs
python3 tools/npm3_sprint_pairs.py replay \
  --output /absolute/path/to/new-repair-pairs \
  --binary /absolute/path/to/frozen/tau-gate --rounds 5
python3 tools/npm3_archive_repair.py summarize \
  --original ecosystem_audit/npm3-sprint-20261109/pair-qualification \
  --output /absolute/path/to/new-repair-pairs
```

Selection, acquisition, original label/event files, and both old/new per-side input maps are verified before reporting compatibility. Candidate replay excludes acquisition and uses local artifacts without flushing the OS cache. Original frozen timings are correctness references, not a paired speed comparison. A separate five-round alternating cost check uses the known former-byte-miss case; the candidate performs additional archive work that the baseline rejected.

The first native attempt used a relative output path, which the existing helper passed incorrectly after changing working directory. It failed before comparison and is retained. The absolute-path rerun passed, then final-binary controls were repeated after recompilation. The native helper's raw Markdown summary hardcodes the older npm 11.19.1; an explicit version erratum preserves it and identifies npm 12.2.2 from the runtime receipt. Best-effort source-commit fields in early control receipts differ from the final source freeze; exact executable hashes and `frozen-final.json` identify the tested candidate.

Human review speed, independent adoption, runtime safety, and a new signed release remain unqualified. Public historical pairs are advisory; no public package lifecycle was executed and no approvals were fabricated.

A separate read-only agent review finds no unresolved code, evidence-consistency, or reporting blocker. The reviewer identifies as Codex (GPT-6); a distinct model family is not independently attested. The [decision trail](npm3-archive-repair-20261109.tsv) records the repairs, failed attempts, repeated controls, and retained limits. Full originating chronology cannot be certified from the unavailable complete transcript.
