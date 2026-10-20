# Qualification scoring contract

`SCORING_SEMANTICS_VERSION` in `tools/qualification.py` identifies the event comparison rules. Version 2 corrects absent-metadata comparisons and requires exact artifact SHA512 values. Snapshot fact extraction and core behavior are unchanged by these scoring corrections.

## Metadata and byte comparisons

The oracle preserves absent lockfile fields as JSON null. The core's `PackageInfo` represents absent `source` and `integrity` as empty strings. A source or integrity change therefore compares an expected null with an explicitly present empty string. A missing report field, a report null, or another value does not match that expected absence. The rule does not normalize names, versions, or unknown execution facts.

Added and removed packages still require every available name, version, source, and integrity value. Unknown oracle identity values remain unassessed. They do not erase checks on the available values.

Artifact events use independently computed SHA512 digests of the original compressed bytes. Both reported sides must equal the corresponding expected digest. Different reported values alone do not satisfy the obligation. Manifest and binding events likewise require exact SHA256 values. Unknown lifecycle facts do not establish script removal or script absence.

Comparison status describes assessment completeness. Miss counts and fact mismatches remain separate. A complete comparison can contain misses. An incomplete core result can contain a genuine known reporting miss without producing an allowed policy result.

## Offline rescore input contract

`rescore` accepts an original replay with every frozen case. It requires these bindings before it creates output.

- The exact corpus bytes match `implementation.json.corpus_sha256`. The original replay split is `all`.
- `implementation-after.json.implementation_unchanged` is true. Its binary and helper hashes equal the original implementation hashes.
- The case directory set equals the frozen case set. Each receipt's case ID, repository, and split match the manifest.
- Each side's verified capture hashes include every frozen source file with its expected SHA256.
- Each saved oracle fact file matches its original receipt hash, status, and known and total package counts.
- Raw core stdout and stderr match their original hashes and byte lengths. Parsed stdout equals `core.json`.
- The core protocol is `complete` with exit 0 or `incomplete` with exit 2. The process exited and its reported status agrees with the receipt.

Timeouts, output-limit termination, missing facts, invalid JSON, and incomplete replay directories cannot be rescored by this command. Those original outcomes remain in the original replay. They require a new bounded replay or another explicitly defined assessment method.

The command reads bounded regular files. It derives new events from the verified original facts and uses the same scorer as a fresh replay. It does not trust the old `expected.json` or old comparison results. It does not open source snapshots or artifact caches and executes no processes.

## Rescore output contract

The output directory must be fresh and outside the original replay. Each new receipt preserves capture, acquisition, collector, oracle, and core observations. Its `scoring` object records the absolute source replay path, original receipt SHA256, original implementation metadata hashes, current scoring helper hashes, semantics version, and regenerated event-file SHA256. The top-level implementation receipt also preserves the complete original binary and helper metadata.

The command rechecks original receipts when it reads each case for scoring. It rechecks source metadata and scoring helper bytes before writing completion metadata and the summary. An interrupted output directory has no completed summary. The denominator includes all frozen cases.

Hashes establish consistency with the preserved receipt tree. They do not authenticate a receipt tree that an attacker rewrites in full. Rescoring provides no new acquisition, binary execution, human review, or independent operator evidence.
