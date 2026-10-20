# Snapshot work limits

Tau-Gate bounds npm evidence work separately for each base or head snapshot.
Exhaustion produces unsupported evidence and an incomplete result. It never
allows an update with unknown evidence.

| Work | Fixed limit | Development maximum | Headroom |
| --- | ---: | ---: | ---: |
| Evidence file reads | 2 GiB | 647,354,823 bytes | 3.32 times |
| Actual DEFLATE output | 4 GiB | 1,704,409,600 bytes | 2.52 times |
| Processed nonzero tar headers | 250,000 | 59,639 | 4.19 times |
| npm package records | 10,000 | 2,718 | 3.68 times |
| Declared dependency references | 50,000 | 4,863 | 10.28 times |
| JSON values per document | 100,000 | 27,547 | 3.63 times |

The limits were fixed from the 121 development snapshots before examination of
holdout failure details. The development measurements are in
[development-resources.json](evidence/development-resources.json) and
[development-inputs.json](evidence/development-inputs.json). The corpus is a
purposive npm sample. These values do not establish ecosystem-wide coverage.
Expanded-limit attempts retain lower bounds, so the output and header maxima
are lower bounds for unrestricted inspection. The limits provide headroom over
observed work while placing a finite ceiling on accepted inspection work.

The evidence-read budget includes registry archives, source manifests, and
source `binding.gyp` files. Each locator consumes its own read budget, including
repeated content. Reads stop at the smaller of the per-file limit and remaining
snapshot budget, plus one probe byte. That probe can exceed the snapshot read
limit by one byte. A failed read retains the charge for bytes already returned,
including reads rejected by the per-file size check. An unavailable file returns
no bytes and consumes no byte budget.

The DEFLATE budget counts bytes before appending literals, stored blocks, or
backreferences. CRC, trailer, and tar failures retain their earlier output
charges. The gzip ISIZE field does not establish the work count. The tar budget
counts each nonzero header before checksum and profile checks. A rejected header
therefore consumes a header charge. Repeated archives consume all their work
again. After cumulative exhaustion, remaining evidence locators return the same
unsupported reason without file reads, hashing, or decompression.

The npm parser checks record and reference counts before graph allocation and
dependency resolution. References include every member of `dependencies`,
`devDependencies`, `optionalDependencies`, and `peerDependencies`. Duplicate names
across maps count separately, even when optional dependencies override regular
ones. The JSON parser counts each scalar, array, and object as one value. Object
keys do not count as values. It checks the value budget before allocating that
value.

One-time lockfile, locator-index, policy, and explicit root-manifest reads retain
their existing per-file byte limits. They do not consume the cumulative evidence
read budget. Each JSON document has its own value budget. Existing per-archive
compressed size, expanded size, entry count, path, integrity, and format checks
remain in force. These bounds do not impose a wall-clock deadline or qualify
other package-manager adapters or native FFI callers.

Run the boundary and CLI checks with `cargo test --release --offline`. The JSON
value-limit regression fails against the preceding parser. Small private test
budgets exercise cumulative repeated archives, CRC and truncation failures,
failed file-size checks, header failures, exhaustion, and recovery after errors.
The CLI checks assert exit 2, deterministic incomplete JSON, and unchanged input
files for oversized npm records, declared references, and JSON values.

The Python evidence collector applies the same fixed record, reference, read,
expanded-byte, and tar-header ceilings before it accepts a bundle. Collection
and subsequent validation each have their own per-snapshot budget; the two
passes are separately bounded. Failed and repeated local reads retain returned
byte charges. A zlib error whose partial output is unavailable to Python is
charged as a full capped 64 MiB attempt. The collector writes distinct archive
bytes directly to its isolated output directory instead of retaining all
archives in memory. A failed collection may leave partial files there, but it
never returns a validated index. Python's JSON decoder and network acquisition
still rely on the existing per-file limit and request timeout; a whole-review
deadline is part of the consumer workflow qualification.
