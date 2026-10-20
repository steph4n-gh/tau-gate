# Measured archive compatibility

The frozen development sample includes ordinary registry archives whose ustar
root is an archive-specific directory instead of `package`, and one with
numeric metadata in the final 24 bytes of the nominal ustar prefix field.
The v4.1 parser treated these as unsupported. Commit `f91a0eb` accepts one
exact, consistent root and that measured timestamp-tail layout. It also
accepts printable ASCII path characters such as spaces, `#`, `$`, `^`, and
`~`, which appeared in development archives. Components still cannot be empty,
`.` or `..`, end in a dot or space, contain Windows-forbidden characters, or
use reserved device names. Case-folded duplicates, lifecycle path aliases,
links, extensions, parent-file conflicts, nonzero padding, malformed end
markers, checksum errors, and incorrect original-byte SRI still fail.

The timestamp exception requires zero bytes 345–475 and two 11-digit octal
fields followed by NUL at bytes 476–487 and 488–499. The full tar header
checksum covers those bytes. Other post-NUL metadata remains unsupported.

Three independently captured archive references were replayed against the
release build from `f91a0eb`. The real `@types/json5` 0.0.29 archive and the
real `@types/cacheable-request` 6.0.3 archive produced complete reviews;
manifest, native-input, lifecycle, candidate, and original archive hashes
matched the independent oracle. The separately constructed `legacy-root`
archive remains incomplete because its prefix contains a different metadata
layout. Its earlier scripts-disabled npm installation proves that npm can
install those bytes; it does not make this unsupported profile safe to infer.
The `@types/cacheable-request` reference was inspected without an npm install
of its external dependencies. These examples establish specific byte-level
correspondence, not general npm archive compatibility or execution safety.

The local replay script and exact result are retained at
`/Volumes/Storage/taugate-qualification/compatibility-check/replay.py`
(SHA256 `c45125bc3af59b6ccd272f7fda49bd54d43ee87db92b2cf90fbca69a287ad97d`)
and `receipt-final.json`
(SHA256 `cff599b99f130abaefe794ff43ed83e2d18c02d32f41af7ec125a96820909016`).
The latter binds the binary hash and three original archive hashes. The
source reference receipt is in
`/Volumes/Storage/taugate-qualification/legacy-oracle-reference/receipt.json`.
