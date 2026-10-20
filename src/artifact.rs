use crate::digest::{sha256, sha512};
use std::collections::BTreeMap;

const MAX_COMPRESSED: usize = 64 * 1024 * 1024;
const MAX_TAR: usize = 64 * 1024 * 1024;
const MAX_MANIFEST: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

pub(crate) struct Budget {
    pub(crate) read_remaining: u64,
    expanded_remaining: u64,
    entries_remaining: u64,
    exhausted: Option<&'static str>,
}

impl Budget {
    pub(crate) fn new() -> Self {
        Self {
            read_remaining: 2 * 1024 * 1024 * 1024,
            expanded_remaining: 4 * 1024 * 1024 * 1024,
            entries_remaining: 250_000,
            exhausted: None,
        }
    }

    pub(crate) fn check(&self) -> Result<(), String> {
        self.exhausted.map_or(Ok(()), |reason| Err(reason.into()))
    }

    pub(crate) fn read(&mut self, count: usize) -> Result<(), String> {
        self.check()?;
        let result = Self::charge(
            &mut self.read_remaining,
            count,
            &mut self.exhausted,
            "snapshot evidence reads exceed 2 GiB",
        );
        if result.is_err() {
            self.read_remaining = 0;
        }
        result
    }

    fn expand(&mut self, count: usize) -> Result<(), String> {
        self.check()?;
        Self::charge(
            &mut self.expanded_remaining,
            count,
            &mut self.exhausted,
            "snapshot expanded evidence exceeds 4 GiB",
        )
    }

    fn entry(&mut self) -> Result<(), String> {
        self.check()?;
        Self::charge(
            &mut self.entries_remaining,
            1,
            &mut self.exhausted,
            "snapshot tar processing exceeds 250000 headers",
        )
    }

    fn charge(
        remaining: &mut u64,
        count: usize,
        exhausted: &mut Option<&'static str>,
        reason: &'static str,
    ) -> Result<(), String> {
        if count as u64 > *remaining {
            *exhausted = Some(reason);
            return Err(reason.into());
        }
        *remaining -= count as u64;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Artifact {
    pub manifest: Vec<u8>,
    pub binding_gyp_sha256: Option<String>,
    pub sha512: String,
}

pub(crate) fn inspect(
    bytes: &[u8],
    integrity: &str,
    expanded: &mut Vec<u8>,
    budget: &mut Budget,
) -> Result<Artifact, String> {
    expanded.clear();
    budget.check()?;
    if bytes.len() > MAX_COMPRESSED {
        return Err("compressed artifact exceeds 64 MiB".into());
    }
    let digest = sha512(bytes);
    if integrity != format!("sha512-{}", base64_digest(&digest)) {
        return Err("artifact requires one matching canonical SHA512 integrity".into());
    }
    gunzip(bytes, expanded, budget)?;
    let (manifest, binding_gyp_sha256) = inspect_tar(expanded, budget)?;
    Ok(Artifact {
        manifest,
        binding_gyp_sha256,
        sha512: digest,
    })
}

fn base64_digest(hex: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let nibble = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect();
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let word = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        result.push(ALPHABET[((word >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((word >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 {
            ALPHABET[((word >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            ALPHABET[(word & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, slot) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(value & 1));
        }
        *slot = value;
    }
    let mut crc = !0u32;
    for byte in bytes {
        crc = table[((crc as u8) ^ byte) as usize] ^ (crc >> 8);
    }
    !crc
}

fn gunzip(bytes: &[u8], output: &mut Vec<u8>, budget: &mut Budget) -> Result<(), String> {
    output.clear();
    if bytes.len() < 18 || bytes[..3] != [0x1f, 0x8b, 8] || bytes[3] & 0xe0 != 0 {
        return Err("invalid gzip header".into());
    }
    let end = bytes.len() - 8;
    let flags = bytes[3];
    let mut start = 10;
    if flags & 4 != 0 {
        let size = bytes
            .get(start..start + 2)
            .ok_or("truncated gzip extra field")?;
        start += 2 + u16::from_le_bytes([size[0], size[1]]) as usize;
    }
    for flag in [8, 16] {
        if flags & flag != 0 {
            let field = bytes.get(start..end).ok_or("truncated gzip text field")?;
            start += field
                .iter()
                .position(|byte| *byte == 0)
                .ok_or("unterminated gzip text field")?
                + 1;
        }
    }
    if flags & 2 != 0 {
        let check = bytes
            .get(start..start + 2)
            .ok_or("truncated gzip header checksum")?;
        if crc32(&bytes[..start]) as u16 != u16::from_le_bytes([check[0], check[1]]) {
            return Err("gzip header checksum mismatch".into());
        }
        start += 2;
    }
    let payload = bytes.get(start..end).ok_or("truncated gzip header")?;
    inflate(payload, output, budget)?;
    if crc32(output) != u32::from_le_bytes(bytes[end..end + 4].try_into().unwrap()) {
        return Err("gzip checksum mismatch".into());
    }
    if output.len() as u32 != u32::from_le_bytes(bytes[end + 4..].try_into().unwrap()) {
        return Err("gzip expanded size mismatch".into());
    }
    Ok(())
}

struct Bits<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Bits<'_> {
    fn read(&mut self, count: usize) -> Result<usize, String> {
        if self.position + count > self.bytes.len() * 8 {
            return Err("truncated DEFLATE stream".into());
        }
        let mut value = 0;
        for shift in 0..count {
            value |=
                (((self.bytes[self.position / 8] >> (self.position % 8)) & 1) as usize) << shift;
            self.position += 1;
        }
        Ok(value)
    }

    fn align(&mut self) {
        self.position = self.position.div_ceil(8) * 8;
    }
}

struct Huffman {
    counts: [usize; 16],
    symbols: Vec<usize>,
}

impl Huffman {
    fn new(lengths: &[usize], allow_single: bool, allow_empty: bool) -> Result<Self, String> {
        let mut counts = [0; 16];
        for &length in lengths {
            if length > 15 {
                return Err("invalid Huffman code length".into());
            }
            counts[length] += 1;
        }
        counts[0] = 0;
        let used: usize = counts.iter().sum();
        let mut available = 1isize;
        for count in counts.iter().skip(1) {
            available = 2 * available - *count as isize;
            if available < 0 {
                return Err("oversubscribed Huffman tree".into());
            }
        }
        if available != 0
            && !(allow_single && used == 1 && counts[1] == 1)
            && !(allow_empty && used == 0)
        {
            return Err("incomplete Huffman tree".into());
        }
        let mut symbols = Vec::with_capacity(used);
        for length in 1..=15 {
            for (symbol, &actual) in lengths.iter().enumerate() {
                if actual == length {
                    symbols.push(symbol);
                }
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<usize, String> {
        let mut code = 0;
        let mut first = 0;
        let mut index = 0;
        for length in 1..=15 {
            code |= bits.read(1)?;
            let count = self.counts[length];
            if code >= first && code - first < count {
                return Ok(self.symbols[index + code - first]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err("invalid Huffman code".into())
    }
}

fn dynamic_trees(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), String> {
    let literals = bits.read(5)? + 257;
    let distances = bits.read(5)? + 1;
    let codes = bits.read(4)? + 4;
    if literals > 286 {
        return Err("invalid DEFLATE literal count".into());
    }
    let order = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut lengths = [0; 19];
    for &index in order.iter().take(codes) {
        lengths[index] = bits.read(3)?;
    }
    let code_tree = Huffman::new(&lengths, false, false)?;
    let mut lengths = Vec::with_capacity(literals + distances);
    while lengths.len() < literals + distances {
        let code = code_tree.decode(bits)?;
        let (value, repeat) = match code {
            0..=15 => (code, 1),
            16 => (
                *lengths.last().ok_or("Huffman repeat has no predecessor")?,
                bits.read(2)? + 3,
            ),
            17 => (0, bits.read(3)? + 3),
            18 => (0, bits.read(7)? + 11),
            _ => return Err("invalid Huffman repeat".into()),
        };
        if lengths.len() + repeat > literals + distances {
            return Err("Huffman repeat exceeds declared lengths".into());
        }
        lengths.resize(lengths.len() + repeat, value);
    }
    if lengths[256] == 0 {
        return Err("DEFLATE tree has no end marker".into());
    }
    Ok((
        Huffman::new(&lengths[..literals], true, false)?,
        Huffman::new(&lengths[literals..], true, true)?,
    ))
}

fn inflate(payload: &[u8], output: &mut Vec<u8>, budget: &mut Budget) -> Result<(), String> {
    output.clear();
    budget.check()?;
    let mut bits = Bits {
        bytes: payload,
        position: 0,
    };
    loop {
        let final_block = bits.read(1)? != 0;
        match bits.read(2)? {
            0 => {
                bits.align();
                let length = bits.read(16)?;
                if length ^ bits.read(16)? != 0xffff {
                    return Err("DEFLATE stored length mismatch".into());
                }
                if output.len() + length > MAX_TAR {
                    return Err("expanded artifact exceeds 64 MiB".into());
                }
                let start = bits.position / 8;
                let bytes = payload
                    .get(start..start + length)
                    .ok_or("truncated DEFLATE stored block")?;
                budget.expand(bytes.len())?;
                output.extend_from_slice(bytes);
                bits.position += length * 8;
            }
            kind @ (1 | 2) => {
                let (literal_tree, distance_tree) = if kind == 1 {
                    let mut lengths = [8; 288];
                    lengths[144..256].fill(9);
                    lengths[256..280].fill(7);
                    (
                        Huffman::new(&lengths, false, false)?,
                        Huffman::new(&[5; 32], false, false)?,
                    )
                } else {
                    dynamic_trees(&mut bits)?
                };
                compressed_block(&mut bits, &literal_tree, &distance_tree, output, budget)?;
            }
            _ => return Err("reserved DEFLATE block type".into()),
        }
        if final_block {
            bits.align();
            if bits.position / 8 != payload.len() {
                return Err("gzip contains trailing data or multiple members".into());
            }
            return Ok(());
        }
    }
}

fn compressed_block(
    bits: &mut Bits<'_>,
    literals: &Huffman,
    distances: &Huffman,
    output: &mut Vec<u8>,
    budget: &mut Budget,
) -> Result<(), String> {
    const LENGTH_BASE: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LENGTH_EXTRA: [usize; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DISTANCE_BASE: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DISTANCE_EXTRA: [usize; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];
    loop {
        match literals.decode(bits)? {
            byte @ 0..=255 => {
                if output.len() == MAX_TAR {
                    return Err("expanded artifact exceeds 64 MiB".into());
                }
                budget.expand(1)?;
                output.push(byte as u8);
            }
            256 => return Ok(()),
            code @ 257..=285 => {
                let length = LENGTH_BASE[code - 257] + bits.read(LENGTH_EXTRA[code - 257])?;
                let distance_code = distances.decode(bits)?;
                if distance_code >= 30 {
                    return Err("reserved DEFLATE distance code".into());
                }
                let distance =
                    DISTANCE_BASE[distance_code] + bits.read(DISTANCE_EXTRA[distance_code])?;
                if distance > output.len() {
                    return Err("DEFLATE distance exceeds produced bytes".into());
                }
                if output.len() + length > MAX_TAR {
                    return Err("expanded artifact exceeds 64 MiB".into());
                }
                budget.expand(length)?;
                for _ in 0..length {
                    output.push(output[output.len() - distance]);
                }
            }
            _ => return Err("reserved DEFLATE length code".into()),
        }
    }
}

fn tar_text(field: &[u8]) -> Result<&str, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err("ambiguous tar text field".into());
    }
    std::str::from_utf8(&field[..end]).map_err(|_| "non-UTF8 tar path".into())
}

fn tar_number(field: &[u8]) -> Result<usize, String> {
    let mut value = 0usize;
    let mut digits = false;
    let mut ended = false;
    for &byte in field {
        match byte {
            b'0'..=b'7' if !ended => {
                digits = true;
                value = value
                    .checked_mul(8)
                    .and_then(|v| v.checked_add((byte - b'0') as usize))
                    .ok_or("tar number overflow")?;
            }
            0 | b' ' => {
                if digits || byte == 0 {
                    ended = true;
                }
            }
            _ => return Err("invalid octal tar number".into()),
        }
    }
    Ok(value)
}

fn inspect_tar(tar: &[u8], budget: &mut Budget) -> Result<(Vec<u8>, Option<String>), String> {
    if tar.len() % 512 != 0 {
        return Err("tar length is not block aligned".into());
    }
    let mut position = 0;
    let mut paths = BTreeMap::new();
    let mut root: Option<String> = None;
    let mut manifest = None;
    let mut binding = None;
    loop {
        let header = tar
            .get(position..position + 512)
            .ok_or("tar is missing its end markers")?;
        if header.iter().all(|byte| *byte == 0) {
            if tar.len() - position < 1024 || tar[position..].iter().any(|byte| *byte != 0) {
                return Err("invalid tar end markers or trailing data".into());
            }
            break;
        }
        budget.entry()?;
        if paths.len() == MAX_ENTRIES {
            return Err("tar exceeds 10000 entries".into());
        }
        if &header[257..265] != b"ustar\x0000" {
            return Err("artifact requires POSIX ustar headers".into());
        }
        let expected = tar_number(&header[148..156])?;
        let actual: usize = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    32
                } else {
                    *byte as usize
                }
            })
            .sum();
        if expected != actual {
            return Err("tar header checksum mismatch".into());
        }
        let directory = match header[156] {
            b'0' | 0 => false,
            b'5' => true,
            _ => return Err("tar links, extensions and special records are unsupported".into()),
        };
        if header[157..257].iter().any(|byte| *byte != 0)
            || header[500..].iter().any(|byte| *byte != 0)
        {
            return Err("unsupported tar link or reserved metadata".into());
        }
        for field in [
            &header[100..108],
            &header[108..116],
            &header[116..124],
            &header[136..148],
        ] {
            tar_number(field)?;
        }
        if tar_number(&header[329..337])? != 0 || tar_number(&header[337..345])? != 0 {
            return Err("tar regular entry has device metadata".into());
        }
        let size = tar_number(&header[124..136])?;
        if size > MAX_TAR || (directory && size != 0) {
            return Err("invalid tar entry size".into());
        }
        let name = tar_text(&header[..100])?;
        let prefix = match tar_text(&header[345..500]) {
            Ok(prefix) => prefix,
            Err(_)
                if header[345..476].iter().all(|byte| *byte == 0)
                    && [&header[476..488], &header[488..500]].iter().all(|field| {
                        field[..11].iter().all(|byte| matches!(byte, b'0'..=b'7')) && field[11] == 0
                    }) =>
            {
                ""
            }
            Err(reason) => return Err(reason),
        };
        let joined = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let path = if directory {
            joined.strip_suffix('/').unwrap_or(&joined)
        } else {
            &joined
        };
        if path.split('/').any(|part| {
            let base = part.split('.').next().unwrap().to_ascii_uppercase();
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with('.')
                || part.ends_with(' ')
                || !part.bytes().all(|b| {
                    (b.is_ascii_graphic() || b == b' ')
                        && !matches!(b, b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|')
                })
                || matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                || (base.len() == 4
                    && (base.starts_with("COM") || base.starts_with("LPT"))
                    && matches!(base.as_bytes()[3], b'1'..=b'9'))
        }) {
            return Err("unsupported nonportable tar path".into());
        }
        let (member_root, relative) = path.split_once('/').unwrap_or((path, ""));
        if root
            .as_deref()
            .is_some_and(|expected| expected != member_root)
        {
            return Err("tar contains inconsistent archive roots".into());
        }
        root.get_or_insert_with(|| member_root.to_owned());
        if relative.is_empty() && !directory {
            return Err("tar root is not a directory".into());
        }
        if directory && matches!(relative, "package.json" | "binding.gyp") {
            return Err("evidence path is not a regular tar file".into());
        }
        let folded = path.to_ascii_lowercase();
        if matches!(
            relative.to_ascii_lowercase().as_str(),
            "package.json" | "binding.gyp"
        ) && !matches!(relative, "package.json" | "binding.gyp")
        {
            return Err("noncanonical lifecycle evidence tar path".into());
        }
        if paths.insert(folded, directory).is_some() {
            return Err("duplicate case-folded tar path".into());
        }
        let start = position + 512;
        let padded = size.div_ceil(512) * 512;
        let data = tar.get(start..start + size).ok_or("truncated tar entry")?;
        let padding = tar
            .get(start + size..start + padded)
            .ok_or("truncated tar padding")?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err("nonzero tar entry padding".into());
        }
        match relative {
            "package.json" => {
                if size > MAX_MANIFEST {
                    return Err("package manifest exceeds 1 MiB".into());
                }
                manifest = Some(data.to_vec());
            }
            "binding.gyp" => binding = Some(sha256(data)),
            _ => {}
        }
        position = start + padded;
    }
    for path in paths.keys() {
        for (offset, _) in path.match_indices('/') {
            if paths.get(&path[..offset]) == Some(&false) {
                return Err("tar file conflicts with a parent directory".into());
            }
        }
    }
    Ok((
        manifest.ok_or("tar is missing package/package.json")?,
        binding,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let value: usize = header.iter().map(|byte| *byte as usize).sum();
        header[148..156].copy_from_slice(format!("{value:06o}\0 ").as_bytes());
    }

    fn tar(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut output = Vec::new();
        for (name, kind, data) in entries {
            let mut header = [0; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[100..108].copy_from_slice(b"0000644\0");
            header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
            header[156] = *kind;
            header[257..265].copy_from_slice(b"ustar\x0000");
            checksum(&mut header);
            output.extend_from_slice(&header);
            output.extend_from_slice(data);
            output.resize(output.len().div_ceil(512) * 512, 0);
        }
        output.resize(output.len() + 1024, 0);
        output
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut output = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        let count = bytes.len().div_ceil(65535).max(1);
        for index in 0..count {
            let start = index * 65535;
            let end = (start + 65535).min(bytes.len());
            let length = (end - start) as u16;
            output.push(u8::from(index + 1 == count));
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(&(!length).to_le_bytes());
            output.extend_from_slice(&bytes[start..end]);
        }
        output.extend_from_slice(&crc32(bytes).to_le_bytes());
        output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        output
    }

    fn integrity(bytes: &[u8]) -> String {
        format!("sha512-{}", base64_digest(&sha512(bytes)))
    }

    #[test]
    fn artifact_content_is_bound_to_original_gzip_bytes() {
        let mut expanded = Vec::new();
        let manifest = br#"{"name":"sample","version":"1.0.0"}"#;
        let bytes = gzip(&tar(&[
            ("package/", b'5', b""),
            ("package/package.json", b'0', manifest),
            ("package/binding.gyp", b'0', b"native"),
        ]));
        let value = inspect(
            &bytes,
            &integrity(&bytes),
            &mut expanded,
            &mut Budget::new(),
        )
        .unwrap();
        assert_eq!(value.manifest, manifest);
        assert_eq!(value.binding_gyp_sha256, Some(sha256(b"native")));
        assert_eq!(value.sha512, sha512(&bytes));
        let mut other_header = bytes.clone();
        other_header[4] = 1;
        assert!(inspect(
            &other_header,
            &integrity(&bytes),
            &mut expanded,
            &mut Budget::new()
        )
        .is_err());
        assert!(inspect(
            &other_header,
            &integrity(&other_header),
            &mut expanded,
            &mut Budget::new()
        )
        .is_ok());
        for invalid in [
            format!(" {}", integrity(&bytes)),
            format!("{} {}", integrity(&bytes), integrity(&bytes)),
            integrity(&bytes).trim_end_matches('=').to_owned(),
            integrity(&bytes).replace("sha512-", "sha256-"),
        ] {
            assert!(inspect(&bytes, &invalid, &mut expanded, &mut Budget::new()).is_err());
        }
    }

    #[test]
    fn repeated_artifact_inspection_recovers_after_failed_integrity_crc_and_truncation() {
        let large_manifest = br#"{"name":"large","version":"1.0.0"}"#;
        let large = gzip(&tar(&[
            ("package/package.json", b'0', large_manifest),
            ("package/binding.gyp", b'0', b"native"),
            ("package/data.bin", b'0', &vec![42; 4 * 1024 * 1024]),
        ]));
        let small_manifest = br#"{"name":"small","version":"2.0.0"}"#;
        let small = gzip(&tar(&[("package/package.json", b'0', small_manifest)]));
        let large_integrity = integrity(&large);
        let small_integrity = integrity(&small);
        let mut bad_crc = large.clone();
        let crc_position = bad_crc.len() - 8;
        bad_crc[crc_position] ^= 1;
        let truncated = large[..large.len() - 10].to_vec();
        let mut expanded = Vec::new();
        for (invalid, invalid_integrity) in [
            (large.as_slice(), small_integrity.clone()),
            (bad_crc.as_slice(), integrity(&bad_crc)),
            (truncated.as_slice(), integrity(&truncated)),
        ] {
            let first =
                inspect(&large, &large_integrity, &mut expanded, &mut Budget::new()).unwrap();
            assert_eq!(first.manifest, large_manifest);
            assert_eq!(first.binding_gyp_sha256, Some(sha256(b"native")));
            assert_eq!(first.sha512, sha512(&large));
            assert!(inspect(
                invalid,
                &invalid_integrity,
                &mut expanded,
                &mut Budget::new()
            )
            .is_err());
            let next =
                inspect(&small, &small_integrity, &mut expanded, &mut Budget::new()).unwrap();
            assert_eq!(next.manifest, small_manifest);
            assert_eq!(next.binding_gyp_sha256, None);
            assert_eq!(next.sha512, sha512(&small));
            assert_eq!(first.manifest, large_manifest);
        }
    }

    #[test]
    fn stored_fixed_and_dynamic_deflate_match_external_zlib_vectors() {
        let mut output = Vec::new();
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        gunzip(&gzip(b"stored"), &mut output, &mut Budget::new()).unwrap();
        assert_eq!(output, b"stored");
        inflate(b"KLJNDB\0", &mut output, &mut Budget::new()).unwrap();
        assert_eq!(output, b"abcabcabcabcabc");
        let dynamic = b"\xed\xcaG\x01\x800\x10EA+_\x01jb\x80\x92\xd0\xd9\x10\x08M=\x88\xe0\xf8\xce3\xae\xf3Zs_\x8f\xaa\x92\x9d\x8b\x82]\x1a\xf2\x1c7\xd9\xe1\x93\xf6\x8f\xa7\xf2\xb9\xd5X[\xc8\x91\xc9d2\x99L&\x93\xc9d2\x99L&\x93\xff\xc8/";
        inflate(dynamic, &mut output, &mut Budget::new()).unwrap();
        assert_eq!(
            output,
            b"The quick brown fox jumps over the lazy dog. ".repeat(100)
        );
        assert!(inflate(
            &dynamic[..dynamic.len() - 1],
            &mut output,
            &mut Budget::new()
        )
        .is_err());
        assert!(inflate(&[7], &mut output, &mut Budget::new()).is_err());
        assert!(inflate(&[1, 1, 0, 0, 0, 1], &mut output, &mut Budget::new()).is_err());
        assert!(inflate(&[3, 2, 0], &mut output, &mut Budget::new()).is_err());
    }

    #[test]
    fn huffman_rejects_oversubscribed_incomplete_and_impossible_trees() {
        assert!(Huffman::new(&[1, 1, 1], true, false).is_err());
        assert!(Huffman::new(&[2, 2], true, false).is_err());
        assert!(Huffman::new(&[16], true, false).is_err());
        assert!(Huffman::new(&[0], true, false).is_err());
        let empty = Huffman::new(&[0], true, true).unwrap();
        assert!(empty
            .decode(&mut Bits {
                bytes: &[0, 0],
                position: 0
            })
            .is_err());
        let single = Huffman::new(&[1], true, false).unwrap();
        assert_eq!(
            single
                .decode(&mut Bits {
                    bytes: &[0],
                    position: 0
                })
                .unwrap(),
            0
        );
        assert!(single
            .decode(&mut Bits {
                bytes: &[1, 0],
                position: 0
            })
            .is_err());
    }

    #[test]
    fn gzip_rejects_crc_size_reserved_flags_junk_and_multiple_members() {
        let mut output = Vec::new();
        let bytes = gzip(b"payload");
        for position in [0, 2, bytes.len() - 8, bytes.len() - 4] {
            let mut changed = bytes.clone();
            changed[position] ^= 1;
            assert!(gunzip(&changed, &mut output, &mut Budget::new()).is_err());
        }
        let mut reserved = bytes.clone();
        reserved[3] = 0x20;
        assert!(gunzip(&reserved, &mut output, &mut Budget::new()).is_err());
        assert!(gunzip(&bytes[..bytes.len() - 1], &mut output, &mut Budget::new()).is_err());
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(gunzip(&junk, &mut output, &mut Budget::new()).is_err());
        let mut concatenated = bytes.clone();
        concatenated.extend_from_slice(&bytes);
        assert!(gunzip(&concatenated, &mut output, &mut Budget::new()).is_err());
    }

    #[test]
    fn gzip_optional_fields_require_valid_bounds_and_header_checksum() {
        let mut output = Vec::new();
        let base = gzip(b"payload");
        let mut bytes = base[..10].to_vec();
        bytes[3] = 4 | 8 | 16 | 2;
        bytes.extend_from_slice(&[2, 0, 42, 43]);
        bytes.extend_from_slice(b"name\0comment\0");
        bytes.extend_from_slice(&(crc32(&bytes) as u16).to_le_bytes());
        bytes.extend_from_slice(&base[10..]);
        gunzip(&bytes, &mut output, &mut Budget::new()).unwrap();
        assert_eq!(output, b"payload");
        bytes[14] ^= 1;
        assert!(gunzip(&bytes, &mut output, &mut Budget::new()).is_err());
        let mut truncated = base.clone();
        truncated[3] = 4;
        truncated[10..12].fill(255);
        assert!(gunzip(&truncated, &mut output, &mut Budget::new()).is_err());
        let mut unterminated = base;
        unterminated[3] = 8;
        unterminated[10..].fill(255);
        assert!(gunzip(&unterminated, &mut output, &mut Budget::new()).is_err());
    }

    #[test]
    fn tar_requires_unique_regular_manifest_and_safe_complete_archive() {
        for path in [
            "../package/package.json",
            "/package/package.json",
            "package/../package.json",
            "package//package.json",
            "package/./package.json",
            "package/C:manifest",
            "package/a\\b",
        ] {
            assert!(
                inspect_tar(&tar(&[(path, b'0', b"{}")]), &mut Budget::new()).is_err(),
                "{path}"
            );
        }
        for kind in [b'x', b'g', b'L', b'K', b'1', b'2', b'3', b'4', b'6', b'7'] {
            assert!(inspect_tar(
                &tar(&[("package/package.json", kind, b"{}")]),
                &mut Budget::new()
            )
            .is_err());
        }
        assert!(inspect_tar(
            &tar(&[
                ("package/package.json", b'0', b"{}"),
                ("package/package.json", b'0', b"{}")
            ]),
            &mut Budget::new()
        )
        .is_err());
        assert!(inspect_tar(
            &tar(&[("package/package.json", b'5', b"")]),
            &mut Budget::new()
        )
        .is_err());
        assert!(inspect_tar(
            &tar(&[("package/README.md", b'0', b"readme")]),
            &mut Budget::new()
        )
        .is_err());
        assert!(inspect_tar(
            &tar(&[
                ("package/package.json", b'0', b"{}"),
                ("package/a", b'0', b"a"),
                ("package/a/b", b'0', b"b")
            ]),
            &mut Budget::new()
        )
        .is_err());
        let valid = tar(&[("package/package.json", b'0', b"{}")]);
        assert!(inspect_tar(&valid[..valid.len() - 512], &mut Budget::new()).is_err());
        assert!(inspect_tar(&valid[..valid.len() - 1], &mut Budget::new()).is_err());
        let mut trailing = valid.clone();
        *trailing.last_mut().unwrap() = 1;
        assert!(inspect_tar(&trailing, &mut Budget::new()).is_err());
        let mut padded = valid.clone();
        padded[514] = 1;
        assert!(inspect_tar(&padded, &mut Budget::new()).is_err());
        let mut bad_checksum = valid.clone();
        bad_checksum[100] ^= 1;
        assert!(inspect_tar(&bad_checksum, &mut Budget::new()).is_err());
        let mut bad_size = valid.clone();
        bad_size[124] = 0x80;
        checksum(&mut bad_size[..512]);
        assert!(inspect_tar(&bad_size, &mut Budget::new()).is_err());
        let mut hidden_name = valid;
        hidden_name[99] = b'x';
        checksum(&mut hidden_name[..512]);
        assert!(inspect_tar(&hidden_name, &mut Budget::new()).is_err());
    }

    #[test]
    fn manifest_size_limit_is_enforced_after_integrity_validation() {
        let allowed = tar(&[("package/package.json", b'0', &vec![b' '; MAX_MANIFEST])]);
        assert_eq!(
            inspect_tar(&allowed, &mut Budget::new()).unwrap().0.len(),
            MAX_MANIFEST
        );
        let oversized = tar(&[("package/package.json", b'0', &vec![b' '; MAX_MANIFEST + 1])]);
        assert!(inspect_tar(&oversized, &mut Budget::new())
            .unwrap_err()
            .contains("1 MiB"));
    }
    #[test]
    fn cumulative_expansion_counts_repeated_archives_and_stops_after_exhaustion() {
        let manifest = br#"{"name":"pkg","version":"1"}"#;
        let plain = tar(&[("package/package.json", b'0', manifest)]);
        let bytes = gzip(&plain);
        let mut budget = Budget::new();
        budget.expanded_remaining = 2 * plain.len() as u64;
        let mut output = Vec::new();
        let first = inspect(&bytes, &integrity(&bytes), &mut output, &mut budget).unwrap();
        inspect(&bytes, &integrity(&bytes), &mut output, &mut budget).unwrap();
        assert_eq!(budget.expanded_remaining, 0);
        let error = inspect(&bytes, &integrity(&bytes), &mut output, &mut budget).unwrap_err();
        assert!(error.contains("expanded evidence"));
        assert!(output.is_empty());
        assert_eq!(
            inspect(b"not an archive", "", &mut output, &mut budget).unwrap_err(),
            error
        );
        assert_eq!(first.manifest, manifest);
    }

    #[test]
    fn expansion_limit_applies_to_stored_literals_and_backreferences() {
        for (payload, expected) in [
            (gzip(b"payload"), b"payload".as_slice()),
            (gzip(b""), b"".as_slice()),
        ] {
            let mut output = Vec::new();
            let mut budget = Budget::new();
            budget.expanded_remaining = expected.len() as u64;
            gunzip(&payload, &mut output, &mut budget).unwrap();
            assert_eq!(output, expected);
            if !expected.is_empty() {
                let mut short = Budget::new();
                short.expanded_remaining = expected.len() as u64 - 1;
                assert!(gunzip(&payload, &mut output, &mut short).is_err());
                assert!(output.is_empty());
            }
        }
        let mut budget = Budget::new();
        budget.expanded_remaining = 15;
        let mut output = Vec::new();
        inflate(b"KLJNDB\0", &mut output, &mut budget).unwrap();
        assert_eq!(output, b"abcabcabcabcabc");
        let mut short = Budget::new();
        short.expanded_remaining = 14;
        assert!(inflate(b"KLJNDB\0", &mut output, &mut short).is_err());
        assert!(output.len() <= 14);
        assert_eq!(14 - short.expanded_remaining, output.len() as u64);
    }

    #[test]
    fn failed_crc_and_truncated_streams_keep_their_produced_byte_charge() {
        let mut bad_crc = gzip(b"bad");
        let end = bad_crc.len() - 8;
        bad_crc[end] ^= 1;
        let mut budget = Budget::new();
        budget.expanded_remaining = 5;
        let mut output = Vec::new();
        assert!(gunzip(&bad_crc, &mut output, &mut budget).is_err());
        assert_eq!(output, b"bad");
        gunzip(&gzip(b"ok"), &mut output, &mut budget).unwrap();
        assert_eq!(output, b"ok");
        assert_eq!(budget.expanded_remaining, 0);

        let mut budget = Budget::new();
        budget.expanded_remaining = 65_537;
        let bytes = gzip(&vec![42; 65_536]);
        assert!(gunzip(&bytes[..bytes.len() - 1], &mut output, &mut budget).is_err());
        assert_eq!(output.len(), 65_535);
        assert_eq!(budget.expanded_remaining, 2);
        gunzip(&gzip(b"ok"), &mut output, &mut budget).unwrap();
        assert_eq!(output, b"ok");
        assert_eq!(budget.expanded_remaining, 0);
    }

    #[test]
    fn cumulative_headers_count_failed_and_repeated_tar_inspections() {
        let bytes = tar(&[("package/package.json", b'0', b"{}")]);
        let mut budget = Budget::new();
        budget.entries_remaining = 2;
        let mut bad = bytes.clone();
        bad[100] ^= 1;
        assert!(inspect_tar(&bad, &mut budget).is_err());
        assert_eq!(inspect_tar(&bytes, &mut budget).unwrap().0, b"{}");
        assert_eq!(budget.entries_remaining, 0);
        assert!(inspect_tar(&bytes, &mut budget)
            .unwrap_err()
            .contains("headers"));
        let mut short = Budget::new();
        short.entries_remaining = 1;
        assert!(inspect_tar(
            &tar(&[
                ("package/package.json", b'0', b"{}"),
                ("package/readme", b'0', b"readme"),
            ]),
            &mut short
        )
        .unwrap_err()
        .contains("headers"));
    }

    #[test]
    fn one_consistent_archive_root_and_safe_printable_names() {
        let manifest = br#"{"name":"sample","version":"1"}"#;
        for root in ["json5", "cacheable-request", "node v24.12"] {
            let root_dir = format!("{root}/");
            let root_manifest = format!("{root}/package.json");
            let ordinary = format!("{root}/array/#/_compare-by-length.js");
            let tilde = format!("{root}/README.md~");
            let bytes = tar(&[
                (&root_dir, b'5', b""),
                (&root_manifest, b'0', manifest),
                (&ordinary, b'0', b"body"),
                (&tilde, b'0', b"old"),
            ]);
            assert_eq!(inspect_tar(&bytes, &mut Budget::new()).unwrap().0, manifest);
        }
        let rejected: [Vec<(&str, u8, &[u8])>; 4] = [
            vec![
                ("json5/package.json", b'0', manifest),
                ("other/README", b'0', b"readme"),
            ],
            vec![
                ("json5/package.json", b'0', manifest),
                ("JSON5/README", b'0', b"readme"),
            ],
            vec![("json5", b'0', manifest)],
            vec![("json5/Package.json", b'0', manifest)],
        ];
        for entries in rejected {
            assert!(inspect_tar(&tar(&entries), &mut Budget::new()).is_err());
        }
    }

    #[test]
    fn legacy_timestamp_tail_accepts_only_valid_octals_after_zero_padding() {
        let manifest = br#"{"name":"sample","version":"1"}"#;
        let mut bytes = tar(&[("cacheable-request/package.json", b'0', manifest)]);
        bytes[476..488].copy_from_slice(b"14332753065\0");
        bytes[488..500].copy_from_slice(b"14332753065\0");
        checksum(&mut bytes[..512]);
        assert_eq!(inspect_tar(&bytes, &mut Budget::new()).unwrap().0, manifest);

        for offset in [345, 346, 475] {
            let mut nonzero_padding = bytes.clone();
            nonzero_padding[offset] = b'x';
            checksum(&mut nonzero_padding[..512]);
            assert!(inspect_tar(&nonzero_padding, &mut Budget::new()).is_err());
        }
        let mut malformed_time = bytes;
        malformed_time[476] = b'8';
        checksum(&mut malformed_time[..512]);
        assert!(inspect_tar(&malformed_time, &mut Budget::new()).is_err());
    }
}
