use crate::error::{GateError, Result};
use std::collections::BTreeMap;

/// A minimal, zero-dependency parser for Tau-Gate.
/// Specifically designed to handle configuration (TOML-like), JSON, and basic YAML metadata extraction.
pub struct MiniParser;

impl MiniParser {
    /// Parses a TOML-like string into a simple key-value map.
    pub fn parse_config(content: &str) -> Result<BTreeMap<String, ConfigValue>> {
        let mut map = BTreeMap::new();
        let mut statement = String::new();
        let mut quote = None;
        for line in content.lines() {
            let mut cleaned = String::new();
            let mut escape = false;
            for c in line.chars() {
                if c == '#' && quote.is_none() {
                    break;
                }
                cleaned.push(c);
                if escape {
                    escape = false;
                    continue;
                }
                if c == '\\' && quote == Some('"') {
                    escape = true;
                    continue;
                }
                if Some(c) == quote {
                    quote = None
                } else if quote.is_none() && (c == '"' || c == '\'') {
                    quote = Some(c)
                }
            }
            statement.push_str(cleaned.trim());
            statement.push(' ');
            let t = statement.trim();
            if t.is_empty() {
                statement.clear();
                continue;
            }
            if quote.is_some() {
                return Err(GateError::Config("Unterminated string".into()));
            }
            let (key, raw) = t
                .split_once('=')
                .ok_or_else(|| GateError::Config("Expected key = value".into()))?;
            let key = key.trim();
            let raw = raw.trim();
            if raw.starts_with('[') && !raw.ends_with(']') {
                continue;
            }
            if !matches!(key, "whitelist" | "mode" | "threshold_percentage") {
                return Err(GateError::Config(format!("Unknown key {key}")));
            }
            let value = if raw.starts_with('[') {
                let mut items = Vec::new();
                for x in raw[1..raw.len() - 1].split(',') {
                    let x = x.trim();
                    if x.is_empty() {
                        continue;
                    }
                    items.push(config_string(x)?);
                }
                ConfigValue::Array(items)
            } else if raw.starts_with('"') || raw.starts_with('\'') {
                ConfigValue::String(config_string(raw)?)
            } else {
                ConfigValue::Float(
                    raw.parse()
                        .map_err(|_| GateError::Config("Invalid number".into()))?,
                )
            };
            if map.insert(key.into(), value).is_some() {
                return Err(GateError::Config("Duplicate key".into()));
            }
            statement.clear();
        }
        if !statement.trim().is_empty() {
            return Err(GateError::Config("Unterminated value".into()));
        }
        Ok(map)
    }

    /// A basic JSON value representation for custom parsing.
    pub fn parse_json(json: &str) -> Result<JsonNode> {
        if json.len() > 64 * 1024 * 1024 {
            return Err(GateError::Generic("JSON exceeds 64 MiB".into()));
        }
        let mut reader = JsonReader {
            text: json,
            bytes: json.as_bytes(),
            pos: 0,
        };
        let value = reader.value(0)?;
        reader.ws();
        if reader.pos != reader.bytes.len() {
            return Err(reader.error());
        }
        Ok(value)
    }

    /// V2.0 Hardening: Detects high-entropy strings (potential obfuscation) in manifests.
    pub fn detect_obfuscation(content: &str) -> bool {
        let mut max_continuous = 0;
        let mut current = 0;
        let mut distinct_chars = std::collections::BTreeSet::new();
        let mut max_distinct = 0;

        for c in content.chars() {
            if c.is_alphanumeric() || c == '/' || c == '+' || c == '=' {
                current += 1;
                distinct_chars.insert(c);
            } else {
                if current > max_continuous {
                    max_continuous = current;
                    max_distinct = distinct_chars.len();
                }
                current = 0;
                distinct_chars.clear();
            }
        }
        if current > max_continuous {
            max_continuous = current;
            max_distinct = distinct_chars.len();
        }
        max_continuous > 128 && max_distinct > 16
    }

    /// A minimal YAML extractor for pnpm-lock.yaml.
    pub fn parse_pnpm_yaml(yaml: &str) -> Result<PnpmMetadata> {
        let mut snapshots = BTreeMap::new();
        let mut packages = BTreeMap::new();
        let mut section = "";
        let mut id = String::new();
        let mut dependency_section = false;
        for line in yaml.lines() {
            let indent = line.chars().take_while(|c| *c == ' ').count();
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            if indent == 0 {
                section = match t {
                    "snapshots:" => "snapshots",
                    "packages:" => "packages",
                    _ => "",
                };
                id.clear();
                dependency_section = false;
                continue;
            }
            if section.is_empty() {
                continue;
            }
            if indent == 2 {
                let (key, _) = t
                    .split_once(':')
                    .ok_or_else(|| GateError::Graph("Unsupported pnpm key".into()))?;
                id = key.trim_matches(|c| c == '"' || c == '\'').into();
                dependency_section = false;
                if section == "snapshots" {
                    snapshots.insert(
                        id.clone(),
                        PnpmSnapshot {
                            dependencies: Vec::new(),
                        },
                    );
                } else {
                    packages.insert(
                        id.clone(),
                        PnpmPackage {
                            has_install_script: t.contains("hasInstallScript: true"),
                        },
                    );
                }
                continue;
            }
            if indent == 4 {
                dependency_section = t == "dependencies:" || t == "optionalDependencies:";
                if section == "packages"
                    && (t == "hasInstallScript: true" || t == "requiresBuild: true")
                {
                    if let Some(p) = packages.get_mut(&id) {
                        p.has_install_script = true;
                    }
                }
                continue;
            }
            if indent == 6 && section == "snapshots" && dependency_section {
                let (name, version) = t
                    .split_once(':')
                    .ok_or_else(|| GateError::Graph("Unsupported pnpm reference".into()))?;
                snapshots.get_mut(&id).context_pnpm()?.dependencies.push((
                    name.trim().trim_matches(|c| c == '"' || c == '\'').into(),
                    version
                        .trim()
                        .trim_matches(|c| c == '"' || c == '\'')
                        .into(),
                ));
            }
        }
        if snapshots.is_empty() {
            return Err(GateError::Graph(
                "INCOMPLETE: unsupported/empty pnpm snapshots".into(),
            ));
        }
        Ok(PnpmMetadata {
            snapshots,
            packages,
        })
    }
}

fn config_string(s: &str) -> Result<String> {
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        return Ok(s[1..s.len() - 1].into());
    }
    match MiniParser::parse_json(s)? {
        JsonNode::String(s) => Ok(s),
        _ => Err(GateError::Config("Expected quoted string".into())),
    }
}
trait PnpmContext<T> {
    fn context_pnpm(self) -> Result<T>;
}
impl<T> PnpmContext<T> for Option<T> {
    fn context_pnpm(self) -> Result<T> {
        self.ok_or_else(|| GateError::Graph("Invalid pnpm snapshot".into()))
    }
}

pub struct PnpmMetadata {
    pub snapshots: BTreeMap<String, PnpmSnapshot>,
    pub packages: BTreeMap<String, PnpmPackage>,
}

pub struct PnpmSnapshot {
    pub dependencies: Vec<(String, String)>,
}

pub struct PnpmPackage {
    pub has_install_script: bool,
}

#[derive(Debug, PartialEq)]
pub enum ConfigValue {
    String(String),
    Float(f64),
    Array(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum JsonNode {
    Object(BTreeMap<String, JsonNode>),
    Array(Vec<JsonNode>),
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

impl JsonNode {
    pub fn get(&self, key: &str) -> Option<&JsonNode> {
        match self {
            JsonNode::Object(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonNode::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonNode::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonNode>> {
        match self {
            JsonNode::Object(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<JsonNode>> {
        match self {
            JsonNode::Array(a) => Some(a),
            _ => None,
        }
    }
}

struct JsonReader<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> JsonReader<'a> {
    fn error(&self) -> GateError {
        GateError::Generic(format!("Invalid JSON at byte {}", self.pos))
    }
    fn ws(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.pos += 1;
        }
    }
    fn take(&mut self, b: u8) -> bool {
        self.ws();
        if self.bytes.get(self.pos) == Some(&b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn string(&mut self) -> Result<String> {
        if !self.take(b'"') {
            return Err(self.error());
        }
        let mut out = String::new();
        loop {
            let b = *self.bytes.get(self.pos).ok_or_else(|| self.error())?;
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = *self.bytes.get(self.pos).ok_or_else(|| self.error())?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut cp = self.hex()?;
                            if (0xd800..=0xdbff).contains(&cp) {
                                if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return Err(self.error());
                                }
                                self.pos += 2;
                                let low = self.hex()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err(self.error());
                                }
                                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                            }
                            out.push(char::from_u32(cp).ok_or_else(|| self.error())?);
                        }
                        _ => return Err(self.error()),
                    }
                }
                0..=31 => return Err(self.error()),
                _ => {
                    self.pos -= 1;
                    // The input is already valid UTF-8. Slice at a character boundary,
                    // without revalidating the entire remaining suffix for every scalar.
                    let text = self.text.get(self.pos..).ok_or_else(|| self.error())?;
                    let c = text.chars().next().ok_or_else(|| self.error())?;
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
    }
    fn hex(&mut self) -> Result<u32> {
        let raw = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.error())?;
        let text = std::str::from_utf8(raw).map_err(|_| self.error())?;
        let n = u32::from_str_radix(text, 16).map_err(|_| self.error())?;
        self.pos += 4;
        Ok(n)
    }
    fn value(&mut self, depth: usize) -> Result<JsonNode> {
        if depth > 128 {
            return Err(self.error());
        }
        self.ws();
        let b = *self.bytes.get(self.pos).ok_or_else(|| self.error())?;
        match b {
            b'"' => Ok(JsonNode::String(self.string()?)),
            b'{' => {
                self.pos += 1;
                let mut m = BTreeMap::new();
                if self.take(b'}') {
                    return Ok(JsonNode::Object(m));
                }
                loop {
                    let k = self.string()?;
                    if !self.take(b':') {
                        return Err(self.error());
                    }
                    let v = self.value(depth + 1)?;
                    if m.insert(k, v).is_some() {
                        return Err(self.error());
                    }
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(self.error());
                    }
                }
                Ok(JsonNode::Object(m))
            }
            b'[' => {
                self.pos += 1;
                let mut a = Vec::new();
                if self.take(b']') {
                    return Ok(JsonNode::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(self.error());
                    }
                }
                Ok(JsonNode::Array(a))
            }
            b't' | b'f' | b'n' => {
                let (word, v) = match b {
                    b't' => (b"true".as_slice(), JsonNode::Bool(true)),
                    b'f' => (b"false".as_slice(), JsonNode::Bool(false)),
                    _ => (b"null".as_slice(), JsonNode::Null),
                };
                if self.bytes.get(self.pos..self.pos + word.len()) != Some(word) {
                    return Err(self.error());
                }
                self.pos += word.len();
                Ok(v)
            }
            _ => {
                let start = self.pos;
                if self.bytes.get(self.pos) == Some(&b'-') {
                    self.pos += 1;
                }
                match self.bytes.get(self.pos) {
                    Some(b'0') => self.pos += 1,
                    Some(b'1'..=b'9') => {
                        self.pos += 1;
                        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                            self.pos += 1;
                        }
                    }
                    _ => return Err(self.error()),
                }
                if self.bytes.get(self.pos) == Some(&b'.') {
                    self.pos += 1;
                    let n = self.pos;
                    while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                        self.pos += 1;
                    }
                    if n == self.pos {
                        return Err(self.error());
                    }
                }
                if self
                    .bytes
                    .get(self.pos)
                    .is_some_and(|b| matches!(b, b'e' | b'E'))
                {
                    self.pos += 1;
                    if self
                        .bytes
                        .get(self.pos)
                        .is_some_and(|b| matches!(b, b'+' | b'-'))
                    {
                        self.pos += 1;
                    }
                    let n = self.pos;
                    while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
                        self.pos += 1;
                    }
                    if n == self.pos {
                        return Err(self.error());
                    }
                }
                let n = std::str::from_utf8(&self.bytes[start..self.pos])
                    .map_err(|_| self.error())?
                    .parse::<f64>()
                    .map_err(|_| self.error())?;
                if !n.is_finite() {
                    return Err(self.error());
                }
                Ok(JsonNode::Number(n))
            }
        }
    }
}

pub fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
impl JsonNode {
    pub fn to_json(&self) -> String {
        match self {
            Self::String(s) => json_string(s),
            Self::Bool(b) => b.to_string(),
            Self::Null => "null".into(),
            Self::Number(n) => {
                if n.is_finite() {
                    n.to_string()
                } else {
                    "null".into()
                }
            }
            Self::Array(a) => format!(
                "[{}]",
                a.iter().map(Self::to_json).collect::<Vec<_>>().join(",")
            ),
            Self::Object(m) => format!(
                "{{{}}}",
                m.iter()
                    .map(|(k, v)| format!("{}:{}", json_string(k), v.to_json()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mini_parser_config() {
        let toml = "threshold_percentage = 15.0\nwhitelist = [\"@astrojs/*\", 'vite']";
        let map = MiniParser::parse_config(toml).unwrap();
        assert_eq!(
            map.get("threshold_percentage"),
            Some(&ConfigValue::Float(15.0))
        );
    }
    #[test]
    fn test_mini_parser_json_basic() {
        let json = r#"{"name": "test", "version": "1.0", "active": true, "deps": ["a", "b"]}"#;
        let node = MiniParser::parse_json(json).unwrap();
        assert_eq!(node.get("name").unwrap().as_str(), Some("test"));
    }
    #[test]
    fn test_pnpm_yaml_extractor() {
        let yaml = r#"
packages:
  /lodash@4.17.21:
    hasInstallScript: true
snapshots:
  /lodash@4.17.21:
    dependencies:
      zod: 3.22.0
  /zod@3.22.0: {}
"#;
        let meta = MiniParser::parse_pnpm_yaml(yaml).unwrap();
        assert!(
            meta.packages
                .get("/lodash@4.17.21")
                .unwrap()
                .has_install_script
        );
        assert!(meta.snapshots.contains_key("/zod@3.22.0"));
    }
}

#[cfg(test)]
mod strict_regressions {
    use super::*;
    #[test]
    fn unicode_and_roundtrip() {
        let s = r#"{"\u0061":"é\ud83d\ude00\n\\\""}"#;
        let j = MiniParser::parse_json(s).unwrap();
        assert_eq!(j.get("a").and_then(JsonNode::as_str), Some("é😀\n\\\""));
        assert_eq!(MiniParser::parse_json(&j.to_json()).unwrap(), j);
    }
    #[test]
    fn malformed_rejected() {
        for s in [
            "{a:1}",
            "[1 2]",
            "[1,]",
            "{}{}",
            "{\"a\":1,\"a\":2}",
            "01",
            "1e",
            "1e9999",
            "\"\\x\"",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "\"raw\nline\"",
        ] {
            assert!(MiniParser::parse_json(s).is_err(), "{s}");
        }
        assert!(
            MiniParser::parse_json(&format!("{}0{}", "[".repeat(130), "]".repeat(130))).is_err()
        );
    }
}

#[cfg(test)]
mod large_string_regression {
    use super::*;
    #[test]
    fn long_ascii_and_multibyte_strings() {
        let text = format!("{}{}", "a".repeat(1024 * 1024), "é😀".repeat(16 * 1024));
        let j = MiniParser::parse_json(&format!("{{\"payload\":{}}}", json_string(&text))).unwrap();
        assert_eq!(
            j.get("payload").and_then(JsonNode::as_str),
            Some(text.as_str())
        );
    }
}
