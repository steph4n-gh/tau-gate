use crate::error::{GateError, Result};
use std::collections::HashMap;

/// A minimal, zero-dependency parser for Tau-Gate.
pub struct MiniParser;

impl MiniParser {
    /// Parses a TOML-like string into a simple key-value map.
    pub fn parse_config(content: &str) -> Result<HashMap<String, ConfigValue>> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();
                let val_raw = value.trim();
                if val_raw.starts_with('[') && val_raw.ends_with(']') {
                    let inner = &val_raw[1..val_raw.len()-1];
                    let items = inner.split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.trim_matches(|c| c == '"' || c == '\'').to_string())
                        .collect();
                    map.insert(key, ConfigValue::Array(items));
                } else if val_raw.starts_with('"') || val_raw.starts_with('\'') {
                    map.insert(key, ConfigValue::String(val_raw.trim_matches(|c| c == '"' || c == '\'').to_string()));
                } else if let Ok(val) = val_raw.parse::<f64>() {
                    map.insert(key, ConfigValue::Float(val));
                }
            }
        }
        Ok(map)
    }

    pub fn parse_json(json: &str) -> Result<JsonNode> {
        let mut tokens = JsonLexer::tokenize(json);
        JsonParser::parse(&mut tokens)
    }

    /// V2.0 Hardening: Detects high-entropy strings (potential obfuscation) in manifests.
    pub fn detect_obfuscation(content: &str) -> bool {
        // Look for long, continuous base64/hex characters without spaces
        let mut max_continuous = 0;
        let mut current = 0;
        for c in content.chars() {
            if c.is_alphanumeric() || c == '/' || c == '+' || c == '=' {
                current += 1;
            } else {
                if current > max_continuous { max_continuous = current; }
                current = 0;
            }
        }
        if current > max_continuous { max_continuous = current; }
        
        // Threshold: If we see a single string of 128+ continuous characters, flag it.
        max_continuous > 128
    }

    pub fn parse_pnpm_yaml(yaml: &str) -> Result<PnpmMetadata> {
        let mut snapshots = HashMap::new();
        let mut packages = HashMap::new();
        let mut current_section = "";
        let mut current_pkg_id = String::new();

        for line in yaml.lines() {
            let indent = line.chars().take_while(|c| c.is_whitespace()).count();
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }

            if line.starts_with("snapshots:") { current_section = "snapshots"; continue; }
            if line.starts_with("packages:") { current_section = "packages"; continue; }

            if indent == 2 && line.ends_with(':') {
                current_pkg_id = line[..line.len()-1].trim_matches(|c| c == '"' || c == '\'').to_string();
                if current_section == "snapshots" {
                    snapshots.insert(current_pkg_id.clone(), PnpmSnapshot { dependencies: Vec::new() });
                } else if current_section == "packages" {
                    packages.insert(current_pkg_id.clone(), PnpmPackage { has_install_script: false });
                }
                continue;
            }

            if indent == 4 && line.starts_with("hasInstallScript:") {
                let has = line.contains("true");
                if current_section == "packages" {
                    if let Some(pkg) = packages.get_mut(&current_pkg_id) {
                        pkg.has_install_script = has;
                    }
                }
            }

            if indent == 6 && current_section == "snapshots" {
                if let Some((name, _ver)) = line.split_once(':') {
                    if let Some(snap) = snapshots.get_mut(&current_pkg_id) {
                        snap.dependencies.push(name.trim().trim_matches(|c| c == '"' || c == '\'').to_string());
                    }
                }
            }
        }
        Ok(PnpmMetadata { snapshots, packages })
    }
}

pub struct PnpmMetadata {
    pub snapshots: HashMap<String, PnpmSnapshot>,
    pub packages: HashMap<String, PnpmPackage>,
}

pub struct PnpmSnapshot {
    pub dependencies: Vec<String>,
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
    Object(HashMap<String, JsonNode>),
    Array(Vec<JsonNode>),
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

impl JsonNode {
    pub fn get(&self, key: &str) -> Option<&JsonNode> {
        match self { JsonNode::Object(m) => m.get(key), _ => None }
    }
    
    pub fn as_str(&self) -> Option<&str> {
        match self { JsonNode::String(s) => Some(s), _ => None }
    }
    
    pub fn as_bool(&self) -> Option<bool> {
        match self { JsonNode::Bool(b) => Some(*b), _ => None }
    }

    pub fn as_object(&self) -> Option<&HashMap<String, JsonNode>> {
        match self { JsonNode::Object(m) => Some(m), _ => None }
    }

    pub fn as_array(&self) -> Option<&Vec<JsonNode>> {
        match self { JsonNode::Array(a) => Some(a), _ => None }
    }
}

struct JsonLexer;
impl JsonLexer {
    fn tokenize(json: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut it = json.chars().peekable();
        while let Some(&c) = it.peek() {
            match c {
                '{' | '}' | '[' | ']' | ':' | ',' => {
                    tokens.push(c.to_string());
                    it.next();
                }
                '"' => {
                    it.next();
                    let mut s = String::new();
                    while let Some(nc) = it.next() {
                        if nc == '"' { break; }
                        if nc == '\\' {
                            if let Some(esc) = it.next() { s.push(esc); }
                        } else {
                            s.push(nc);
                        }
                    }
                    tokens.push(format!("\"{}\"", s));
                }
                c if c.is_whitespace() => { it.next(); }
                _ => {
                    let mut s = String::new();
                    while let Some(&nc) = it.peek() {
                        if nc.is_alphanumeric() || nc == '.' || nc == '-' || nc == '_' {
                            s.push(nc);
                            it.next();
                        } else {
                            break;
                        }
                    }
                    if !s.is_empty() { tokens.push(s); }
                }
            }
        }
        tokens
    }
}

struct JsonParser;
impl JsonParser {
    fn parse(tokens: &mut Vec<String>) -> Result<JsonNode> {
        if tokens.is_empty() { return Err(GateError::Generic("Empty JSON".to_string())); }
        let token = tokens.remove(0);
        match token.as_str() {
            "{" => Self::parse_object(tokens),
            "[" => Self::parse_array(tokens),
            s if s.starts_with('"') => Ok(JsonNode::String(s[1..s.len()-1].to_string())),
            "true" => Ok(JsonNode::Bool(true)),
            "false" => Ok(JsonNode::Bool(false)),
            "null" => Ok(JsonNode::Null),
            s => {
                if let Ok(n) = s.parse::<f64>() {
                    Ok(JsonNode::Number(n))
                } else {
                    Err(GateError::Generic(format!("Invalid JSON token: {}", s)))
                }
            }
        }
    }

    fn parse_object(tokens: &mut Vec<String>) -> Result<JsonNode> {
        let mut map = HashMap::new();
        while !tokens.is_empty() {
            if tokens[0] == "}" { tokens.remove(0); return Ok(JsonNode::Object(map)); }
            let key_raw = tokens.remove(0);
            let key = if key_raw.starts_with('"') { key_raw[1..key_raw.len()-1].to_string() } else { key_raw };
            if tokens.is_empty() || tokens.remove(0) != ":" { return Err(GateError::Generic("Expected ':' in JSON object".to_string())); }
            let val = Self::parse(tokens)?;
            map.insert(key, val);
            if tokens.is_empty() { break; }
            if tokens[0] == "," { tokens.remove(0); }
        }
        Err(GateError::Generic("Unclosed JSON object".to_string()))
    }

    fn parse_array(tokens: &mut Vec<String>) -> Result<JsonNode> {
        let mut arr = Vec::new();
        while !tokens.is_empty() {
            if tokens[0] == "]" { tokens.remove(0); return Ok(JsonNode::Array(arr)); }
            arr.push(Self::parse(tokens)?);
            if tokens.is_empty() { break; }
            if tokens[0] == "," { tokens.remove(0); }
        }
        Err(GateError::Generic("Unclosed JSON array".to_string()))
    }
}
