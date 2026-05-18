/// A lightweight, pure-Rust Semantic Versioning matcher.
/// Parses basic npm version ranges (^, ~, exact) and selects the highest valid version.
pub struct Semver;

impl Semver {
    /// Given a version range requirement and a list of available versions,
    /// returns the highest version that satisfies the requirement.
    pub fn resolve<'a>(requirement: &str, available_versions: &'a [String]) -> Option<&'a String> {
        if requirement == "latest" || requirement == "*" || requirement.is_empty() {
            let mut sorted: Vec<&String> = available_versions.iter().collect();
            sorted.sort_by(|a, b| Self::compare_versions(a, b));
            return sorted.last().copied();
        }

        let clean_req = requirement
            .trim_start_matches('^')
            .trim_start_matches('~')
            .trim();

        let mut best_match: Option<&String> = None;
        for version in available_versions {
            if requirement.starts_with('^') {
                let req_parts: Vec<&str> = clean_req.split('.').collect();
                let v_parts: Vec<&str> = version.split('.').collect();

                // v3.0.5 Ironclad: Robust Caret logic (lock non-zero OR non-numeric/pre-release).
                let mut is_compatible = true;
                let mut locked_idx = 0;
                for (i, p) in req_parts.iter().enumerate() {
                    match p.parse::<u32>() {
                        Ok(n) => {
                            if n > 0 || i == req_parts.len() - 1 {
                                locked_idx = i;
                                break;
                            }
                        }
                        // Non-numeric component (pre-release suffix)
                        Err(_) => {
                            locked_idx = i;
                            break;
                        }
                    }
                }

                for i in 0..=locked_idx {
                    let rv = req_parts.get(i).unwrap_or(&"0");
                    let vv = v_parts.get(i).unwrap_or(&"0");
                    if rv != vv {
                        is_compatible = false;
                        break;
                    }
                }

                if is_compatible
                    && Self::compare_versions(version, clean_req) != std::cmp::Ordering::Less
                {
                    if let Some(current_best) = best_match {
                        if Self::compare_versions(version, current_best)
                            == std::cmp::Ordering::Greater
                        {
                            best_match = Some(version);
                        }
                    } else {
                        best_match = Some(version);
                    }
                }
            } else if requirement.starts_with('~') {
                let req_parts: Vec<&str> = clean_req.split('.').collect();
                let v_parts: Vec<&str> = version.split('.').collect();
                if req_parts.len() >= 2
                    && v_parts.len() >= 2
                    && req_parts[0] == v_parts[0]
                    && req_parts[1] == v_parts[1]
                    && Self::compare_versions(version, clean_req) != std::cmp::Ordering::Less
                {
                    if let Some(current_best) = best_match {
                        if Self::compare_versions(version, current_best)
                            == std::cmp::Ordering::Greater
                        {
                            best_match = Some(version);
                        }
                    } else {
                        best_match = Some(version);
                    }
                }
            } else if version == clean_req {
                return Some(version);
            }
        }

        best_match
    }

    fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
        // v3.0.3 Hardening: Strict SemVer precedence. Stable > Pre-release.
        let a_raw_parts: Vec<&str> = a.split('.').collect();
        let b_raw_parts: Vec<&str> = b.split('.').collect();

        let max_len = std::cmp::max(a_raw_parts.len(), b_raw_parts.len());
        for i in 0..max_len {
            let a_part = a_raw_parts.get(i);
            let b_part = b_raw_parts.get(i);

            match (a_part, b_part) {
                (Some(ap), Some(bp)) => {
                    let an = ap.parse::<u32>();
                    let bn = bp.parse::<u32>();
                    match (an, bn) {
                        (Ok(an_val), Ok(bn_val)) => {
                            if an_val != bn_val {
                                return an_val.cmp(&bn_val);
                            }
                        }
                        (Ok(_), Err(_)) => return std::cmp::Ordering::Greater,
                        (Err(_), Ok(_)) => return std::cmp::Ordering::Less,
                        (Err(_), Err(_)) => {
                            if ap != bp {
                                return ap.cmp(bp);
                            }
                        }
                    }
                }
                (Some(ap), None) => {
                    // a is longer.
                    if let Ok(val) = ap.parse::<u32>() {
                        if val == 0 {
                            continue;
                        }
                        return std::cmp::Ordering::Greater;
                    }
                    return std::cmp::Ordering::Less; // Pre-release
                }
                (None, Some(bp)) => {
                    // b is longer.
                    if let Ok(val) = bp.parse::<u32>() {
                        if val == 0 {
                            continue;
                        }
                        return std::cmp::Ordering::Less;
                    }
                    return std::cmp::Ordering::Greater; // Pre-release
                }
                (None, None) => break,
            }
        }
        std::cmp::Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_compare() {
        assert_eq!(
            Semver::compare_versions("1.2.3", "1.2.4"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            Semver::compare_versions("2.0.0", "1.9.9"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            Semver::compare_versions("1.0", "1.0.0"),
            std::cmp::Ordering::Equal
        );
        // v3.0.3 Test: Stable > Pre-release/Malicious
        assert_eq!(
            Semver::compare_versions("1.0.0-malicious", "1.0.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            Semver::compare_versions("1.0.0", "1.0.0-alpha"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_semver_resolve_caret() {
        let versions = vec![
            "1.0.0".to_string(),
            "1.2.0".to_string(),
            "1.3.5".to_string(),
            "2.0.0".to_string(),
            "0.1.0".to_string(),
            "0.1.5".to_string(),
            "0.2.0".to_string(),
            "0.0.3".to_string(),
            "0.0.4".to_string(),
        ];
        assert_eq!(Semver::resolve("^1.0.0", &versions).unwrap(), "1.3.5");
        // v3.0.4 Paradox Resolution Tests
        assert_eq!(Semver::resolve("^0.1.0", &versions).unwrap(), "0.1.5");
        assert_eq!(Semver::resolve("^0.0.3", &versions).unwrap(), "0.0.3");
    }

    #[test]
    fn test_semver_resolve_tilde() {
        let versions = vec![
            "1.2.0".to_string(),
            "1.2.4".to_string(),
            "1.3.0".to_string(),
        ];
        assert_eq!(Semver::resolve("~1.2.0", &versions).unwrap(), "1.2.4");
    }

    #[test]
    fn test_semver_resolve_exact() {
        let versions = vec!["1.2.0".to_string(), "1.2.4".to_string()];
        assert_eq!(Semver::resolve("1.2.0", &versions).unwrap(), "1.2.0");
    }
}
