/// A lightweight, pure-Rust Semantic Versioning matcher.
/// Parses basic npm version ranges (^, ~, exact) and selects the highest valid version.
pub struct Semver;

impl Semver {
    /// Given a version range requirement and a list of available versions,
    /// returns the highest version that satisfies the requirement.
    pub fn resolve<'a>(requirement: &str, available_versions: &'a [String]) -> Option<&'a String> {
        if requirement == "latest" || requirement == "*" || requirement == "" {
            let mut sorted: Vec<&String> = available_versions.iter().collect();
            sorted.sort_by(|a, b| Self::compare_versions(a, b));
            return sorted.last().copied();
        }

        let clean_req = requirement.trim_start_matches('^').trim_start_matches('~').trim();

        let mut best_match: Option<&String> = None;
        for version in available_versions {
            if requirement.starts_with('^') {
                if let Some(req_major) = clean_req.split('.').next() {
                    if let Some(v_major) = version.split('.').next() {
                        if req_major == v_major && Self::compare_versions(version, clean_req) != std::cmp::Ordering::Less {
                            if let Some(current_best) = best_match {
                                if Self::compare_versions(version, current_best) == std::cmp::Ordering::Greater {
                                    best_match = Some(version);
                                }
                            } else {
                                best_match = Some(version);
                            }
                        }
                    }
                }
            } else if requirement.starts_with('~') {
                let req_parts: Vec<&str> = clean_req.split('.').collect();
                let v_parts: Vec<&str> = version.split('.').collect();
                if req_parts.len() >= 2 && v_parts.len() >= 2 {
                    if req_parts[0] == v_parts[0] && req_parts[1] == v_parts[1] && Self::compare_versions(version, clean_req) != std::cmp::Ordering::Less {
                        if let Some(current_best) = best_match {
                            if Self::compare_versions(version, current_best) == std::cmp::Ordering::Greater {
                                best_match = Some(version);
                            }
                        } else {
                            best_match = Some(version);
                        }
                    }
                }
            } else {
                if version == clean_req {
                    return Some(version);
                }
            }
        }

        best_match
    }

    fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
        let a_parts: Vec<u32> = a.split('.').filter_map(|p| p.parse().ok()).collect();
        let b_parts: Vec<u32> = b.split('.').filter_map(|p| p.parse().ok()).collect();

        for i in 0..std::cmp::max(a_parts.len(), b_parts.len()) {
            let a_val = a_parts.get(i).unwrap_or(&0);
            let b_val = b_parts.get(i).unwrap_or(&0);
            match a_val.cmp(b_val) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
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
        assert_eq!(Semver::compare_versions("1.2.3", "1.2.4"), std::cmp::Ordering::Less);
        assert_eq!(Semver::compare_versions("2.0.0", "1.9.9"), std::cmp::Ordering::Greater);
        assert_eq!(Semver::compare_versions("1.0", "1.0.0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_semver_resolve_caret() {
        let versions = vec!["1.0.0".to_string(), "1.2.0".to_string(), "1.3.5".to_string(), "2.0.0".to_string()];
        assert_eq!(Semver::resolve("^1.0.0", &versions).unwrap(), "1.3.5");
    }

    #[test]
    fn test_semver_resolve_tilde() {
        let versions = vec!["1.2.0".to_string(), "1.2.4".to_string(), "1.3.0".to_string()];
        assert_eq!(Semver::resolve("~1.2.0", &versions).unwrap(), "1.2.4");
    }
    
    #[test]
    fn test_semver_resolve_exact() {
        let versions = vec!["1.2.0".to_string(), "1.2.4".to_string()];
        assert_eq!(Semver::resolve("1.2.0", &versions).unwrap(), "1.2.0");
    }
}
