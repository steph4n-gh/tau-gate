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

        // v3.0.6 Ironclad: NPM Pre-release Filter Rule.
        let is_pre_release_req = requirement.contains('-');
        let is_stable_req = !is_pre_release_req;

        let mut best_match: Option<&String> = None;
        for version in available_versions {
            if is_stable_req && version.contains('-') {
                continue;
            }

            // v3.0.8 Deep Perimeter: Unified Tuple Locking Rule.
            // If the range has a prerelease tag, it only matches the same tuple.
            if is_pre_release_req {
                let req_tuple = clean_req.split('-').next().unwrap_or("");
                let v_tuple = version.split('-').next().unwrap_or("");
                if req_tuple != v_tuple {
                    continue;
                }
            }

            if requirement.starts_with('^') {
                let req_parts: Vec<&str> = clean_req.split('.').collect();
                let v_parts: Vec<&str> = version.split('.').collect();

                // v3.0.5 Ironclad: Robust Caret logic (lock non-zero OR non-numeric/pre-release).
                let mut is_compatible = true;
                let mut locked_idx = 0;
                for (i, p) in req_parts.iter().enumerate() {
                    let part_clean = p.split('-').next().unwrap_or("");
                    match part_clean.parse::<u32>() {
                        Ok(n) => {
                            if n > 0 || i == req_parts.len() - 1 {
                                locked_idx = i;
                                break;
                            }
                        }
                        Err(_) => {
                            locked_idx = i;
                            break;
                        }
                    }
                }

                for i in 0..=locked_idx {
                    let rv = req_parts
                        .get(i)
                        .unwrap_or(&"0")
                        .split('-')
                        .next()
                        .unwrap_or("");
                    let vv = v_parts
                        .get(i)
                        .unwrap_or(&"0")
                        .split('-')
                        .next()
                        .unwrap_or("");
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
                    && req_parts[0].split('-').next() == v_parts[0].split('-').next()
                    && req_parts[1].split('-').next() == v_parts[1].split('-').next()
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
        // v3.0.8 Deep Perimeter: Hyphen-First Splitting.
        let (a_stable, a_pre) = if let Some(idx) = a.find('-') {
            (&a[..idx], Some(&a[idx + 1..]))
        } else {
            (a, None)
        };
        let (b_stable, b_pre) = if let Some(idx) = b.find('-') {
            (&b[..idx], Some(&b[idx + 1..]))
        } else {
            (b, None)
        };

        // 1. Compare stable parts
        let a_parts: Vec<&str> = a_stable.split('.').collect();
        let b_parts: Vec<&str> = b_stable.split('.').collect();
        let max_len = std::cmp::max(a_parts.len(), b_parts.len());

        for i in 0..max_len {
            let ap = a_parts.get(i).unwrap_or(&"0");
            let bp = b_parts.get(i).unwrap_or(&"0");

            let an = ap.parse::<u32>();
            let bn = bp.parse::<u32>();

            match (an, bn) {
                (Ok(anv), Ok(bnv)) => {
                    if anv != bnv {
                        return anv.cmp(&bnv);
                    }
                }
                (Ok(_), Err(_)) => return std::cmp::Ordering::Less,
                (Err(_), Ok(_)) => return std::cmp::Ordering::Greater,
                _ => {
                    if ap != bp {
                        return ap.cmp(bp);
                    }
                }
            }
        }

        // 2. Compare pre-release parts (if stable parts are equal)
        match (a_pre, b_pre) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater, // Stable > Pre-release
            (Some(_), None) => std::cmp::Ordering::Less,    // Pre-release < Stable
            (Some(ap), Some(bp)) => {
                let ap_parts: Vec<&str> = ap.split('.').collect();
                let bp_parts: Vec<&str> = bp.split('.').collect();
                let max_pre_len = std::cmp::max(ap_parts.len(), bp_parts.len());

                for i in 0..max_pre_len {
                    let app = ap_parts.get(i);
                    let bpp = bp_parts.get(i);

                    match (app, bpp) {
                        (Some(ap_sub), Some(bp_sub)) => {
                            let an = ap_sub.parse::<u32>();
                            let bn = bp_sub.parse::<u32>();
                            match (an, bn) {
                                (Ok(anv), Ok(bnv)) => {
                                    if anv != bnv {
                                        return anv.cmp(&bnv);
                                    }
                                }
                                // v3.0.7/v3.0.8: Numeric < String
                                (Ok(_), Err(_)) => return std::cmp::Ordering::Less,
                                (Err(_), Ok(_)) => return std::cmp::Ordering::Greater,
                                _ => {
                                    if ap_sub != bp_sub {
                                        return ap_sub.cmp(bp_sub);
                                    }
                                }
                            }
                        }
                        (Some(_), None) => return std::cmp::Ordering::Greater,
                        (None, Some(_)) => return std::cmp::Ordering::Less,
                        (None, None) => break,
                    }
                }
                std::cmp::Ordering::Equal
            }
        }
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
        // v3.0.6/v3.0.8 Test: Numeric pre-release sorting
        assert_eq!(
            Semver::compare_versions("1.0.0-10", "1.0.0-9"),
            std::cmp::Ordering::Greater
        );
        // v3.0.8 Test: Type precedence (Numeric < String)
        assert_eq!(
            Semver::compare_versions("1.0.0-alpha.1", "1.0.0-alpha.beta"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_semver_resolve_caret() {
        let versions = vec![
            "1.2.0".to_string(),
            "1.3.5".to_string(),
            "2.0.0".to_string(),
            "0.1.0".to_string(),
            "0.1.5".to_string(),
            "0.2.0".to_string(),
            "0.0.3".to_string(),
            "0.0.4".to_string(),
            "1.4.0-alpha".to_string(),
            "1.1.0-alpha.2".to_string(),
            "1.1.0-alpha.1".to_string(),
        ];
        assert_eq!(Semver::resolve("^1.2.0", &versions).unwrap(), "1.3.5");
        // v3.0.6 Paradox Resolution: Prerelease filter rule (stable range ignores pre-release)
        assert_ne!(Semver::resolve("^1.2.0", &versions).unwrap(), "1.4.0-alpha");

        // v3.0.8 Deep Perimeter: Tuple Locking (Pre-release req only matches same tuple for other pre-releases)
        assert_eq!(Semver::resolve("^1.1.0-alpha.0", &versions).unwrap(), "1.1.0-alpha.2");
        assert_ne!(Semver::resolve("^1.1.0-alpha.0", &versions).unwrap(), "1.4.0-alpha");

        assert_eq!(Semver::resolve("^0.1.0", &versions).unwrap(), "0.1.5");
        assert_eq!(Semver::resolve("^0.0.3", &versions).unwrap(), "0.0.3");
    }

    #[test]
    fn test_semver_resolve_tilde() {
        let versions = vec![
            "1.3.0".to_string(),
            "1.2.1-alpha.1".to_string(),
            "1.2.1-alpha.2".to_string(),
        ];
        // v3.0.8 Deep Perimeter: Tilde Tuple Lock
        assert_eq!(Semver::resolve("~1.2.1-alpha.0", &versions).unwrap(), "1.2.1-alpha.2");
    }

    #[test]
    fn test_semver_resolve_exact() {
        let versions = vec!["1.2.0".to_string(), "1.2.4".to_string()];
        assert_eq!(Semver::resolve("1.2.0", &versions).unwrap(), "1.2.0");
    }
}
