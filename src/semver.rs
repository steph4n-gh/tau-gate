//! Compatibility shim for the retired network resolver. Frozen lockfiles need no range resolution.
pub struct Semver;
impl Semver {
    /// Only exact identities are supported. Tags/ranges return None; never guess npm resolution.
    pub fn resolve<'a>(requirement: &str, versions: &'a [String]) -> Option<&'a String> {
        versions.iter().find(|v| {
            v.as_str() == requirement
                && !requirement.is_empty()
                && requirement
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_digit)
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_only() {
        let versions = vec!["0.1.0".into(), "0.9.0".into()];
        assert_eq!(Semver::resolve("0.1.0", &versions), Some(&versions[0]));
        for r in ["^0.1.0", "latest", "*", "", "~0.1"] {
            assert!(Semver::resolve(r, &versions).is_none());
        }
    }
}
