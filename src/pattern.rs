//! Name patterns, used alike by every label that names something: hostnames (`host:`),
//! containers (`container:`) and the names a container may look up (`portcullis.domains`).
//!
//! A pattern is a name of dot-separated labels, where:
//! - `*` within a label stands for any characters of that one label, none included:
//!   `*.example.com` matches `a.example.com`, not `a.b.example.com` or `example.com`, and
//!   `cdn-*.example.com` matches `cdn-1.example.com`;
//! - `**` as the first label stands for one or more labels: `**.example.com` matches
//!   `a.example.com` and `a.b.example.com`, not `example.com`.
//!
//! Neither ever matches across a dot, or an empty label.

use std::fmt;

/// What a pattern names; hostnames are normalized and checked as DNS names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    /// A DNS name: case doesn't matter, a trailing dot is ignored.
    Host,
    /// A container name or network alias, as Docker's DNS resolves them.
    Container,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamePattern {
    /// The pattern as written, normalized for hostnames.
    text: String,
}

impl NamePattern {
    /// Parse a pattern, or say why it isn't one.
    pub fn parse(value: &str, kind: NameKind) -> Result<Self, &'static str> {
        let text = match kind {
            NameKind::Host => crate::dns::normalize(value.trim()),
            NameKind::Container => value.trim().to_string(),
        };
        if text.is_empty() {
            return Err("empty name");
        }
        let labels: Vec<&str> = text.split('.').collect();
        for (index, label) in labels.iter().enumerate() {
            if label.is_empty() {
                return Err("empty label");
            }
            if label.contains("**") && (*label != "**" || index > 0) {
                return Err("** only stands for whole labels, at the start");
            }
            if label.len() > 63 {
                return Err("label longer than 63 characters");
            }
            let valid = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '*');
            if !label.chars().all(valid) {
                return Err("only letters, digits, -, _ and * are allowed");
            }
        }
        // A wildcard alone would allow names of every domain; containers only share a
        // network with few others.
        if kind == NameKind::Host && labels.iter().all(|label| label.contains('*')) {
            return Err("matches names of any domain; name one, like *.example.com");
        }
        Ok(Self { text })
    }

    /// A hostname pattern known to be valid, for tests.
    #[cfg(test)]
    #[must_use]
    pub fn host(value: &str) -> Self {
        Self::parse(value, NameKind::Host).unwrap_or_else(|reason| panic!("{value}: {reason}"))
    }

    /// A container pattern known to be valid, for tests.
    #[cfg(test)]
    #[must_use]
    pub fn container(value: &str) -> Self {
        Self::parse(value, NameKind::Container).unwrap_or_else(|reason| panic!("{value}: {reason}"))
    }

    /// The pattern, normalized; for an exact name, the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether this matches one name only.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        !self.text.contains('*')
    }

    /// Whether `name` (normalized, for hostnames) matches.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        if self.is_exact() {
            return self.text == name;
        }
        let (any_depth, pattern) = match self.text.strip_prefix("**.") {
            Some(rest) => (true, rest),
            None => (false, self.text.as_str()),
        };
        let pattern_labels = pattern.split('.').count();
        let name_labels: Vec<&str> = name.split('.').collect();
        if name_labels.iter().any(|label| label.is_empty()) {
            return false;
        }
        let deeper = match name_labels.len().checked_sub(pattern_labels) {
            Some(0) => !any_depth,
            Some(_) => any_depth,
            None => false,
        };
        deeper
            && pattern
                .split('.')
                .rev()
                .zip(name_labels.iter().rev())
                .all(|(pattern, label)| label_matches(pattern.as_bytes(), label.as_bytes()))
    }
}

impl fmt::Display for NamePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Whether a label matches a label pattern where `*` stands for any characters. Linear in
/// the label's length for each `*`: labels are at most 63 bytes.
fn label_matches(pattern: &[u8], label: &[u8]) -> bool {
    let (mut p, mut l) = (0, 0);
    // Where the last `*` was, and where in the label it matched up to.
    let mut star: Option<(usize, usize)> = None;
    while let Some(character) = label.get(l) {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, l));
                p += 1;
            }
            Some(c) if c == character => {
                p += 1;
                l += 1;
            }
            _ => match star {
                // Let the last `*` take one more character.
                Some((star_p, star_l)) => {
                    p = star_p + 1;
                    l = star_l + 1;
                    star = Some((star_p, star_l + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|c| *c == b'*'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(pattern: &str) -> NamePattern {
        NamePattern::parse(pattern, NameKind::Host).expect("pattern")
    }

    #[test]
    fn matches_exact_names() {
        let pattern = host("API.Example.com.");
        assert_eq!(pattern.as_str(), "api.example.com");
        assert!(pattern.is_exact());
        assert!(pattern.matches("api.example.com"));
        assert!(!pattern.matches("x.api.example.com"));
        assert!(!pattern.matches("example.com"));
    }

    #[test]
    fn one_star_label_matches_one_level() {
        let pattern = host("*.archive.org");
        assert!(!pattern.is_exact());
        assert!(pattern.matches("ia800.archive.org"));
        assert!(!pattern.matches("a.ia800.archive.org"));
        assert!(!pattern.matches("archive.org"));
        assert!(!pattern.matches("evilarchive.org"));
        assert!(!pattern.matches("ia800.archive.org.evil.test"));
        assert!(!pattern.matches(".archive.org"));
    }

    #[test]
    fn double_star_matches_any_depth_below() {
        let pattern = host("**.archive.org");
        assert!(pattern.matches("ia800.archive.org"));
        assert!(pattern.matches("a.b.c.archive.org"));
        assert!(!pattern.matches("archive.org"));
        assert!(!pattern.matches("xarchive.org"));
        assert!(!pattern.matches("a..archive.org"));
    }

    #[test]
    fn stars_within_labels() {
        let pattern = host("is*-ssl.mzstatic.com");
        assert!(pattern.matches("is1-ssl.mzstatic.com"));
        assert!(pattern.matches("is-ssl.mzstatic.com"));
        assert!(pattern.matches("is12345-ssl.mzstatic.com"));
        assert!(!pattern.matches("is1.ssl.mzstatic.com"));
        assert!(!pattern.matches("xis1-ssl.mzstatic.com"));
        assert!(!pattern.matches("is1-ssl.x.mzstatic.com"));

        let pattern = host("s*.api.*.com");
        assert!(pattern.matches("s1.api.bsplayer-subtitles.com"));
        assert!(!pattern.matches("s1.api.a.b.com"));

        assert!(label_matches(b"a*b*c", b"aXXbYYc"));
        assert!(label_matches(b"a*b*c", b"abbbc"));
        assert!(!label_matches(b"a*b*c", b"aXXbYY"));
        assert!(label_matches(b"*", b"x"));
        assert!(label_matches(b"**", b"x"));
    }

    #[test]
    fn rejects_patterns_that_arent_names() {
        for invalid in [
            "", "*", "**", "*.*", "**.*", "a..b", "a.**.b", "***.b.c", "a**.b.c", "a b.c", "a/b.c",
            "ünï.c",
        ] {
            assert!(
                NamePattern::parse(invalid, NameKind::Host).is_err(),
                "{invalid}"
            );
        }
        let long = format!("{}.com", "a".repeat(64));
        assert!(NamePattern::parse(&long, NameKind::Host).is_err());
    }

    #[test]
    fn container_patterns() {
        let any = NamePattern::parse("*", NameKind::Container).expect("pattern");
        assert!(any.matches("db"));
        assert!(!any.matches("db.alias"));
        let workers = NamePattern::parse("app-worker-*", NameKind::Container).expect("pattern");
        assert!(workers.matches("app-worker-1"));
        assert!(!workers.matches("app-web-1"));
        // Names keep their case.
        let exact = NamePattern::parse("Db", NameKind::Container).expect("pattern");
        assert!(exact.matches("Db"));
        assert!(!exact.matches("db"));
    }
}
