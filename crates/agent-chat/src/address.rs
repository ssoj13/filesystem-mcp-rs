//! Chat addresses: `project:topic:name:parent`, and what `to` may say.
//!
//! The name is the only key. The other three segments describe a subscriber so that `agent_ls`
//! reads as a graph of agents and a mask can reach a group; they are not part of its identity, so
//! an agent can change topic without becoming someone else. Used by `store` to route and by
//! `session` to issue an address on the first tool call.

use std::fmt;
use std::path::Path;

/// What an unset segment reads as.
pub const NONE: &str = "-";

/// The names handed out, each with a number the store adds so that it never comes round again.
const NAMES: &[&str] = &[
    "Erdos",
    "Halsted",
    "Freud",
    "Brahe",
    "Hofmann",
    "Shulgin",
    "Mullis",
    "Lilly",
    "Sagan",
    "Feynman",
    "Leary",
    "Moreau",
    "Paracelsus",
    "Davy",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub project: String,
    pub topic: String,
    pub name: String,
    pub parent: String,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.project, self.topic, self.name, self.parent
        )
    }
}

/// Who a message is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// One subscriber by name, alive or closed: the message waits for a closed one.
    Name(String),
    /// Every live subscriber matching all four segments, each one literal or `*`.
    Mask([String; 4]),
}

impl Target {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let parts: Vec<&str> = raw.split(':').collect();
        match parts.as_slice() {
            [name] if !name.is_empty() && !name.contains('*') => Ok(Self::Name((*name).to_owned())),
            [_, _, _, _] => Ok(Self::Mask(segments(&parts))),
            _ => Err(format!(
                "bad address {raw:?}: use a name (Erdos), project:topic:name:parent, or a mask \
                 with * per segment"
            )),
        }
    }

    /// Does this name one subscriber rather than a group? A full address with no wildcard does,
    /// so it reaches a closed subscriber the way a bare name does. Only a group skips those.
    pub fn is_exact(&self) -> bool {
        match self {
            Self::Name(_) => true,
            Self::Mask(segments) => segments.iter().all(|segment| segment != "*"),
        }
    }

    pub fn matches(&self, address: &Address) -> bool {
        match self {
            Self::Name(name) => *name == address.name,
            Self::Mask([project, topic, name, parent]) => {
                let hit = |pattern: &str, value: &str| pattern == "*" || pattern == value;
                hit(project, &address.project)
                    && hit(topic, &address.topic)
                    && hit(name, &address.name)
                    && hit(parent, &address.parent)
            }
        }
    }
}

fn segments(parts: &[&str]) -> [String; 4] {
    [
        parts[0].to_owned(),
        parts[1].to_owned(),
        parts[2].to_owned(),
        parts[3].to_owned(),
    ]
}

/// A value safe to put in one segment: `:` would change what the address parses to.
pub fn clean_segment(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c == ':' || c == '*' || c.is_whitespace() {
                '_'
            } else {
                c
            }
        })
        .collect();
    if cleaned.is_empty() {
        NONE.to_owned()
    } else {
        cleaned
    }
}

/// The first name in use by nobody: the list, then the list again with a number.
pub fn next_name(taken: impl Fn(&str) -> bool) -> String {
    if let Some(name) = NAMES.iter().find(|name| !taken(name)) {
        return (*name).to_owned();
    }
    (2u32..)
        .flat_map(|n| NAMES.iter().map(move |name| format!("{name}-{n}")))
        .find(|name| !taken(name))
        .unwrap_or_else(|| NONE.to_owned())
}

/// The project a directory belongs to: the name of its git root, if it has one.
pub fn git_project(dir: &Path) -> Option<String> {
    dir.ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
        .and_then(Path::file_name)
        .map(|name| clean_segment(&name.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(project: &str, topic: &str, name: &str, parent: &str) -> Address {
        Address {
            project: project.to_owned(),
            topic: topic.to_owned(),
            name: name.to_owned(),
            parent: parent.to_owned(),
        }
    }

    #[test]
    fn an_address_prints_in_the_order_it_parses() {
        let hofmann = address("fs", "-", "Hofmann", "Erdos");
        assert_eq!(hofmann.to_string(), "fs:-:Hofmann:Erdos");
        assert!(
            Target::parse(&hofmann.to_string())
                .unwrap()
                .matches(&hofmann)
        );
    }

    #[test]
    fn a_bare_name_matches_only_that_name_whatever_the_rest_says() {
        let target = Target::parse("Erdos").unwrap();
        assert!(target.is_exact());
        assert!(target.matches(&address("any", "thing", "Erdos", "-")));
        assert!(!target.matches(&address("any", "thing", "Hofmann", "Erdos")));
    }

    #[test]
    fn a_mask_needs_every_segment_to_match() {
        let children = Target::parse("fs:*:*:Erdos").unwrap();
        assert!(!children.is_exact());
        assert!(children.matches(&address("fs", "x", "Hofmann", "Erdos")));
        assert!(!children.matches(&address("other", "x", "Hofmann", "Erdos")));
        assert!(!children.matches(&address("fs", "x", "Hofmann", "-")));
    }

    #[test]
    fn a_full_address_without_a_wildcard_is_exact() {
        assert!(Target::parse("fs:-:Erdos:-").unwrap().is_exact());
    }

    #[test]
    fn nonsense_is_refused_rather_than_read_as_a_name() {
        for bad in ["", "a:b", "a:b:c", "a:b:c:d:e", "*"] {
            assert!(Target::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn a_segment_cannot_smuggle_in_a_separator_or_a_wildcard() {
        assert_eq!(clean_segment("a:b c*"), "a_b_c_");
        assert_eq!(clean_segment("  "), NONE);
    }

    #[test]
    fn names_run_out_into_numbered_ones() {
        assert_eq!(next_name(|_| false), "Erdos");
        assert_eq!(next_name(|name| name == "Erdos"), "Halsted");
        assert_eq!(
            next_name(|name| !name.contains('-') || name == "Erdos-2"),
            "Halsted-2"
        );
    }

    #[test]
    fn the_project_is_the_git_root_not_the_working_directory() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("my repo");
        let deep = repo.join("src/deep");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir(repo.join(".git")).unwrap();
        assert_eq!(git_project(&deep).as_deref(), Some("my_repo"));
    }
}
