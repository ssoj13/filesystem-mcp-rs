//! Subtree totals per directory, built from the entries of one complete traversal.
//!
//! Nothing here relies on the order the entries arrive in (the NTFS reader does not promise
//! one): every entry adds itself to its parent, and [`DirAggregator::finish`] rolls the direct
//! totals up from the deepest directory.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{MAIN_SEPARATOR, Path};

/// What a directory holds. `bytes` and `files` count every non-directory entry below it,
/// `dirs` every directory below it (not the directory itself).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    pub(crate) bytes: u64,
    pub(crate) files: u64,
    pub(crate) dirs: u64,
}

impl Totals {
    fn bump(&mut self, is_dir: bool, size: u64) {
        if is_dir {
            self.dirs += 1;
        } else {
            self.files += 1;
            self.bytes = self.bytes.saturating_add(size);
        }
    }

    fn absorb(&mut self, other: Totals) {
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.files += other.files;
        self.dirs += other.dirs;
    }
}

pub(crate) struct DirAggregator {
    dirs: HashMap<String, Totals>,
}

impl DirAggregator {
    /// `root` gets a row even when nothing lies below it, so an empty root still counts as
    /// having totals.
    pub(crate) fn new(root: &str) -> Self {
        let mut dirs = HashMap::new();
        dirs.insert(root.to_owned(), Totals::default());
        Self { dirs }
    }

    pub(crate) fn add(&mut self, path: &str, is_dir: bool, size: u64) {
        if is_dir && !self.dirs.contains_key(path) {
            self.dirs.insert(path.to_owned(), Totals::default());
        }
        let Some(parent) = Path::new(path).parent().and_then(Path::to_str) else {
            return;
        };
        if let Some(totals) = self.dirs.get_mut(parent) {
            totals.bump(is_dir, size);
            return;
        }
        let mut totals = Totals::default();
        totals.bump(is_dir, size);
        self.dirs.insert(parent.to_owned(), totals);
    }

    /// One row per directory seen, with the totals of everything beneath it.
    pub(crate) fn finish(self) -> Vec<(String, Totals)> {
        let mut rows: Vec<(String, Totals)> = self.dirs.into_iter().collect();
        // Component order puts every directory ahead of its descendants and keeps them
        // contiguous; plain byte order does not, because `\` sorts after `-` and `.`.
        rows.sort_unstable_by(|a, b| component_order(&a.0, &b.0));
        let mut stack: Vec<usize> = Vec::new();
        for index in 0..rows.len() {
            while let Some(&top) = stack.last() {
                if is_inside(&rows[index].0, &rows[top].0) {
                    break;
                }
                stack.pop();
                fold(&mut rows, top, stack.last().copied());
            }
            stack.push(index);
        }
        while let Some(top) = stack.pop() {
            fold(&mut rows, top, stack.last().copied());
        }
        rows
    }
}

fn fold(rows: &mut [(String, Totals)], child: usize, parent: Option<usize>) {
    if let Some(parent) = parent {
        let totals = rows[child].1;
        rows[parent].1.absorb(totals);
    }
}

fn component_order(a: &str, b: &str) -> Ordering {
    let key = |byte: u8| {
        if byte == MAIN_SEPARATOR as u8 {
            0
        } else {
            byte
        }
    };
    a.bytes().map(key).cmp(b.bytes().map(key))
}

fn is_inside(child: &str, dir: &str) -> bool {
    let separator = MAIN_SEPARATOR as u8;
    child.len() > dir.len()
        && child.starts_with(dir)
        && (dir.as_bytes().last() == Some(&separator) || child.as_bytes()[dir.len()] == separator)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn join(parts: &[&str]) -> String {
        parts.join(std::path::MAIN_SEPARATOR_STR)
    }

    fn totals(rows: Vec<(String, Totals)>) -> BTreeMap<String, Totals> {
        rows.into_iter().collect()
    }

    fn t(bytes: u64, files: u64, dirs: u64) -> Totals {
        Totals { bytes, files, dirs }
    }

    /// `r\a-b` sorts between `r\a` and `r\a\c` in byte order; the roll-up must not care.
    fn entries() -> Vec<(String, bool, u64)> {
        vec![
            (join(&["r", "a"]), true, 0),
            (join(&["r", "a-b"]), true, 0),
            (join(&["r", "a", "c"]), true, 0),
            (join(&["r", "a", "c", "1"]), false, 10),
            (join(&["r", "a", "2"]), false, 5),
            (join(&["r", "a-b", "3"]), false, 7),
            (join(&["r", "4"]), false, 1),
        ]
    }

    fn expected() -> BTreeMap<String, Totals> {
        BTreeMap::from([
            ("r".to_owned(), t(23, 4, 3)),
            (join(&["r", "a"]), t(15, 2, 1)),
            (join(&["r", "a", "c"]), t(10, 1, 0)),
            (join(&["r", "a-b"]), t(7, 1, 0)),
        ])
    }

    #[test]
    fn totals_roll_up_whatever_order_the_entries_arrive_in() {
        for reverse in [false, true] {
            let mut list = entries();
            if reverse {
                list.reverse();
            }
            let mut agg = DirAggregator::new("r");
            for (path, is_dir, size) in &list {
                agg.add(path, *is_dir, *size);
            }
            assert_eq!(totals(agg.finish()), expected(), "reverse={reverse}");
        }
    }

    #[test]
    fn a_file_may_arrive_before_the_directory_that_holds_it() {
        let mut agg = DirAggregator::new("r");
        agg.add(&join(&["r", "d", "f"]), false, 3);
        agg.add(&join(&["r", "d"]), true, 0);
        let got = totals(agg.finish());
        assert_eq!(got[&join(&["r", "d"])], t(3, 1, 0));
        assert_eq!(got["r"], t(3, 1, 1));
    }

    #[test]
    fn an_empty_root_still_has_a_row() {
        let rows = DirAggregator::new("r").finish();
        assert_eq!(rows, vec![("r".to_owned(), t(0, 0, 0))]);
    }

    #[test]
    fn a_drive_root_owns_its_direct_children() {
        // `Path::parent` keeps the separator of a drive root, so the root row must too.
        let root = if cfg!(windows) { r"\\?\C:\" } else { "/" };
        let mut agg = DirAggregator::new(root);
        agg.add(&format!("{root}x"), true, 0);
        agg.add(&format!("{root}x{MAIN_SEPARATOR}f"), false, 9);
        let got = totals(agg.finish());
        assert_eq!(got[root], t(9, 1, 1));
        assert_eq!(got[&format!("{root}x")], t(9, 1, 0));
    }
}
