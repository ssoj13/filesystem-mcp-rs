//! Which tools belong together, declared once.
//!
//! A model picks a tool from the list it is given, and a list of 130 names does not say that
//! `file_stats` and `locate_sql` answer the same question from two ends, or that `run_command`
//! wants `tail_file` after it. That knowledge used to live in scattered sentences of prose, so it
//! was patchy (18 of 102 descriptions named another tool) and it drifted. Here it is data, and
//! two things are generated from it:
//!
//! 1. **The tool map** at the top of the server instructions: one line per family, then the
//!    chains that are usually run in order. Feature-gated tools drop out of it when they are not
//!    compiled in, so it never advertises a tool the server does not serve.
//! 2. **A `See also` tail** on the description of a tool whose neighbour it is easy to confuse
//!    with or to forget. Only where a wrong pick is likely, and never repeating a name the
//!    description already carries: [`SEE_ALSO`] is short on purpose, because every character
//!    here is loaded into every session (`docs/TOOL_STYLE.md`).
//!
//! **The map goes first because clients cut long instructions.** Claude Code shows about the
//! first 2,000 characters of a server's instructions and ends the text with `[truncated]`; the
//! part of these instructions that used to matter most sat after that cut and was never seen.
//! [`HEAD_LIMIT`] is that limit, and a test keeps the session-lock notice and the whole map
//! inside it.
//!
//! The tests below are the guard that keeps this honest: every name here must be a tool the full
//! surface serves, every served tool must belong to a family, and the head must fit.

use rmcp::handler::server::router::tool::ToolRouter;

/// How much of the instructions a client is known to show. Measured in Claude Code 2026-09:
/// the server's instructions end with `[truncated]` at about this length.
#[cfg_attr(not(test), allow(dead_code))]
pub const HEAD_LIMIT: usize = 2_000;

/// One line of the map. An item is a tool name, or a prefix that ends in `*`: `s3_*` stands for
/// every served tool that starts with `s3_`. The second string is a note, shown in brackets when
/// it is not empty; it says what the tool is *for* in this company, which the name does not.
pub struct Family {
    pub name: &'static str,
    pub items: &'static [(&'static str, &'static str)],
}

pub const FAMILIES: &[Family] = &[
    Family {
        name: "Read",
        items: &[
            ("read_text_file", "head/tail/offset"),
            ("read_multiple_files", ""),
            ("extract_lines", ""),
            ("extract_symbols", ""),
            ("tail_file", "follow a log"),
            ("watch_file", "change events"),
            ("read_json", "JSONPath"),
            ("read_pdf", ""),
            ("read_media_file", ""),
            ("read_binary", ""),
            ("xlsx_*", ""),
            ("docx_*", ""),
        ],
    },
    Family {
        name: "Find",
        items: &[
            ("search_files", "paths by glob/metadata"),
            ("grep_files", "text inside files"),
            ("grep_context", ""),
            ("locate_search", "names, asked again"),
        ],
    },
    Family {
        name: "Space",
        items: &[
            ("disk_usage", "free space"),
            ("file_stats", "children:true = what is big"),
            ("locate_sql", "under=folder"),
            ("list_directory", ""),
            ("list_directory_with_sizes", ""),
            ("directory_tree", ""),
            ("find_duplicates", ""),
            ("get_file_info", ""),
            ("list_allowed_directories", ""),
        ],
    },
    Family {
        name: "Index",
        items: &[
            ("locate_refresh", "queue a scan"),
            ("locate_status", "progress"),
            ("bgnd_scan_ctl", "stop/pause"),
        ],
    },
    Family {
        name: "Write",
        items: &[
            ("write_file", ""),
            ("edit_file", "diff, dry-run"),
            ("edit_lines", ""),
            ("bulk_edits", "many files"),
            ("patch_binary", ""),
            ("write_binary", ""),
            ("blob_*", "large payloads"),
        ],
    },
    Family {
        name: "Files",
        items: &[
            ("create_directory", ""),
            ("copy_file", ""),
            ("move_file", ""),
            ("delete_path", "measure first"),
            ("file_touch", ""),
            ("create_archive", ""),
            ("extract_archive", ""),
            ("extract_binary", ""),
            ("file_hash*", ""),
            ("compare_*", ""),
            ("file_diff", ""),
        ],
    },
    Family {
        name: "Run",
        items: &[
            ("run_command", "managed/detached"),
            ("kill_process", ""),
            ("list_processes", ""),
            ("search_processes", ""),
            ("which", ""),
            ("proc_*", ""),
            ("port_*", ""),
            ("net_connections", ""),
            ("env_*", ""),
            ("sys_info", ""),
        ],
    },
    Family {
        name: "Memory",
        items: &[
            ("seq_think", "plan"),
            ("mem_get_summary", ""),
            ("mem_search", ""),
            ("mem_get", ""),
            ("mem_put", ""),
            ("mem_update", ""),
            ("mem_link", ""),
        ],
    },
    Family {
        name: "Network",
        items: &[("http_*", ""), ("s3_*", "")],
    },
    Family {
        name: "Screen",
        items: &[
            ("arm", "before any input"),
            ("capture", ""),
            ("monitors", ""),
            ("screenshot_*", ""),
            ("mouse_*", ""),
            ("key_*", ""),
            ("input_macro", ""),
            ("win_*", ""),
            ("ui", ""),
            ("ui_*", ""),
            ("ocr", ""),
            ("find_image", ""),
            ("color", ""),
            ("wait", ""),
            ("notify", ""),
            ("clip*", ""),
            ("annotate", ""),
            ("ctl_caps", ""),
        ],
    },
    Family {
        name: "LLM",
        items: &[("ai_*", "")],
    },
];

/// Steps that are usually run in order, drawn as `a > b > c`. Shown only when every step is
/// served. A chain is a recommendation, not a protocol: it says what tends to come next.
pub const CHAINS: &[(&str, &[&str])] = &[
    (
        "Space",
        &["disk_usage", "file_stats", "locate_sql", "delete_path"],
    ),
    ("Index", &["locate_refresh", "locate_status", "locate_sql"]),
    (
        "Large write",
        &["blob_begin", "blob_append", "blob_finalize", "write_file"],
    ),
    ("Long command", &["run_command", "tail_file"]),
    (
        "Recall",
        &["mem_get_summary", "mem_search", "mem_get", "mem_put"],
    ),
];

/// Where a wrong pick is likely: the tool, and the neighbours worth a look. A name the
/// description already carries is not repeated.
pub const SEE_ALSO: &[(&str, &[&str])] = &[
    ("search_files", &["grep_files", "locate_search"]),
    ("grep_files", &["search_files", "locate_search"]),
    ("locate_search", &["locate_sql", "grep_files"]),
    ("locate_sql", &["file_stats", "locate_search"]),
    ("locate_refresh", &["bgnd_scan_ctl"]),
    ("locate_status", &["bgnd_scan_ctl"]),
    ("bgnd_scan_ctl", &["locate_refresh", "locate_status"]),
    (
        "file_stats",
        &["list_directory_with_sizes", "locate_sql", "disk_usage"],
    ),
    ("list_directory_with_sizes", &["locate_sql"]),
    (
        "list_directory",
        &["list_directory_with_sizes", "directory_tree"],
    ),
    ("directory_tree", &["file_stats"]),
    ("disk_usage", &["file_stats"]),
    ("get_file_info", &["file_stats"]),
    ("find_duplicates", &["locate_sql", "file_hash"]),
    ("delete_path", &["file_stats"]),
    ("run_command", &["tail_file"]),
    ("tail_file", &["read_text_file"]),
    ("read_text_file", &["tail_file", "grep_files"]),
    ("edit_file", &["edit_lines", "bulk_edits"]),
    ("file_hash", &["file_hash_multiple"]),
    ("file_hash_multiple", &["find_duplicates"]),
    ("compare_files", &["file_diff"]),
    ("compare_directories", &["compare_files"]),
    ("mem_get_summary", &["mem_search"]),
    ("mem_search", &["mem_get"]),
    ("mem_put", &["mem_update", "mem_link"]),
    ("seq_think", &["mem_get_summary"]),
];

/// Does `text` carry `tool` as a whole name, not as a piece of a longer one (`file_stats` is not
/// mentioned by `list_file_stats_x`)?
pub fn mentions(text: &str, tool: &str) -> bool {
    let is_name_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(tool).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + tool.len()..].chars().next();
        !before.is_some_and(is_name_char) && !after.is_some_and(is_name_char)
    })
}

/// Is `item` served? A trailing `*` makes it a prefix.
fn served(item: &str, has: &dyn Fn(&str) -> bool, names: &[String]) -> bool {
    match item.strip_suffix('*') {
        Some(prefix) => names.iter().any(|name| name.starts_with(prefix)),
        None => has(item),
    }
}

/// The tool map for the tools that are served, as the block that follows the lock notice.
pub fn tool_map(names: &[String]) -> String {
    let has = |name: &str| names.iter().any(|n| n == name);
    let mut lines = Vec::new();
    for family in FAMILIES {
        let shown: Vec<String> = family
            .items
            .iter()
            .filter(|(item, _)| served(item, &has, names))
            .map(|(item, note)| {
                if note.is_empty() {
                    (*item).to_owned()
                } else {
                    format!("{item} ({note})")
                }
            })
            .collect();
        if !shown.is_empty() {
            lines.push(format!("{}: {}", family.name, shown.join(", ")));
        }
    }
    let chains: Vec<String> = CHAINS
        .iter()
        .filter(|(_, steps)| steps.iter().all(|step| has(step)))
        .map(|(label, steps)| format!("{label}: {}", steps.join(" > ")))
        .collect();
    if !chains.is_empty() {
        lines.push(format!("Usual order - {}", chains.join("; ")));
    }
    lines.join("\n")
}

/// The opening of the server instructions: the lock notice, then the tool map. Everything a
/// client may cut off comes after it.
pub fn instructions_head(names: &[String]) -> String {
    format!(
        "== SESSION LOCK ==\n\
         Once you call any tool here, use ONLY this server for file and shell work (no built-in \
         Read/Write/Edit/Grep/Glob/Shell on paths it reaches). Do not guess: re-check, and verify \
         after edits and commands.\n\n\
         == TOOL MAP (what works together) ==\n{}\n\n",
        tool_map(names)
    )
}

/// Append `See also: ...` to the description of every tool in [`SEE_ALSO`] that is served, naming
/// the neighbours that are served and that the description does not already name.
pub fn annotate<T>(router: &mut ToolRouter<T>) {
    let names: Vec<String> = router.map.keys().map(|name| name.to_string()).collect();
    for (name, route) in router.map.iter_mut() {
        let Some((_, related)) = SEE_ALSO.iter().find(|(tool, _)| *tool == name.as_ref()) else {
            continue;
        };
        let description = route.attr.description.as_deref().unwrap_or("").to_owned();
        let missing: Vec<&str> = related
            .iter()
            .copied()
            .filter(|tool| names.iter().any(|n| n == tool) && !mentions(&description, tool))
            .collect();
        if missing.is_empty() {
            continue;
        }
        let mut text = description.trim_end().to_owned();
        if !text.ends_with(['.', '!', '?']) {
            text.push('.');
        }
        text.push_str(" See also: ");
        text.push_str(&missing.join(", "));
        text.push('.');
        route.attr.description = Some(text.into());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::FileSystemServer;

    /// Names of every tool the router serves in this build.
    fn served_names() -> Vec<String> {
        FileSystemServer::build_tool_router()
            .map
            .keys()
            .map(|name| name.to_string())
            .collect()
    }

    /// The same "is every optional family compiled in" question the surface guard asks: only a
    /// full build has to serve every name written down here.
    const fn full_surface() -> bool {
        cfg!(all(
            feature = "http-tools",
            feature = "s3-tools",
            feature = "screenshot-tools",
            feature = "ctl-input",
            feature = "ctl-uia",
            feature = "ctl-ocr",
            feature = "ctl-notify",
            feature = "ctl-clip-files",
            feature = "locate-tools"
        ))
    }

    fn every_declared_name() -> BTreeSet<&'static str> {
        let mut names = BTreeSet::new();
        for family in FAMILIES {
            names.extend(family.items.iter().map(|(item, _)| *item));
        }
        for (_, steps) in CHAINS {
            names.extend(steps.iter().copied());
        }
        for (tool, related) in SEE_ALSO {
            names.insert(*tool);
            names.extend(related.iter().copied());
        }
        names
    }

    #[test]
    fn every_name_written_down_is_a_tool_the_full_surface_serves() {
        if !full_surface() {
            return;
        }
        let served = served_names();
        let missing: Vec<&str> = every_declared_name()
            .into_iter()
            .filter(|name| match name.strip_suffix('*') {
                Some(prefix) => !served.iter().any(|tool| tool.starts_with(prefix)),
                None => !served.iter().any(|tool| tool == name),
            })
            .collect();
        assert!(
            missing.is_empty(),
            "core/tool_graph.rs names tools the router does not serve (renamed, removed or \
             mistyped): {missing:?}"
        );
    }

    #[test]
    fn every_served_tool_belongs_to_a_family() {
        let claimed: Vec<&str> = FAMILIES
            .iter()
            .flat_map(|family| family.items.iter().map(|(item, _)| *item))
            .collect();
        let orphans: Vec<String> = served_names()
            .into_iter()
            .filter(|tool| {
                !claimed.iter().any(|item| match item.strip_suffix('*') {
                    Some(prefix) => tool.starts_with(prefix),
                    None => item == tool,
                })
            })
            .collect();
        assert!(
            orphans.is_empty(),
            "a tool that no family lists is a tool the map cannot tell the model about; add \
             each of these to FAMILIES in core/tool_graph.rs: {orphans:?}"
        );
    }

    #[test]
    fn a_see_also_never_points_a_tool_at_itself_or_twice_at_the_same_neighbour() {
        for (tool, related) in SEE_ALSO {
            assert!(!related.contains(tool), "{tool} lists itself");
            let unique: BTreeSet<_> = related.iter().collect();
            assert_eq!(
                unique.len(),
                related.len(),
                "{tool} lists a neighbour twice"
            );
        }
        let tools: BTreeSet<_> = SEE_ALSO.iter().map(|(tool, _)| tool).collect();
        assert_eq!(
            tools.len(),
            SEE_ALSO.len(),
            "a tool has two SEE_ALSO entries"
        );
    }

    #[test]
    fn mentions_matches_whole_names_only() {
        assert!(mentions("Use file_stats for sizes.", "file_stats"));
        assert!(mentions("file_stats", "file_stats"));
        assert!(mentions("(file_stats)", "file_stats"));
        assert!(!mentions("Use my_file_stats_x", "file_stats"));
        assert!(!mentions("Use file_stats2", "file_stats"));
        assert!(!mentions("nothing here", "file_stats"));
    }

    #[test]
    fn the_lock_notice_and_the_whole_map_fit_where_clients_still_read() {
        let head = instructions_head(&served_names());
        assert!(head.contains("== TOOL MAP"));
        assert!(
            head.chars().count() <= HEAD_LIMIT - 20,
            "the head is {} characters; clients cut the instructions near {HEAD_LIMIT}, so the \
             map would be cut with them. Shorten a note or move a tool out of a family.",
            head.chars().count()
        );
    }

    #[test]
    fn the_map_names_only_tools_that_are_served() {
        let served = served_names();
        // A build without a family must not advertise it.
        let map = tool_map(&served);
        for token in map.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '*')) {
            if token.contains('_') && !token.ends_with('*') {
                assert!(
                    served.iter().any(|tool| tool == token),
                    "the map names {token}"
                );
            }
        }
        let reduced = tool_map(&["read_text_file".to_owned(), "grep_files".to_owned()]);
        assert!(reduced.contains("Read: read_text_file"));
        assert!(!reduced.contains("locate_sql"));
        assert!(!reduced.contains("Network"));
        assert!(!reduced.contains("Usual order"));
    }

    #[test]
    fn descriptions_carry_their_neighbours_once() {
        let router = FileSystemServer::build_tool_router();
        let description = |name: &str| {
            router
                .map
                .get(name)
                .and_then(|route| route.attr.description.as_deref())
                .unwrap_or("")
                .to_owned()
        };
        if full_surface() {
            // Not repeated where the prose already names it: grep_files is in the prose, so
            // only the missing neighbour is added.
            let search = description("locate_search");
            assert!(search.ends_with(" See also: locate_sql."), "{search}");
            assert!(description("file_stats").contains("See also:"));
            assert!(description("file_stats").contains("locate_sql"));
            assert!(description("locate_sql").contains("file_stats"));
            assert!(description("delete_path").contains("file_stats"));
            assert!(description("run_command").contains("tail_file"));
        }
    }
}
