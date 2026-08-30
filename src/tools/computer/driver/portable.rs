//! Driver operations that are logic, not platform.
//!
//! These used to live inside the Windows backend, which meant every new OS had
//! to reimplement them (and drift). They are expressed purely in terms of the
//! domain traits — `WinDrv::list`, `geom`, `alive` — plus portable capture, so
//! they are written once and every backend inherits them.
//!
//! Only genuinely OS-specific calls belong in a backend. If something here
//! needs an `#[cfg]`, it is in the wrong file.

use crate::tools::computer::safety::CtlError;

use super::{LayoutEntry, WinInfo, WinTarget};

/// Does this window match the target? (Id is exact; title/exe are
/// case-insensitive substrings.)
fn hit(w: &WinInfo, target: &WinTarget) -> bool {
    match target {
        WinTarget::Id { id } => w.id == *id,
        WinTarget::Title { title } => w.title.to_lowercase().contains(&title.to_lowercase()),
        WinTarget::Exe { exe } => w.exe.to_lowercase().contains(&exe.to_lowercase()),
    }
}

/// Resolve a [`WinTarget`] against a window list to EXACTLY one id.
///
/// Ambiguity and zero hits are both explicit [`CtlError::NoMatch`] — "first
/// match wins" would silently click the wrong window, which is precisely the
/// class of bug that costs days to find.
fn resolve_in(wins: &[WinInfo], target: &WinTarget) -> anyhow::Result<u32> {
    let matches: Vec<&WinInfo> = wins.iter().filter(|w| hit(w, target)).collect();
    match matches.len() {
        1 => Ok(matches[0].id),
        0 => Err(anyhow::Error::new(CtlError::NoMatch {
            reason: format!("no visible window matches {target:?}"),
        })),
        n => {
            let names: Vec<String> = matches
                .iter()
                .take(5)
                .map(|w| format!("{}({})", w.title, w.exe))
                .collect();
            Err(anyhow::Error::new(CtlError::NoMatch {
                reason: format!("{n} windows match {target:?}: {}", names.join(", ")),
            }))
        }
    }
}

/// Resolve a [`WinTarget`] to exactly one live window id.
pub fn resolve_target(target: &WinTarget) -> anyhow::Result<u32> {
    resolve_in(&super::list_windows(None)?, target)
}

/// Move a window fully onto monitor `idx` (top-left at the monitor origin,
/// sized to the monitor) and return fresh geometry.
///
/// Restore first: a minimized or maximized window ignores a geometry change,
/// so the state change and the move are two separate seam calls.
pub fn to_monitor(id: u32, monitor: u32) -> anyhow::Result<WinInfo> {
    let ms = crate::tools::computer::capture::monitors()?;
    let m = ms
        .get(monitor as usize)
        .ok_or_else(|| anyhow::anyhow!("monitor {monitor} not found (0..={})", ms.len() - 1))?;
    super::geom(id, None, None, None, None, Some("restore"))?;
    super::geom(id, Some(m.x), Some(m.y), Some(m.w as i32), Some(m.h as i32), None)
}

/// Snapshot every visible top-level window into
/// `<data>/computer-mcp-rs/layouts/<name>.json`.
pub fn layout_save(name: &str) -> anyhow::Result<Vec<LayoutEntry>> {
    let entries: Vec<LayoutEntry> = super::list_windows(None)?
        .into_iter()
        .filter(|w| w.w > 0 && w.h > 0)
        .map(|w| LayoutEntry { id: w.id, title: w.title, exe: w.exe, x: w.x, y: w.y, w: w.w, h: w.h })
        .collect();
    std::fs::write(layout_path(name)?, serde_json::to_string_pretty(&entries)?)?;
    Ok(entries)
}

/// Restore a layout by window id. `dry_run` reports what WOULD move without
/// touching anything. Ids are bound to live windows: anything reopened since
/// the save keeps its id only by luck — the response lists applied/skipped per
/// entry so the agent sees exactly what happened.
pub fn layout_load(name: &str, dry_run: bool) -> anyhow::Result<Vec<(LayoutEntry, bool)>> {
    let raw = std::fs::read_to_string(layout_path(name)?)?;
    let entries: Vec<LayoutEntry> = serde_json::from_str(&raw)?;
    let win = super::backend()
        .win()
        .ok_or_else(|| super::unsupported("window management"))?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        if dry_run || !win.alive(e.id) {
            out.push((e, false));
            continue;
        }
        let placed = win
            .geom(e.id, Some(e.x), Some(e.y), Some(e.w), Some(e.h), None)
            .is_ok();
        out.push((e, placed));
    }
    Ok(out)
}

/// `<data>/computer-mcp-rs/layouts/<name>.json`, with the name sanitized to a
/// single path segment (it arrives from an agent).
fn layout_path(name: &str) -> anyhow::Result<std::path::PathBuf> {
    let safe: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe.is_empty() {
        return Err(anyhow::anyhow!("layout name must be alphanumeric"));
    }
    let dir = dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("computer-mcp-rs")
        .join("layouts");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{safe}.json")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(id: u32, title: &str, exe: &str) -> WinInfo {
        WinInfo {
            id,
            title: title.into(),
            exe: exe.into(),
            pid: 0,
            x: 0,
            y: 0,
            w: 100,
            h: 100,
            z: 0,
            active: false,
            minimized: false,
            maximized: false,
        }
    }

    fn scene() -> Vec<WinInfo> {
        vec![
            w(1, "Notepad — draft", "notepad.exe"),
            w(2, "Cargo build", "WindowsTerminal.exe"),
            w(3, "notepad — other", "notepad.exe"),
        ]
    }

    #[test]
    fn resolves_unique_id_and_title() {
        assert_eq!(resolve_in(&scene(), &WinTarget::Id { id: 2 }).unwrap(), 2);
        assert_eq!(
            resolve_in(&scene(), &WinTarget::Title { title: "cargo".into() }).unwrap(),
            2,
            "title match is case-insensitive"
        );
    }

    #[test]
    fn ambiguity_is_an_error_naming_the_candidates() {
        let e = resolve_in(&scene(), &WinTarget::Exe { exe: "notepad".into() }).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains('2') || msg.contains("2 windows"), "reports the count: {msg}");
        assert!(msg.contains("Notepad"), "names candidates: {msg}");
    }

    #[test]
    fn no_match_is_an_error_not_an_empty_ok() {
        let e = resolve_in(&scene(), &WinTarget::Title { title: "nothing".into() }).unwrap_err();
        assert!(matches!(e.downcast_ref::<CtlError>(), Some(CtlError::NoMatch { .. })));
    }

    #[test]
    fn layout_name_is_sanitized_to_one_segment() {
        let p = layout_path("my-layout_2").unwrap();
        assert!(p.ends_with("my-layout_2.json"));
        // Traversal characters are filtered out, not rejected late.
        let p = layout_path("../../etc/passwd").unwrap();
        assert!(p.ends_with("etcpasswd.json"), "got {p:?}");
        assert!(layout_path("///").is_err(), "empty after sanitizing must fail loudly");
    }
}
