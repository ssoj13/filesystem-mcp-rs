//! Macro engine: a sequence of input/capture/wait steps executed in ONE MCP
//! round trip (PLAN2.md §3 `input_macro` — the biggest latency saver).
//!
//! Semantics: fail-fast (critic A), per-step arm re-check (input steps already
//! gate inside input::*), 40-step and 30 s wall caps, results aligned with the
//! step list so the agent can see exactly which step failed and why.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::capture::{self, CapTarget, hash_dist, default_cursor_size};
use super::input::{self, Btn};
use super::safety::SafetyGate;
use super::win::{self, WinTarget};

/// Default dhash distance above which a screen counts as "changed" (§6.6).
const CHANGE_EPS: u32 = 6;

/// Point in virtual-screen px.
#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
pub struct Pt {
    pub x: i32,
    pub y: i32,
}

/// One macro step; `t` discriminates:
/// move|click|drag|scroll|key|type|wait|wait_screen|capture|focus.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Step {
    Move { x: i32, y: i32 },
    Click {
        x: Option<i32>,
        y: Option<i32>,
        button: Option<Btn>,
        clicks: Option<u32>,
        /// Modifier keys held across the click: ctrl/alt/shift/win.
        mods: Option<Vec<String>>,
    },
    Drag {
        from: Option<Pt>,
        to: Pt,
        button: Option<Btn>,
        /// Tempo: real duration in ms (0 = instant).
        duration_ms: Option<u32>,
        /// Trajectory: linear | out (default linear).
        ease: Option<super::input::Ease>,
        /// Settle at `from` with button down before moving (ms).
        hold_ms: Option<u32>,
    },
    Scroll { dy: i32, dx: Option<i32> },
    Key { key: String, hold_ms: Option<u32> },
    Type { text: String, paste: Option<bool> },
    Wait { ms: u32 },
    WaitScreen {
        target: Option<CapTarget>,
        /// dhash to compare against; omitted -> hash the screen now, then wait for change.
        since: Option<u64>,
        timeout_ms: Option<u32>,
        poll_ms: Option<u32>,
    },
    Capture { target: Option<CapTarget> },
    Focus { target: WinTarget },
}

/// Outcome of one step (aligned by index with the input steps).
#[derive(Debug, Serialize)]
pub struct StepResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// Whole-macro outcome.
#[derive(Debug, Serialize)]
pub struct MacroResult {
    pub results: Vec<StepResult>,
    pub elapsed_ms: u64,
}

const MAX_STEPS: usize = 40;
const MAX_WALL: Duration = Duration::from_secs(30);

/// Execute raw JSON steps under `gate`. Each step is deserialized lazily so
/// string values can reference earlier results: `${0.hash}`, `${2.matches.0.x}`.
/// A whole-string ref keeps the referenced JSON type; an inline ref inside a
/// longer string is stringified. Unresolvable refs are loud errors.
pub fn run(
    gate: &SafetyGate,
    raw_steps: &[serde_json::Value],
    gap_ms: u32,
    stop_on_fail: bool,
) -> anyhow::Result<MacroResult> {
    if raw_steps.len() > MAX_STEPS {
        return Err(anyhow::anyhow!("{MAX_STEPS}-step cap exceeded ({})", raw_steps.len()));
    }
    let started = Instant::now();
    let mut results: Vec<StepResult> = Vec::with_capacity(raw_steps.len());
    for (idx, raw) in raw_steps.iter().enumerate() {
        if started.elapsed() > MAX_WALL {
            results.push(StepResult {
                ok: false,
                err: Some(format!("30 s wall cap hit at step {idx}")),
                value: None,
            });
            return Ok(MacroResult { results, elapsed_ms: started.elapsed().as_millis() as u64 });
        }
        if gap_ms > 0 && idx > 0 {
            std::thread::sleep(Duration::from_millis(gap_ms as u64));
        }
        let mut raw_step = raw.clone();
        resolve_refs(&mut raw_step, &results)?;
        let step: Step = serde_json::from_value(raw_step).map_err(|e| {
            anyhow::anyhow!("step {idx}: invalid step definition: {e}")
        })?;
        let res = run_step(gate, &step);
        let ok = res.is_ok();
        let value = res.as_ref().ok().cloned();
        let err = res.as_ref().err().map(|e| e.to_string());
        results.push(StepResult { ok, value, err });
        if !ok && stop_on_fail {
            return Ok(MacroResult { results, elapsed_ms: started.elapsed().as_millis() as u64 });
        }
    }
    Ok(MacroResult { results, elapsed_ms: started.elapsed().as_millis() as u64 })
}

fn run_step(gate: &SafetyGate, step: &Step) -> anyhow::Result<serde_json::Value> {
    match step {
        Step::Move { x, y } => {
            gate.check()?;
            let f = input::move_cursor(*x, *y)?;
            Ok(serde_json::json!({ "focus": f }))
        }
        Step::Click { x, y, button, clicks, mods } => {
            let btn = *button.as_ref().unwrap_or(&Btn::Left);
            let mod_keys: Vec<_> = mods
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|n| {
                    input::vk(n).ok_or_else(|| anyhow::anyhow!("unknown modifier {n:?}"))
                })
                .collect::<Result<_, _>>()?;
            let f = input::click(gate, *x, *y, btn, clicks.unwrap_or(1), &mod_keys)?;
            Ok(serde_json::json!({ "focus": f }))
        }
        Step::Drag { from, to, button, duration_ms, ease, hold_ms } => {
            let btn = *button.as_ref().unwrap_or(&Btn::Left);
            let start = match from {
                Some(p) => (p.x, p.y),
                None => cursor_now(),
            };
            let f = input::drag(
                gate,
                start,
                (to.x, to.y),
                btn,
                duration_ms.unwrap_or(0),
                ease.unwrap_or(super::input::Ease::Linear),
                hold_ms.unwrap_or(0),
            )?;
            Ok(serde_json::json!({ "focus": f }))
        }
        Step::Scroll { dy, dx } => {
            let f = input::scroll(gate, *dy, dx.unwrap_or(0))?;
            Ok(serde_json::json!({ "focus": f }))
        }
        Step::Key { key, hold_ms } => {
            let f = input::key_tap(gate, key, hold_ms.unwrap_or(0))?;
            Ok(serde_json::json!({ "focus": f }))
        }
        Step::Type { text, paste } => {
            let paste = paste.unwrap_or(true);
            // Paste safety: the expected window is whatever is focused NOW —
            // a focus change between steps refuses the paste (critic §10.2).
            let expect = if paste { Some(input::focus().hwnd) } else { None };
            let r = input::type_text(gate, text, paste, 0, expect)?;
            Ok(serde_json::json!({ "mode": r.mode, "chars": r.chars, "focus": r.focus, "clipboard_restored": r.clipboard_restored }))
        }
        Step::Wait { ms } => {
            std::thread::sleep(Duration::from_millis(*ms as u64));
            Ok(serde_json::json!({ "waited_ms": ms }))
        }
        Step::WaitScreen { target, since, timeout_ms, poll_ms } => {
            let cap = target.clone().unwrap_or(CapTarget::Cursor { size: default_cursor_size() });
            let baseline = match since {
                Some(h) => *h,
                None => capture::capture(cap.clone())?.hash,
                // No `since`: baseline = now; wait until screen differs from now.
            };
            let deadline = Duration::from_millis(timeout_ms.unwrap_or(3000) as u64);
            let poll = Duration::from_millis(poll_ms.unwrap_or(200) as u64);
            let started = Instant::now();
            loop {
                if started.elapsed() > deadline {
                    return Err(anyhow::anyhow!("wait_screen timeout"));
                }
                std::thread::sleep(poll);
                let now = capture::capture(cap.clone())?.hash;
                if hash_dist(baseline, now) > CHANGE_EPS {
                    return Ok(serde_json::json!({ "changed": true, "hash": now }));
                }
            }
        }
        Step::Capture { target } => {
            let cap = target.clone().unwrap_or(CapTarget::Monitor { monitor: 0 });
            let r = capture::capture(cap)?;
            Ok(serde_json::json!({ "path": r.path, "hash": r.hash, "rect": r.rect }))
        }
        Step::Focus { target } => {
            gate.check()?;
            let hwnd = win::resolve_target(target)?;
            win::focus_window(hwnd)?;
            Ok(serde_json::json!({ "focus": input::focus() }))
        }
    }
}

/// Reference pattern: `${N}` or `${N.path.segments}` — step index into the
/// results array, then a dot-path into that step's result value.
fn resolve_refs(value: &mut serde_json::Value, results: &[StepResult]) -> anyhow::Result<()> {
    match value {
        serde_json::Value::String(s) => {
            let mut out = String::with_capacity(s.len());
            let mut rest = s.as_str();
            let mut replaced = false;
            while let Some(start) = rest.find("${") {
                let Some(end) = rest[start..].find('}') else {
                    break;
                };
                // `end` is relative to `start`; the closing brace is absolute.
                let token = &rest[start + 2..start + end];
                let (idx, path) = parse_ref(token)
                    .ok_or_else(|| anyhow::anyhow!("invalid ref ${{{token}}} (want N or N.path)"))?;
                let v = lookup_ref(results, idx, &path)?;
                replaced = true;
                let whole_string = start == 0 && start + end == rest.len() - 1;
                if whole_string {
                    *value = v;
                    return Ok(());
                }
                out.push_str(&rest[..start]);
                // Inline string refs splice the raw text; other types keep
                // their JSON representation.
                match &v {
                    serde_json::Value::String(s2) => out.push_str(s2),
                    other => out.push_str(&other.to_string()),
                }
                rest = &rest[start + end + 1..];
            }
            if replaced {
                out.push_str(rest);
                *value = serde_json::Value::String(out);
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for it in items {
                resolve_refs(it, results)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                resolve_refs(v, results)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `"5"` / `"5.hash"` / `"5.matches.0.x"` -> (5, path segments).
fn parse_ref(token: &str) -> Option<(usize, Vec<String>)> {
    let mut segs = token.split('.');
    let idx = segs.next()?.parse::<usize>().ok()?;
    Some((idx, segs.map(str::to_string).collect()))
}

fn lookup_ref(
    results: &[StepResult],
    idx: usize,
    path: &[String],
) -> anyhow::Result<serde_json::Value> {
    let res = results.get(idx).ok_or_else(|| {
        anyhow::anyhow!("ref ${{{idx}}} points ahead (only steps 0..{} have run)", results.len())
    })?;
    let Some(v) = &res.value else {
        return Err(anyhow::anyhow!("ref ${{{idx}}}: step failed, no result"));
    };
    let mut cur = v;
    for seg in path {
        // Numeric segments index arrays; everything else keys objects.
        cur = match cur {
            serde_json::Value::Array(items) => {
                let i: usize = seg.parse().map_err(|_| {
                    anyhow::anyhow!("ref ${{{idx}}}: {seg:?} is not an array index")
                })?;
                items.get(i).ok_or_else(|| {
                    anyhow::anyhow!("ref ${{{idx}}}: array index {i} out of range")
                })?
            }
            obj => obj.get(seg).ok_or_else(|| {
                anyhow::anyhow!("ref ${{{idx}}}: no key {seg:?} in result")
            })?,
        };
    }
    Ok(cur.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(idx_ok: bool, v: serde_json::Value) -> StepResult {
        StepResult { ok: idx_ok, value: Some(v), err: None }
    }

    #[test]
    fn refs_whole_string_keeps_type() {
        let mut v = serde_json::json!("${0.hash}");
        let results = vec![res(true, serde_json::json!({ "hash": 42u64 }))];
        resolve_refs(&mut v, &results).unwrap();
        assert_eq!(v, serde_json::json!(42u64));
    }

    #[test]
    fn refs_inline_stringifies() {
        let mut v = serde_json::json!("step0=${0.a} and ${0.b.c}");
        let results = vec![res(true, serde_json::json!({ "a": 7, "b": { "c": "x" } }))];
        resolve_refs(&mut v, &results).unwrap();
        assert_eq!(v, serde_json::json!("step0=7 and x"));
    }

    #[test]
    fn refs_walk_arrays() {
        let mut v = serde_json::json!("${1.matches.0.x}");
        let results = vec![
            res(true, serde_json::json!({})),
            res(true, serde_json::json!({ "matches": [ { "x": 99 } ] })),
        ];
        resolve_refs(&mut v, &results).unwrap();
        assert_eq!(v, serde_json::json!(99));
    }

    #[test]
    fn refs_errors_are_loud() {
        let results = vec![res(false, serde_json::json!({}))];
        let mut v = serde_json::json!("${0.hash}");
        assert!(resolve_refs(&mut v, &results).is_err()); // step failed
        let mut v = serde_json::json!("${3.hash}");
        assert!(resolve_refs(&mut v, &results).is_err()); // points ahead
        let mut v = serde_json::json!("${0.nope}");
        assert!(resolve_refs(&mut v, &results).is_err()); // missing key
        let mut v = serde_json::json!("${xx}");
        assert!(resolve_refs(&mut v, &results).is_err()); // malformed
    }
}

fn cursor_now() -> (i32, i32) {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;
    let mut p = POINT::default();
    // SAFETY: out-pointer only.
    unsafe { GetCursorPos(&mut p) }.ok().map(|_| (p.x, p.y)).unwrap_or((0, 0))
}
