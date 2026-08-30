//! Safety gate: TTL arming, ops-per-minute runaway cap, JSONL audit.
//!
//! Every input-injecting and bulk-mutating tool must call [`SafetyGate::check`]
//! before acting and [`SafetyGate::record`] after each executed action. The gate
//! lives in the lib (not the MCP layer) so non-MCP consumers inherit it.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Domain errors surfaced to MCP as typed codes (PLAN2.md §3).
///
/// Every message carries its payload: these strings are what an agent reads to
/// decide what to do next, so "no window match" without the candidates, or an
/// op-cap error without the back-off, forces blind retries.
#[derive(Debug, thiserror::Error)]
pub enum CtlError {
    /// Input attempted while the gate is not armed. `remaining_ms` is always 0
    /// while disarmed; the field keeps the wire shape stable for future pre-warn.
    #[error("not armed (arm first; {remaining_ms} ms left on the current window)")]
    NotArmed { remaining_ms: u64 },

    /// Runaway protection tripped: too many input ops in the sliding window.
    #[error("op cap exceeded, retry after {retry_after_ms} ms")]
    OpCapExceeded { retry_after_ms: u64 },

    /// Window target resolved to zero or several windows.
    #[error("no window match: {reason}")]
    NoMatch { reason: String },

    /// Foreground change did not verify within the settle window.
    ///
    /// Every backend that can focus a window is expected to raise it; today
    /// only win32 implements focusing, so a non-Windows build genuinely never
    /// constructs this variant. Remove the attribute when the second backend
    /// lands — it is a dated note, not blanket permission.
    #[cfg_attr(not(windows), allow(dead_code))]
    #[error("focus failed for window {hwnd}")]
    FocusFailed { hwnd: u32 },
}

impl CtlError {
    /// Stable wire code for MCP error mapping.
    pub fn code(&self) -> &'static str {
        match self {
            CtlError::NotArmed { .. } => "not_armed",
            CtlError::OpCapExceeded { .. } => "op_cap",
            CtlError::NoMatch { .. } => "no_match",
            CtlError::FocusFailed { .. } => "focus_failed",
        }
    }
}

/// Process-global gate handle (set once from main/test setup, read everywhere).
static GATE: OnceLock<Arc<SafetyGate>> = OnceLock::new();

/// Install the process-global gate with the ops-per-minute runaway cap.
#[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
pub fn init_gate(max_ops_per_min: u32) {
    let _ = GATE.set(Arc::new(SafetyGate::new(max_ops_per_min)));
}

/// The process-global gate (input/uia tool handlers borrow it).
#[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
pub fn gate() -> std::sync::Arc<SafetyGate> {
    GATE.get().cloned().expect("computer safety gate not initialized (init_gate)")
}

// ---- Environment configuration (set in mcpServers env; empty = unset) ----

/// key_type mode: `paste` (clipboard roundtrip, default) or `chars`
/// (per-char KEYEVENTF_UNICODE with delay).
pub const ENV_TYPE_MODE: &str = "FS_MCP_CTL_TYPE_MODE";
/// Per-char delay for `chars` mode (ms). Empirically verified on Win11
/// Notepad (typing_mode_matrix): intervals below ~25 ms deterministically
/// mangle runs of chars into repeats of the LAST char ("123"->"333");
/// 30 ms is clean ×3.
pub const ENV_TYPE_INTERVAL_MS: &str = "FS_MCP_CTL_TYPE_INTERVAL_MS";
/// Default arm TTL (ms).
pub const ENV_ARM_TTL_MS: &str = "FS_MCP_CTL_ARM_TTL_MS";
/// Input ops per minute runaway cap.
pub const ENV_OPS_PER_MIN: &str = "FS_MCP_CTL_OPS_PER_MIN";

fn env_trimmed(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Effective paste flag: explicit arg > env > default (paste).
/// Unknown env values are a loud error, never a silent fallback.
#[cfg(feature = "ctl-input")]
pub fn resolve_paste(explicit: Option<bool>) -> anyhow::Result<bool> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    match env_trimmed(ENV_TYPE_MODE) {
        None => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("paste") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("chars") => Ok(false),
        Some(other) => Err(anyhow::anyhow!(
            "{ENV_TYPE_MODE}={other:?} is invalid (paste|chars)"
        )),
    }
}

/// Effective per-char interval: explicit arg > env > default (paste: 0,
/// chars: 12 ms — the safe floor: Win11 Notepad drops unicode chars below
/// ~10 ms, PLAN2 §6.7).
#[cfg(feature = "ctl-input")]
pub fn resolve_interval_ms(explicit: Option<u32>, paste: bool) -> anyhow::Result<u32> {
    if let Some(v) = explicit {
        return Ok(v);
    }
    match env_trimmed(ENV_TYPE_INTERVAL_MS) {
        Some(v) => v.parse::<u32>().map_err(|_| {
            anyhow::anyhow!("{ENV_TYPE_INTERVAL_MS}={v:?} is not a number (ms)")
        }),
        None => Ok(if paste { 0 } else { 30 }),
    }
}

/// Effective arm TTL: explicit arg > env > default (30 s).
#[cfg(feature = "ctl-input")]
pub fn resolve_arm_ttl_ms(explicit: Option<u32>) -> u32 {
    explicit
        .or_else(|| env_trimmed(ENV_ARM_TTL_MS).and_then(|v| v.parse().ok()))
        .unwrap_or(30_000)
}

/// Effective ops-per-minute cap: CLI arg > env > default (240).
#[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
pub fn resolve_ops_per_min(explicit: Option<u32>) -> u32 {
    explicit
        .or_else(|| env_trimmed(ENV_OPS_PER_MIN).and_then(|v| v.parse().ok()))
        .unwrap_or(240)
}

struct GateState {
    armed_until: Option<Instant>,
    armed_at_epoch_ms: u64,
    ttl_ms: u64,
    ops: VecDeque<Instant>,
}

/// Process-local safety gate. Cheap to clone via `Arc`; internally locked.
pub struct SafetyGate {
    state: Mutex<GateState>,
    max_ops_per_min: u32,
    audit_path: PathBuf,
}

impl SafetyGate {
    /// `max_ops_per_min` bounds executed input actions in a sliding 60 s window.
    pub fn new(max_ops_per_min: u32) -> Self {
        Self {
            state: Mutex::new(GateState {
                armed_until: None,
                armed_at_epoch_ms: 0,
                ttl_ms: 0,
                ops: VecDeque::new(),
            }),
            max_ops_per_min,
            audit_path: default_audit_path(),
        }
    }

    /// Arm the gate for `ttl`. Returns the absolute expiry (epoch ms).
    pub fn arm(&self, ttl: Duration) -> u64 {
        let mut st = self.state.lock().expect("gate poisoned");
        let until = Instant::now() + ttl;
        st.armed_until = Some(until);
        st.armed_at_epoch_ms = epoch_ms();
        st.ttl_ms = ttl.as_millis() as u64;
        epoch_ms() + ttl.as_millis() as u64
    }

    /// Throw [`CtlError::NotArmed`] unless currently armed (per-step re-check,
    /// PLAN2.md critic A: an arm must never silently expire mid-sequence).
    pub fn check(&self) -> Result<(), CtlError> {
        let st = self.state.lock().expect("gate poisoned");
        match st.armed_until {
            Some(until) if Instant::now() < until => Ok(()),
            Some(_) => Err(CtlError::NotArmed { remaining_ms: 0 }),
            None => Err(CtlError::NotArmed { remaining_ms: 0 }),
        }
    }

    /// Count one executed op against the sliding cap and append an audit line.
    /// Called AFTER the action executed, so the audit log reflects reality.
    pub fn record(&self, action: &str, detail: serde_json::Value) -> Result<(), CtlError> {
        {
            let mut st = self.state.lock().expect("gate poisoned");
            let now = Instant::now();
            st.ops.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
            if st.ops.len() as u32 >= self.max_ops_per_min {
                let retry_after = st
                    .ops
                    .front()
                    .map(|t| Duration::from_secs(60).saturating_sub(now.duration_since(*t)))
                    .unwrap_or_default();
                return Err(CtlError::OpCapExceeded {
                    retry_after_ms: retry_after.as_millis() as u64,
                });
            }
            st.ops.push_back(now);
        }
        audit_append(&self.audit_path, action, detail);
        Ok(())
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn default_audit_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("computer-mcp-rs")
        .join("audit.jsonl")
}

/// Append one JSONL audit line. Audit failure is logged, never propagated:
/// losing a log line must not turn a completed action into an MCP error.
fn audit_append(path: &PathBuf, action: &str, detail: serde_json::Value) {
    let entry = serde_json::json!({
        "ts": epoch_ms(),
        "action": action,
        "detail": detail,
    });
    if let Err(e) = append_line(path, &entry.to_string()) {
        tracing::warn!("audit append failed ({}): {}", path.display(), e);
    }
}

fn append_line(path: &PathBuf, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_check_disarm_cycle() {
        let gate = SafetyGate::new(60);
        assert!(matches!(
            gate.check(),
            Err(CtlError::NotArmed { remaining_ms: 0 })
        ));
        let until = gate.arm(Duration::from_millis(10));
        assert!(until > 0);
        assert!(gate.check().is_ok());
        std::thread::sleep(Duration::from_millis(30));
        assert!(gate.check().is_err());
    }

    #[test]
    fn ttl_expiry_refuses() {
        let gate = SafetyGate::new(60);
        gate.arm(Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(30));
        assert!(matches!(
            gate.check(),
            Err(CtlError::NotArmed { remaining_ms: 0 })
        ));
    }

    #[test]
    fn op_cap_trips() {
        let gate = SafetyGate::new(2);
        gate.record("t", serde_json::json!({})).unwrap();
        gate.record("t", serde_json::json!({})).unwrap();
        assert!(matches!(
            gate.record("t", serde_json::json!({})),
            Err(CtlError::OpCapExceeded { .. })
        ));
    }
}
