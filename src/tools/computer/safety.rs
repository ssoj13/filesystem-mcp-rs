//! Safety gate: TTL arming, ops-per-minute runaway cap, JSONL audit - and the error type a
//! refused action is reported with.
//!
//! Every input-injecting and bulk-mutating tool must call [`SafetyGate::check`] before acting and
//! [`SafetyGate::record`] after each executed action. The gate lives in the lib (not the MCP
//! layer) so non-MCP consumers inherit it.
//!
//! One file, not two. An earlier split put [`CtlError`] beside the gate on the theory that a
//! build which reads the desktop without driving it - `ctl-ocr` - would need the error and not
//! the gate. It does not: every one of the four variants describes an input-domain refusal ("not
//! armed", "op cap exceeded", "no window match", "focus failed"), and every construction site is
//! `ctl-input` or narrower. Both halves therefore have exactly the same visibility, and the split
//! bought nothing but a second file to keep in step.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    let _ = GATE.set(Arc::new(SafetyGate::with_audit(
        max_ops_per_min,
        default_audit_path(),
    )));
}

/// The process-global gate (input/uia tool handlers borrow it).
#[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
pub fn gate() -> std::sync::Arc<SafetyGate> {
    GATE.get()
        .cloned()
        .expect("computer safety gate not initialized (init_gate)")
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
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
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
/// ~10 ms).
#[cfg(feature = "ctl-input")]
pub fn resolve_interval_ms(explicit: Option<u32>, paste: bool) -> anyhow::Result<u32> {
    if let Some(v) = explicit {
        return Ok(v);
    }
    match env_trimmed(ENV_TYPE_INTERVAL_MS) {
        Some(v) => v
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("{ENV_TYPE_INTERVAL_MS}={v:?} is not a number (ms)")),
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
    /// Where the audit trail is appended, or `None` when the state directory could not be
    /// resolved. Resolved once at construction so the "auditing is off" warning is emitted
    /// once at startup instead of on every recorded op.
    audit_path: Option<PathBuf>,
}

impl SafetyGate {
    /// `max_ops_per_min` bounds executed input actions in a sliding 60 s window; the audit
    /// trail goes to `audit_path`, or nowhere when that is `None`.
    ///
    /// The path is always passed in, never defaulted inside, so that no caller can reach
    /// `default_audit_path` by accident: that function creates `<state>/safety/` and migrates
    /// the pre-2026-09 log, which is right exactly once at startup and destructive anywhere
    /// else. Production goes through [`init_gate`]; tests pass `None` or a temp path.
    pub fn with_audit(max_ops_per_min: u32, audit_path: Option<PathBuf>) -> Self {
        Self {
            state: Mutex::new(GateState {
                armed_until: None,
                armed_at_epoch_ms: 0,
                ttl_ms: 0,
                ops: VecDeque::new(),
            }),
            max_ops_per_min,
            audit_path,
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

    /// Throw [`CtlError::NotArmed`] unless currently armed (per-step re-check:
    /// an arm must never silently expire mid-sequence).
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
            st.ops
                .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
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
        if let Some(path) = &self.audit_path {
            audit_append(path, action, detail);
        }
        Ok(())
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `<state>/safety/audit.jsonl`, migrating the pre-2026-09 log from the old computer-control
/// directory - the one non-regenerable file there (the sibling ocrs models and layouts are
/// re-created on demand and are only repointed, never moved).
///
/// `None` when the state directory cannot be resolved. This is a security audit trail, so the
/// unresolvable case fails loudly in the log instead of relocating the record into the
/// world-writable, periodically-swept OS temp directory, which is what the previous
/// `data_dir().unwrap_or_else(temp_dir)` fallback did.
fn default_audit_path() -> Option<PathBuf> {
    let dir = match crate::core::paths::sub_dir(crate::core::paths::SubDir::Safety) {
        Ok(dir) => dir,
        Err(e) => {
            // The path is resolved once per process, so this is not a transient miss that a
            // later write retries: say so, and name what could not be created.
            tracing::warn!(
                "computer-control auditing is DISABLED for the lifetime of this process: \
                 cannot create the safety state directory under the state root: {e}. \
                 Every input action will run unrecorded until the server is restarted."
            );
            return None;
        }
    };
    let new = dir.join("audit.jsonl");
    if let Some(legacy) = crate::core::paths::legacy_ctl_audit()
        && let crate::core::paths::Migrated::Ambiguous { old, cause, .. } =
            crate::core::paths::migrate(&legacy, &new)
    {
        match cause {
            crate::core::paths::Cause::BothExist => tracing::warn!(
                "Old audit log left at {}: a log already exists at {}. Merge or remove one by hand.",
                old.display(),
                new.display()
            ),
            // Nothing exists at `new` after a failed move - `migrate` cleans up - so this must not
            // send the operator looking for a second file. Auditing itself still works: the new
            // log is created on the first append.
            crate::core::paths::Cause::Failed(why) => tracing::warn!(
                "Old audit log left at {}: moving it into the state directory failed: {why}. \
                 New entries are recorded at {}; the old file is yours to keep or delete.",
                old.display(),
                new.display()
            ),
        }
    }
    Some(new)
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
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_check_disarm_cycle() {
        let gate = SafetyGate::with_audit(60, None);
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
        let gate = SafetyGate::with_audit(60, None);
        gate.arm(Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(30));
        assert!(matches!(
            gate.check(),
            Err(CtlError::NotArmed { remaining_ms: 0 })
        ));
    }

    /// The cap trips on the third op, and the two that were allowed are on disk: the audit
    /// trail must record exactly what executed, so it is asserted here against a per-test
    /// directory rather than appended to the operator's real log.
    #[test]
    fn op_cap_trips_and_records_only_executed_ops() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let audit = tmp.path().join("safety/audit.jsonl");
        let gate = SafetyGate::with_audit(2, Some(audit.clone()));

        gate.record("t", serde_json::json!({})).expect("first op");
        gate.record("t", serde_json::json!({})).expect("second op");
        assert!(matches!(
            gate.record("t", serde_json::json!({})),
            Err(CtlError::OpCapExceeded { .. })
        ));

        let lines = std::fs::read_to_string(&audit).expect("audit log written");
        assert_eq!(lines.lines().count(), 2, "only executed ops are audited");
    }

    /// With no audit path the gate writes nothing at all - not the log, not even the directory
    /// `append_line` would otherwise create - while gating exactly as before.
    ///
    /// The absence is asserted against the very path that the paired `Some` gate below creates
    /// from an identical op sequence, so "not there" is a real difference between the two
    /// configurations rather than a vacuous claim about an unrelated path.
    #[test]
    fn a_gate_without_an_audit_path_writes_nothing() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let audit = tmp.path().join("safety/audit.jsonl");
        let dir = audit.parent().expect("audit parent").to_path_buf();

        let quiet = SafetyGate::with_audit(1, None);
        quiet.record("t", serde_json::json!({})).expect("first op");
        assert!(
            matches!(
                quiet.record("t", serde_json::json!({})),
                Err(CtlError::OpCapExceeded { .. })
            ),
            "the cap must still trip without an audit path"
        );
        assert!(!dir.exists(), "no audit path means no directory is created");

        // Same cap, same ops, only `audit_path` differs - and now the file is there.
        let loud = SafetyGate::with_audit(1, Some(audit.clone()));
        loud.record("t", serde_json::json!({})).expect("first op");
        let lines = std::fs::read_to_string(&audit).expect("audit log written");
        assert_eq!(lines.lines().count(), 1);
    }
}
