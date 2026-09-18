//! What a computer-control tool can refuse with, and - for the domains that inject input - the
//! gate that does the refusing.
//!
//! [`CtlError`] is the whole of this module for a build that reads the desktop without driving
//! it: `ctl-ocr` resolves windows and recognises text, and needs to say "no window match" or
//! "focus failed" without ever arming anything. The arm gate, the ops-per-minute cap and the
//! audit trail live in [`gate`] and exist only for `ctl-input`.

/// The arm gate. See [`gate`] for why it is gated more narrowly than this module.
#[cfg(feature = "ctl-input")]
mod gate;
// The `ENV_*` names stay inside `gate`: its own resolvers are their only readers, and
// `env_spec` is where the keys are advertised.
#[cfg(feature = "ctl-input")]
pub use gate::{
    SafetyGate, gate, init_gate, resolve_arm_ttl_ms, resolve_interval_ms, resolve_ops_per_min,
    resolve_paste,
};

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
