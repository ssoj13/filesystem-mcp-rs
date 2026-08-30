//! Fallback backend: a platform we have no implementation for (yet).
//!
//! It implements NO domain, so every facade call turns into a loud
//! `unsupported on this platform (null): <what>`. That is deliberate: a silent
//! no-op backend would let an agent "successfully" click into the void and
//! report success, which is far worse than an error.
//!
//! Also reachable on purpose via `FS_MCP_CTL_BACKEND=null` — that is how the
//! unsupported paths get tested on a machine that has a real desktop.

use super::Backend;

pub struct Null;

impl Backend for Null {
    fn name(&self) -> &'static str {
        "null"
    }

    /// Nothing to verify: it refuses everything by design.
    fn verified_on_hardware(&self) -> bool {
        false
    }
}
