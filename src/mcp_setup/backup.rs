//! Optional user backup immediately before mutating a config file.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::mcp_setup::error::{Result, SetupError};

/// Writes `path` copy next to the original as `<name>.mcp-setup-user-backup-<ms>`.
/// If `path` does not exist, returns `Ok(None)`.
pub fn backup_file_if_exists(path: &Path) -> Result<Option<std::path::PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return Ok(None);
    };
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let backup_name = format!("{name}.mcp-setup-user-backup-{ms}");
    let Some(parent) = path.parent() else {
        return Err(SetupError::io(
            path.to_path_buf(),
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent"),
        ));
    };
    let dest = parent.join(backup_name);
    std::fs::copy(path, &dest).map_err(|e| SetupError::io(&dest, e))?;
    Ok(Some(dest))
}
