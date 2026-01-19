use anyhow::Result;
use similar::TextDiff;

pub fn unified_diff(old: &str, new: &str, file: &str) -> Result<String> {
    let diff = TextDiff::from_lines(old, new);
    let text = diff
        .unified_diff()
        .context_radius(3)
        .header(file, file)
        .to_string();
    Ok(text)
}
