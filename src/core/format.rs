pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".into();
    }
    let i = ((63 - bytes.leading_zeros()) / 10).min((UNITS.len() - 1) as u32) as usize;
    let unit = UNITS[i];
    let value = bytes as f64 / 1024_f64.powi(i as i32);
    if i == 0 {
        format!("{bytes} {unit}")
    } else {
        format!("{value:.2} {unit}")
    }
}
