pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".into();
    }
    let i = (bytes as f64).log(1024.0).floor() as usize;
    let unit = UNITS.get(i).copied().unwrap_or("TB");
    let value = bytes as f64 / 1024_f64.powi(i as i32);
    if i == 0 {
        format!("{bytes} {unit}")
    } else {
        format!("{value:.2} {unit}")
    }
}
