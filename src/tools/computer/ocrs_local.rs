//! Local neural OCR via `ocrs` (pure Rust, RTen inference, CPU) — the second
//! OCR engine alongside Windows.Media.Ocr.
//!
//! WHY: Windows.Media.Ocr handles Cyrillic well but is mediocre on Latin UI
//! text; `ocrs` is better there. Both run 100% locally — zero LLM tokens.
//!
//! MODELS: downloaded automatically on first use into
//! `dirs::data_dir()/computer-mcp-rs/ocrs` (override:
//! `FS_MCP_CTL_OCRS_MODELS_DIR`). URLs are the upstream defaults from
//! ocrs-cli (verbatim): ocrs-models.s3-accelerate.amazonaws.com/*.rten.
//! Downloads go to `<name>.part` and are renamed only when complete, so a
//! killed download can never leave a truncated model behind.
//!
//! Latin-only (upstream limitation) — Cyrillic keeps using engine=media.

use std::path::PathBuf;
use std::sync::OnceLock;

use ocrs::{ImageSource, OcrEngine, OcrEngineParams};
use rten::Model;

use super::ocr::{OcrMatch, OcrOut};

const DETECT_URL: &str = "https://ocrs-models.s3-accelerate.amazonaws.com/text-detection.rten";
const RECOG_URL: &str = "https://ocrs-models.s3-accelerate.amazonaws.com/text-recognition.rten";

/// Env override for the models directory (empty = unset).
pub const ENV_OCRS_MODELS_DIR: &str = "FS_MCP_CTL_OCRS_MODELS_DIR";

fn models_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(ENV_OCRS_MODELS_DIR) {
        let d = PathBuf::from(dir.trim());
        if !d.as_os_str().is_empty() {
            return d;
        }
    }
    dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("computer-mcp-rs")
        .join("ocrs")
}

fn model_path(name: &str) -> PathBuf {
    models_dir().join(name)
}

/// Download one model file (atomic: `<name>.part` -> rename). reqwest::blocking:
/// the same proven stack as the http tools (ureq hung on this box).
fn download_model(url: &str, path: &PathBuf) -> anyhow::Result<()> {
    let part = path.with_extension("part");
    tracing::info!("downloading OCR model {} -> {}", url, part.display());
    let mut resp = reqwest::blocking::Client::new()
        .get(url)
        .timeout(std::time::Duration::from_secs(300))
        .send()
        .map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::File::create(&part)?;
    std::io::copy(&mut resp, &mut file)?;
    file.sync_all()?;
    std::fs::rename(&part, path)?;
    tracing::info!("OCR model stored: {}", path.display());
    Ok(())
}

/// Ensure both models exist locally (downloading on first use).
fn ensure_models() -> anyhow::Result<()> {
    for (name, url) in [
        ("text-detection.rten", DETECT_URL),
        ("text-recognition.rten", RECOG_URL),
    ] {
        let p = model_path(name);
        if !p.is_file() {
            download_model(url, &p)?;
        }
    }
    Ok(())
}

/// Process-cached engine (models are static per run; loading costs ~100 ms).
static ENGINE: OnceLock<OcrEngine> = OnceLock::new();

fn engine() -> anyhow::Result<&'static OcrEngine> {
    if let Some(e) = ENGINE.get() {
        return Ok(e);
    }
    ensure_models()?;
    let detection = Model::load_file(model_path("text-detection.rten"))
        .map_err(|e| anyhow::anyhow!("load text-detection.rten: {e}"))?;
    let recognition = Model::load_file(model_path("text-recognition.rten"))
        .map_err(|e| anyhow::anyhow!("load text-recognition.rten: {e}"))?;
    let engine = OcrEngine::new(OcrEngineParams {
        detection_model: Some(detection),
        recognition_model: Some(recognition),
        ..Default::default()
    })
    .map_err(|e| anyhow::anyhow!("OcrEngine::new: {e}"))?;
    ENGINE.set(engine).map_err(|_| anyhow::anyhow!("OCR engine already initialized"))?;
    ENGINE.get().ok_or_else(|| anyhow::anyhow!("OCR engine unavailable"))
}

/// Recognize `img` via ocrs. Same OcrOut shape as the media engine
/// (per-line text + screen-relative rects; no confidence in either engine).
pub fn recognize(img: &image::RgbaImage, find: Option<&str>) -> anyhow::Result<OcrOut> {
    let engine = engine()?;
    let rgb = image::DynamicImage::ImageRgba8(img.clone()).into_rgb8();
    let source = ImageSource::from_bytes(rgb.as_raw(), rgb.dimensions())
        .map_err(|e| anyhow::anyhow!("ImageSource: {e}"))?;
    let input = engine.prepare_input(source).map_err(|e| anyhow::anyhow!("prepare_input: {e}"))?;

    let words = engine
        .detect_words(&input)
        .map_err(|e| anyhow::anyhow!("detect_words: {e}"))?;
    let lines = engine.find_text_lines(&input, &words);
    let texts = engine
        .recognize_text(&input, &lines)
        .map_err(|e| anyhow::anyhow!("recognize_text: {e}"))?;

    let mut text = String::new();
    let mut out_lines: Vec<OcrMatch> = Vec::new();
    // texts[i] corresponds to lines[i] (None = skipped upstream).
    for (line_opt, line_rects) in texts.iter().zip(lines.iter()) {
        let Some(line_item) = line_opt else { continue };
        // Spurious single-char detections are upstream noise (see ocrs-cli).
        let s = line_item.to_string();
        if s.chars().count() <= 1 {
            continue;
        }
        // Word rects: union of rotated word boxes -> axis-aligned line rect.
        let mut rect: Option<(i32, i32, i32, i32)> = None;
        for w in line_rects {
            let corners = w.corners();
            let mut cell = (i32::MAX, i32::MAX, i32::MIN, i32::MIN);
            for c in corners {
                cell.0 = cell.0.min(c.x as i32);
                cell.1 = cell.1.min(c.y as i32);
                cell.2 = cell.2.max(c.x as i32);
                cell.3 = cell.3.max(c.y as i32);
            }
            rect = Some(match rect {
                None => cell,
                Some((l, t, rt, b)) => (l.min(cell.0), t.min(cell.1), rt.max(cell.2), b.max(cell.3)),
            });
        }
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&s);
        if let Some((l, t, rt, b)) = rect {
            out_lines.push(OcrMatch {
                text: s,
                x: l,
                y: t,
                w: rt - l,
                h: b - t,
            });
        }
    }
    let matches = match find {
        None => Vec::new(),
        Some(needle) => {
            let n = needle.to_lowercase();
            out_lines
                .iter()
                .filter(|l| l.text.to_lowercase().contains(&n))
                .cloned()
                .collect()
        }
    };
    Ok(OcrOut { text, lines: out_lines, matches })
}
