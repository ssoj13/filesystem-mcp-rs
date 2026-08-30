//! Windows OCR (Windows.Media.Ocr via WinRT) — text with bounding boxes
//! (PLAN2.md §8 P3). Middle rung of the click hierarchy: UIA -> OCR -> pixels.
//!
//! No per-word confidence exists in WinRT OCR (critic §10.6) — output is
//! {text, rects} only. Missing language packs = explicit error, never a silent
//! fallback.

use image::RgbaImage;
use image::ImageEncoder as _;

// The result shape is engine-independent and lives in the computer module, so
// `ocr` (WinRT, here) and `ocrs_local` (portable) return the very same type.
use crate::tools::computer::{OcrMatch, OcrOut};

/// Recognize `img` (RGBA). `find` (case-insensitive) switches on bbox-matching.
pub fn recognize(img: &RgbaImage, find: Option<&str>) -> anyhow::Result<OcrOut> {
    let engine = windows::Media::Ocr::OcrEngine::TryCreateFromUserProfileLanguages()
        .map_err(|e| {
            anyhow::anyhow!(
                "no OCR language pack usable ({e}); add one: Settings > Time & Language > Language"
            )
        })?;
    let bitmap = to_software_bitmap(img)?;
    let result = {
        let op = engine
            .RecognizeAsync(&bitmap)
            .map_err(|e| anyhow::anyhow!("RecognizeAsync: {e}"))?;
        // IAsyncOperation implements IntoFuture (not Future) — convert first.
        futures::executor::block_on(op.into_future()).map_err(|e| anyhow::anyhow!("recognize: {e}"))?
    };

    let mut text = String::new();
    let mut lines: Vec<OcrMatch> = Vec::new();
    for line in result.Lines().map_err(|e| anyhow::anyhow!("Lines: {e}"))? {
        let line_text: String = line
            .Text()
            .map_err(|e| anyhow::anyhow!("Text: {e}"))?
            .to_string_lossy();
        let mut rect = None::<(f32, f32, f32, f32)>;
        for word in line.Words().map_err(|e| anyhow::anyhow!("Words: {e}"))? {
            let r = word.BoundingRect().map_err(|e| anyhow::anyhow!("BoundingRect: {e}"))?;
            let cell = (r.X, r.Y, r.X + r.Width, r.Y + r.Height);
            rect = Some(match rect {
                None => cell,
                Some((l, t, rt, b)) => (l.min(cell.0), t.min(cell.1), rt.max(cell.2), b.max(cell.3)),
            });
        }
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&line_text);
        if let Some((l, t, rt, b)) = rect {
            lines.push(OcrMatch {
                text: line_text.clone(),
                x: l as i32,
                y: t as i32,
                w: (rt - l) as i32,
                h: (b - t) as i32,
            });
        }
    }

    let matches = match find {
        None => Vec::new(),
        Some(needle) => {
            let n = needle.to_lowercase();
            lines
                .iter()
                .filter(|l| l.text.to_lowercase().contains(&n))
            .cloned()
                .collect()
        }
    };
    Ok(OcrOut { text, lines, matches })
}

/// RGBA image -> WinRT SoftwareBitmap via in-memory PNG + BitmapDecoder
/// (decoder handles pixel-format/alpha conversion for us).
fn to_software_bitmap(img: &RgbaImage) -> anyhow::Result<windows::Graphics::Imaging::SoftwareBitmap> {
    use windows::Graphics::Imaging::BitmapDecoder;
    use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};

    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(std::io::Cursor::new(&mut png)).write_image(
        img.as_raw(),
        img.width(),
        img.height(),
        image::ExtendedColorType::Rgba8,
    )?;

    // windows-future 0.3 has no blocking .get(): WinRT futures are awaited via
    // futures::executor::block_on (we run on the blocking pool, no reactor).
    // Encoder -> stream -> decoder path lets WinRT own pixel-format conversion.
    let stream = InMemoryRandomAccessStream::new().map_err(|e| anyhow::anyhow!("stream: {e}"))?;
    let writer = DataWriter::CreateDataWriter(&stream).map_err(|e| anyhow::anyhow!("DataWriter: {e}"))?;
    writer
        .WriteBytes(&png)
        .map_err(|e| anyhow::anyhow!("WriteBytes: {e}"))?;
    let op = writer.StoreAsync().map_err(|e| anyhow::anyhow!("StoreAsync: {e}"))?;
    futures::executor::block_on(op.into_future()).map_err(|e| anyhow::anyhow!("store: {e}"))?;
    let op = writer.FlushAsync().map_err(|e| anyhow::anyhow!("FlushAsync: {e}"))?;
    futures::executor::block_on(op.into_future()).map_err(|e| anyhow::anyhow!("flush: {e}"))?;

    let op = BitmapDecoder::CreateAsync(&stream).map_err(|e| anyhow::anyhow!("BitmapDecoder: {e}"))?;
    let decoder = futures::executor::block_on(op.into_future()).map_err(|e| anyhow::anyhow!("decode: {e}"))?;
    let op = decoder
        .GetSoftwareBitmapAsync()
        .map_err(|e| anyhow::anyhow!("GetSoftwareBitmapAsync: {e}"))?;
    let bitmap = futures::executor::block_on(op.into_future()).map_err(|e| anyhow::anyhow!("bitmap: {e}"))?;
    Ok(bitmap)
}
