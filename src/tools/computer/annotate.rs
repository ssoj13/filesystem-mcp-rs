//! Annotate a screenshot: boxes, markers and text labels drawn over a PNG.
//!
//! Closes the perception loop. `ui`, `find_image` and `ocr` all return rects in
//! screen space, but nothing in their output tells the agent (or the operator)
//! whether those rects actually sit on the intended widgets — a wrong
//! coordinate only shows up later as a misplaced click. Painting the rects back
//! onto the pixels makes the mistake visible before it is acted on.
//!
//! Text uses `font8x8`'s public-domain 8x8 bitmap tables (const arrays: no font
//! file, no FFI). Encoding, verified against the crate source: one byte per
//! row, top row first, bit `1 << col` set = lit pixel, LSB = leftmost column.

use image::{Rgba, RgbaImage};
use serde::Deserialize;

/// Crosshair half-length in px (arms reach this far from the point).
const ARM: i32 = 10;
/// Gap left empty around the crosshair center so the pixel under it stays visible.
const GAP: i32 = 3;
/// Rect outline thickness in px.
const THICK: u32 = 2;

/// Distinguishable defaults, cycled by shape index when no color is given.
const PALETTE: [(u8, u8, u8); 8] = [
    (255, 48, 48),   // red
    (48, 255, 80),   // lime
    (72, 160, 255),  // blue
    (255, 208, 48),  // amber
    (255, 72, 255),  // magenta
    (48, 255, 255),  // cyan
    (255, 136, 32),  // orange
    (255, 255, 255), // white
];

/// One annotation: a rect when both `w` and `h` are given, a crosshair marker
/// at `(x, y)` otherwise.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct Shape {
    pub x: i32,
    pub y: i32,
    pub w: Option<u32>,
    pub h: Option<u32>,
    /// Text drawn next to the shape. Printable ASCII; anything else is blank.
    pub label: Option<String>,
    /// Color name (red|lime|green|blue|amber|yellow|magenta|cyan|orange|white|
    /// black) or `#rrggbb`. Unknown names are an error, never a silent default.
    pub color: Option<String>,
}

/// Draw every shape, returning the indices of shapes that fell entirely
/// outside the image (reported, not silently dropped).
///
/// `origin` is the image's top-left in the shapes' coordinate space: pass the
/// capture rect origin when the shapes are screen coords and the image is a
/// crop, `(0, 0)` when both are already image-local.
pub fn draw(
    img: &mut RgbaImage,
    origin: (i32, i32),
    shapes: &[Shape],
    scale: u32,
) -> anyhow::Result<Vec<usize>> {
    let scale = scale.clamp(1, 8);
    let mut outside = Vec::new();
    for (i, s) in shapes.iter().enumerate() {
        let (r, g, b) = match &s.color {
            Some(name) => parse_color(name)?,
            None => PALETTE[i % PALETTE.len()],
        };
        let c = Rgba([r, g, b, 255]);
        let x = s.x - origin.0;
        let y = s.y - origin.1;
        let boxed = matches!((s.w, s.h), (Some(w), Some(h)) if w > 0 && h > 0);
        // Bounding box of everything this shape paints (crosshair arms included).
        let (bx, by, bw, bh) = if boxed {
            (x, y, s.w.unwrap_or(0) as i32, s.h.unwrap_or(0) as i32)
        } else {
            (x - ARM, y - ARM, ARM * 2, ARM * 2)
        };
        if bx + bw < 0 || by + bh < 0 || bx >= img.width() as i32 || by >= img.height() as i32 {
            outside.push(i);
            continue;
        }
        if boxed {
            rect_outline(img, x, y, s.w.unwrap_or(0), s.h.unwrap_or(0), THICK, c);
        } else {
            marker(img, x, y, c);
        }
        if let Some(label) = &s.label {
            let th = 8 * scale as i32;
            // Above the shape when it fits, otherwise just below it.
            let ty = if by - th - 3 >= 0 { by - th - 3 } else { by + bh + 3 };
            text(img, bx, ty, label, scale, c);
        }
    }
    Ok(outside)
}

/// Default output path next to the other capture artifacts.
pub fn out_path() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("computer-mcp-rs");
    dir.join(format!("annot-{}-{}.png", super::capture::now_ms(), std::process::id()))
}

/// Color name or `#rrggbb` -> RGB. Unknown input is an error: a silently
/// mis-colored annotation would be worse than a loud refusal.
fn parse_color(name: &str) -> anyhow::Result<(u8, u8, u8)> {
    let n = name.trim().to_ascii_lowercase();
    if let Some(hex) = n.strip_prefix('#') {
        if hex.len() != 6 {
            return Err(anyhow::anyhow!("color {name:?}: expected #rrggbb"));
        }
        let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16);
        let (r, g, b) = (byte(0), byte(2), byte(4));
        return match (r, g, b) {
            (Ok(r), Ok(g), Ok(b)) => Ok((r, g, b)),
            _ => Err(anyhow::anyhow!("color {name:?}: not hex")),
        };
    }
    match n.as_str() {
        "red" => Ok(PALETTE[0]),
        "lime" | "green" => Ok(PALETTE[1]),
        "blue" => Ok(PALETTE[2]),
        "amber" | "yellow" => Ok(PALETTE[3]),
        "magenta" => Ok(PALETTE[4]),
        "cyan" => Ok(PALETTE[5]),
        "orange" => Ok(PALETTE[6]),
        "white" => Ok((255, 255, 255)),
        "black" => Ok((0, 0, 0)),
        _ => Err(anyhow::anyhow!(
            "unknown color {name:?} (red|lime|blue|amber|magenta|cyan|orange|white|black|#rrggbb)"
        )),
    }
}

/// Bounds-checked pixel write: shapes may hang off the image, that is normal.
fn px(img: &mut RgbaImage, x: i32, y: i32, c: Rgba<u8>) {
    if x >= 0 && y >= 0 && (x as u32) < img.width() && (y as u32) < img.height() {
        img.put_pixel(x as u32, y as u32, c);
    }
}

fn fill(img: &mut RgbaImage, x: i32, y: i32, w: i32, h: i32, c: Rgba<u8>) {
    for dy in 0..h {
        for dx in 0..w {
            px(img, x + dx, y + dy, c);
        }
    }
}

fn rect_outline(img: &mut RgbaImage, x: i32, y: i32, w: u32, h: u32, t: u32, c: Rgba<u8>) {
    let (w, h, t) = (w as i32, h as i32, t as i32);
    fill(img, x, y, w, t, c); // top
    fill(img, x, y + h - t, w, t, c); // bottom
    fill(img, x, y, t, h, c); // left
    fill(img, x + w - t, y, t, h, c); // right
}

/// Crosshair with an empty center, so the annotated pixel itself stays visible.
fn marker(img: &mut RgbaImage, x: i32, y: i32, c: Rgba<u8>) {
    for d in GAP..=ARM {
        px(img, x + d, y, c);
        px(img, x - d, y, c);
        px(img, x, y + d, c);
        px(img, x, y - d, c);
    }
}

/// Draw `s` at `(x, y)` in `fg` over a dark backdrop (labels land on arbitrary
/// screenshot content, so they need their own contrast).
fn text(img: &mut RgbaImage, x: i32, y: i32, s: &str, scale: u32, fg: Rgba<u8>) {
    let sc = scale as i32;
    let cells: Vec<usize> = s.chars().map(|ch| if (ch as u32) < 128 { ch as usize } else { 0x7f }).collect();
    let bg = Rgba([16, 16, 16, 255]);
    fill(img, x - 1, y - 1, cells.len() as i32 * 8 * sc + 2, 8 * sc + 2, bg);
    for (i, &cell) in cells.iter().enumerate() {
        let glyph = font8x8::legacy::BASIC_LEGACY[cell];
        for (row, bits) in glyph.iter().enumerate() {
            for col in 0..8 {
                if bits & (1 << col) == 0 {
                    continue;
                }
                fill(
                    img,
                    x + (i as i32 * 8 + col) * sc,
                    y + row as i32 * sc,
                    sc,
                    sc,
                    fg,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canvas() -> RgbaImage {
        RgbaImage::from_pixel(200, 100, Rgba([0, 0, 0, 255]))
    }

    fn lit(img: &RgbaImage) -> usize {
        img.pixels().filter(|p| p.0[..3] != [0, 0, 0]).count()
    }

    #[test]
    fn rect_paints_its_border_not_its_interior() {
        let mut img = canvas();
        let shapes = [Shape { x: 20, y: 20, w: Some(40), h: Some(30), label: None, color: Some("red".into()) }];
        assert!(draw(&mut img, (0, 0), &shapes, 2).unwrap().is_empty());
        assert_eq!(img.get_pixel(20, 20).0, [255, 48, 48, 255], "corner");
        assert_eq!(img.get_pixel(40, 35).0, [0, 0, 0, 255], "interior stays untouched");
    }

    #[test]
    fn origin_shifts_screen_coords_into_image_space() {
        let mut img = canvas();
        // Screen rect at (1020,520) inside a crop whose origin is (1000,500).
        let shapes = [Shape { x: 1020, y: 520, w: Some(10), h: Some(10), label: None, color: Some("lime".into()) }];
        draw(&mut img, (1000, 500), &shapes, 1).unwrap();
        assert_eq!(img.get_pixel(20, 20).0, [48, 255, 80, 255]);
    }

    #[test]
    fn shapes_outside_the_image_are_reported_not_dropped_silently() {
        let mut img = canvas();
        let shapes = [
            Shape { x: 10, y: 10, w: Some(5), h: Some(5), label: None, color: None },
            Shape { x: 900, y: 900, w: Some(5), h: Some(5), label: None, color: None },
        ];
        assert_eq!(draw(&mut img, (0, 0), &shapes, 1).unwrap(), vec![1]);
    }

    #[test]
    fn marker_leaves_the_target_pixel_readable() {
        let mut img = canvas();
        let shapes = [Shape { x: 100, y: 50, w: None, h: None, label: None, color: Some("cyan".into()) }];
        draw(&mut img, (0, 0), &shapes, 1).unwrap();
        assert_eq!(img.get_pixel(100, 50).0, [0, 0, 0, 255], "center left clear");
        assert_eq!(img.get_pixel(100 + ARM as u32, 50).0, [48, 255, 255, 255], "arm tip drawn");
    }

    #[test]
    fn label_renders_glyph_pixels() {
        let mut plain = canvas();
        let mut labeled = canvas();
        let bare = [Shape { x: 40, y: 40, w: Some(20), h: Some(20), label: None, color: Some("white".into()) }];
        let named = [Shape { x: 40, y: 40, w: Some(20), h: Some(20), label: Some("OK 7".into()), color: Some("white".into()) }];
        draw(&mut plain, (0, 0), &bare, 2).unwrap();
        draw(&mut labeled, (0, 0), &named, 2).unwrap();
        assert!(lit(&labeled) > lit(&plain), "label must add lit pixels");
    }

    #[test]
    fn unknown_color_is_an_error() {
        let mut img = canvas();
        let shapes = [Shape { x: 1, y: 1, w: Some(2), h: Some(2), label: None, color: Some("burgundy".into()) }];
        assert!(draw(&mut img, (0, 0), &shapes, 1).is_err());
    }

    #[test]
    fn hex_color_parses() {
        assert_eq!(parse_color("#0a141e").unwrap(), (10, 20, 30));
        assert!(parse_color("#12345").is_err());
        assert!(parse_color("#gggggg").is_err());
    }
}
