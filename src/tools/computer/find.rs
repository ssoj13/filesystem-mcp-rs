//! Template matching: find a small template image inside a screen capture.
//!
//! Completes the click hierarchy (PLAN2.md §2): UIA -> OCR -> template -> pixels.
//! Pure-Rust coarse-to-fine NCC on downscaled luma — no OpenCV, no GPU:
//!
//! 1. coarse pass on 1/4-scale luma, stride 1, max-abs-diff scoring
//! 2. full-res refinement within +-4 px around the best coarse candidates
//!
//! UI text/icons are pixel-identical at the same DPI/scale, so fixed-scale
//! matching is sufficient for the automation use case (multi-scale matching
//! is a documented non-goal for v1).

use image::RgbaImage;
use serde::Serialize;

/// One match location (screen-space rect of the template occurrence).
#[derive(Debug, Clone, Serialize)]
pub struct ImageMatch {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    /// 0.0..=1.0, 1.0 = pixel-perfect (fraction of channels within tolerance).
    pub score: f32,
}

/// Channel tolerance for "pixel matches" (out of 255).
const PIX_TOL: f32 = 28.0;
/// Score threshold for a candidate to be reported.
const SCORE_MIN: f32 = 0.85;

/// Luma plane for matching.
fn luma(img: &RgbaImage) -> Vec<u8> {
    img.pixels()
        .map(|p| {
            let [r, g, b, _] = p.0;
            ((r as u32 * 299 + g as u32 * 587 + b as u32 * 114) / 1000).min(255) as u8
        })
        .collect()
}

/// Downscale luma by an integer factor (box average).
fn downscale(plane: &[u8], w: u32, h: u32, factor: u32) -> (Vec<u8>, u32, u32) {
    let ow = w / factor;
    let oh = h / factor;
    let f2 = (factor * factor) as usize;
    let mut out = Vec::with_capacity((ow * oh) as usize);
    for oy in 0..oh {
        for ox in 0..ow {
            let mut acc = 0usize;
            for dy in 0..factor {
                for dx in 0..factor {
                    acc += plane[((oy * factor + dy) * w + ox * factor + dx) as usize] as usize;
                }
            }
            out.push((acc / f2) as u8);
        }
    }
    (out, ow, oh)
}

/// Match score of the template at (ox, oy) in the scene luma: fraction of
/// template pixels within [`PIX_TOL`] luma of the scene pixel.
fn score_at(
    scene: &[u8],
    sw: u32,
    tpl: &[u8],
    tw: u32,
    th: u32,
    ox: u32,
    oy: u32,
) -> f32 {
    let mut hit = 0usize;
    let mut total = 0usize;
    for ty in 0..th {
        let srow = (oy + ty) as usize * sw as usize + ox as usize;
        let trow = ty as usize * tw as usize;
        for tx in 0..tw {
            let d = (scene[srow + tx as usize] as i32 - tpl[trow + tx as usize] as i32).abs();
            if d as f32 <= PIX_TOL {
                hit += 1;
            }
            total += 1;
        }
    }
    hit as f32 / total as f32
}

/// Find `template` inside `scene`. Returns up to `max` matches with
/// score >= threshold (default 0.85), best first. Coordinates are
/// template-relative to the scene's top-left; add the capture rect origin
/// for screen coords (the tool layer does this).
pub fn find_template(
    scene: &RgbaImage,
    template: &RgbaImage,
    threshold: f32,
    max: usize,
) -> anyhow::Result<Vec<ImageMatch>> {
    let (sw, sh) = (scene.width(), scene.height());
    let (tw, th) = (template.width(), template.height());
    if tw == 0 || th == 0 {
        return Err(anyhow::anyhow!("empty template"));
    }
    if tw > sw || th > sh {
        return Err(anyhow::anyhow!(
            "template {tw}x{th} is larger than scene {sw}x{sh}"
        ));
    }

    // Coarse pass at 1/4 scale.
    const F: u32 = 4;
    let (scene_s, sws, shs) = downscale(&luma(scene), sw, sh, F);
    let (tpl_s, tws, ths) = downscale(&luma(template), tw, th, F);

    let mut coarse: Vec<(u32, u32, f32)> = Vec::new();
    let mut best = 0.0f32;
    for oy in 0..=(shs - ths) {
        for ox in 0..=(sws - tws) {
            let s = score_at(&scene_s, sws, &tpl_s, tws, ths, ox, oy);
            if s >= SCORE_MIN {
                coarse.push((ox * F, oy * F, s));
            }
            best = best.max(s);
        }
    }
    if coarse.is_empty() {
        return Err(anyhow::anyhow!(
            "no coarse candidate (best coarse score {best:.2} < {SCORE_MIN})"
        ));
    }
    coarse.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

    // Full-res refinement around each coarse candidate (+-F px window).
    let thr = threshold.clamp(0.5, 1.0);
    let mut out: Vec<ImageMatch> = Vec::new();
    'cand: for (cx, cy, _) in coarse.iter().take(8) {
        let x0 = cx.checked_sub(F).unwrap_or(0).min(sw - tw);
        let y0 = cy.checked_sub(F).unwrap_or(0).min(sh - th);
        for dy in 0..=(2 * F) {
            for dx in 0..=(2 * F) {
                let (ox, oy) = (x0 + dx, y0 + dy);
                if ox + tw > sw || oy + th > sh {
                    continue;
                }
                let s = score_at(&luma(scene), sw, &luma(template), tw, th, ox, oy);
                if s >= thr {
                    out.push(ImageMatch {
                        x: ox as i32,
                        y: oy as i32,
                        w: tw as i32,
                        h: th as i32,
                        score: s,
                    });
                    if out.len() >= max {
                        break 'cand;
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    out.dedup_by(|a, b| a.x == b.x && a.y == b.y);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic match: a crop of a high-frequency synthetic scene is
    /// found at its original offset with a near-perfect score. High-frequency
    /// on purpose: smooth gradients produce score plateaus wider than the
    /// tolerance (shifted windows score the same).
    #[test]
    fn finds_exact_crop() {
        let mut seed = 12345u32;
        let mut px = |x: u32, y: u32| {
            // xorshift-ish per-pixel noise, stable across runs.
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223 ^ x ^ (y << 8));
            image::Rgba([seed as u8, (seed >> 8) as u8, (seed >> 16) as u8, 255])
        };
        let scene = RgbaImage::from_fn(200, 120, |x, y| {
            if (40..104).contains(&x) && (30..70).contains(&y) {
                px(x * 7 + 1, y * 11 + 3)
            } else {
                image::Rgba([10, 10, 10, 255])
            }
        });
        let tpl = image::imageops::crop_imm(&scene, 48, 34, 40, 30).to_image();
        let hits = find_template(&scene, &tpl, 0.95, 5).expect("match expected");
        assert!(!hits.is_empty());
        assert_eq!(hits[0].x, 48);
        assert_eq!(hits[0].y, 34);
        assert!(hits[0].score > 0.99);
    }

    #[test]
    fn no_false_positive_on_flat_scene() {
        let scene = RgbaImage::from_pixel(200, 120, image::Rgba([9, 9, 9, 255]));
        let tpl = RgbaImage::from_fn(32, 24, |x, y| {
            if x % 2 == 0 || y % 3 == 0 {
                image::Rgba([240, 20, 20, 255])
            } else {
                image::Rgba([9, 9, 9, 255])
            }
        });
        let hits = find_template(&scene, &tpl, 0.95, 5).unwrap_or_default();
        assert!(hits.is_empty(), "flat scene must not match a busy template");
    }
}
