//! Screen geometry and pixel sampling (CGDisplay).

use core_graphics::display::{CGDisplayBounds, CGGetActiveDisplayList, CGMainDisplayID, CGWindowListCreateImage};
use core_graphics::geometry::{CGRect, CGPoint, CGSize};
use core_graphics::window::{
    kCGNullWindowID, kCGWindowImageDefault, kCGWindowListOptionOnScreenOnly,
};
use foreign_types::ForeignType;

/// Union of all active display bounds in global screen coordinates.
pub fn virtual_screen() -> anyhow::Result<(i32, i32, i32, i32)> {
    let mut ids = [0u32; 32];
    let mut count = 0u32;
    let err = unsafe { CGGetActiveDisplayList(ids.len() as u32, ids.as_mut_ptr(), &mut count) };
    if err != 0 {
        return Err(anyhow::anyhow!("CGGetActiveDisplayList failed: {err}"));
    }
    let mut min_x = i32::MAX;
    let mut min_y = i32::MAX;
    let mut max_x = i32::MIN;
    let mut max_y = i32::MIN;
    for &id in &ids[..count as usize] {
        let b = unsafe { CGDisplayBounds(id) };
        min_x = min_x.min(b.origin.x as i32);
        min_y = min_y.min(b.origin.y as i32);
        max_x = max_x.max((b.origin.x + b.size.width) as i32);
        max_y = max_y.max((b.origin.y + b.size.height) as i32);
    }
    if count == 0 {
        let b = unsafe { CGDisplayBounds(CGMainDisplayID()) };
        return Ok((
            b.origin.x as i32,
            b.origin.y as i32,
            b.size.width as i32,
            b.size.height as i32,
        ));
    }
    Ok((min_x, min_y, max_x - min_x, max_y - min_y))
}

/// Sample one screen pixel via a 1×1 CGWindowListCreateImage capture.
pub fn color_at(x: i32, y: i32) -> anyhow::Result<(u8, u8, u8)> {
    let rect = CGRect::new(&CGPoint::new(x as f64, y as f64), &CGSize::new(1.0, 1.0));
    let img = unsafe {
        CGWindowListCreateImage(
            rect,
            kCGWindowListOptionOnScreenOnly,
            kCGNullWindowID,
            kCGWindowImageDefault,
        )
    };
    if img.is_null() {
        return Err(anyhow::anyhow!("({x},{y}) is outside the visible screen"));
    }
    let cg = unsafe { core_graphics::image::CGImage::from_ptr(img) };
    let data = cg.data();
    let bytes = data.bytes();
    if bytes.len() < 4 {
        return Err(anyhow::anyhow!("empty capture at ({x},{y})"));
    }
    Ok((bytes[2], bytes[1], bytes[0]))
}
