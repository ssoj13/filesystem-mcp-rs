//! Accessibility API — the macOS automation substrate.
//!
//! CGWindowList supplies stable `u32` window ids and coarse geometry; AX is
//! authoritative for focus, window chrome actions, values, and the UI element tree.
//! Every AX entry point calls [`require_trusted`] first so permission failures are
//! loud and actionable.

pub mod window;

use core_foundation::array::CFArray;
use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::string::CFString;
use core_graphics::geometry::{CGPoint, CGSize};
use std::ffi::c_void;
use std::ptr;

const K_AX_ERROR_SUCCESS: i32 = 0;
const K_AX_VALUE_CGPOINT_TYPE: u32 = 1;
const K_AX_VALUE_CGSIZE_TYPE: u32 = 2;

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXUIElementCreateApplication(pid: i32) -> *mut c_void;
    fn AXUIElementCopyAttributeValue(
        element: *mut c_void,
        attribute: *const c_void,
        value: *mut *const c_void,
    ) -> i32;
    fn AXUIElementSetAttributeValue(
        element: *mut c_void,
        attribute: *const c_void,
        value: *const c_void,
    ) -> i32;
    fn AXUIElementPerformAction(element: *mut c_void, action: *const c_void) -> i32;
    fn AXUIElementCopyActionNames(element: *mut c_void, names: *mut *const c_void) -> i32;
    fn AXValueCreate(value_type: u32, value: *const c_void) -> *const c_void;
    fn AXValueGetValue(value: *const c_void, value_type: u32, value_out: *mut c_void) -> bool;
    fn AXIsProcessTrusted() -> bool;
}

/// Whether this process has Accessibility permission.
pub fn is_trusted() -> bool {
    unsafe { AXIsProcessTrusted() }
}

/// Require Accessibility before any AX call.
pub fn require_trusted() -> anyhow::Result<()> {
    if is_trusted() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Accessibility permission required — enable the host app in \
             System Settings → Privacy & Security → Accessibility"
        ))
    }
}

fn attr(name: &str) -> CFString {
    CFString::new(name)
}

/// One AX element handle. Never crosses the MCP boundary.
pub(crate) struct Element(*mut c_void);

impl Element {
    pub(crate) fn application(pid: i32) -> anyhow::Result<Self> {
        require_trusted()?;
        let p = unsafe { AXUIElementCreateApplication(pid) };
        if p.is_null() {
            return Err(anyhow::anyhow!("AXUIElementCreateApplication({pid}) failed"));
        }
        Ok(Self(p))
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self(self.0)
    }

    fn from_raw(p: *mut c_void) -> Self {
        Self(p)
    }

    fn copy_attr(&self, name: &str) -> anyhow::Result<*const c_void> {
        let key = attr(name);
        let mut out: *const c_void = ptr::null();
        let err = unsafe {
            AXUIElementCopyAttributeValue(self.0, key.as_concrete_TypeRef() as *const c_void, &mut out)
        };
        if err != K_AX_ERROR_SUCCESS || out.is_null() {
            return Err(anyhow::anyhow!("AX copy {name} failed: {err}"));
        }
        Ok(out)
    }

    fn set_attr(&self, name: &str, value: *const c_void) -> anyhow::Result<()> {
        let key = attr(name);
        let err = unsafe {
            AXUIElementSetAttributeValue(self.0, key.as_concrete_TypeRef() as *const c_void, value)
        };
        if err != K_AX_ERROR_SUCCESS {
            return Err(anyhow::anyhow!("AX set {name} failed: {err}"));
        }
        Ok(())
    }

    pub(crate) fn set_bool(&self, name: &str, value: bool) -> anyhow::Result<()> {
        let b = CFBoolean::from(value);
        self.set_attr(name, b.as_concrete_TypeRef() as *const c_void)
    }

    pub(crate) fn set_string(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let s = CFString::new(value);
        self.set_attr(name, s.as_concrete_TypeRef() as *const c_void)
    }

    pub(crate) fn perform(&self, action: &str) -> anyhow::Result<()> {
        let key = attr(action);
        let err = unsafe { AXUIElementPerformAction(self.0, key.as_concrete_TypeRef() as *const c_void) };
        if err != K_AX_ERROR_SUCCESS {
            return Err(anyhow::anyhow!("AX perform {action} failed: {err}"));
        }
        Ok(())
    }

    pub(crate) fn child(&self, name: &str) -> anyhow::Result<Self> {
        let ptr = self.copy_attr(name)?;
        Ok(Self::from_raw(ptr as *mut c_void))
    }

    pub(crate) fn children(&self) -> anyhow::Result<Vec<Self>> {
        let ptr = self.copy_attr("AXChildren")?;
        let arr = unsafe { CFArray::<*const c_void>::wrap_under_get_rule(ptr as _) };
        let mut out = Vec::with_capacity(arr.len() as usize);
        for i in 0..arr.len() {
            let p = arr.get(i).ok_or_else(|| anyhow::anyhow!("AXChildren index {i}"))?;
            out.push(Self::from_raw(*p as *mut c_void));
        }
        Ok(out)
    }

    pub(crate) fn action_names(&self) -> Vec<String> {
        let mut names_ptr: *const c_void = ptr::null();
        let err = unsafe { AXUIElementCopyActionNames(self.0, &mut names_ptr) };
        if err != K_AX_ERROR_SUCCESS || names_ptr.is_null() {
            return Vec::new();
        }
        let arr = unsafe { CFArray::<*const c_void>::wrap_under_get_rule(names_ptr as _) };
        (0..arr.len())
            .filter_map(|i| arr.get(i))
            .filter_map(|p| cfstring(*p as *const c_void))
            .collect()
    }

    pub(crate) fn title(&self) -> String {
        self.copy_attr("AXTitle").ok().and_then(cfstring).unwrap_or_default()
    }

    pub(crate) fn identifier(&self) -> String {
        self.copy_attr("AXIdentifier").ok().and_then(cfstring).unwrap_or_default()
    }

    pub(crate) fn role(&self) -> String {
        self.copy_attr("AXRole").ok().and_then(cfstring).unwrap_or_default()
    }

    pub(crate) fn subrole(&self) -> String {
        self.copy_attr("AXSubrole").ok().and_then(cfstring).unwrap_or_default()
    }

    pub(crate) fn value_string(&self) -> Option<String> {
        self.copy_attr("AXValue").ok().and_then(cfstring)
    }

    pub(crate) fn enabled(&self) -> bool {
        self.copy_attr("AXEnabled")
            .ok()
            .map(|p| unsafe { CFBoolean::wrap_under_get_rule(p as *const _) }.into())
            .unwrap_or(false)
    }

    pub(crate) fn minimized(&self) -> bool {
        self.copy_attr("AXMinimized")
            .ok()
            .map(|p| unsafe { CFBoolean::wrap_under_get_rule(p as *const _) }.into())
            .unwrap_or(false)
    }

    pub(crate) fn bounds(&self) -> (i32, i32, i32, i32) {
        let (x, y) = self
            .copy_attr("AXPosition")
            .ok()
            .and_then(|p| read_point(p).ok())
            .unwrap_or((0.0, 0.0));
        let (w, h) = self
            .copy_attr("AXSize")
            .ok()
            .and_then(|s| read_size(s).ok())
            .unwrap_or((0.0, 0.0));
        (x as i32, y as i32, w as i32, h as i32)
    }

    pub(crate) fn set_position(&self, x: i32, y: i32) -> anyhow::Result<()> {
        let v = ax_point(x as f64, y as f64)?;
        self.set_attr("AXPosition", v)
    }

    pub(crate) fn set_size(&self, w: i32, h: i32) -> anyhow::Result<()> {
        let v = ax_size(w as f64, h as f64)?;
        self.set_attr("AXSize", v)
    }
}

fn ax_point(x: f64, y: f64) -> anyhow::Result<*const c_void> {
    let p = CGPoint::new(x, y);
    let v = unsafe { AXValueCreate(K_AX_VALUE_CGPOINT_TYPE, &p as *const CGPoint as *const c_void) };
    if v.is_null() {
        Err(anyhow::anyhow!("AXValueCreate(point) failed"))
    } else {
        Ok(v)
    }
}

fn ax_size(w: f64, h: f64) -> anyhow::Result<*const c_void> {
    let s = CGSize::new(w, h);
    let v = unsafe { AXValueCreate(K_AX_VALUE_CGSIZE_TYPE, &s as *const CGSize as *const c_void) };
    if v.is_null() {
        Err(anyhow::anyhow!("AXValueCreate(size) failed"))
    } else {
        Ok(v)
    }
}

fn read_point(value: *const c_void) -> anyhow::Result<(f64, f64)> {
    let mut p = CGPoint::new(0.0, 0.0);
    let ok = unsafe {
        AXValueGetValue(value, K_AX_VALUE_CGPOINT_TYPE, &mut p as *mut CGPoint as *mut c_void)
    };
    if !ok {
        return Err(anyhow::anyhow!("AXValueGetValue(point) failed"));
    }
    Ok((p.x, p.y))
}

fn read_size(value: *const c_void) -> anyhow::Result<(f64, f64)> {
    let mut s = CGSize::new(0.0, 0.0);
    let ok = unsafe {
        AXValueGetValue(value, K_AX_VALUE_CGSIZE_TYPE, &mut s as *mut CGSize as *mut c_void)
    };
    if !ok {
        return Err(anyhow::anyhow!("AXValueGetValue(size) failed"));
    }
    Ok((s.width, s.height))
}

pub(crate) fn cfstring(val: *const c_void) -> Option<String> {
    if val.is_null() {
        return None;
    }
    unsafe { Some(CFString::wrap_under_get_rule(val as *const _).to_string()) }
}

/// Match a CGWindowList [`WindowMeta`] to its AX window element.
pub(crate) fn resolve_window(meta: &super::win::WindowMeta) -> anyhow::Result<Element> {
    require_trusted()?;
    let app = Element::application(meta.pid)?;
    let wins_ptr = app.copy_attr("AXWindows")?;
    let wins = unsafe { CFArray::<*const c_void>::wrap_under_get_rule(wins_ptr as _) };
    let want_title = meta.title.to_lowercase();
    let mut best: Option<Element> = None;
    let mut best_score = i32::MAX;
    for i in 0..wins.len() {
        let wptr = wins.get(i).ok_or_else(|| anyhow::anyhow!("AXWindows index {i}"))?;
        let el = Element::from_raw(*wptr as *mut c_void);
        let (x, y, w, h) = el.bounds();
        let t = el.title();
        let title_ok = want_title.is_empty()
            || t.to_lowercase().contains(&want_title)
            || want_title.contains(&t.to_lowercase());
        if !title_ok {
            continue;
        }
        let score = (x - meta.x).abs() + (y - meta.y).abs() + (w - meta.w).abs() + (h - meta.h).abs();
        if score < best_score {
            best_score = score;
            best = Some(el);
        }
    }
    best.ok_or_else(|| anyhow::anyhow!("no AX window matched pid={} title={:?}", meta.pid, meta.title))
}
