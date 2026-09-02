//! NSPasteboard: change counter (`wait`) and file URL lists (`clip_files`).

use std::path::Path;
use std::sync::Mutex;

use objc2::ClassType;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_app_kit::{NSPasteboard, NSPasteboardWriting};
use objc2_foundation::{NSArray, NSAutoreleasePool, NSString, NSURL};

/// Serialize pasteboard access (text via arboard and files via NSPasteboard share it).
pub static CLIP_MTX: Mutex<()> = Mutex::new(());

/// Monotonic pasteboard change count (general pasteboard).
pub fn seq() -> anyhow::Result<u32> {
    let _guard = CLIP_MTX.lock().expect("clipboard mutex poisoned");
    unsafe {
        let _pool = NSAutoreleasePool::new();
        let pb = NSPasteboard::generalPasteboard();
        Ok(pb.changeCount() as u32)
    }
}

/// Read file paths currently on the general pasteboard.
pub fn get_files() -> anyhow::Result<Vec<String>> {
    let _guard = CLIP_MTX.lock().expect("clipboard mutex poisoned");
    unsafe {
        let _pool = NSAutoreleasePool::new();
        let pb = NSPasteboard::generalPasteboard();
        let classes = NSArray::from_slice(&[NSURL::class()]);
        let Some(objects) = pb.readObjectsForClasses_options(&classes, None) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for i in 0..objects.count() {
            let obj = objects.objectAtIndex(i);
            if let Some(url) = obj.downcast_ref::<NSURL>() {
                if let Some(path) = url.path() {
                    out.push(path.to_string());
                }
            }
        }
        Ok(out)
    }
}

/// Put absolute file paths on the general pasteboard.
pub fn set_files(files: &[String]) -> anyhow::Result<()> {
    if files.is_empty() {
        return Err(anyhow::anyhow!("empty file list"));
    }
    for f in files {
        if !Path::new(f).is_absolute() {
            return Err(anyhow::anyhow!("clipboard file path must be absolute: {f}"));
        }
    }
    let _guard = CLIP_MTX.lock().expect("clipboard mutex poisoned");
    unsafe {
        let _pool = NSAutoreleasePool::new();
        let pb = NSPasteboard::generalPasteboard();
        pb.clearContents();
        let urls: Vec<Retained<NSURL>> = files
            .iter()
            .map(|f| NSURL::fileURLWithPath(&NSString::from_str(f)))
            .collect();
        let objects: Vec<Retained<ProtocolObject<dyn NSPasteboardWriting>>> = urls
            .into_iter()
            .map(ProtocolObject::from_retained)
            .collect();
        let arr = NSArray::from_retained_slice(&objects);
        if !pb.writeObjects(&arr) {
            return Err(anyhow::anyhow!("NSPasteboard.writeObjects failed"));
        }
    }
    Ok(())
}
