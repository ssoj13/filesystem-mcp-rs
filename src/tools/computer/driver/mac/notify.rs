//! Desktop notifications via `UNUserNotificationCenter` (UserNotifications.framework).

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSAutoreleasePool, NSError, NSString, NSUUID};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
    UNUserNotificationCenter,
};

/// Show a user notification. Blocking until the request is handed to the center.
pub fn notify(title: Option<&str>, msg: &str) -> anyhow::Result<()> {
    let title = title.unwrap_or("computer-mcp-rs");
    unsafe {
        let _pool = NSAutoreleasePool::new();
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let opts = UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound;
        let (auth_tx, auth_rx) = mpsc::channel();
        let auth_block = RcBlock::new(move |granted: Bool, err: *mut NSError| {
            let _ = auth_tx.send((granted.as_bool(), !err.is_null()));
        });
        center.requestAuthorizationWithOptions_completionHandler(opts, &auth_block);
        let (granted, auth_err) = auth_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| anyhow::anyhow!("notification authorization timed out"))?;
        if auth_err || !granted {
            return Err(anyhow::anyhow!(
                "notification permission denied — enable alerts for the host app in System Settings"
            ));
        }

        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(title));
        content.setBody(&NSString::from_str(msg));
        let id = NSUUID::UUID().UUIDString();
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &id,
            &content,
            None,
        );
        let (tx, rx) = mpsc::channel();
        let add_block = RcBlock::new(move |err: *mut NSError| {
            let _ = tx.send(!err.is_null());
        });
        center.addNotificationRequest_withCompletionHandler(&request, Some(&add_block));
        let failed = rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| anyhow::anyhow!("notification delivery timed out"))?;
        if failed {
            return Err(anyhow::anyhow!("UNUserNotificationCenter declined the request"));
        }
    }
    Ok(())
}
