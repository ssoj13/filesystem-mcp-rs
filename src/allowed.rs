use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;

/// Thread-safe store for allowed directories.
#[derive(Clone, Default)]
pub struct AllowedDirs {
    inner: Arc<RwLock<Vec<PathBuf>>>,
}

impl AllowedDirs {
    pub fn new(initial: Vec<PathBuf>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(normalize_many(initial))),
        }
    }

    pub async fn set(&self, dirs: Vec<PathBuf>) {
        let mut guard = self.inner.write().await;
        *guard = normalize_many(dirs);
    }

    pub async fn snapshot(&self) -> Vec<PathBuf> {
        self.inner.read().await.clone()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}

fn normalize_many(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    dirs.into_iter().map(normalize_dir).collect()
}

fn normalize_dir(dir: PathBuf) -> PathBuf {
    if dir.is_absolute() {
        canonicalize_lossy(&dir).unwrap_or(dir)
    } else {
        let joined = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(&dir);
        canonicalize_lossy(&joined).unwrap_or(joined)
    }
}

fn canonicalize_lossy(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}
