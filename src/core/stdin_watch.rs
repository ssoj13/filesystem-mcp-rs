//! Notices the end of the stdio transport's input, which is how a stdio client says it has left.
//!
//! rmcp ends its service loop on that EOF but neither cancels handlers still running nor bounds the
//! rest of the shutdown, and the runtime then waits for blocking work on the way out. A server held
//! up that way stays behind indefinitely: reproduced by closing stdin during a long `run_command`,
//! and first seen on a real session. Nothing downstream can be trusted to return, so `main` uses
//! this to start a deadline from outside all of it. Children still running keep running: one in
//! `detached` mode is meant to outlive the server, and one in flight finishes on its own or is the
//! caller's to stop, with nobody left to report it to.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

/// An `AsyncRead` that runs `action` once, the first time its inner reader reports end of file or
/// fails: either way no more requests will ever come.
pub struct OnEof<R> {
    inner: R,
    action: Option<Box<dyn FnOnce() + Send>>,
}

impl<R> OnEof<R> {
    pub fn new(inner: R, action: impl FnOnce() + Send + 'static) -> Self {
        Self {
            inner,
            action: Some(Box::new(action)),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for OnEof<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        // An empty buffer proves nothing: only a read with room in it that returned no bytes is EOF.
        let eof = matches!(polled, Poll::Ready(Ok(())))
            && buf.filled().len() == before
            && buf.remaining() > 0;
        let failed = matches!(polled, Poll::Ready(Err(_)));
        if (eof || failed)
            && let Some(action) = self.action.take()
        {
            action();
        }
        polled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;

    fn counted(data: &'static [u8]) -> (OnEof<&'static [u8]>, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let reader = OnEof::new(data, move || {
            seen.fetch_add(1, Ordering::Relaxed);
        });
        (reader, count)
    }

    #[tokio::test]
    async fn data_does_not_fire_it_and_the_end_fires_it_once() {
        let (mut reader, count) = counted(b"abc");
        let mut buf = [0u8; 3];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_read_with_no_room_is_not_the_end() {
        let (mut reader, count) = counted(b"abc");
        let mut empty = [0u8; 0];
        assert_eq!(reader.read(&mut empty).await.unwrap(), 0);
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }
}
