//! Stopping a token request from another thread.
//!
//! A request blocks a thread for as long as a person takes to touch the
//! key, and the thing that decides to give up (a closed connect card, a
//! closed pane) lives somewhere else entirely. Dropping the future that
//! awaits the blocking task does not stop the task, so the transport has
//! to be TOLD: the HID loop polls a flag between reads, and Windows Hello
//! is cancelled by id, which only the thread that made the call knows.
//! The token carries both.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

type Hook = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct Inner {
    cancelled: AtomicBool,
    /// What to run on cancel besides raising the flag, registered by a
    /// transport that cannot poll (Windows Hello). Taken exactly once.
    hook: Mutex<Option<Hook>>,
}

/// A cancellation flag shared between the caller and the transport.
///
/// Cloning shares it. [`CancelToken::cancel`] is idempotent and may be
/// called from any thread, before, during or after the request.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<Inner>);

impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stop the request this token was handed to.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        let hook = self.0.hook.lock().ok().and_then(|mut slot| slot.take());
        if let Some(hook) = hook {
            hook();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Register what a cancel must also do, for the duration of one call.
    ///
    /// The flag is re-checked under the lock, so a cancel that raced the
    /// registration still runs the hook (at once, here) instead of
    /// slipping between the check and the store. The returned guard
    /// clears the slot when the call ends, so a late cancel never reaches
    /// into an operation that is already over.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn on_cancel(&self, hook: Hook) -> HookGuard<'_> {
        let mut slot = match self.0.hook.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.is_cancelled() {
            drop(slot);
            hook();
        } else {
            *slot = Some(hook);
        }
        HookGuard(self)
    }
}

/// Clears the registered hook when the call it belonged to returns.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct HookGuard<'a>(&'a CancelToken);

impl Drop for HookGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.0.0.hook.lock() {
            slot.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_cancel_runs_the_registered_hook_once() {
        let token = CancelToken::new();
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let _guard = token.on_cancel(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_cancel_before_registration_still_reaches_the_hook() {
        // The call has not reached the point where it can be cancelled by
        // id yet; the cancel must not be lost in that window.
        let token = CancelToken::new();
        token.cancel();
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let _guard = token.on_cancel(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_cancel_after_the_call_ended_runs_nothing() {
        let token = CancelToken::new();
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        drop(token.on_cancel(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })));
        token.cancel();
        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }
}
