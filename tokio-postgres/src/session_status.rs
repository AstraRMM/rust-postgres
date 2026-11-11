//! Protocol-level session status shared between a [`Client`](crate::Client)
//! and its [`Connection`](crate::Connection).
//!
//! The connection task records the transaction status byte of every
//! `ReadyForQuery` it processes and counts requests whose `ReadyForQuery` has
//! not arrived yet. Pools use this to decide, without a round trip, whether a
//! returned client is idle outside a transaction or needs cleanup first.

use futures_util::task::AtomicWaker;
use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::task::Poll;

/// The server's transaction status, as last reported by `ReadyForQuery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransactionStatus {
    /// Not in a transaction block (`I`).
    Idle,
    /// In a transaction block (`T`).
    InTransaction,
    /// In a failed transaction block; queries are rejected until it ends (`E`).
    Failed,
    /// No status has been recorded, or the server sent an unknown byte.
    Unknown,
}

impl TransactionStatus {
    fn from_byte(byte: u8) -> TransactionStatus {
        match byte {
            b'I' => TransactionStatus::Idle,
            b'T' => TransactionStatus::InTransaction,
            b'E' => TransactionStatus::Failed,
            _ => TransactionStatus::Unknown,
        }
    }
}

pub(crate) struct SessionShared {
    /// Requests handed to the connection whose `ReadyForQuery` has not been
    /// processed yet.
    pending: AtomicU64,
    caller_pending: AtomicU64,
    /// Status byte of the most recent `ReadyForQuery` (the startup sequence
    /// ends with `I`).
    status: AtomicU8,
    /// `ParameterStatus` messages received after startup.
    parameter_changes: AtomicU64,
    /// Set once the connection future has been dropped.
    closed: AtomicBool,
    waker: AtomicWaker,
}

impl SessionShared {
    pub(crate) fn new() -> SessionShared {
        SessionShared {
            pending: AtomicU64::new(0),
            caller_pending: AtomicU64::new(0),
            status: AtomicU8::new(b'I'),
            parameter_changes: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    pub(crate) fn request_sent(&self, detached: bool) {
        if !detached {
            self.caller_pending.fetch_add(1, Ordering::SeqCst);
        }
        self.pending.fetch_add(1, Ordering::SeqCst);
    }

    /// Publishes the status before the counts drop, so a reader that sees
    /// no caller request pending reads a status at least that recent.
    pub(crate) fn request_complete(&self, ready_status: Option<u8>, detached: bool) {
        if let Some(byte) = ready_status {
            self.status.store(byte, Ordering::SeqCst);
        }
        // Saturating: a response without a matching counted request would be
        // a protocol error the connection reports anyway.
        if !detached {
            decrement(&self.caller_pending);
        }
        decrement(&self.pending);
        self.waker.wake();
    }

    pub(crate) fn parameter_changed(&self) {
        self.parameter_changes.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn connection_dropped(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.waker.wake();
    }

    pub(crate) fn pending(&self) -> u64 {
        self.pending.load(Ordering::SeqCst)
    }

    pub(crate) fn caller_pending(&self) -> u64 {
        self.caller_pending.load(Ordering::SeqCst)
    }

    pub(crate) fn transaction_status(&self) -> TransactionStatus {
        TransactionStatus::from_byte(self.status.load(Ordering::SeqCst))
    }

    pub(crate) fn parameter_changes(&self) -> u64 {
        self.parameter_changes.load(Ordering::SeqCst)
    }

    fn settled(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.pending() == 0
    }

    /// Resolves once no request is pending or the connection has gone away.
    /// Only one task may wait at a time (later registrations replace earlier
    /// wakers).
    pub(crate) async fn settle(&self) {
        poll_fn(|cx| {
            if self.settled() {
                return Poll::Ready(());
            }
            self.waker.register(cx.waker());
            if self.settled() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

fn decrement(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
}

#[cfg(test)]
mod tests {
    use super::{SessionShared, TransactionStatus};

    #[test]
    fn detached_requests_are_pending_but_not_caller_pending() {
        let session = SessionShared::new();
        session.request_sent(true);
        session.request_sent(true);
        assert_eq!(session.pending(), 2);
        assert_eq!(session.caller_pending(), 0);
        session.request_complete(Some(b'I'), true);
        assert_eq!((session.pending(), session.caller_pending()), (1, 0));
        session.request_complete(Some(b'I'), true);
        assert_eq!((session.pending(), session.caller_pending()), (0, 0));
        assert!(session.settled());
    }

    #[test]
    fn caller_requests_count_until_their_ready_for_query() {
        let session = SessionShared::new();
        session.request_sent(false);
        session.request_sent(true);
        assert_eq!((session.pending(), session.caller_pending()), (2, 1));
        session.request_complete(Some(b'T'), false);
        assert_eq!((session.pending(), session.caller_pending()), (1, 0));
        assert_eq!(
            session.transaction_status(),
            TransactionStatus::InTransaction
        );
        session.request_complete(Some(b'T'), true);
        assert_eq!((session.pending(), session.caller_pending()), (0, 0));

        session.request_sent(true);
        session.request_sent(false);
        session.request_complete(Some(b'I'), true);
        assert_eq!((session.pending(), session.caller_pending()), (1, 1));
        assert!(!session.settled());
        session.request_complete(Some(b'E'), false);
        assert_eq!((session.pending(), session.caller_pending()), (0, 0));
        assert_eq!(session.transaction_status(), TransactionStatus::Failed);
    }

    #[test]
    fn unsent_and_unmatched_completions_saturate() {
        let session = SessionShared::new();
        session.request_sent(false);
        session.request_complete(None, false);
        assert_eq!(session.transaction_status(), TransactionStatus::Idle);
        session.request_complete(None, false);
        session.request_complete(None, true);
        assert_eq!((session.pending(), session.caller_pending()), (0, 0));
    }
}
