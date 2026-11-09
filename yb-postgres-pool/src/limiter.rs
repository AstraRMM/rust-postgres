//! Process-wide physical connection limit.

use crate::error::{ErrorKind, PoolError};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A physical-connection budget shared by every pool given a clone.
///
/// Each physical connection holds one permit from just before it dials
/// until its connection task ends (the socket is closed), including while
/// it is idle, borrowed, being cleaned up or draining after retirement.
/// [`PoolSet`](crate::PoolSet) creates one for all of its pools; standalone
/// pools may share one explicitly.
#[derive(Clone)]
pub struct ConnectionLimiter {
    semaphore: Arc<Semaphore>,
    max: u32,
}

impl fmt::Debug for ConnectionLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionLimiter")
            .field("max", &self.max)
            .field("in_use", &self.in_use())
            .finish()
    }
}

impl ConnectionLimiter {
    /// A limiter allowing `max` physical connections.
    pub fn new(max: u32) -> ConnectionLimiter {
        ConnectionLimiter {
            semaphore: Arc::new(Semaphore::new(max as usize)),
            max,
        }
    }

    /// The limit.
    pub fn max(&self) -> u32 {
        self.max
    }

    /// Physical connections currently holding a permit.
    pub fn in_use(&self) -> u32 {
        self.max
            .saturating_sub(self.semaphore.available_permits() as u32)
    }

    pub(crate) fn try_acquire(&self) -> Result<OwnedSemaphorePermit, PoolError> {
        self.semaphore.clone().try_acquire_owned().map_err(|_| {
            PoolError::new(
                ErrorKind::ProcessLimit,
                format!(
                    "all {} process-wide connection permits are in use",
                    self.max
                ),
            )
        })
    }

    pub(crate) async fn acquire(
        &self,
        budget: Duration,
    ) -> Result<OwnedSemaphorePermit, PoolError> {
        if let Ok(permit) = self.semaphore.clone().try_acquire_owned() {
            return Ok(permit);
        }
        match tokio::time::timeout(budget, self.semaphore.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            _ => Err(PoolError::new(
                ErrorKind::ProcessLimit,
                format!(
                    "all {} process-wide connection permits stayed in use for {:?}",
                    self.max, budget
                ),
            )),
        }
    }
}
