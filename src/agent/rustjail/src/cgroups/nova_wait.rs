// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

//! Bounded asynchronous observation; the caller retains the original owner.
use anyhow::{bail, Result};
use std::time::Duration;
use tokio::time::{sleep_until, Instant};

pub(crate) async fn wait_empty<F>(budget: Duration, mut observe: F) -> Result<()>
where
    F: FnMut() -> Result<bool>,
{
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| anyhow::anyhow!("invalid cgroup empty observation deadline"))?;
    loop {
        if Instant::now() >= deadline {
            bail!("original cgroup empty observation timed out; retain owner");
        }
        let empty = observe()?;
        // An observation that overruns the deadline is not a timely witness.
        if Instant::now() >= deadline {
            bail!("original cgroup empty observation timed out; retain owner");
        }
        if empty {
            return Ok(());
        }
        sleep_until(std::cmp::min(
            deadline,
            Instant::now() + Duration::from_millis(10),
        ))
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    #[tokio::test]
    async fn observes_late_empty_without_resending_kill() {
        let reads = Cell::new(0);
        wait_empty(Duration::from_secs(1), || {
            reads.set(reads.get() + 1);
            Ok(reads.get() == 3)
        })
        .await
        .unwrap();
        assert_eq!(reads.get(), 3);
    }

    #[tokio::test]
    async fn error_does_not_become_empty_or_retry() {
        let reads = Cell::new(0);
        let error = wait_empty(Duration::from_secs(1), || {
            reads.set(reads.get() + 1);
            bail!("original read failed")
        })
        .await
        .unwrap_err();
        assert_eq!(reads.get(), 1);
        assert_eq!(error.to_string(), "original read failed");
    }

    #[tokio::test]
    async fn timeout_never_infers_empty() {
        let error = wait_empty(Duration::from_millis(2), || Ok(false))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(wait_empty(Duration::ZERO, || panic!("expired observation"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn canceled_wait_leaves_original_available_for_new_observation() {
        let reads = Cell::new(0);
        let observe = || {
            reads.set(reads.get() + 1);
            Ok(false)
        };
        let mut first = Box::pin(wait_empty(Duration::from_secs(1), observe));
        poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(first);
        assert_eq!(reads.get(), 1);
        wait_empty(Duration::from_secs(1), || {
            reads.set(reads.get() + 1);
            Ok(true)
        })
        .await
        .unwrap();
        assert_eq!(reads.get(), 2);
    }
}
