// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use tokio::sync::Mutex;

/// Serialize cleanup callers and record completion only after actual success.
/// Errors and cancellation leave it incomplete; underlying steps must support
/// retries. This in-memory guard is not a durable resource-release witness.
#[derive(Default)]
pub(crate) struct CleanupOnce(Mutex<bool>);

impl CleanupOnce {
    pub(crate) async fn run<E>(
        &self,
        cleanup: impl Future<Output = Result<(), E>>,
    ) -> Result<(), E> {
        let mut complete = self.0.lock().await;
        if !*complete {
            cleanup.await?;
            *complete = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn failure_is_not_completion_and_success_is_not_repeated() {
        let guard = CleanupOnce::default();
        assert_eq!(
            guard.run(async { Err("injected EBUSY") }).await,
            Err("injected EBUSY")
        );
        guard.run(async { Ok::<_, &str>(()) }).await.unwrap();
        guard
            .run(async {
                panic!("completed cleanup must not be polled");
                #[allow(unreachable_code)]
                Ok::<_, &str>(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancellation_does_not_publish_success() {
        let guard = Arc::new(CleanupOnce::default());
        let started = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let guard = guard.clone();
            let started = started.clone();
            async move {
                guard
                    .run(async {
                        started.notify_one();
                        std::future::pending::<Result<(), ()>>().await
                    })
                    .await
            }
        });
        started.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        guard.run(async { Ok::<_, ()>(()) }).await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_callers_execute_only_one_successful_cleanup() {
        let guard = Arc::new(CleanupOnce::default());
        let count = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let guard = guard.clone();
            let count = count.clone();
            tasks.push(tokio::spawn(async move {
                guard
                    .run(async {
                        count.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok::<_, ()>(())
                    })
                    .await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
