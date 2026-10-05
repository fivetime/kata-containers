// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

// Included by share_virtio_fs_standalone.rs. Keep Child ownership in its worker;
// shutdown requests and waits for native child termination instead of signalling
// a saved numeric PID and returning before its waiter has finished.
#[derive(Debug)]
pub(crate) struct VirtiofsProcess {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    // Present only for a daemon spawned as the leader of its own process
    // group (Nova shares, ADR-045): the worker may then kill that group.
    group_kill: Option<tokio::sync::oneshot::Sender<()>>,
    group_leader: bool,
    worker: tokio::task::JoinHandle<Result<()>>,
    complete: bool,
    failure: Option<String>,
}

impl VirtiofsProcess {
    pub(crate) fn spawn(child: Child, ready: Sender<Result<()>>) -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            shutdown: Some(tx),
            group_kill: None,
            group_leader: false,
            worker: tokio::spawn(run_virtiofsd(child, ready, rx, None)),
            complete: false,
            failure: None,
        }
    }

    /// Like spawn, for a child spawned with `process_group(0)`. Only such a
    /// child may be stopped with `kill_group`.
    pub(crate) fn spawn_group_leader(child: Child, ready: Sender<Result<()>>) -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (kill_tx, kill_rx) = tokio::sync::oneshot::channel();
        Self {
            shutdown: Some(tx),
            group_kill: Some(kill_tx),
            group_leader: true,
            worker: tokio::spawn(run_virtiofsd(child, ready, rx, Some(kill_rx))),
            complete: false,
            failure: None,
        }
    }

    /// Stop a group leader whose VMM never connected or never closed its
    /// socket. The worker still owns the unreaped leader, so its process
    /// group id cannot have been reused; it signals the whole group (the
    /// sandbox child included) and then reaps the leader.
    pub(crate) async fn kill_group(&mut self) -> Result<()> {
        if !self.group_leader {
            return Err(anyhow!("virtiofsd is not a process group leader"));
        }
        if self.failure.is_none() && !self.complete {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(kill) = self.group_kill.take() {
                let _ = kill.send(());
            }
        }
        self.stop().await
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        if let Some(failure) = &self.failure {
            return Err(anyhow!("virtiofsd waiter failed: {}", failure));
        }
        if self.complete {
            return Ok(());
        }
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        // Borrow the handle so cancellation or timeout keeps the same worker
        // available for another cleanup attempt; never detach a replacement.
        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.worker)
            .await
            .context("wait for virtiofsd termination timed out")?;
        let result = joined
            .context("join virtiofsd waiter")
            .and_then(|result| result);
        match result {
            Ok(()) => {
                self.complete = true;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(format!("{:#}", error));
                Err(error)
            }
        }
    }
}

async fn run_virtiofsd(
    mut child: Child,
    ready: Sender<Result<()>>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    group_kill: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<()> {
    let stderr = child.stderr.take().context("virtiofsd stderr is missing")?;
    let mut lines = BufReader::new(stderr).lines();
    let mut read_logs = true;
    loop {
        tokio::select! {
            status = child.wait() => {
                status.context("wait for virtiofsd")?;
                let _ = ready.send(Err(anyhow!("virtiofsd exited before readiness"))).await;
                return Ok(());
            }
            _ = &mut shutdown => {
                // QEMU has already stopped and closed the vhost-user socket.
                // virtiofsd's parent waits for its sandbox child to finish.
                // Killing only that parent breaks the descendant wait chain.
                // The caller's bounded wait retains this worker on timeout.
                let Some(group_kill) = group_kill else {
                    child.wait().await.context("wait for virtiofsd after VMM stop")?;
                    return Ok(());
                };
                tokio::select! {
                    status = child.wait() => {
                        status.context("wait for virtiofsd after VMM stop")?;
                    }
                    _ = group_kill => {
                        // The leader is not reaped yet: its pid names this group.
                        let group = child.id().context("virtiofsd group leader id")?;
                        nix::sys::signal::killpg(
                            nix::unistd::Pid::from_raw(group as i32),
                            nix::sys::signal::Signal::SIGKILL,
                        )
                        .context("kill virtiofsd process group")?;
                        child.wait().await.context("wait for killed virtiofsd")?;
                    }
                }
                return Ok(());
            }
            line = lines.next_line(), if read_logs => {
                match line {
                    Ok(Some(line)) => {
                        if !line.trim_end().is_empty() {
                            info!(sl!(), "source: virtiofsd {}", line.trim_end());
                        }
                        if line.contains("Waiting for vhost-user socket connection") {
                            let _ = ready.send(Ok(())).await;
                        }
                    }
                    Ok(None) => read_logs = false,
                    Err(error) => {
                        read_logs = false;
                        let _ = ready.send(Err(anyhow!("virtiofsd stderr: {}", error))).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod native_virtiofs_wait_tests {
    use super::*;

    #[tokio::test]
    async fn stop_preserves_descendant_wait_chain_and_replays() {
        let marker = std::env::temp_dir().join(format!(
            "kata-virtiofs-wait-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let child = Command::new("/bin/sh")
            .args(["-c", "echo 'Waiting for vhost-user socket connection' >&2; (sleep 0.1; printf done > \"$KATA_WAIT_MARKER\") & wait"])
            .env("KATA_WAIT_MARKER", &marker)
            .stderr(Stdio::piped())
            .spawn().unwrap();
        let pid = child.id().unwrap();
        let (ready, mut receiver) = channel(2);
        let mut process = VirtiofsProcess::spawn(child, ready);
        tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        process.stop().await.unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "done");
        std::fs::remove_file(marker).unwrap();
        assert!(process.worker.is_finished());
        // waitpid reports ECHILD only after the original child was reaped.
        assert_eq!(
            nix::sys::wait::waitpid(
                nix::unistd::Pid::from_raw(pid as i32),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG)
            ),
            Err(nix::Error::ECHILD)
        );
        process.stop().await.unwrap();
    }
}
