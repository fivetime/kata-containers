// Copyright (c) 2022 Red Hat
//
// SPDX-License-Identifier: Apache-2.0
//

mod block_source;
mod cmdline_generator;
mod inner;
mod qmp;

use crate::device::pci_path::PciPath;
use crate::device::DeviceType;
use crate::hypervisor_persist::HypervisorState;
use crate::{Hypervisor, MemoryConfig};
use crate::{HypervisorConfig, VcpuThreadIds};
use inner::QemuInner;
use kata_types::capabilities::{Capabilities, CapabilityBits};
use persist::sandbox_persist::Persist;

use anyhow::{Context, Result};
use async_trait::async_trait;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, Mutex};

// Nova Kata (ADR-052): how long a destination waits for its source.
const MIGRATION_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// How often the transfer received is asked whether it ended, so that the
/// VM is resumed the moment it did.
const MIGRATION_RESUME_POLL: std::time::Duration = std::time::Duration::from_millis(100);
/// Consecutive queries of the transfer that fail before the watch is given
/// up: a QEMU that answers no more is gone.
const MIGRATION_RESUME_FAILURES: u32 = 50;
/// How long a connection has to say what it carries.
const MIGRATION_PREFACE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug)]
pub struct Qemu {
    inner: Arc<RwLock<QemuInner>>,
    exit_waiter: Mutex<(mpsc::Receiver<()>, i32)>,
}

impl Default for Qemu {
    fn default() -> Self {
        Self::new()
    }
}

impl Qemu {
    pub fn new() -> Self {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        Self {
            inner: Arc::new(RwLock::new(QemuInner::new(exit_notify))),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        }
    }

    pub async fn set_hypervisor_config(&self, config: HypervisorConfig) {
        let mut inner = self.inner.write().await;
        inner.set_hypervisor_config(config)
    }
}

#[async_trait]
impl Hypervisor for Qemu {
    async fn prepare_vm(
        &self,
        id: &str,
        netns: Option<String>,
        annotations: &HashMap<String, String>,
        selinux_label: Option<String>,
    ) -> Result<()> {
        // Nova Kata (ADR-052): a malformed migrate-in request fails the
        // start; the sandbox never boots a fresh VM in its place.
        let incoming = crate::migration::migrate_in(annotations)?;
        let mut inner = self.inner.write().await;
        inner.set_incoming(incoming);
        inner.prepare_vm(id, netns, selinux_label).await
    }

    async fn start_vm(&self, timeout: i32) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.start_vm(timeout).await
    }

    async fn stop_vm(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.stop_vm().await
    }

    async fn wait_vm(&self) -> Result<i32> {
        info!(sl!(), "Wait QEMU VM");

        let mut waiter = self.exit_waiter.lock().await;

        //wait until the qemu process exited.
        waiter.0.recv().await;

        let inner = self.inner.read().await;
        if let Ok(exit_code) = inner.wait_vm().await {
            waiter.1 = exit_code;
        }

        Ok(waiter.1)
    }

    async fn pause_vm(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.pause_vm()
    }

    async fn resume_vm(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.resume_vm()
    }

    async fn save_vm(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.save_vm().await
    }

    async fn add_device(&self, device: DeviceType) -> Result<DeviceType> {
        let mut inner = self.inner.write().await;
        inner.add_device(device).await
    }

    async fn remove_device(&self, device: DeviceType) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.remove_device(device).await
    }

    async fn update_device(&self, device: DeviceType) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.update_device(device).await
    }

    fn supports_network_removal(&self) -> bool {
        true
    }
    async fn remove_network_device(&self, device: crate::NetworkDevice) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.remove_network_device(device).await
    }
    fn supports_live_migration(&self) -> bool {
        true
    }
    async fn migration_send(
        &self,
        uri: &str,
        params: &crate::migration::MigrationParams,
    ) -> Result<()> {
        self.inner.write().await.migration_send(uri, params)
    }
    async fn migration_progress(&self) -> Result<crate::migration::MigrationProgress> {
        self.inner.write().await.migration_progress()
    }
    async fn migration_cancel(&self) -> Result<()> {
        self.inner.write().await.migration_cancel()
    }
    /// Bind the migration's listener now, so that a port in use fails the
    /// create, and export the devices the source copies; accept the
    /// source's connections in a task and give each to QEMU by what its
    /// preface says it carries: the VM (QEMU waits in `-incoming defer`),
    /// a block copy's NBD client (bridged to QEMU's NBD server on a unix
    /// socket of the sandbox), or the word that the copied blocks are
    /// written. A source that never connects leaves the VM waiting until
    /// the destination's rollback deletes it.
    async fn migration_receive(&self) -> Result<()> {
        let (listener, nbd_socket, tls) = {
            let mut inner = self.inner.write().await;
            let listener = inner.migration_listen()?;
            let tls = if inner.migration_incoming_tls()? {
                Some(crate::migration_tls::server_config(std::path::Path::new(
                    crate::migration_tls::TLS_DIR,
                ))?)
            } else {
                None
            };
            let nbd_socket = inner.migration_exports_start()?;
            (listener, nbd_socket, tls)
        };
        listener
            .set_nonblocking(true)
            .context("migration_failed: the listener")?;
        let listener =
            tokio::net::TcpListener::from_std(listener).context("migration_failed: the listener")?;
        let accepting =
            tokio::spawn(accept_migration(listener, self.inner.clone(), nbd_socket, tls));
        let inner = self.inner.clone();
        tokio::spawn(async move {
            // Nova Kata (ADR-052): the VM is resumed the moment QEMU reports
            // the transfer complete, as Cloud Hypervisor resumes its own.
            // With return-path set at both ends the source's QEMU is stopped
            // for good by then (postmigrate), so this VM is the one writer;
            // the finish that Nova's post brings later finds it running.
            // Waiting for that finish cost the guest the seconds between the
            // source's record of its release and the destination's reading
            // of it. A VM whose devices the source copies is complete only
            // once the source said their last blocks are written, which
            // migration_progress waits for.
            let mut failures = 0;
            loop {
                tokio::time::sleep(MIGRATION_RESUME_POLL).await;
                let progress = match inner.write().await.migration_progress() {
                    Ok(progress) => progress,
                    Err(error) => {
                        failures += 1;
                        if failures >= MIGRATION_RESUME_FAILURES {
                            warn!(sl!(), "the transfer received cannot be queried: {:?}", error);
                            accepting.abort();
                            return;
                        }
                        continue;
                    }
                };
                failures = 0;
                if progress.status == "completed" {
                    match inner.write().await.resume_vm() {
                        Ok(()) => info!(sl!(), "the VM received is resumed at the transfer's end"),
                        Err(error) => {
                            error!(sl!(), "the VM received is not resumed: {:?}", error)
                        }
                    }
                    accepting.abort();
                    return;
                }
                if progress.ended() {
                    info!(sl!(), "the transfer received ended {}", progress.status);
                    accepting.abort();
                    return;
                }
            }
        });
        Ok(())
    }
    async fn migration_networks(&self) -> Result<Vec<crate::migration::NetworkPin>> {
        self.inner.read().await.migration_networks()
    }
    fn supports_block_growth(&self) -> bool { true }
    async fn grow_block_device(&self, device: DeviceType, requested: u64) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.grow_block_device(device, requested).await
    }

    async fn get_agent_socket(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_agent_socket().await
    }

    async fn disconnect(&self) {
        let mut inner = self.inner.write().await;
        inner.disconnect().await
    }

    async fn hypervisor_config(&self) -> HypervisorConfig {
        let inner = self.inner.read().await;
        inner.hypervisor_config()
    }

    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        let mut inner = self.inner.write().await;
        inner.get_thread_ids().await
    }

    async fn get_vmm_master_tid(&self) -> Result<u32> {
        let inner = self.inner.read().await;
        inner.get_vmm_master_tid().await
    }

    async fn get_ns_path(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_ns_path().await
    }

    async fn cleanup(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.cleanup().await
    }

    async fn resize_vcpu(&self, old_vcpus: u32, new_vcpus: u32) -> Result<(u32, u32)> {
        let mut inner = self.inner.write().await;
        inner.resize_vcpu(old_vcpus, new_vcpus).await
    }

    async fn get_pids(&self) -> Result<Vec<u32>> {
        let inner = self.inner.read().await;
        inner.get_pids().await
    }

    async fn check(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.check().await
    }

    async fn get_jailer_root(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_jailer_root().await
    }

    async fn save_state(&self) -> Result<HypervisorState> {
        self.save().await
    }

    async fn capabilities(&self) -> Result<Capabilities> {
        let inner = self.inner.read().await;
        inner.capabilities().await
    }

    async fn get_hypervisor_metrics(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_hypervisor_metrics().await
    }

    async fn set_capabilities(&self, flag: CapabilityBits) {
        let mut inner = self.inner.write().await;
        inner.set_capabilities(flag)
    }

    async fn set_guest_memory_block_size(&self, size: u32) {
        let mut inner = self.inner.write().await;
        inner.set_guest_memory_block_size(size);
    }

    async fn guest_memory_block_size(&self) -> u32 {
        let inner = self.inner.read().await;
        inner.guest_memory_block_size()
    }

    async fn resize_memory(&self, new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        let mut inner = self.inner.write().await;
        inner.resize_memory(new_mem_mb)
    }

    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        Err(anyhow::anyhow!("Not yet supported"))
    }

    async fn resolve_vfio_device_pci_path(&self, hostdev_id: &str) -> Result<PciPath> {
        self.inner
            .write()
            .await
            .resolve_vfio_device_pci_path(hostdev_id)
    }
}

/// Nova Kata (ADR-052): the connections of the migration this VM receives.
/// The first must come within MIGRATION_ACCEPT_TIMEOUT; the loop ends when
/// the transfer ends (the watcher aborts it). The preface of a connection
/// is read a byte at a time: what follows it belongs to QEMU.
async fn accept_migration(
    listener: tokio::net::TcpListener,
    inner: Arc<RwLock<QemuInner>>,
    nbd_socket: Option<String>,
    tls: Option<Arc<rustls::ServerConfig>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // The first connection of any kind must come in time; the VM's own
    // follows a block copy, which may take long.
    let first_by = tokio::time::Instant::now() + MIGRATION_ACCEPT_TIMEOUT;
    let mut connected = false;
    loop {
        let accepted = if connected {
            listener.accept().await
        } else {
            match tokio::time::timeout_at(first_by, listener.accept()).await {
                Ok(accepted) => accepted,
                Err(_) => {
                    warn!(sl!(), "no migration connected within {:?}", MIGRATION_ACCEPT_TIMEOUT);
                    return;
                }
            }
        };
        let (mut stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                error!(sl!(), "the migration's connection was not accepted: {:?}", error);
                return;
            }
        };
        connected = true;
        let preface = async {
            let mut line = Vec::with_capacity(crate::migration::PREFACE_MAX);
            loop {
                let byte = stream.read_u8().await?;
                line.push(byte);
                if byte == b'\n' || line.len() >= crate::migration::PREFACE_MAX {
                    break;
                }
            }
            Ok::<Vec<u8>, std::io::Error>(line)
        };
        let kind = match tokio::time::timeout(MIGRATION_PREFACE_TIMEOUT, preface).await {
            Ok(Ok(line)) => match crate::migration::parse_preface(&line) {
                Ok(kind) => kind,
                Err(error) => {
                    warn!(sl!(), "a connection from {} is refused: {:?}", peer, error);
                    continue;
                }
            },
            Ok(Err(error)) => {
                warn!(sl!(), "a connection from {} ended before its preface: {:?}", peer, error);
                continue;
            }
            Err(_) => {
                warn!(sl!(), "a connection from {} said nothing; it is dropped", peer);
                continue;
            }
        };
        match kind {
            crate::migration::PREFACE_RAM => {
                info!(sl!(), "the migration connected from {}", peer);
                let stream = match stream.into_std() {
                    Ok(stream) => stream,
                    Err(error) => {
                        error!(sl!(), "the migration's connection: {:?}", error);
                        return;
                    }
                };
                if let Err(error) = inner.write().await.migration_accepted(&stream) {
                    error!(sl!(), "QEMU did not take the migration's connection: {:?}", error);
                    return;
                }
            }
            crate::migration::PREFACE_NBD => {
                let Some(socket) = nbd_socket.clone() else {
                    warn!(sl!(), "a block copy from {} is refused: nothing is exported", peer);
                    continue;
                };
                info!(sl!(), "a block copy connected from {}", peer);
                tokio::spawn(async move {
                    match tokio::net::UnixStream::connect(&socket).await {
                        Ok(mut unix) => {
                            if let Err(error) =
                                tokio::io::copy_bidirectional(&mut stream, &mut unix).await
                            {
                                debug!(sl!(), "the block copy's connection ended: {:?}", error);
                            }
                        }
                        Err(error) => {
                            error!(sl!(), "QEMU's NBD server at {}: {:?}", socket, error)
                        }
                    }
                });
            }
            _ => {
                // The copied blocks are all written: the VM is whole here.
                // With TLS only a source of the CA says so; anything else
                // is dropped and the VM waits.
                if let Some(config) = tls.clone() {
                    let acceptor = tokio_rustls::TlsAcceptor::from(config);
                    let mut secure = match tokio::time::timeout(
                        MIGRATION_PREFACE_TIMEOUT,
                        acceptor.accept(stream),
                    )
                    .await
                    {
                        Ok(Ok(secure)) => secure,
                        Ok(Err(error)) => {
                            warn!(sl!(), "the word from {} is refused: {:?}", peer, error);
                            continue;
                        }
                        Err(_) => {
                            warn!(sl!(), "the word from {} came with no TLS in time", peer);
                            continue;
                        }
                    };
                    inner.write().await.mark_disk_synced();
                    if let Err(error) = secure.write_all(crate::migration::PREFACE_ACK).await {
                        warn!(sl!(), "acknowledge the copy's end to {}: {:?}", peer, error);
                    }
                    let _ = secure.shutdown().await;
                } else {
                    inner.write().await.mark_disk_synced();
                    if let Err(error) = stream.write_all(crate::migration::PREFACE_ACK).await {
                        warn!(sl!(), "acknowledge the copy's end to {}: {:?}", peer, error);
                    }
                    let _ = stream.shutdown().await;
                }
                info!(sl!(), "the source says the copied blocks are written");
            }
        }
    }
}

#[async_trait]
impl Persist for Qemu {
    type State = HypervisorState;
    type ConstructorArgs = ();

    /// Save a state of the component.
    async fn save(&self) -> Result<Self::State> {
        let inner = self.inner.read().await;
        inner.save().await.context("save qemu hypervisor state")
    }

    /// Restore a component from a specified state.
    async fn restore(
        _hypervisor_args: Self::ConstructorArgs,
        hypervisor_state: Self::State,
    ) -> Result<Self> {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        let inner = QemuInner::restore(exit_notify, hypervisor_state).await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        })
    }
}
