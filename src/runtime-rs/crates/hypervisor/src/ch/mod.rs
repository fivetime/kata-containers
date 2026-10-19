// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use super::HypervisorState;
use crate::device::DeviceType;
use crate::{Hypervisor, MemoryConfig, VcpuThreadIds};
use anyhow::{Context, Result};
use async_trait::async_trait;
use kata_types::capabilities::{Capabilities, CapabilityBits};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use persist::sandbox_persist::Persist;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

// Convenience macro to obtain the scope logger
#[macro_export]
macro_rules! sl {
      () => {
          slog_scope::logger().new(o!("subsystem" => "cloud-hypervisor"))
      };
  }

mod inner;
mod inner_device;
mod inner_growth;
mod inner_hypervisor;
mod migration;
mod utils;

use inner::CloudHypervisorInner;

#[derive(Debug)]
pub struct CloudHypervisor {
    inner: Arc<RwLock<CloudHypervisorInner>>,
    exit_waiter: Mutex<(mpsc::Receiver<i32>, i32)>,
}

impl CloudHypervisor {
    pub fn new() -> Self {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        Self {
            inner: Arc::new(RwLock::new(CloudHypervisorInner::new(Some(exit_notify)))),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        }
    }

    pub async fn set_hypervisor_config(&self, config: HypervisorConfig) {
        let mut inner = self.inner.write().await;
        inner.set_hypervisor_config(config)
    }
}

impl Default for CloudHypervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Hypervisor for CloudHypervisor {
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
        debug!(sl!(), "Waiting CH vmm");
        let mut waiter = self.exit_waiter.lock().await;
        if let Some(exitcode) = waiter.0.recv().await {
            waiter.1 = exitcode;
        }

        Ok(waiter.1)
    }

    async fn pause_vm(&self) -> Result<()> {
        let inner = self.inner.write().await;
        inner.pause_vm().await
    }

    async fn resume_vm(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.resume_vm().await
    }

    fn supports_live_migration(&self) -> bool {
        true
    }

    async fn migration_send(
        &self,
        uri: &str,
        params: &crate::migration::MigrationParams,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.migration_send(uri, params).await
    }

    async fn migration_progress(&self) -> Result<crate::migration::MigrationProgress> {
        let inner = self.inner.read().await;
        inner.migration_progress()
    }

    async fn migration_cancel(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.migration_cancel()
    }

    async fn migration_receive(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.migration_receive().await
    }

    async fn migration_networks(&self) -> Result<Vec<crate::migration::NetworkPin>> {
        let inner = self.inner.read().await;
        inner.migration_networks()
    }

    async fn save_vm(&self) -> Result<()> {
        let inner = self.inner.write().await;
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

    fn supports_network_removal(&self) -> bool {
        true
    }
    fn supports_block_growth(&self) -> bool {
        true
    }
    async fn grow_block_device(&self, device: DeviceType, requested: u64) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.grow_block_device(device, requested).await
    }
    async fn remove_network_device(&self, device: crate::NetworkDevice) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.remove_network_device(device).await
    }

    async fn update_device(&self, device: DeviceType) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.update_device(device).await
    }

    async fn get_agent_socket(&self) -> Result<String> {
        let inner = self.inner.write().await;
        inner.get_agent_socket().await
    }

    async fn disconnect(&self) {
        let mut inner = self.inner.write().await;
        inner.disconnect().await
    }

    async fn hypervisor_config(&self) -> HypervisorConfig {
        let inner = self.inner.write().await;
        inner.hypervisor_config()
    }

    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        let inner = self.inner.read().await;
        inner.get_thread_ids().await
    }

    async fn cleanup(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.cleanup().await
    }

    async fn resize_vcpu(&self, old_vcpu: u32, new_vcpu: u32) -> Result<(u32, u32)> {
        let inner = self.inner.read().await;
        inner.resize_vcpu(old_vcpu, new_vcpu).await
    }

    async fn get_pids(&self) -> Result<Vec<u32>> {
        let inner = self.inner.read().await;
        inner.get_pids().await
    }

    async fn get_vmm_master_tid(&self) -> Result<u32> {
        let inner = self.inner.read().await;
        inner.get_vmm_master_tid().await
    }

    async fn get_ns_path(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_ns_path().await
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
        inner.guest_memory_block_size_mb()
    }

    async fn resize_memory(&self, new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        let inner = self.inner.read().await;
        inner.resize_memory(new_mem_mb).await
    }

    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        Err(anyhow::anyhow!("Not yet supported"))
    }
}

#[async_trait]
impl Persist for CloudHypervisor {
    type State = HypervisorState;
    type ConstructorArgs = ();

    async fn save(&self) -> Result<Self::State> {
        let inner = self.inner.read().await;
        inner.save().await.context("save CH hypervisor state")
    }

    async fn restore(
        _hypervisor_args: Self::ConstructorArgs,
        hypervisor_state: Self::State,
    ) -> Result<Self> {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        let inner = CloudHypervisorInner::restore(exit_notify, hypervisor_state).await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        })
    }
}
