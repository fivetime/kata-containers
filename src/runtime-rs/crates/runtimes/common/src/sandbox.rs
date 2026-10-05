// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    types::{ContainerProcess, SandboxExitInfo, SandboxStatus},
    ContainerManager,
};

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct SandboxNetworkEnv {
    pub netns: Option<String>,
    pub network_created: bool,
}

impl std::fmt::Debug for SandboxNetworkEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxNetworkEnv")
            .field("netns", &self.netns)
            .field("network_created", &self.network_created)
            .finish()
    }
}

#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn start_template(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn cleanup(&self) -> Result<()>;
    async fn shutdown(&self) -> Result<()>;
    async fn status(&self) -> Result<SandboxStatus>;
    async fn wait(&self) -> Result<SandboxExitInfo>;

    // utils
    async fn set_iptables(&self, is_ipv6: bool, data: Vec<u8>) -> Result<Vec<u8>>;
    async fn get_iptables(&self, is_ipv6: bool) -> Result<Vec<u8>>;
    async fn direct_volume_stats(&self, volume_path: &str) -> Result<String>;
    async fn direct_volume_resize(&self, resize_req: agent::ResizeVolumeRequest) -> Result<()>;
    async fn agent_sock(&self) -> Result<String>;
    async fn wait_process(
        &self,
        cm: Arc<dyn ContainerManager>,
        process_id: ContainerProcess,
        shim_pid: u32,
    ) -> Result<()>;

    // Docker 26+ network rescan: discover interfaces that Docker configured
    // between the Create and Start RPCs.
    async fn rescan_network(&self) -> Result<()>;

    // metrics function
    async fn agent_metrics(&self) -> Result<String>;
    async fn hypervisor_metrics(&self) -> Result<String>;

    // set agent policy
    async fn set_policy(&self, policy: &str) -> Result<()>;

    // Nova Kata (ADR-052): live migration.
    /// A task update that is a migration action of the sandbox: done, and
    /// true; any other update: false, untouched.
    async fn migration_update(&self, _req: &crate::types::UpdateRequest) -> Result<bool> {
        Ok(false)
    }
    /// Once the sandbox container is created: a sandbox that receives a VM
    /// begins receiving. Nothing otherwise.
    async fn migration_receive(&self) -> Result<()> {
        Ok(())
    }
    /// Before the sandbox container starts: a sandbox that received a VM
    /// waits for the transfer's end, resumes it and redials its agent.
    /// Nothing otherwise.
    async fn migration_finish(&self) -> Result<()> {
        Ok(())
    }
    /// Whether the sandbox received a VM whose container runs already.
    async fn migrated_in(&self) -> bool {
        false
    }
}
