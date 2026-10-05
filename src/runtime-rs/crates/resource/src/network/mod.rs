// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

mod dan;
mod endpoint;
pub use dan::{dan_config_path, Dan, DanNetworkConfig};
pub use endpoint::endpoint_persist::EndpointState;
pub use endpoint::Endpoint;
mod network_entity;
mod network_info;
pub use network_info::NetworkInfo;
mod network_model;
pub use network_model::NetworkModel;
mod network_with_netns;
pub(crate) use network_with_netns::netns_has_interfaces;
pub use network_with_netns::NetworkWithNetNsConfig;
use network_with_netns::NetworkWithNetns;
mod network_pair;
use network_pair::NetworkPair;
mod utils;
pub use kata_sys_util::netns::{generate_netns_name, NetnsGuard};
use tokio::sync::RwLock;

use anyhow::{Context, Result};
use async_trait::async_trait;
use hypervisor::{device::device_manager::DeviceManager, Hypervisor};

#[derive(Debug)]
pub enum NetworkConfig {
    NetNs(NetworkWithNetNsConfig),
    Dan(DanNetworkConfig),
}

/// Nova Kata (ADR-044): an interface of the namespace that joins or leaves
/// the running guest. Its owner made it and takes it away; the runtime is
/// told its name and what it must be.
#[derive(Clone, Debug, PartialEq)]
pub struct EndpointUpdate {
    pub port_id: String,
    pub interface: String,
    pub mac: String,
    pub mtu: u32,
}

impl EndpointUpdate {
    /// What the host interface of the endpoint is labelled with, for the
    /// owner of the namespace to read: `pending` while the guest is given
    /// the interface, `attached` once it has it, `released` when the VMM
    /// holds the host interface no more.
    pub fn alias(&self, state: &str) -> String {
        format!("nova-kata-net:{}:{}", self.port_id, state)
    }
}

/// What the guest is told of an interface that has joined.
#[derive(Clone, Debug)]
pub struct AttachedEndpoint {
    pub interface: agent::Interface,
    pub host_interface: String,
}

fn network_update_unsupported<T>() -> Result<T> {
    Err(anyhow::anyhow!(
        "network_update_unsupported: this network changes no endpoint of a running guest"
    ))
}

#[async_trait]
pub trait Network: Send + Sync {
    /// Nova Kata (ADR-044): give the VMM the interface. Repeated for an
    /// interface the guest has, it changes nothing.
    async fn attach_endpoint(&self, _update: &EndpointUpdate) -> Result<AttachedEndpoint> {
        network_update_unsupported()
    }
    /// The guest has been told of the interface.
    async fn confirm_endpoint(&self, _update: &EndpointUpdate) -> Result<()> {
        network_update_unsupported()
    }
    /// Read again the addresses, routes and neighbours of the interfaces
    /// the guest has: the owner of the namespace has changed them.
    async fn refresh(&self) -> Result<()> {
        network_update_unsupported()
    }
    /// Take the interface from the VMM. With `keep` the host interface
    /// stays, labelled `released`, as the evidence of it; without, it is
    /// deleted, as after an attach that failed.
    async fn detach_endpoint(&self, _update: &EndpointUpdate, _keep: bool) -> Result<()> {
        network_update_unsupported()
    }
    async fn setup(&self) -> Result<()>;
    async fn interfaces(&self) -> Result<Vec<agent::Interface>>;
    async fn routes(&self) -> Result<Vec<agent::Route>>;
    async fn neighs(&self) -> Result<Vec<agent::ARPNeighbor>>;
    async fn save(&self) -> Option<Vec<EndpointState>>;
    async fn remove(&self, h: &dyn Hypervisor) -> Result<()>;
    /// Returns the list of network endpoints. Used to resolve PCI paths
    /// via QMP before sending update_interface to the agent.
    async fn endpoints(&self) -> Vec<std::sync::Arc<dyn endpoint::Endpoint>> {
        vec![]
    }
}

pub async fn new(
    config: &NetworkConfig,
    d: Arc<RwLock<DeviceManager>>,
) -> Result<Arc<dyn Network>> {
    match config {
        NetworkConfig::NetNs(c) => Ok(Arc::new(
            NetworkWithNetns::new(c, d)
                .await
                .context("new network with netns")?,
        )),
        NetworkConfig::Dan(c) => Ok(Arc::new(
            Dan::new(c, d)
                .await
                .context("New directly attachable network")?,
        )),
    }
}
