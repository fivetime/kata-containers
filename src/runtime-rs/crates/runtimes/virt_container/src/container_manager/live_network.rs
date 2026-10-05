// SPDX-License-Identifier: Apache-2.0
//
// Nova Kata (ADR-044): an interface joins or leaves a running guest. The
// owner of the sandbox's namespace makes the interface there, with its
// addresses and routes, and announces it with an annotation of a task
// update; nothing of the request names a path.
use anyhow::{bail, Context, Result};
use common::types::UpdateRequest;
use resource::network::EndpointUpdate;
use serde::Deserialize;

pub const UPDATE_KEY: &str = "io.katacontainers.network-update.v1";
pub const UPDATE_PREFIX: &str = "io.katacontainers.network-update.";
pub const GENERATION_KEY: &str = "io.openstack.nova.generation";
const MIN_MTU: u32 = 576;
const MAX_MTU: u32 = 65535;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkUpdate {
    pub action: String,
    pub generation: String,
    pub request_id: String,
    // Of an attach and a detach; a refresh names no interface.
    #[serde(default)]
    pub port_id: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
}

impl NetworkUpdate {
    pub fn attaches(&self) -> bool {
        self.action == "attach"
    }

    /// The interface that joins or leaves; None for a refresh.
    pub fn endpoint(&self) -> Option<EndpointUpdate> {
        Some(EndpointUpdate {
            port_id: self.port_id.clone()?,
            interface: self.interface.clone()?,
            mac: self.mac.clone()?,
            mtu: self.mtu?,
        })
    }
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .map(|id| id.to_string() == value)
        .unwrap_or(false)
}

fn canonical_mac(value: &str) -> bool {
    let octets: Vec<&str> = value.split(':').collect();
    octets.len() == 6
        && octets.iter().all(|octet| {
            octet.len() == 2
                && octet
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub fn parse(req: &UpdateRequest) -> Result<Option<NetworkUpdate>> {
    let keys: Vec<_> = req
        .annotations
        .keys()
        .filter(|key| key.starts_with(UPDATE_PREFIX))
        .collect();
    if keys.is_empty() {
        return Ok(None);
    }
    if keys.len() != 1 || keys[0] != UPDATE_KEY {
        bail!("network_update_unsupported: unknown or multiple protocol versions");
    }
    if req
        .annotations
        .keys()
        .any(|key| key.starts_with("io.katacontainers.volume-update."))
    {
        bail!("network_update_invalid: combined volume and interface updates are unsupported");
    }
    if !req.value.is_empty() && req.value != b"{}" {
        bail!("network_update_invalid: combined resource and interface updates are unsupported");
    }
    let text = &req.annotations[UPDATE_KEY];
    if text.len() > 4096 {
        bail!("network_update_invalid: request too large");
    }
    let value: NetworkUpdate = serde_json::from_str(text).context("network_update_invalid")?;
    if !matches!(value.action.as_str(), "attach" | "detach" | "refresh") {
        bail!("network_update_unsupported: operation");
    }
    if !canonical_uuid(&value.request_id)
        || value.generation.is_empty()
        || value.generation.len() > 128
    {
        bail!("network_update_invalid: identifiers");
    }
    req.container_id
        .strip_prefix("nova-")
        .filter(|id| canonical_uuid(id))
        .context("network_update_invalid: instance identity")?;
    let named = [
        value.port_id.is_some(),
        value.interface.is_some(),
        value.mac.is_some(),
        value.mtu.is_some(),
    ];
    if value.action == "refresh" {
        if named.contains(&true) {
            bail!("network_update_invalid: a refresh names no interface");
        }
        return Ok(Some(value));
    }
    let Some(endpoint) = value.endpoint() else {
        bail!("network_update_invalid: the interface is not described");
    };
    if !canonical_uuid(&endpoint.port_id) {
        bail!("network_update_invalid: identifiers");
    }
    // The name of the interface is derived from its port, as its owner
    // derives it.
    let token = endpoint.port_id.replace('-', "");
    if endpoint.interface != format!("nk{}", &token[..13]) {
        bail!("network_update_invalid: the interface is not derived from its port");
    }
    if !canonical_mac(&endpoint.mac) || !(MIN_MTU..=MAX_MTU).contains(&endpoint.mtu) {
        bail!("network_update_invalid: MAC address or MTU");
    }
    Ok(Some(value))
}

pub fn validate_generation(
    request: &NetworkUpdate,
    spec: &oci_spec::runtime::Spec,
) -> Result<()> {
    if spec
        .annotations()
        .as_ref()
        .and_then(|a| a.get(GENERATION_KEY))
        != Some(&request.generation)
    {
        bail!("network_update_conflict: running instance generation differs");
    }
    Ok(())
}

#[cfg(test)]
#[path = "live_network_tests.rs"]
mod tests;
