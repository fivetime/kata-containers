// SPDX-License-Identifier: Apache-2.0
//
// Nova Kata (ADR-052): live migration of a sandbox's VM between hosts.
//
// The source's shim sends its VM to the destination's VMM; the
// destination's shim starts its VMM to receive it, with the devices of the
// source at the same addresses, and later resumes it and takes over the
// container that runs in the guest. The gateway of each host names what
// each shim does; nothing here decides whether a migration may happen.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// The annotation of the sandbox container's spec that starts the sandbox
/// to receive a VM instead of booting one.
pub const MIGRATE_IN_KEY: &str = "io.openstack.nova.kata.migrate-in.v1";
pub const MIGRATE_IN_PREFIX: &str = "io.openstack.nova.kata.migrate-in.";
const MAX_MIGRATE_IN_BYTES: usize = 64 * 1024;
const MAX_DEVICES: usize = 256;

/// A block device of the source: its host path there and its index (the
/// QEMU node `drive-<index>`, which names its SCSI address or its slot).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlockPin {
    pub path: String,
    pub index: u64,
}

/// A network device of the source: its guest MAC and its PCI place.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPin {
    pub mac: String,
    pub bus: String,
    pub slot: i64,
}

/// The devices of a running sandbox, as its VMM has them. The source
/// writes it; the destination's gateway turns each block path into its own
/// and gives it back in the migrate-in annotation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceManifest {
    pub version: u32,
    pub vmm: String,
    #[serde(default)]
    pub blocks: Vec<BlockPin>,
    #[serde(default)]
    pub networks: Vec<NetworkPin>,
}

/// The migrate-in annotation: where to listen and the devices to place.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrateIn {
    pub version: u32,
    pub source_generation: String,
    /// `tcp:<address>:<port>`, which the VMM listens on.
    pub uri: String,
    #[serde(default)]
    pub blocks: Vec<BlockPin>,
    #[serde(default)]
    pub networks: Vec<NetworkPin>,
}

impl MigrateIn {
    pub fn block_pins(&self) -> HashMap<String, u64> {
        self.blocks
            .iter()
            .map(|pin| (pin.path.clone(), pin.index))
            .collect()
    }

    pub fn network_pin(&self, mac: &str) -> Option<&NetworkPin> {
        let mac = mac.to_ascii_lowercase();
        self.networks.iter().find(|pin| pin.mac == mac)
    }
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

/// A listening URI: `tcp:` an address (IPv4, or IPv6 in brackets) and a
/// port that is not 0.
pub fn validate_tcp_uri(uri: &str) -> Result<()> {
    let rest = uri
        .strip_prefix("tcp:")
        .context("migration_invalid: the URI is not tcp:")?;
    let (host, port) = rest
        .rsplit_once(':')
        .context("migration_invalid: the URI has no port")?;
    let port: u16 = port.parse().context("migration_invalid: the port")?;
    if port == 0 || host.is_empty() {
        bail!("migration_invalid: the URI's address or port");
    }
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<std::net::IpAddr>()
        .context("migration_invalid: the URI's address is not an IP address")?;
    Ok(())
}

fn validate_pins(blocks: &[BlockPin], networks: &[NetworkPin]) -> Result<()> {
    if blocks.len() > MAX_DEVICES || networks.len() > MAX_DEVICES {
        bail!("migration_invalid: too many devices");
    }
    let mut paths = std::collections::HashSet::new();
    let mut indexes = std::collections::HashSet::new();
    for pin in blocks {
        if !pin.path.starts_with('/') || !paths.insert(&pin.path) || !indexes.insert(pin.index)
        {
            bail!("migration_invalid: a block device's path or index");
        }
    }
    let mut macs = std::collections::HashSet::new();
    let mut places = std::collections::HashSet::new();
    for pin in networks {
        if !canonical_mac(&pin.mac)
            || !macs.insert(&pin.mac)
            || !pin.bus.starts_with("pci-bridge-")
            || !(1..=31).contains(&pin.slot)
            || !places.insert((&pin.bus, pin.slot))
        {
            bail!("migration_invalid: a network device's MAC or place");
        }
    }
    Ok(())
}

/// The migrate-in request of a sandbox, if its annotations hold one.
/// Unknown versions and malformed requests are refused: a sandbox that was
/// asked to receive never boots a fresh VM instead.
pub fn migrate_in(annotations: &HashMap<String, String>) -> Result<Option<MigrateIn>> {
    let keys: Vec<_> = annotations
        .keys()
        .filter(|key| key.starts_with(MIGRATE_IN_PREFIX))
        .collect();
    if keys.is_empty() {
        return Ok(None);
    }
    if keys.len() != 1 || keys[0] != MIGRATE_IN_KEY {
        bail!("migration_unsupported: unknown or multiple migrate-in versions");
    }
    let text = &annotations[MIGRATE_IN_KEY];
    if text.len() > MAX_MIGRATE_IN_BYTES {
        bail!("migration_invalid: the migrate-in request is too large");
    }
    let request: MigrateIn = serde_json::from_str(text).context("migration_invalid")?;
    if request.version != 1 {
        bail!("migration_unsupported: migrate-in version");
    }
    if request.source_generation.is_empty() || request.source_generation.len() > 128 {
        bail!("migration_invalid: the source generation");
    }
    validate_tcp_uri(&request.uri)?;
    validate_pins(&request.blocks, &request.networks)?;
    Ok(Some(request))
}

/// What the source asks of its VMM's transfer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MigrationParams {
    /// The longest stop of the guest the VMM aims at, in milliseconds.
    pub downtime_ms: u64,
    /// Bytes a second; 0 leaves the VMM's own limit.
    pub max_bandwidth: u64,
}

/// How a transfer stands, on the side that asks.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MigrationProgress {
    /// `none`, `active`, `completed`, `failed` or `cancelled`.
    pub status: String,
    #[serde(default)]
    pub transferred: u64,
    #[serde(default)]
    pub remaining: u64,
    #[serde(default)]
    pub total_ms: u64,
    #[serde(default)]
    pub downtime_ms: u64,
    #[serde(default)]
    pub error: String,
}

impl MigrationProgress {
    pub fn ended(&self) -> bool {
        matches!(self.status.as_str(), "completed" | "failed" | "cancelled")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: &str) -> HashMap<String, String> {
        HashMap::from([(MIGRATE_IN_KEY.to_string(), body.to_string())])
    }

    #[test]
    fn no_annotation_is_no_migration() {
        assert_eq!(migrate_in(&HashMap::new()).unwrap(), None);
    }

    #[test]
    fn a_valid_request_is_read() {
        let body = r#"{"version":1,"source_generation":"g1","uri":"tcp:0.0.0.0:47000",
            "blocks":[{"path":"/dev/rbd3","index":2}],
            "networks":[{"mac":"fa:16:3e:00:00:01","bus":"pci-bridge-0","slot":1}]}"#;
        let got = migrate_in(&request(body)).unwrap().unwrap();
        assert_eq!(got.block_pins().get("/dev/rbd3"), Some(&2));
        assert_eq!(got.network_pin("FA:16:3E:00:00:01").unwrap().slot, 1);
    }

    #[test]
    fn malformed_requests_are_refused() {
        for body in [
            r#"{"version":2,"source_generation":"g","uri":"tcp:0.0.0.0:1"}"#,
            r#"{"version":1,"source_generation":"","uri":"tcp:0.0.0.0:1"}"#,
            r#"{"version":1,"source_generation":"g","uri":"unix:/x"}"#,
            r#"{"version":1,"source_generation":"g","uri":"tcp:0.0.0.0:0"}"#,
            r#"{"version":1,"source_generation":"g","uri":"tcp:host:1"}"#,
            r#"{"version":1,"source_generation":"g","uri":"tcp:0.0.0.0:1","x":1}"#,
            r#"{"version":1,"source_generation":"g","uri":"tcp:0.0.0.0:1",
                "blocks":[{"path":"/a","index":1},{"path":"/b","index":1}]}"#,
            r#"{"version":1,"source_generation":"g","uri":"tcp:0.0.0.0:1",
                "blocks":[{"path":"rel","index":1}]}"#,
            r#"{"version":1,"source_generation":"g","uri":"tcp:0.0.0.0:1",
                "networks":[{"mac":"FA:16:3E:00:00:01","bus":"pci-bridge-0","slot":1}]}"#,
            r#"{"version":1,"source_generation":"g","uri":"tcp:0.0.0.0:1",
                "networks":[{"mac":"fa:16:3e:00:00:01","bus":"pcie.0","slot":1}]}"#,
            r#"{"version":1,"source_generation":"g","uri":"tcp:0.0.0.0:1",
                "networks":[{"mac":"fa:16:3e:00:00:01","bus":"pci-bridge-0","slot":1},
                            {"mac":"fa:16:3e:00:00:02","bus":"pci-bridge-0","slot":1}]}"#,
        ] {
            assert!(migrate_in(&request(body)).is_err(), "{}", body);
        }
        let other = HashMap::from([(
            "io.openstack.nova.kata.migrate-in.v2".to_string(),
            "{}".to_string(),
        )]);
        assert!(migrate_in(&other).is_err());
    }

    #[test]
    fn ipv6_listeners_are_accepted() {
        validate_tcp_uri("tcp:[::]:47000").unwrap();
        validate_tcp_uri("tcp:[fd00::1]:47000").unwrap();
        assert!(validate_tcp_uri("tcp:[::]").is_err());
    }
}
