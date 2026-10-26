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
/// QEMU node `drive-<index>`, which names its SCSI address).
/// `copy`: the device's content is the source host's alone (a tenant root
/// file), and travels with the VM: the source mirrors it into the
/// destination's own device, which the destination exports for that
/// (QEMU's block copy over NBD, as libvirt's).
/// `bus` and `slot` (ADR-058): the PCI place of a virtio-blk device
/// hot-plugged on a bridge, which the destination gives it again; a SCSI
/// disk, or one of the command line, has none.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlockPin {
    pub path: String,
    pub index: u64,
    #[serde(default)]
    pub copy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<i64>,
}

impl BlockPin {
    /// The PCI place, when the device has one.
    pub fn place(&self) -> Option<(String, i64)> {
        match (&self.bus, self.slot) {
            (Some(bus), Some(slot)) => Some((bus.clone(), slot)),
            _ => None,
        }
    }
}

/// A network device of the source: its guest MAC and its PCI place.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPin {
    pub mac: String,
    pub bus: String,
    pub slot: i64,
    /// Modern (transitional) virtio, as a hot-plugged NIC is; a cold-plugged
    /// one is legacy (disable-modern) where the configuration says so. The
    /// PCI configuration of the two differs, and the state of one does not
    /// load into the other.
    #[serde(default)]
    pub modern: bool,
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
    /// The source's container is paused (its workload frozen in the guest,
    /// which the transfer carries): it is adopted as paused.
    #[serde(default)]
    pub paused: bool,
    /// Every connection of the migration is TLS, with the certificates of
    /// migration_tls::TLS_DIR (libvirt's native TLS).
    #[serde(default)]
    pub tls: bool,
}

impl MigrateIn {
    pub fn block_pins(&self) -> HashMap<String, u64> {
        self.blocks
            .iter()
            .map(|pin| (pin.path.clone(), pin.index))
            .collect()
    }

    /// The indexes of the devices the source copies into this VM's.
    pub fn copied_indexes(&self) -> Vec<u64> {
        let mut indexes: Vec<u64> = self
            .blocks
            .iter()
            .filter(|pin| pin.copy)
            .map(|pin| pin.index)
            .collect();
        indexes.sort_unstable();
        indexes
    }

    /// The PCI place of each block device that had one, by index.
    pub fn block_places(&self) -> HashMap<u64, (String, i64)> {
        self.blocks
            .iter()
            .filter_map(|pin| pin.place().map(|place| (pin.index, place)))
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
    tcp_address(uri).map(|_| ())
}

/// The address of a `tcp:<IP>:<port>` URI.
pub fn tcp_address(uri: &str) -> Result<std::net::SocketAddr> {
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
    let ip = host
        .parse::<std::net::IpAddr>()
        .context("migration_invalid: the URI's address is not an IP address")?;
    Ok(std::net::SocketAddr::new(ip, port))
}

fn validate_pins(blocks: &[BlockPin], networks: &[NetworkPin]) -> Result<()> {
    if blocks.len() > MAX_DEVICES || networks.len() > MAX_DEVICES {
        bail!("migration_invalid: too many devices");
    }
    let mut paths = std::collections::HashSet::new();
    let mut indexes = std::collections::HashSet::new();
    // Disks and NICs share the bridges' slots.
    let mut places = std::collections::HashSet::new();
    for pin in blocks {
        let place_ok = match (&pin.bus, pin.slot) {
            (None, None) => true,
            (Some(bus), Some(slot)) => {
                bus.starts_with("pci-bridge-")
                    && (1..=31).contains(&slot)
                    && places.insert((bus.clone(), slot))
            }
            _ => false,
        };
        if !pin.path.starts_with('/')
            || !paths.insert(&pin.path)
            || !indexes.insert(pin.index)
            || !place_ok
        {
            bail!("migration_invalid: a block device's path, index or place");
        }
    }
    let mut macs = std::collections::HashSet::new();
    for pin in networks {
        if !canonical_mac(&pin.mac)
            || !macs.insert(&pin.mac)
            || !pin.bus.starts_with("pci-bridge-")
            || !(1..=31).contains(&pin.slot)
            || !places.insert((pin.bus.clone(), pin.slot))
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
    /// The indexes of the block devices mirrored into the destination's
    /// before the VM is sent (the manifest's `copy` devices).
    #[serde(default)]
    pub copy: Vec<u64>,
    /// Every connection of the migration is TLS (migration_tls).
    #[serde(default)]
    pub tls: bool,
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
    /// The block copy that precedes the VM: its bytes, and the phase,
    /// `copying` (the devices are mirrored), `ram` (the mirrors converged;
    /// the VM is sent) or `syncing` (the VM is sent; the mirrors' last
    /// blocks are written and the destination told). Empty without a copy.
    #[serde(default)]
    pub disk_transferred: u64,
    #[serde(default)]
    pub disk_total: u64,
    #[serde(default)]
    pub phase: String,
    /// The transfer ended, and neither side knows whether the other holds
    /// the VM (the destination's word on the last blocks was not read):
    /// neither VM is resumed; the operator decides.
    #[serde(default)]
    pub undecided: bool,
    #[serde(default)]
    pub error: String,
}

impl MigrationProgress {
    pub fn ended(&self) -> bool {
        matches!(self.status.as_str(), "completed" | "failed" | "cancelled")
    }
}

/// Every connection of a migration begins with a line that says what it
/// carries, written by the source's shim before the connection is handed
/// to its VMM: the VM (`ram`), a block copy's NBD client (`nbd`), or the
/// word that the copied blocks are all written (`synced`), which the
/// destination acknowledges with `ok` before it resumes the VM.
pub const PREFACE_RAM: &str = "ram";
pub const PREFACE_NBD: &str = "nbd";
pub const PREFACE_SYNCED: &str = "synced";
pub const PREFACE_ACK: &[u8] = b"ok\n";
const PREFACE_PROTOCOL: &str = "nova-kata-migration/1";
pub const PREFACE_MAX: usize = 48;

pub fn preface(kind: &str) -> Vec<u8> {
    format!("{PREFACE_PROTOCOL} {kind}\n").into_bytes()
}

/// The kind a preface line names, or an error for anything else.
pub fn parse_preface(line: &[u8]) -> Result<&'static str> {
    let text = std::str::from_utf8(line).context("migration_invalid: the preface")?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    match text
        .strip_prefix(PREFACE_PROTOCOL)
        .and_then(|rest| rest.strip_prefix(' '))
    {
        Some(PREFACE_RAM) => Ok(PREFACE_RAM),
        Some(PREFACE_NBD) => Ok(PREFACE_NBD),
        Some(PREFACE_SYNCED) => Ok(PREFACE_SYNCED),
        _ => bail!("migration_invalid: the preface {text:?}"),
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
            "blocks":[{"path":"/dev/rbd3","index":2},{"path":"/run/x/root-g","index":1,"copy":true}],
            "networks":[{"mac":"fa:16:3e:00:00:01","bus":"pci-bridge-0","slot":1}]}"#;
        let got = migrate_in(&request(body)).unwrap().unwrap();
        assert_eq!(got.block_pins().get("/dev/rbd3"), Some(&2));
        assert_eq!(got.copied_indexes(), vec![1]);
        assert_eq!(got.network_pin("FA:16:3E:00:00:01").unwrap().slot, 1);
        assert!(got.block_places().is_empty());
    }

    #[test]
    fn a_disk_keeps_its_pci_place() {
        let body = r#"{"version":1,"source_generation":"g1","uri":"tcp:0.0.0.0:47000",
            "blocks":[{"path":"/dev/rbd3","index":2,"bus":"pci-bridge-0","slot":3}],
            "networks":[{"mac":"fa:16:3e:00:00:01","bus":"pci-bridge-0","slot":1}]}"#;
        let got = migrate_in(&request(body)).unwrap().unwrap();
        assert_eq!(
            got.block_places().get(&2),
            Some(&("pci-bridge-0".to_string(), 3))
        );
        // A place half given, off a bridge, or a NIC's.
        for blocks in [
            r#"[{"path":"/dev/rbd3","index":2,"bus":"pci-bridge-0"}]"#,
            r#"[{"path":"/dev/rbd3","index":2,"slot":3}]"#,
            r#"[{"path":"/dev/rbd3","index":2,"bus":"pcie.0","slot":3}]"#,
            r#"[{"path":"/dev/rbd3","index":2,"bus":"pci-bridge-0","slot":32}]"#,
            r#"[{"path":"/dev/rbd3","index":2,"bus":"pci-bridge-0","slot":1}]"#,
        ] {
            let body = format!(
                r#"{{"version":1,"source_generation":"g1","uri":"tcp:0.0.0.0:47000",
                "blocks":{blocks},
                "networks":[{{"mac":"fa:16:3e:00:00:01","bus":"pci-bridge-0","slot":1}}]}}"#
            );
            assert!(migrate_in(&request(&body)).is_err(), "{blocks}");
        }
    }

    #[test]
    fn a_preface_names_what_a_connection_carries() {
        for kind in [PREFACE_RAM, PREFACE_NBD, PREFACE_SYNCED] {
            let line = preface(kind);
            assert!(line.len() <= PREFACE_MAX);
            assert_eq!(parse_preface(&line).unwrap(), kind);
        }
        for bad in ["nova-kata-migration/1 disk\n", "nova-kata-migration/2 ram\n", "QEVM", ""] {
            assert!(parse_preface(bad.as_bytes()).is_err());
        }
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
