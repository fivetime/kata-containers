// SPDX-License-Identifier: Apache-2.0
use anyhow::{bail, Context, Result};
use common::types::UpdateRequest;
use serde::Deserialize;
use std::sync::Arc;
use resource::volume::Volume;

pub const UPDATE_KEY: &str = "io.katacontainers.volume-update.v1";
pub const GENERATION_KEY: &str = "io.openstack.nova.generation";
pub const ATTACH_FEATURE: &str = "block-device-attach-v1";
pub const DETACH_FEATURE: &str = "block-device-detach-v1";
pub const PAUSED_VERIFY_FEATURE: &str = "block-device-verify-paused-v1";

pub fn validate_paused_verification(prior: Option<&PendingVolume>, request: &BlockAttach,
    details: &agent::GuestDetailsResponse) -> Result<()> {
    if !details.agent_details.as_ref().is_some_and(|a|
        a.extra_features.iter().any(|f| f == PAUSED_VERIFY_FEATURE)) {
        bail!("volume_update_unsupported: paused verification capability absent");
    }
    let prior = prior.context("volume_update_conflict: paused attachment is not creation-owned")?;
    if !prior.created || prior.request != *request || prior.detach.is_some()
        || prior.device.is_none() || prior.volume.is_none() {
        bail!("volume_update_conflict: paused verification requires original complete creation attachment");
    }
    Ok(())
}

pub fn validate_agent_capability(details: &agent::GuestDetailsResponse, driver: &str) -> Result<()> {
    // This is hypervisor configuration, not an agent Storage.driver value.
    if !matches!(driver, kata_types::config::hypervisor::VIRTIO_BLK_PCI
        | kata_types::config::hypervisor::VIRTIO_SCSI) || !details.agent_details.as_ref()
        .is_some_and(|agent| agent.extra_features.iter().any(|flag| flag == ATTACH_FEATURE)) {
        bail!("volume_update_unsupported: guest block-attach capability or driver unavailable");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BlockAttach {
    pub action: String,
    pub generation: String,
    pub request_id: String,
    #[serde(default)]
    pub attach_request_id: Option<String>,
    pub volume_uuid: String,
    pub attachment_uuid: String,
    pub source: String,
    pub destination: String,
    pub readonly: bool,
}

pub struct PendingVolume {
    pub created: bool,
    pub request: BlockAttach,
    pub metadata_identity: serde_json::Value,
    pub volume: Option<Arc<dyn Volume>>,
    pub device: Option<agent::types::Device>,
    pub detach: Option<PendingDetach>,
}

pub struct PendingDetach {
    pub request: BlockAttach,
    pub resume_required: bool,
    pub pause_attempted: bool,
    pub paused: bool,
    pub prepared: bool,
    pub prepare_uncertain: bool,
    pub removal_attempted: bool,
    pub removed: bool,
    pub committed: bool,
    pub resume_attempted: bool,
    pub complete: bool,
}

pub fn validate_detach_target(request: &BlockAttach, original: &BlockAttach) -> Result<()> {
    if request.action != "detach" || request.attach_request_id.as_ref() != Some(&original.request_id)
        || request.generation != original.generation || request.volume_uuid != original.volume_uuid
        || request.attachment_uuid != original.attachment_uuid || request.source != original.source
        || request.destination != original.destination || request.readonly != original.readonly {
        bail!("volume_update_conflict: detach target differs from original attachment");
    }
    Ok(())
}

/// The by-id link of a volume, as a libvirt guest has it: `virtio-` and the
/// first 20 characters of its ID.
pub fn by_id_destination(volume_uuid: &str) -> String {
    format!("/dev/disk/by-id/virtio-{}", &volume_uuid[..volume_uuid.len().min(20)])
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).map(|id| id.to_string() == value).unwrap_or(false)
}

pub fn parse(req: &UpdateRequest) -> Result<Option<BlockAttach>> {
    let keys: Vec<_> = req.annotations.keys()
        .filter(|key| key.starts_with("io.katacontainers.volume-update.")).collect();
    if keys.is_empty() { return Ok(None); }
    if keys.len() != 1 || keys[0] != UPDATE_KEY {
        bail!("volume_update_unsupported: unknown or multiple protocol versions");
    }
    if !req.value.is_empty() && req.value != b"{}" {
        bail!("volume_update_invalid: combined resource and volume updates are unsupported");
    }
    let text = &req.annotations[UPDATE_KEY];
    if text.len() > 8192 { bail!("volume_update_invalid: request too large"); }
    let value: BlockAttach = serde_json::from_str(text).context("volume_update_invalid")?;
    match value.action.as_str() {
        "attach" if value.attach_request_id.is_none() => (),
        "detach" if value.attach_request_id.as_deref().is_some_and(|id|
            canonical_uuid(id) && id != value.request_id) => (),
        _ => bail!("volume_update_unsupported: operation or attach request identity"),
    }
    if !canonical_uuid(&value.request_id) || !canonical_uuid(&value.volume_uuid)
        || !canonical_uuid(&value.attachment_uuid) || value.generation.is_empty()
        || value.generation.len() > 128 {
        bail!("volume_update_invalid: identifiers");
    }
    let instance = req.container_id.strip_prefix("nova-")
        .filter(|id| canonical_uuid(id)).context("volume_update_invalid: instance identity")?;
    let parts: Vec<_> = value.source.split('/').collect();
    if parts.len() != 7 || parts[0] != "" || parts[1] != "openstack"
        || parts[2] != "nova" || parts[3] != instance || parts[4].len() != 16
        || !parts[4].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || parts[5] != "volumes" || parts[6] != value.volume_uuid {
        bail!("volume_update_invalid: direct-volume source identity");
    }
    // Nova Kata (ADR-058): a volume is given by its by-id link, which the
    // agent makes to the guest kernel's name of the disk.
    if value.destination != by_id_destination(&value.volume_uuid) {
        bail!("volume_update_invalid: destination");
    }
    Ok(Some(value))
}

pub fn validate_generation(request: &BlockAttach, spec: &oci_spec::runtime::Spec) -> Result<()> {
    if spec.annotations().as_ref().and_then(|a| a.get(GENERATION_KEY)) != Some(&request.generation) {
        bail!("volume_update_conflict: running instance generation differs");
    }
    Ok(())
}

pub fn validate_metadata(request: &BlockAttach, info: &kata_types::mount::DirectVolumeMountInfo) -> Result<()> {
    let mode = if request.readonly { "ro" } else { "rw" };
    if info.volume_type != "directvol" || !info.fs_type.is_empty()
        || info.options != vec![mode.to_string()] {
        bail!("volume_update_conflict: direct-volume type or mode changed");
    }
    for (key, expected) in [("openstack.generation", &request.generation),
        ("openstack.volume_uuid", &request.volume_uuid),
        ("openstack.attachment_uuid", &request.attachment_uuid)] {
        if info.metadata.get(key) != Some(expected) {
            bail!("volume_update_conflict: direct-volume ownership changed");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "live_volume_tests.rs"]
mod tests;
