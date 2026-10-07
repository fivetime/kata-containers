// SPDX-License-Identifier: Apache-2.0
//! Explicit creation-time registration for raw data volumes. Existing unlisted
//! volumes retain their ordinary storage/bind-mount behavior.
use super::live_volume::{self, BlockAttach, PendingVolume};
use anyhow::{bail, Context, Result};
use common::types::UpdateRequest;
use oci_spec::runtime as oci;
use resource::volume::Volume;
use std::{collections::{HashMap, HashSet}, sync::Arc};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

pub const INITIAL_KEY: &str = "io.katacontainers.volume-initial.v1";
pub const CREATED_KEY: &str = "io.katacontainers.block-attachments.v1";
pub const CREATED_FEATURE: &str = "block-device-created-v1";

pub fn parse_initial(id: &str, spec: &oci::Spec) -> Result<Vec<BlockAttach>> {
    let Some(annotations) = spec.annotations() else { return Ok(vec![]); };
    // The guest registration annotation is produced here, never accepted from
    // the host input spec as authority to adopt an arbitrary guest device.
    if annotations.keys().any(|key| key.starts_with("io.katacontainers.block-attachments.")) {
        bail!("volume_update_invalid: guest registration is runtime-owned");
    }
    let keys: Vec<_> = annotations.keys().filter(|key| key.starts_with("io.katacontainers.volume-initial.")).collect();
    if keys.is_empty() { return Ok(vec![]); }
    if keys.len() != 1 || keys[0] != INITIAL_KEY { bail!("unknown initial-volume protocol"); }
    let text = &annotations[INITIAL_KEY];
    if text.len() > 65536 { bail!("initial-volume list too large"); }
    let entries: Vec<serde_json::Value> = serde_json::from_str(text)?;
    if entries.len() > 128 { bail!("too many initial volumes"); }
    let mut destinations = HashSet::new();
    let mut volumes = HashSet::new();
    let mut requests = HashSet::new();
    let mut attachments = HashSet::new();
    let mut result = vec![];
    for entry in entries {
        let update = UpdateRequest { container_id: id.into(), value: vec![],
            annotations: HashMap::from([(live_volume::UPDATE_KEY.into(), entry.to_string())]) };
        let request = live_volume::parse(&update)?.context("initial volume absent")?;
        live_volume::validate_generation(&request, spec)?;
        if request.action != "attach" || !destinations.insert(request.destination.clone())
            || !volumes.insert(request.volume_uuid.clone()) || !requests.insert(request.request_id.clone())
            || !attachments.insert(request.attachment_uuid.clone()) {
            bail!("invalid or duplicate initial volume identity");
        }
        let mounts = spec.mounts().as_ref().context("initial volume mount absent")?;
        let matches: Vec<_> = mounts.iter().filter(|m| m.destination().to_str() == Some(request.destination.as_str())).collect();
        let mode = if request.readonly { "ro" } else { "rw" };
        if matches.len() != 1 || matches[0].typ().as_deref() != Some("directvol")
            || matches[0].source().as_ref().and_then(|s| s.to_str()) != Some(request.source.as_str())
            || matches[0].options().as_ref() != Some(&vec!["rbind".into(), mode.into()])
            || spec.linux().as_ref().and_then(|l| l.devices().as_ref()).is_some_and(|devices|
                devices.iter().any(|d| d.path().to_str() == Some(request.destination.as_str()))) {
            bail!("initial volume differs from original OCI mount or collides with a device");
        }
        result.push(request);
    }
    Ok(result)
}

pub fn validate_capability(details: &agent::GuestDetailsResponse, driver: &str) -> Result<()> {
    live_volume::validate_agent_capability(details, driver)?;
    if !details.agent_details.as_ref().is_some_and(|a| a.extra_features.iter().any(|f| f == CREATED_FEATURE)) {
        bail!("volume_update_unsupported: guest creation registration unavailable");
    }
    Ok(())
}

// Must run before handler_volumes inserts any selected native data device.
pub fn audit_initial(requests: Vec<BlockAttach>) -> Result<Vec<PendingVolume>> {
    requests.into_iter().map(|request| {
        let metadata = resource::volume::direct_volumes::volume_mount_info(&request.source)?;
        live_volume::validate_metadata(&request, &metadata)?;
        let host = std::fs::metadata(&metadata.device)?;
        if !host.file_type().is_block_device() || metadata.metadata.get("openstack.device_number")
            != Some(&format!("{}:{}", libc::major(host.rdev()), libc::minor(host.rdev()))) {
            bail!("initial host block identity differs");
        }
        Ok(PendingVolume { request, metadata_identity: serde_json::to_value(&metadata)?,
            volume: None, device: None, detach: None, created: true })
    }).collect()
}

pub struct CreatedVolumes {
    pub destinations: HashSet<String>,
    records: Vec<PendingVolume>,
}

pub fn bind_initial(mut records: Vec<PendingVolume>, volumes: &[Arc<dyn Volume>]) -> Result<CreatedVolumes> {
    let mut destinations = HashSet::new();
    for record in &mut records {
        let mut matching = vec![];
        for volume in volumes {
            let mounts = volume.get_volume_mount()?;
            if mounts.iter().any(|m| m.destination().to_str() == Some(record.request.destination.as_str())) {
                if mounts.len() != 1 { bail!("initial native volume has multiple mounts"); }
                matching.push(volume.clone());
            }
        }
        if matching.len() != 1 { bail!("initial native volume missing or ambiguous"); }
        let volume = matching.remove(0);
        let storage = volume.get_storage()?;
        if storage.len() != 1 || !matches!(storage[0].driver.as_str(), "blk" | "scsi")
            || storage[0].source.is_empty() || storage[0].fs_type != "bind" || volume.get_device_id()?.is_none() {
            bail!("initial volume is not a supported native raw block device");
        }
        record.device = Some(agent::types::Device { id: storage[0].source.clone(),
            field_type: storage[0].driver.clone(), container_path: record.request.destination.clone(), ..Default::default() });
        record.volume = Some(volume);
        destinations.insert(record.request.destination.clone());
    }
    Ok(CreatedVolumes { destinations, records })
}

impl CreatedVolumes {
    pub fn apply(self, spec: &mut oci::Spec, devices: &mut Vec<agent::types::Device>,
                 registry: &mut HashMap<String, PendingVolume>) -> Result<()> {
        if self.records.is_empty() { return Ok(()); }
        let mut placeholders = vec![];
        let mut registrations = vec![];
        let mut numbers = HashSet::new();
        for record in &self.records {
            if registry.contains_key(&record.request.request_id) || devices.iter()
                .any(|d| d.container_path == record.request.destination)
                || spec.linux().as_ref().and_then(|l| l.devices().as_ref()).is_some_and(|ds|
                    ds.iter().any(|d| d.path().to_str() == Some(record.request.destination.as_str()))) {
                bail!("initial device registration collision");
            }
            let number = record.metadata_identity.get("metadata")
                .and_then(|m| m.get("openstack.device_number")).and_then(|n| n.as_str())
                .context("initial host number absent")?;
            let (major, minor) = number.split_once(':').context("invalid initial host number")?;
            let (major, minor) = (major.parse::<u32>()?, minor.parse::<u32>()?);
            if !numbers.insert((major, minor)) || spec.linux().as_ref().and_then(|l| l.devices().as_ref())
                .is_some_and(|ds| ds.iter().any(|d| d.typ() == oci::LinuxDeviceType::B
                    && d.major() == i64::from(major) && d.minor() == i64::from(minor))) {
                bail!("initial host block numbers are ambiguous");
            }
            placeholders.push(oci::LinuxDeviceBuilder::default().path(record.request.destination.clone())
                .typ(oci::LinuxDeviceType::B).major(i64::from(major)).minor(i64::from(minor))
                .file_mode(0o600u32).uid(0u32).gid(0u32).build()?);
            registrations.push(serde_json::json!({"request_id":record.request.request_id,
                "destination":record.request.destination}));
        }
        // The existing agent Device resolver replaces distinct host numbers with
        // the discovered guest device before rustjail creates and captures nodes.
        let linux = spec.linux_mut().as_mut().context("initial OCI linux spec absent")?;
        linux.devices_mut().get_or_insert_with(Vec::new).extend(placeholders);
        spec.annotations_mut().get_or_insert_with(HashMap::new)
            .insert(CREATED_KEY.into(), serde_json::to_string(&registrations)?);
        for record in self.records {
            devices.push(record.device.clone().context("initial resolved descriptor absent")?);
            registry.insert(record.request.request_id.clone(), record);
        }
        Ok(())
    }
}
