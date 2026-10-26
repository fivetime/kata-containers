// Copyright 2026 OpenStack Nova Kata contributors
//
// SPDX-License-Identifier: Apache-2.0

// Nova Kata (openstack-nova-kata ADR-058): a volume given to a container
// as a bind mount of its block device at its by-id link (a rescue
// container's, or any without the initial-volume plan) becomes a device of
// the spec at that link, as an initial volume is. rustjail makes its node;
// the creation handshake moves it to the guest kernel's name and links the
// by-id path to it, so that the workload's /dev names every disk alike.

use anyhow::{Context, Result};
use oci_spec::runtime::{LinuxDeviceBuilder, LinuxDeviceType, Spec};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

const BY_ID: &str = "/dev/disk/by-id/";

pub fn by_id_binds_to_devices(spec: &mut Spec) -> Result<()> {
    let Some(mounts) = spec.mounts().clone() else {
        return Ok(());
    };
    let mut kept = Vec::with_capacity(mounts.len());
    let mut devices = Vec::new();
    for mount in mounts {
        let by_id = mount
            .destination()
            .to_str()
            .is_some_and(|d| d.starts_with(BY_ID));
        let source = mount.source().clone().filter(|_| by_id);
        let Some(source) = source else {
            kept.push(mount);
            continue;
        };
        let metadata = std::fs::metadata(&source)
            .with_context(|| format!("stat the block device of {:?}", mount.destination()))?;
        if !metadata.file_type().is_block_device() {
            kept.push(mount);
            continue;
        }
        let readonly = mount
            .options()
            .as_ref()
            .is_some_and(|options| options.iter().any(|o| o == "ro"));
        devices.push(
            LinuxDeviceBuilder::default()
                .path(mount.destination().clone())
                .typ(LinuxDeviceType::B)
                .major(libc::major(metadata.rdev()) as i64)
                .minor(libc::minor(metadata.rdev()) as i64)
                .file_mode(if readonly { 0o440u32 } else { 0o660u32 })
                .uid(0u32)
                .gid(0u32)
                .build()?,
        );
    }
    if devices.is_empty() {
        return Ok(());
    }
    spec.set_mounts(Some(kept));
    let linux = spec.linux_mut().get_or_insert_with(Default::default);
    linux
        .devices_mut()
        .get_or_insert_with(Vec::new)
        .extend(devices);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{MountBuilder, SpecBuilder};

    #[test]
    fn only_a_block_device_at_a_by_id_link_becomes_a_device() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mounts = vec![
            MountBuilder::default()
                .destination("/dev/disk/by-id/virtio-0123abcd-0123-4567-8")
                .typ("bind")
                .source(file.path())
                .build()
                .unwrap(),
            MountBuilder::default()
                .destination("/data")
                .typ("bind")
                .source("/dev/null")
                .build()
                .unwrap(),
        ];
        let mut spec = SpecBuilder::default().mounts(mounts.clone()).build().unwrap();
        by_id_binds_to_devices(&mut spec).unwrap();
        // A regular file there, and a device elsewhere, stay mounts.
        assert_eq!(spec.mounts().as_ref().unwrap(), &mounts);
    }
}
