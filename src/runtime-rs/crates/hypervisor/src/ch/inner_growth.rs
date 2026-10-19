// Copyright 2026 OpenStack Nova Kata contributors
//
// SPDX-License-Identifier: Apache-2.0

// Nova Kata: the growth of a raw block device under Cloud Hypervisor, as
// under QEMU and Dragonball (openstack-nova-kata ADR-033).

use super::inner::CloudHypervisorInner;
use crate::device::DeviceType;
use anyhow::{anyhow, Context, Result};
use ch_config::ch_api::{cloud_hypervisor_vm_info, cloud_hypervisor_vm_resize_disk};

nix::ioctl_read!(growth_block_size, 0x12, 114, u64);

fn validate_growth_device(device: &crate::BlockDeviceModern) -> Result<()> {
    if device.device_id.is_empty()
        || device.attach_count != 1
        || device.config.is_readonly
        || device.config.vmdk.is_some()
        || device.config.major < 0
        || device.config.minor < 0
    {
        return Err(anyhow!(
            "block growth requires one attached writable raw device with known identity"
        ));
    }
    Ok(())
}

/// The VMM is shown the host device's size, which its owner made: a stale
/// or unaligned request is refused before the VMM is asked.
fn validate_growth_size(host_bytes: u64, requested: u64) -> Result<()> {
    if requested == 0 || requested % 512 != 0 {
        return Err(anyhow!(
            "block growth requires positive sector-aligned capacity"
        ));
    }
    if host_bytes != requested {
        return Err(anyhow!("host capacity differs from requested block growth"));
    }
    Ok(())
}

impl CloudHypervisorInner {
    /// Show the guest the new size of a raw block device whose host device
    /// its owner grew. The size must be the host device's own; the storage
    /// is never resized here.
    pub(crate) async fn grow_block_device(
        &mut self,
        device: DeviceType,
        requested: u64,
    ) -> Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
        let DeviceType::BlockModern(shared) = device else {
            return Err(anyhow!("block growth unsupported for this device type"));
        };
        let device = shared.lock().await;
        validate_growth_device(&device)?;
        let source = &device.config.path_on_host;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_block_device()
            || libc::major(metadata.rdev()) as i64 != device.config.major
            || libc::minor(metadata.rdev()) as i64 != device.config.minor
        {
            return Err(anyhow!("block growth host device identity changed"));
        }
        let mut host_bytes = 0_u64;
        unsafe { growth_block_size(file.as_raw_fd(), &mut host_bytes) }
            .context("read owned host block capacity")?;
        validate_growth_size(host_bytes, requested)?;
        // The VMM's name of the disk: recorded when it was added, else (a
        // disk the VM booted or was migrated with) found by its path.
        let id = match self.device_ids.get(&device.device_id) {
            Some(id) => id.clone(),
            None => {
                let info = cloud_hypervisor_vm_info(&self.api_socket)
                    .await
                    .context("read the disks of the VM")?;
                let named: Vec<String> = info
                    .config
                    .disks
                    .iter()
                    .flatten()
                    .filter(|disk| disk.path.as_deref() == Some(std::path::Path::new(source)))
                    .filter_map(|disk| disk.id.clone())
                    .collect();
                match named.as_slice() {
                    [id] => id.clone(),
                    _ => {
                        return Err(anyhow!(
                            "block growth: the VMM has not one disk of the device"
                        ))
                    }
                }
            }
        };
        cloud_hypervisor_vm_resize_disk(&self.api_socket, &id, requested)
            .await
            .context("cloud hypervisor block growth outcome may be uncertain; retain attachment")?;
        Ok(())
    }
}

#[cfg(test)]
mod nova_block_growth_ch_tests {
    use super::*;

    fn attached() -> crate::BlockDeviceModern {
        crate::BlockDeviceModern {
            device_id: "owned".into(),
            attach_count: 1,
            config: crate::BlockConfigModern {
                major: 252,
                minor: 1,
                ..Default::default()
            },
        }
    }

    #[test]
    fn nova_block_growth_ch_admits_one_writable_raw_device() {
        assert!(validate_growth_device(&attached()).is_ok());
        let mut device = attached();
        device.attach_count = 2;
        assert!(validate_growth_device(&device).is_err());
        let mut device = attached();
        device.config.is_readonly = true;
        assert!(validate_growth_device(&device).is_err());
        let mut device = attached();
        device.device_id.clear();
        assert!(validate_growth_device(&device).is_err());
        let mut device = attached();
        device.config.minor = -1;
        assert!(validate_growth_device(&device).is_err());
    }

    #[test]
    fn nova_block_growth_ch_takes_the_host_size_only() {
        assert!(validate_growth_size(2 << 30, 2 << 30).is_ok());
        assert!(validate_growth_size(2 << 30, 1 << 30).is_err());
        assert!(validate_growth_size(2 << 30, (2 << 30) + 512).is_err());
        assert!(validate_growth_size(1000, 1000).is_err());
        assert!(validate_growth_size(0, 0).is_err());
    }
}
