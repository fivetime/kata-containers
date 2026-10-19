// Copyright 2026 OpenStack Nova Kata contributors
//
// SPDX-License-Identifier: Apache-2.0

// Nova Kata (openstack-nova-kata ADR-032): ResizeVolume grows online the
// ext4 filesystem of a container's root to its block device, which the
// runtime has just shown the guest grown. Only a container's root under the
// shared containers directory is grown; it never shrinks.

use anyhow::{anyhow, bail, Context, Result};
use std::os::fd::AsRawFd;
use std::path::{Component, Path};
use std::time::Duration;

nix::ioctl_read!(blk_get_size64, 0x12, 114, u64);
nix::ioctl_write_ptr!(ext4_resize_fs, b'f', 16, u64);

const SHARED_CONTAINERS: &str = "/run/kata-containers/shared/containers/";
// The guest learns a grown disk from a configuration change interrupt, which
// its virtio-blk driver handles after the VMM has replied.
const DEVICE_GROWTH_WAIT: Duration = Duration::from_secs(10);
const DEVICE_GROWTH_POLL: Duration = Duration::from_millis(100);

fn validate(path: &str, size: u64) -> Result<()> {
    let guest = Path::new(path);
    if !guest.is_absolute()
        || guest
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || !path.starts_with(SHARED_CONTAINERS)
        || !path.ends_with("/rootfs")
    {
        bail!("resize_volume: only a container's root is grown, not {path}");
    }
    if size == 0 || size % 512 != 0 {
        bail!("resize_volume: {size} is not a positive sector-aligned size");
    }
    Ok(())
}

/// The number of filesystem blocks of `size` bytes; a partial block is not
/// used, as resize2fs does.
fn blocks_of(size: u64, block_size: u64) -> Result<u64> {
    if block_size == 0 || !block_size.is_power_of_two() {
        bail!("resize_volume: invalid filesystem block size {block_size}");
    }
    Ok(size / block_size)
}

fn device_size(device: &std::fs::File) -> Result<u64> {
    let mut bytes = 0_u64;
    unsafe { blk_get_size64(device.as_raw_fd(), &mut bytes) }
        .context("resize_volume: read the device size")?;
    Ok(bytes)
}

pub async fn resize_volume(path: &str, size: u64) -> Result<()> {
    validate(path, size)?;
    let mount = kata_sys_util::mount::get_linux_mount_info(path)
        .map_err(|e| anyhow!("resize_volume: {path} is not mounted: {e}"))?;
    if mount.fs_type != "ext4" {
        bail!("resize_volume: {path} is {}, not ext4", mount.fs_type);
    }
    let device = std::fs::File::open(&mount.device)
        .with_context(|| format!("resize_volume: open {}", mount.device))?;
    let deadline = tokio::time::Instant::now() + DEVICE_GROWTH_WAIT;
    loop {
        let device_bytes = device_size(&device)?;
        if device_bytes >= size {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("resize_volume: the device has {device_bytes} bytes, not {size}");
        }
        tokio::time::sleep(DEVICE_GROWTH_POLL).await;
    }
    let root = std::fs::File::open(path).with_context(|| format!("resize_volume: open {path}"))?;
    let stat = nix::sys::statfs::fstatfs(&root).context("resize_volume: statfs")?;
    let blocks = blocks_of(size, stat.block_size() as u64)?;
    // The kernel grows a mounted ext4 itself; the same size again is nothing
    // to do, a smaller one is refused.
    unsafe { ext4_resize_fs(root.as_raw_fd(), &blocks) }
        .with_context(|| format!("resize_volume: grow {path} to {blocks} blocks"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_container_root_is_grown() {
        let root = "/run/kata-containers/shared/containers/abc/rootfs";
        assert!(validate(root, 1 << 30).is_ok());
        for path in [
            "/run/kata-containers/shared/containers/abc/rootfs/../x/rootfs",
            "/run/kata-containers/sandbox/storage/abc",
            "run/kata-containers/shared/containers/abc/rootfs",
            "/",
        ] {
            assert!(validate(path, 1 << 30).is_err(), "{path}");
        }
        assert!(validate(root, 0).is_err());
        assert!(validate(root, 1000).is_err());
    }

    #[test]
    fn blocks_are_whole() {
        assert_eq!(blocks_of(12 << 30, 4096).unwrap(), 3 << 20);
        assert_eq!(blocks_of((1 << 30) + 1024, 4096).unwrap(), 1 << 18);
        assert!(blocks_of(1 << 30, 0).is_err());
        assert!(blocks_of(1 << 30, 3000).is_err());
    }
}
