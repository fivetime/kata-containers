// Copyright 2026 OpenStack Nova Kata contributors
//
// SPDX-License-Identifier: Apache-2.0

// Nova Kata (openstack-nova-kata ADR-058): the config drive is no disk. The
// runtime hands the container its ISO as a read-only file mount at
// /config-drive; the agent attaches the file read-only to two loop devices
// of the guest. One is mounted where the mount was, as before; the other is
// a device of the workload's /dev at its kernel name, which
// /dev/disk/by-label/config-2 links to, as a libvirt guest finds its config
// drive CD-ROM. The mount needs a device of its own: a second mount without
// "-o ro" of a device already mounted read-only fails with EBUSY, while on a
// read-only device of its own it fails with EACCES and mount(8) retries
// read-only, as on a libvirt guest. The loops are the VM's: a Nova sandbox
// has one container, and they go with it.

use anyhow::{anyhow, bail, Context, Result};
use nix::mount::MsFlags;
use oci_spec::runtime::{LinuxDeviceBuilder, LinuxDeviceType, Mount, Spec};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

pub const DESTINATION: &str = "/config-drive";
/// The spec's record, for rustjail, of the loop device the label links to.
pub const NODE_KEY: &str = "io.openstack.nova.kata.config-drive-node.v1";
pub const LABEL: &str = "config-2";
const MOUNT_DIR: &str = "/run/kata-containers/config-drive";

const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A;
const LO_FLAGS_READ_ONLY: u32 = 1;
const LOOP_MAJOR: i64 = 7;

#[repr(C)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; 64],
    lo_crypt_name: [u8; 64],
    lo_encrypt_key: [u8; 32],
    lo_init: [u64; 2],
}

#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo64,
    reserved: [u64; 8],
}

/// Attaches `file` read-only to a free loop device; its minor number.
fn attach_loop(file: &File) -> Result<u32> {
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
        .context("open loop-control")?;
    // Another attach may take the free device first: ask again.
    for _ in 0..8 {
        let minor = unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE as _) };
        if minor < 0 {
            return Err(std::io::Error::last_os_error()).context("find a free loop device");
        }
        let device = OpenOptions::new()
            .read(true)
            .open(format!("/dev/loop{minor}"))
            .with_context(|| format!("open loop{minor}"))?;
        let mut config: LoopConfig = unsafe { std::mem::zeroed() };
        config.fd = file.as_raw_fd() as u32;
        config.info.lo_flags = LO_FLAGS_READ_ONLY;
        let name = b"config-2";
        config.info.lo_file_name[..name.len()].copy_from_slice(name);
        if unsafe { libc::ioctl(device.as_raw_fd(), LOOP_CONFIGURE as _, &config) } == 0 {
            return Ok(minor as u32);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBUSY) {
            return Err(error).with_context(|| format!("attach the config drive to loop{minor}"));
        }
    }
    bail!("no free loop device for the config drive")
}

/// Turns the container's config drive mount, if it has one, into a mount
/// of the ISO through a loop device and a loop device of its /dev.
pub fn prepare(cid: &str, spec: &mut Spec) -> Result<()> {
    let Some(mounts) = spec.mounts_mut().as_mut() else {
        return Ok(());
    };
    let found: Vec<usize> = mounts
        .iter()
        .enumerate()
        .filter(|(_, m)| m.destination() == Path::new(DESTINATION))
        .map(|(index, _)| index)
        .collect();
    let index = match found.as_slice() {
        [] => return Ok(()),
        [index] => *index,
        _ => bail!("config drive: more than one mount at {DESTINATION}"),
    };
    let mount = &mounts[index];
    let source = mount
        .source()
        .clone()
        .ok_or_else(|| anyhow!("config drive: the mount has no source"))?;
    // A directory there is a config drive of another kind; it stays as it is.
    if mount.typ().as_deref() != Some("bind") || !source.is_file() {
        return Ok(());
    }
    if !mount
        .options()
        .as_ref()
        .is_some_and(|options| options.iter().any(|o| o == "ro"))
    {
        bail!("config drive: the mount is not read-only");
    }
    let file = File::open(&source).context("config drive: open the ISO")?;

    let mounted = attach_loop(&file)?;
    let target = Path::new(MOUNT_DIR).join(cid);
    fs::create_dir_all(&target).context("config drive: mount point")?;
    nix::mount::mount(
        Some(Path::new(&format!("/dev/loop{mounted}"))),
        &target,
        Some("iso9660"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("config drive: mount the ISO")?;
    let mut bind = Mount::default();
    bind.set_destination(DESTINATION.into());
    bind.set_typ(Some("bind".to_string()));
    bind.set_source(Some(target));
    bind.set_options(Some(
        ["rbind", "ro", "nosuid", "nodev", "noexec"]
            .iter()
            .map(|o| o.to_string())
            .collect(),
    ));
    mounts[index] = bind;

    let node = attach_loop(&file)?;
    let device = fs::metadata(format!("/dev/loop{node}"))?;
    if !device.file_type().is_block_device() || libc::minor(device.rdev()) != node {
        bail!("config drive: loop{node} is not that loop device");
    }
    let linux = spec.linux_mut().get_or_insert_with(Default::default);
    let devices = linux.devices_mut().get_or_insert_with(Vec::new);
    let path = format!("/dev/loop{node}");
    if devices.iter().any(|d| d.path() == Path::new(&path)) {
        bail!("config drive: the container has a device at {path}");
    }
    devices.push(
        LinuxDeviceBuilder::default()
            .path(path)
            .typ(LinuxDeviceType::B)
            .major(LOOP_MAJOR)
            .minor(node as i64)
            .file_mode(0o440u32)
            .uid(0u32)
            .gid(0u32)
            .build()?,
    );
    spec.annotations_mut()
        .get_or_insert_with(Default::default)
        .insert(NODE_KEY.to_string(), format!("loop{node}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{MountBuilder, SpecBuilder};

    fn spec(mount: Mount) -> Spec {
        SpecBuilder::default().mounts(vec![mount]).build().unwrap()
    }

    #[test]
    fn a_spec_without_a_file_config_drive_is_unchanged() {
        let mut empty = SpecBuilder::default().mounts(vec![]).build().unwrap();
        prepare("c", &mut empty).unwrap();
        assert!(empty.mounts().as_ref().unwrap().is_empty());

        let dir = tempfile::tempdir().unwrap();
        let directory = MountBuilder::default()
            .destination(DESTINATION)
            .typ("bind")
            .source(dir.path())
            .options(vec!["rbind".to_string(), "ro".to_string()])
            .build()
            .unwrap();
        let mut with_directory = spec(directory.clone());
        prepare("c", &mut with_directory).unwrap();
        assert_eq!(with_directory.mounts().as_ref().unwrap()[0], directory);
    }

    #[test]
    fn a_writable_config_drive_is_refused() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mount = MountBuilder::default()
            .destination(DESTINATION)
            .typ("bind")
            .source(file.path())
            .options(vec!["rbind".to_string(), "rw".to_string()])
            .build()
            .unwrap();
        assert!(prepare("c", &mut spec(mount)).is_err());
    }
}
