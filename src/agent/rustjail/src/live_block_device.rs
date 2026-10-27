// SPDX-License-Identifier: Apache-2.0
//! Device-node creation for an already opened workload /dev directory.
//! The caller owns device discovery, workload identity, cgroup permissions and
//! request replay. EEXIST is a conflict, never evidence of an earlier request.
use anyhow::{bail, Context, Result};
use std::{ffi::CString, fs::File, io, os::fd::{AsRawFd, FromRawFd}};
use std::{collections::HashMap, os::unix::fs::MetadataExt};
#[path = "live_block_guard.rs"]
mod guard;
#[path = "live_block_created.rs"]
mod created;

#[derive(Debug)]
pub enum DetachAdmission { FreezePending, Busy }
impl std::fmt::Display for DetachAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FreezePending => "block_detach_freeze_pending",
            Self::Busy => "block_device_busy",
        })
    }
}
impl std::error::Error for DetachAdmission {}

#[derive(Debug)]
struct AttachedNode {
    created: bool,
    request: String,
    /// The guest kernel's name of the disk, the node's name in /dev.
    name: String,
    /// Nova Kata (ADR-058): the disk's link in /dev/disk/by-id.
    link: String,
    node: File,
    detach: Option<PendingDetach>,
}

/// Nova Kata (ADR-058): the workload's /dev has each disk at the guest
/// kernel's name, as a libvirt guest's has, and the stable reference of a
/// volume, /dev/disk/by-id/virtio-<first 20 characters of its ID>, links to
/// it. The workload has no udev to make the link. The destination a disk is
/// given by is that link; its name is the kernel's, found once it is
/// resolved.
const BY_ID_PREFIX: &str = "/dev/disk/by-id/";

/// The link's name of a destination, `virtio-` and 20 characters of an ID.
pub fn by_id_link(destination: &str) -> Result<&str> {
    let link = destination.strip_prefix(BY_ID_PREFIX).unwrap_or("");
    let id = link.strip_prefix("virtio-").unwrap_or("");
    if id.len() != 20
        || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-') {
        bail!("invalid block device destination");
    }
    Ok(link)
}

/// The guest kernel's name of a block device, from its sysfs uevent.
pub fn kernel_name(major: u32, minor: u32) -> Result<String> {
    kernel_name_in(&std::fs::read_to_string(format!("/sys/dev/block/{major}:{minor}/uevent"))
        .context("read block device uevent")?)
}

fn kernel_name_in(uevent: &str) -> Result<String> {
    let names: Vec<_> = uevent.lines().filter_map(|line| line.strip_prefix("DEVNAME=")).collect();
    match names.as_slice() {
        [name] if !name.is_empty() && name.len() <= 32
            && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) => Ok(name.to_string()),
        _ => bail!("block device has no plain kernel name"),
    }
}

fn open_directory(parent: &File, name: &str, create: bool) -> Result<File> {
    let cname = CString::new(name)?;
    if create && unsafe { libc::mkdirat(parent.as_raw_fd(), cname.as_ptr(), 0o755) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error).context("create workload device directory");
        }
    }
    let fd = unsafe { libc::openat(parent.as_raw_fd(), cname.as_ptr(),
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 { return Err(io::Error::last_os_error()).context("open workload device directory"); }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn by_id_directory(directory: &File, create: bool) -> Result<File> {
    let disk = open_directory(directory, "disk", create)?;
    open_directory(&disk, "by-id", create)
}

// The target is absolute, /dev/<name>: the tenant image's own link keeper
// (openstack-nova-kata's nova-kata-blockdev, which stands in for udev)
// removes the relative links it does not compute, and leaves these alone.
fn link_in(by: &File, link: &str, name: &str) -> Result<()> {
    let target = CString::new(format!("/dev/{name}"))?;
    let link = CString::new(link)?;
    if unsafe { libc::symlinkat(target.as_ptr(), by.as_raw_fd(), link.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).context("link workload block node");
    }
    Ok(())
}

/// Links `link` in /dev/disk/by-id to the node `name`; an existing entry is
/// a conflict.
pub fn create_link(directory: &File, link: &str, name: &str) -> Result<()> {
    link_in(&by_id_directory(directory, true)?, link, name)
}

/// Nova Kata (ADR-058): the config drive's /dev/disk/by-label link to its
/// loop device, whose name the agent recorded in the spec under `key`.
pub fn create_label_link(directory: &File, spec: &oci_spec::runtime::Spec, key: &str,
                         label: &str) -> Result<()> {
    let Some(name) = spec.annotations().as_ref().and_then(|a| a.get(key)) else { return Ok(()); };
    let number = name.strip_prefix("loop").unwrap_or("");
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid config drive device");
    }
    let disk = open_directory(directory, "disk", true)?;
    link_in(&open_directory(&disk, "by-label", true)?, label, name)
}

/// Removes the link; one that is gone already is removed.
fn remove_link(directory: &File, link: &str) -> Result<()> {
    let by_id = match by_id_directory(directory, false) {
        Ok(by_id) => by_id,
        Err(error) if error.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => return Ok(()),
        Err(error) => return Err(error),
    };
    let link = CString::new(link)?;
    if unsafe { libc::unlinkat(by_id.as_raw_fd(), link.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error).context("remove workload block link");
        }
    }
    Ok(())
}

#[derive(Debug)]
struct PendingDetach {
    request_id: String,
    claim: Option<File>,
    withdrawn: bool,
    complete: bool,
}

#[derive(Debug, Default)]
pub struct BlockDeviceNodes {
    attached: HashMap<String, AttachedNode>,
}

fn open_node(directory: &File, name: &str) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(),
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 { return Err(io::Error::last_os_error()).context("open attached device node"); }
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl BlockDeviceNodes {
    pub fn contains_active(&self, request_id: &str) -> bool {
        self.attached.get(request_id).is_some_and(|node| node.detach.is_none())
    }

    // A paused workload may verify an existing registration, never create one.
    pub fn verify_existing(&mut self, directory: &File, request_id: &str,
        request: &str, link: &str, major: u32, minor: u32) -> Result<()> {
        if !self.contains_active(request_id) { bail!("unknown or detaching block registration"); }
        self.attach(directory, request_id, request, link, major, minor)
    }

    pub fn detach_completed(&self, attach_id: &str, request_id: &str) -> Result<bool> {
        let node = self.attached.get(attach_id).context("unknown block attachment")?;
        match &node.detach {
            Some(pending) if pending.request_id != request_id => bail!("detach request conflicts"),
            Some(pending) => Ok(pending.complete),
            None => Ok(false),
        }
    }

    /// Caller holds completed freeze and serializes resume. Retain the claim
    /// across a lost reply; never recreate a withdrawn node on an uncertain RPC.
    pub fn prepare_detach(&mut self, directory: &File, attach_id: &str, request_id: &str) -> Result<()> {
        if request_id.is_empty() || request_id.len() > 128 { bail!("invalid detach request ID"); }
        let node = self.attached.get_mut(attach_id).context("unknown block attachment")?;
        if let Some(pending) = &node.detach {
            if pending.request_id != request_id { bail!("detach request conflicts with prior operation"); }
            if pending.complete { return Ok(()); }
            if pending.withdrawn {
                match open_node(directory, &node.name) {
                    Err(error) if error.downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => {
                        return remove_link(directory, &node.link);
                    }
                    _ => bail!("withdrawn block device pathname is occupied or unreadable"),
                }
            }
        } else {
            let claim = guard::claim(directory, &node.node, &node.name)?;
            claim.sync_all().context("flush block device before withdrawal")?;
            node.detach = Some(PendingDetach {
                request_id: request_id.into(), claim: Some(claim), withdrawn: false, complete: false,
            });
        }
        let old = node.node.metadata()?;
        let current = open_node(directory, &node.name)?.metadata()?;
        if old.dev() != current.dev() || old.ino() != current.ino() || old.rdev() != current.rdev() {
            bail!("block node identity changed before withdrawal");
        }
        let name = CString::new(node.name.as_str())?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error()).context("withdraw workload block node");
        }
        node.detach.as_mut().unwrap().withdrawn = true;
        remove_link(directory, &node.link)
    }

    /// Only the native runtime's confirmed VMM removal authorizes this phase.
    /// Completion is a tombstone for this attachment, not authority over reuse.
    pub fn complete_detach(&mut self, attach_id: &str, request_id: &str) -> Result<()> {
        let node = self.attached.get_mut(attach_id).context("unknown block attachment")?;
        let pending = node.detach.as_mut().context("detach was not prepared")?;
        if pending.request_id != request_id || !pending.withdrawn { bail!("detach completion conflicts"); }
        pending.claim.take();
        pending.complete = true;
        Ok(())
    }

    /// Requires the caller's completed freeze and sandbox operation lock.
    /// Never unlinks the node or treats admission as completed detach.
    pub fn claim_for_detach(&self, directory: &File, request_id: &str, request: &str) -> Result<File> {
        let prior = self.attached.get(request_id).context("unknown block attachment")?;
        if prior.detach.is_some() { bail!("attachment is detaching or detached"); }
        if prior.request != request { bail!("block attachment identity differs"); }
        guard::claim(directory, &prior.node, &prior.name)
    }

    /// In-memory replay is scoped to this original LinuxContainer. Unknown
    /// existing nodes are never adopted after a lost agent/container state.
    /// The node takes the kernel's name of the disk; `link` is its link in
    /// /dev/disk/by-id.
    pub fn attach(&mut self, directory: &File, request_id: &str, request: &str,
                  link: &str, major: u32, minor: u32) -> Result<()> {
        if request_id.is_empty() || request_id.len() > 128 {
            bail!("invalid block-device request ID");
        }
        let name = kernel_name(major, minor)?;
        let name = name.as_str();
        if let Some(prior) = self.attached.get_mut(request_id) {
            if prior.detach.is_some() { bail!("attachment is detaching or detached"); }
            if (!prior.created && prior.request != request) || prior.name != name || prior.link != link {
                bail!("block-device request conflicts with prior attachment");
            }
            let original = prior.node.metadata()?;
            let current = open_node(directory, name)?.metadata()?;
            if original.dev() != current.dev() || original.ino() != current.ino()
                || current.mode() & libc::S_IFMT != libc::S_IFBLK
                || current.rdev() != libc::makedev(major, minor) {
                bail!("attached device node identity changed");
            }
            // The creation record precedes any AttachBlockDevice RPC. Its first
            // replay binds that RPC only after checking the same original node,
            // request ID, destination and resolved device numbers.
            if prior.created {
                prior.request = request.to_owned();
                prior.created = false;
            }
            return Ok(());
        }
        if self.attached.values().any(|node| node.link == link && node.detach.is_none()) {
            bail!("block-device link is another attachment's");
        }
        create_block_node(directory, name, major, minor)?;
        let node = open_node(directory, name)?;
        let metadata = node.metadata()?;
        if metadata.mode() & libc::S_IFMT != libc::S_IFBLK
            || metadata.rdev() != libc::makedev(major, minor) {
            bail!("new device node changed before registration");
        }
        if let Err(error) = create_link(directory, link, name) {
            // The node is this request's own, made just now: take it back.
            let cname = CString::new(name)?;
            unsafe { libc::unlinkat(directory.as_raw_fd(), cname.as_ptr(), 0) };
            return Err(error);
        }
        self.attached.insert(request_id.to_owned(), AttachedNode {
            request: request.to_owned(), name: name.to_owned(), link: link.to_owned(),
            node, detach: None, created: false,
        });
        Ok(())
    }
}

/// Nova Kata (ADR-058): the workload's root disk in its /dev at the guest
/// kernel's name, as a libvirt guest has its root, so that /proc/mounts,
/// /sys/block and /dev name it alike. A root that is no block device (a
/// shared file system) has none. Called during the creation handshake,
/// before the init child runs tenant code.
pub fn create_root_node(directory: &File, init_pid: i32) -> Result<()> {
    let root = std::fs::metadata(format!("/proc/{init_pid}/root"))
        .context("stat init child root")?;
    let (major, minor) = (libc::major(root.dev()), libc::minor(root.dev()));
    if !std::path::Path::new(&format!("/sys/dev/block/{major}:{minor}")).exists() {
        return Ok(());
    }
    let name = kernel_name(major, minor)?;
    match create_block_node(directory, &name, major, minor) {
        Ok(()) => Ok(()),
        Err(error) if error.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) => {
            let existing = open_node(directory, &name)?.metadata()?;
            if existing.mode() & libc::S_IFMT == libc::S_IFBLK
                && existing.rdev() == libc::makedev(major, minor) {
                Ok(())
            } else {
                bail!("the root disk's name is another node's")
            }
        }
        Err(error) => Err(error),
    }
}

/// Nova Kata (ADR-058): every other block device of the spec at a by-id
/// link (a volume bound into a container without the initial-volume plan,
/// which the agent made a device) moves to the kernel's name, and the link
/// takes its place. Called during the creation handshake after
/// capture_created, whose nodes are links already.
pub fn place_by_id_nodes(directory: &File, spec: &oci_spec::runtime::Spec) -> Result<()> {
    let Some(devices) = spec.linux().as_ref().and_then(|l| l.devices().as_ref()) else {
        return Ok(());
    };
    for device in devices {
        let Some(path) = device.path().to_str() else { continue; };
        if device.typ() != oci_spec::runtime::LinuxDeviceType::B || !path.starts_with(BY_ID_PREFIX) {
            continue;
        }
        let link = by_id_link(path)?;
        let node = open_node(directory, &format!("disk/by-id/{link}"))?;
        let metadata = node.metadata()?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        let (major, minor) = (libc::major(metadata.rdev()), libc::minor(metadata.rdev()));
        if metadata.mode() & libc::S_IFMT != libc::S_IFBLK
            || i64::from(major) != device.major() || i64::from(minor) != device.minor() {
            bail!("the node at a by-id link is not its device");
        }
        created::move_to_kernel_name(directory, link, &kernel_name(major, minor)?)?;
    }
    Ok(())
}

/// Called only during the native init-child creation handshake, before the
/// child is released from its exec FIFO. Never use this to recover by old PID.
pub fn pin_workload_dev(init_pid: i32) -> Result<File> {
    if init_pid <= 0 {
        bail!("invalid init child PID");
    }
    let root = File::open(format!("/proc/{init_pid}/root"))
        .context("open init child root during creation")?;
    let fd = unsafe {
        libc::openat(root.as_raw_fd(), b"dev\0".as_ptr().cast(),
                     libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("pin init child device directory");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Create one root-owned block node without changing the agent's cwd or mount
/// namespace. Only a single basename is accepted; no path traversal is possible.
/// A restrictive process umask may reduce permissions, never increase them.
pub fn create_block_node(dev_directory: &File, name: &str, major: u32, minor: u32) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("block device creation requires the root agent");
    }
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        bail!("invalid block device basename");
    }
    let name = CString::new(name).context("block device basename contains NUL")?;
    if !dev_directory.metadata()?.is_dir() {
        bail!("workload device directory is not a directory");
    }
    let device = libc::makedev(major, minor);
    if libc::major(device) != major || libc::minor(device) != minor {
        bail!("block device number is not representable");
    }
    // mknodat creates the node atomically and refuses all existing entries,
    // including symlinks. It never opens the block device or follows its name.
    let result = unsafe {
        libc::mknodat(dev_directory.as_raw_fd(), name.as_ptr(),
                     libc::S_IFBLK | 0o600, device)
    };
    if result != 0 {
        return Err(io::Error::last_os_error()).context("create workload block node");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_destination_is_a_volumes_by_id_link() {
        assert_eq!(by_id_link("/dev/disk/by-id/virtio-0123abcd-0123-4567-8").unwrap(),
                   "virtio-0123abcd-0123-4567-8");
        for bad in ["/dev/vdb", "/dev/disk/by-id/virtio-0123", "/dev/disk/by-id/scsi-0123abcd-0123-4567-8",
                    "/dev/disk/by-id/virtio-0123ABCD-0123-4567-8",
                    "/dev/disk/by-id/virtio-0123abcd/0123-4567-8"] {
            assert!(by_id_link(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_node_takes_the_kernels_name() {
        assert_eq!(kernel_name_in("MAJOR=254\nMINOR=16\nDEVNAME=vdb\nDEVTYPE=disk\n").unwrap(), "vdb");
        for bad in ["MAJOR=254\n", "DEVNAME=../vdb\n", "DEVNAME=vdb\nDEVNAME=vdc\n", "DEVNAME=\n"] {
            assert!(kernel_name_in(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_link_is_made_and_removed_under_dev() {
        let dev = tempfile::tempdir().unwrap();
        let directory = File::open(dev.path()).unwrap();
        create_link(&directory, "virtio-0123abcd-0123-4567-8", "vdb").unwrap();
        let link = dev.path().join("disk/by-id/virtio-0123abcd-0123-4567-8");
        assert_eq!(std::fs::read_link(&link).unwrap(), std::path::Path::new("/dev/vdb"));
        assert!(create_link(&directory, "virtio-0123abcd-0123-4567-8", "vdc").is_err());
        remove_link(&directory, "virtio-0123abcd-0123-4567-8").unwrap();
        remove_link(&directory, "virtio-0123abcd-0123-4567-8").unwrap();
        assert!(link.symlink_metadata().is_err());
    }
}
