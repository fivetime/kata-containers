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
    name: String,
    node: File,
    detach: Option<PendingDetach>,
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
        request: &str, name: &str, major: u32, minor: u32) -> Result<()> {
        if !self.contains_active(request_id) { bail!("unknown or detaching block registration"); }
        self.attach(directory, request_id, request, name, major, minor)
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
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => return Ok(()),
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
        Ok(())
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
    pub fn attach(&mut self, directory: &File, request_id: &str, request: &str,
                  name: &str, major: u32, minor: u32) -> Result<()> {
        if request_id.is_empty() || request_id.len() > 128 {
            bail!("invalid block-device request ID");
        }
        if let Some(prior) = self.attached.get_mut(request_id) {
            if prior.detach.is_some() { bail!("attachment is detaching or detached"); }
            if (!prior.created && prior.request != request) || prior.name != name {
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
        create_block_node(directory, name, major, minor)?;
        let node = open_node(directory, name)?;
        let metadata = node.metadata()?;
        if metadata.mode() & libc::S_IFMT != libc::S_IFBLK
            || metadata.rdev() != libc::makedev(major, minor) {
            bail!("new device node changed before registration");
        }
        self.attached.insert(request_id.to_owned(), AttachedNode {
            request: request.to_owned(), name: name.to_owned(), node, detach: None, created: false,
        });
        Ok(())
    }
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
