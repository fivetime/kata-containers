// SPDX-License-Identifier: Apache-2.0
//! Register only nodes from this init child's creation spec before exec release.
//! This is not adoption of an existing running container or agent recovery.
use super::{by_id_link, create_link, kernel_name, AttachedNode, BlockDeviceNodes, open_node};
use anyhow::{bail, Context, Result};
use oci_spec::runtime::{LinuxDeviceType, Spec};
use serde::Deserialize;
use std::{collections::HashSet, convert::TryFrom, ffi::CString, fs::File, io,
          os::{fd::AsRawFd, unix::fs::MetadataExt}};

pub const CREATED_KEY: &str = "io.katacontainers.block-attachments.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatedAttachment {
    request_id: String,
    destination: String,
}

fn canonical_request(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36 && bytes.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { *byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(byte) }
    }) && (b'1'..=b'5').contains(&bytes[14]) && b"89ab".contains(&bytes[19])
}

impl BlockDeviceNodes {
    /// The caller must hold the creation handshake: the init child has finished
    /// creating /dev but cannot execute tenant code yet. Return the entire new
    /// registry atomically; failures neither unlink nor recreate any node.
    pub fn capture_created(directory: &File, spec: &Spec) -> Result<Self> {
        let mut result = Self::default();
        let Some(annotations) = spec.annotations() else { return Ok(result); };
        let keys: Vec<_> = annotations.keys()
            .filter(|key| key.starts_with("io.katacontainers.block-attachments.")).collect();
        if keys.is_empty() { return Ok(result); }
        if keys.len() != 1 || keys[0] != CREATED_KEY { bail!("unknown block creation protocol"); }
        let text = &annotations[CREATED_KEY];
        if text.len() > 65536 { bail!("block creation list too large"); }
        let entries: Vec<CreatedAttachment> = serde_json::from_str(text)
            .context("invalid block creation list")?;
        if entries.len() > 128 { bail!("too many created block attachments"); }
        if entries.is_empty() { return Ok(result); }
        let devices = spec.linux().as_ref().and_then(|linux| linux.devices().as_ref())
            .context("created block device spec missing")?;
        let mut names = HashSet::new();
        let mut requests = HashSet::new();
        for entry in entries {
            let link = by_id_link(&entry.destination).unwrap_or("");
            if !canonical_request(&entry.request_id) || link.is_empty()
                || !names.insert(entry.destination.clone()) || !requests.insert(entry.request_id.clone()) {
                bail!("invalid or duplicate created attachment identity");
            }
            let matching: Vec<_> = devices.iter()
                .filter(|device| device.path().to_str() == Some(entry.destination.as_str())).collect();
            if matching.len() != 1 || matching[0].typ() != LinuxDeviceType::B {
                bail!("created attachment lacks one exact OCI block device");
            }
            let major = u32::try_from(matching[0].major()).context("invalid created major")?;
            let minor = u32::try_from(matching[0].minor()).context("invalid created minor")?;
            // Nova Kata (ADR-058): the node made at the destination, the
            // by-id link, moves to the kernel's name of the disk, and the
            // link takes its place. The init child runs no tenant code yet.
            let name = kernel_name(major, minor)?;
            let name = name.as_str();
            move_to_kernel_name(directory, link, name)?;
            let node = open_node(directory, name)?;
            let actual = node.metadata()?;
            if actual.mode() & libc::S_IFMT != libc::S_IFBLK || actual.rdev() != libc::makedev(major, minor) {
                bail!("created block node differs from resolved OCI device");
            }
            result.attached.insert(entry.request_id.clone(), AttachedNode {
                request: format!("created:{}:{}:{}:{}", entry.request_id, entry.destination, major, minor),
                name: name.into(), link: link.into(), node, detach: None, created: true,
            });
        }
        Ok(result)
    }
}

/// Renames the node at /dev/disk/by-id/`link` to /dev/`name` and links the
/// former to the latter. A node already at `name` is a conflict.
fn move_to_kernel_name(directory: &File, link: &str, name: &str) -> Result<()> {
    if name.is_empty() || name.contains('/') { bail!("invalid kernel name"); }
    let from = CString::new(format!("disk/by-id/{link}"))?;
    let to = CString::new(name)?;
    // renameat2 with RENAME_NOREPLACE: an existing /dev/<name> is refused.
    let result = unsafe {
        libc::syscall(libc::SYS_renameat2, directory.as_raw_fd(), from.as_ptr(),
                      directory.as_raw_fd(), to.as_ptr(), libc::RENAME_NOREPLACE)
    };
    if result != 0 {
        return Err(io::Error::last_os_error()).context("move created block node to its kernel name");
    }
    create_link(directory, link, name)
}
