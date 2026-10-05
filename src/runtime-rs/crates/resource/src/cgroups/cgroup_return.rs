// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

//! Return only this shim to its original cgroup after the VMM has stopped.
//! The retained descriptor is not persisted. It is reopened by pathname only
//! when systemd removed and recreated the original group: a service leaf
//! (containerd.service) that emptied when its daemon restarted, since the
//! shim had already left it. systemd names that path for that unit only.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Error, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) struct CgroupReturn {
    procs: File,
    path: PathBuf,
    creator_pid: u32,
}

fn original_path(membership: &str) -> io::Result<PathBuf> {
    let mut v2 = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"));
    let path = v2
        .next()
        .ok_or_else(|| Error::other("missing cgroup v2 membership"))?;
    if v2.next().is_some()
        || !path.starts_with('/')
        || path == "/"
        || path[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.contains('\0')
    {
        return Err(Error::other(
            "original cgroup must be one canonical non-root v2 group",
        ));
    }
    Ok(PathBuf::from("/sys/fs/cgroup")
        .join(&path[1..])
        .join("cgroup.procs"))
}

/// Only a systemd service leaf may be reopened after its group was removed.
fn reopenable(procs: &Path) -> bool {
    procs
        .parent()
        .and_then(|dir| dir.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.len() > ".service".len() && name.ends_with(".service"))
}

fn open_procs(path: &Path) -> io::Result<File> {
    let procs = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: procs owns a live fd and stat is writable storage of the
    // required size. Read the result only after fstatfs reports success.
    if unsafe { libc::fstatfs(procs.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized stat above.
    if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(Error::other("original cgroup descriptor is not cgroup2"));
    }
    Ok(procs)
}

fn write_pid(procs: &File, pid: u32) -> io::Result<()> {
    let value = format!("{}\n", pid);
    if procs.write_at(value.as_bytes(), 0)? != value.len() {
        return Err(Error::new(
            ErrorKind::WriteZero,
            "short cgroup membership write",
        ));
    }
    Ok(())
}

impl CgroupReturn {
    /// Capture BEFORE joining a sandbox/overhead group, in the shim's existing
    /// trusted service/delegation leaf. Refuse a namespace-root fallback.
    pub(crate) fn capture() -> io::Result<Self> {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let path = original_path(&membership)?;
        Ok(Self {
            procs: open_procs(&path)?,
            path,
            creator_pid: std::process::id(),
        })
    }

    /// Caller must already have stopped/waited for the VMM and its helpers.
    /// Do not move any child, guessed PID, parent group, or replacement path.
    /// A removed original group (ENODEV) is reopened once by its path only
    /// when it is a systemd service leaf; anything else fails.
    pub(crate) fn restore_self(&self) -> io::Result<()> {
        if self.creator_pid != std::process::id() {
            return Err(Error::other(
                "cgroup return descriptor belongs to another process",
            ));
        }
        match write_pid(&self.procs, self.creator_pid) {
            Err(err) if err.raw_os_error() == Some(libc::ENODEV) && reopenable(&self.path) => {
                write_pid(&open_procs(&self.path)?, self.creator_pid)
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_service_leaf_only() {
        assert_eq!(
            original_path("0::/system.slice/containerd.service\n").unwrap(),
            PathBuf::from("/sys/fs/cgroup/system.slice/containerd.service/cgroup.procs")
        );
        for value in [
            "",
            "1:cpu:/service\n",
            "0::/\n",
            "0::relative\n",
            "0::/a//b\n",
            "0::/a/../b\n",
            "0::/a/.\n",
            "0::/a/\n",
            "0::/a\n0::/b\n",
            "0::/a\0b\n",
        ] {
            assert!(original_path(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn only_a_service_leaf_is_reopened() {
        for (value, want) in [
            ("0::/system.slice/containerd.service\n", true),
            ("0::/system.slice/containerd.service/shim\n", false),
            ("0::/user.slice/user-0.slice/session-1.scope\n", false),
            ("0::/system.slice\n", false),
            ("0::/.service\n", false),
        ] {
            assert_eq!(
                reopenable(&original_path(value).unwrap()),
                want,
                "{value:?}"
            );
        }
    }
}
