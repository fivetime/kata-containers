// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

//! Experimental agent-side cgroup-v2 owner. Never restore these handles from JSON.
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Default)]
struct State {
    exec_procs: Option<File>,
    terminating: bool,
    removed: bool,
}

#[derive(Debug)]
pub(crate) struct RetainedCgroup {
    parent: File,
    name: String,
    directory: File,
    procs: File,
    kill: File,
    events: File,
    state: Mutex<State>,
}

pub(crate) fn in_scope(path: &str) -> bool {
    path.starts_with("/openstack/")
}

fn instance_name(path: &str) -> io::Result<&str> {
    let name = path.strip_prefix("/openstack/").unwrap_or("");
    let uuid = name.strip_prefix("nova-").unwrap_or("").as_bytes();
    if uuid.len() != 36
        || !uuid.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
    {
        return Err(Error::other(
            "require canonical /openstack/nova-UUID cgroup",
        ));
    }
    Ok(name)
}

fn parse_empty(data: &[u8]) -> io::Result<bool> {
    let text = std::str::from_utf8(data).map_err(Error::other)?;
    let mut empty = None;
    for line in text.lines() {
        let (key, value) = line
            .split_once(' ')
            .ok_or_else(|| Error::other("malformed cgroup.events"))?;
        if key == "populated" {
            if empty.is_some() {
                return Err(Error::other("duplicate populated observation"));
            }
            empty = Some(match value {
                "0" => true,
                "1" => false,
                _ => return Err(Error::other("invalid populated observation")),
            });
        }
    }
    empty.ok_or_else(|| Error::other("missing populated observation"))
}

fn check_fs(file: &File) -> io::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: owned live descriptor and writable statfs storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the structure.
    if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(Error::other("retained target is not cgroup2"));
    }
    Ok(())
}

fn parse_frozen(data: &[u8]) -> io::Result<bool> {
    let text = std::str::from_utf8(data).map_err(Error::other)?;
    let mut frozen = None;
    for line in text.lines() {
        let (key, value) = line
            .split_once(' ')
            .ok_or_else(|| Error::other("malformed cgroup.events"))?;
        if key == "frozen" {
            if frozen.is_some() {
                return Err(Error::other("duplicate frozen observation"));
            }
            frozen = Some(match value {
                "0" => false,
                "1" => true,
                _ => return Err(Error::other("invalid frozen observation")),
            });
        }
    }
    frozen.ok_or_else(|| Error::other("missing frozen observation"))
}

fn open_at(parent: &File, name: &str, flags: i32) -> io::Result<File> {
    // Every caller supplies one component; no symlinks, parent traversal or
    // descriptor alias paths can escape the original directory.
    if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
        return Err(Error::other("not one child component"));
    }
    let name = CString::new(name)?;
    // SAFETY: owned parent, terminated name, no O_CREAT/variadic mode argument.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    check_fs(&file)?;
    Ok(file)
}

fn mkdir_at(parent: &File, name: &str) -> io::Result<()> {
    let name = CString::new(name)?;
    // SAFETY: constant or previously validated single component and live parent.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn write_control(file: &File, value: &[u8]) -> io::Result<()> {
    if file.write_at(value, 0)? != value.len() {
        return Err(Error::new(
            ErrorKind::WriteZero,
            "short cgroup control write",
        ));
    }
    Ok(())
}

fn remove_child(parent: &File, name: &str, original: &File) -> io::Result<()> {
    let current = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let expected = original.metadata()?;
    let actual = current.metadata()?;
    if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
        return Err(Error::other("cgroup directory was replaced"));
    }
    let name = CString::new(name)?;
    // SAFETY: identity checked child, live parent and AT_REMOVEDIR only. Caller
    // has fenced attachment and observed the owned subtree unpopulated. The
    // guest agent must remain the sole writer outside the tenant subtree.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn remove_descendants(directory: &File, depth: usize, budget: &mut usize) -> io::Result<()> {
    if depth > 64 || *budget == 0 {
        return Err(Error::other("cgroup cleanup traversal bound exceeded"));
    }
    *budget -= 1;
    // This procfs fd alias refers to an owned live descriptor, never a guest
    // pathname or discovered process. cgroupfs does not permit tenant symlinks.
    for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::other("non-UTF8 cgroup child"))?;
            let child = open_at(directory, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            remove_descendants(&child, depth + 1, budget)?;
            remove_child(directory, &name, &child)?;
        }
    }
    Ok(())
}

impl RetainedCgroup {
    /// Only fresh Nova nodes; a pre-existing UUID group is never adopted. Root
    /// is the trusted agent cgroup mount, not a tenant-controlled bind mount.
    pub(crate) fn create(root: &Path, path: &str) -> io::Result<Self> {
        let name = instance_name(path)?.to_owned();
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        check_fs(&root)?;
        if let Err(error) = mkdir_at(&root, "openstack") {
            if error.kind() != ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        let parent = open_at(&root, "openstack", libc::O_RDONLY | libc::O_DIRECTORY)?;
        mkdir_at(&parent, &name)?;
        let directory = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        // No fallback on kernels without kill support. Failure leaves the fresh
        // group for explicit recovery, never deleting an uncertain target.
        let procs = open_at(&directory, "cgroup.procs", libc::O_WRONLY)?;
        let kill = open_at(&directory, "cgroup.kill", libc::O_WRONLY)?;
        let events = open_at(&directory, "cgroup.events", libc::O_RDONLY)?;
        Ok(Self {
            parent,
            name,
            directory,
            procs,
            kill,
            events,
            state: Mutex::default(),
        })
    }

    /// The agent supplies its own not-yet-released child PID during namespace
    /// setup. No PID scan or runtime request PID is accepted here.
    pub(crate) fn attach(&self, pid: i32) -> io::Result<()> {
        if pid <= 0 {
            return Err(Error::other("positive owned child PID required"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::other("cgroup state poisoned"))?;
        if state.terminating {
            return Err(Error::other("cgroup termination already attempted"));
        }
        let pid = pid.to_string();
        match write_control(&self.procs, pid.as_bytes()) {
            Ok(()) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => (),
            Err(error) => return Err(error),
        }
        if state.exec_procs.is_none() {
            // Exclusive creation. A tenant-precreated/replaced leaf is an error,
            // not permission to adopt it or disable subtree controllers.
            mkdir_at(&self.directory, "nova-exec")?;
            let leaf = open_at(
                &self.directory,
                "nova-exec",
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            state.exec_procs = Some(open_at(&leaf, "cgroup.procs", libc::O_WRONLY)?);
        }
        write_control(state.exec_procs.as_ref().unwrap(), pid.as_bytes())
    }

    pub(crate) fn kill_all(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::other("cgroup state poisoned"))?;
        state.terminating = true; // Fence new attachment even after write failure.
        if state.removed {
            return Ok(());
        }
        write_control(&self.kill, b"1")
    }

    // Read only the retained events descriptor. The async caller must keep
    // this owner alive across awaits; neither timeout nor cancellation resets
    // the attachment fence or permits reopening a same-name cgroup.
    pub(crate) fn is_empty(&self) -> io::Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::other("cgroup state poisoned"))?;
        if !state.terminating {
            return Err(Error::other("cgroup termination not attempted"));
        }
        if state.removed {
            return Ok(true);
        }
        self.read_empty()
    }

    fn read_empty(&self) -> io::Result<bool> {
        let mut data = [0u8; 4096];
        let count = self.events.read_at(&mut data, 0)?;
        if count == data.len() {
            return Err(Error::other("cgroup.events too large"));
        }
        parse_empty(&data[..count])
    }

    /// Observe completion, not the requested value in cgroup.freeze. The caller
    /// must serialize resume and keep this original owner across the operation.
    pub(crate) fn is_frozen(&self) -> io::Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::other("cgroup state poisoned"))?;
        if state.terminating || state.removed {
            return Err(Error::other("cgroup is terminating or removed"));
        }
        let mut data = [0u8; 4096];
        let count = self.events.read_at(&mut data, 0)?;
        if count == data.len() {
            return Err(Error::other("cgroup.events too large"));
        }
        parse_frozen(&data[..count])
    }

    /// Positive empty observation plus bounded removal, not a successful-write
    /// inference. No retries against a re-opened same-name root are permitted.
    pub(crate) fn destroy(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::other("cgroup state poisoned"))?;
        state.terminating = true;
        if state.removed {
            return Ok(());
        }
        if !self.read_empty()? {
            return Err(Error::other("original cgroup is still populated"));
        }
        remove_descendants(&self.directory, 0, &mut 4096)?;
        remove_child(&self.parent, &self.name, &self.directory)?;
        state.removed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nova_frozen_requires_explicit_completion_event() {
        assert!(parse_frozen(b"populated 1\nfrozen 1\n").unwrap());
        assert!(!parse_frozen(b"populated 1\nfrozen 0\n").unwrap());
        for data in [
            b"".as_slice(),
            b"populated 0\n",
            b"frozen 1\nfrozen 1\n",
            b"frozen 1\nfrozen 0\n",
            b"frozen 2\n",
            b"frozen 1 \n",
            b"frozen\n",
            b"\xff",
        ] {
            assert!(parse_frozen(data).is_err(), "{data:?}");
        }
    }

    #[test]
    fn empty_requires_one_positive_population_field() {
        assert!(parse_empty(b"populated 0\nfrozen 0\n").unwrap());
        assert!(!parse_empty(b"populated 1\nfrozen 0\n").unwrap());
        for data in [
            b"".as_slice(),
            b"frozen 0\n",
            b"populated 0\npopulated 1\n",
            b"populated 0\npopulated 0\n",
            b"populated 00\n",
            b"populated 2\n",
            b"populated 0 \n",
            b"populated\n",
            b"\xff",
        ] {
            assert!(parse_empty(data).is_err(), "{data:?}");
        }
    }

    #[test]
    fn only_canonical_instance_nodes() {
        assert_eq!(
            instance_name("/openstack/nova-12345678-1234-1234-abcd-123456789abc").unwrap(),
            "nova-12345678-1234-1234-abcd-123456789abc"
        );
        for value in [
            "",
            "/",
            "/openstack",
            "/openstack/nova-../x",
            "/openstack/nova-x",
            "/other/nova-12345678-1234-1234-abcd-123456789abc",
            "/openstack/nova-12345678-1234-1234-ABCD-123456789abc",
            "/openstack/nova-12345678-1234-1234-abcd-123456789abc/child",
        ] {
            assert!(instance_name(value).is_err(), "{value}");
        }
    }

    #[test]
    fn ordinary_filesystem_is_rejected_before_mkdir() {
        assert!(RetainedCgroup::create(
            Path::new("/tmp"),
            "/openstack/nova-12345678-1234-1234-abcd-123456789abc"
        )
        .is_err());
    }
}
