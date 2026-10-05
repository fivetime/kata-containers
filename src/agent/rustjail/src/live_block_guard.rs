// SPDX-License-Identifier: Apache-2.0
//! Admission only: caller must hold completed workload freeze and serialize
//! resume. A returned file is not proof of device removal or storage release.
use anyhow::{bail, Context, Result};
use std::{collections::HashSet, ffi::CString, fs::{self, File}, io,
          os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}, path::Path};

fn device_number(path: &Path) -> Result<u64> {
    let text = fs::read_to_string(path)?;
    let (major, minor) = text.trim().split_once(':').context("invalid sysfs device number")?;
    let (major, minor) = (major.parse::<u32>()?, minor.parse::<u32>()?);
    let value = libc::makedev(major, minor);
    if libc::major(value) != major || libc::minor(value) != minor {
        bail!("sysfs device number not representable");
    }
    Ok(value)
}

fn family(device: u64) -> Result<HashSet<u64>> {
    let path = fs::canonicalize(format!("/sys/dev/block/{}:{}", libc::major(device), libc::minor(device)))?;
    if !path.starts_with("/sys/devices") || device_number(&path.join("dev"))? != device {
        bail!("block sysfs identity differs");
    }
    let mut result = HashSet::from([device]);
    for entry in fs::read_dir(&path)? {
        let entry = entry?;
        // Sysfs mixes attribute files and directories. Only actual child
        // directories can represent partitions; never traverse link targets.
        if !entry.file_type()?.is_dir() { continue; }
        let child = entry.path();
        match fs::metadata(child.join("partition")) {
            Ok(_) => { result.insert(device_number(&child.join("dev"))?); }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(result)
}

fn flags(path: &Path) -> Result<u32> {
    let text = fs::read_to_string(path)?;
    let values: Vec<_> = text.lines().filter_map(|line| line.strip_prefix("flags:")) .collect();
    if values.len() != 1 { bail!("missing or duplicate descriptor flags"); }
    Ok(u32::from_str_radix(values[0].trim(), 8)?)
}

fn numeric(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

fn handles(devices: &HashSet<u64>, claim: &File) -> Result<()> {
    let own = std::process::id().to_string();
    let own_fd = claim.as_raw_fd().to_string();
    // Inspect task-specific tables as a thread can unshare its descriptor table.
    for process in fs::read_dir("/proc")? {
        let process = process?;
        if !numeric(&process.file_name()) { continue; }
        let tasks = match fs::read_dir(process.path().join("task")) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        for task in tasks {
            let task = task?;
            if !numeric(&task.file_name()) { continue; }
            let descriptors = match fs::read_dir(task.path().join("fd")) {
                Ok(entries) => entries,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            for descriptor in descriptors {
                let descriptor = descriptor?;
                if process.file_name() == own.as_str() && descriptor.file_name() == own_fd.as_str() {
                    continue; // This agent's admission claim, shared by its worker threads.
                }
                let metadata = match fs::metadata(descriptor.path()) {
                    Ok(metadata) => metadata,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                if metadata.mode() & libc::S_IFMT != libc::S_IFBLK || !devices.contains(&metadata.rdev()) {
                    continue;
                }
                let info = task.path().join("fdinfo").join(descriptor.file_name());
                let mode = flags(&info)?;
                if mode & libc::O_PATH as u32 == 0 {
                    return Err(super::DetachAdmission::Busy.into());
                }
            }
        }
    }
    Ok(())
}

pub(super) fn claim(directory: &File, original: &File, name: &str) -> Result<File> {
    let old = original.metadata()?;
    if old.mode() & libc::S_IFMT != libc::S_IFBLK { bail!("original is not a block node"); }
    let name = CString::new(name)?;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(),
        libc::O_RDONLY | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBUSY) {
            return Err(super::DetachAdmission::Busy.into());
        }
        return Err(error).context("claim block device for detach");
    }
    let claim = unsafe { File::from_raw_fd(fd) };
    let now = claim.metadata()?;
    if now.dev() != old.dev() || now.ino() != old.ino() || now.rdev() != old.rdev()
        || now.mode() & libc::S_IFMT != libc::S_IFBLK {
        bail!("block node replaced before detach admission");
    }
    let devices = family(now.rdev())?;
    handles(&devices, &claim)?;
    if family(now.rdev())? != devices { bail!("block partition topology changed"); }
    Ok(claim)
}
