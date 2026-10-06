// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

//! Nova share attachments (ADR-045). The sandbox container's OCI spec names
//! host directories, each already mounted by the gateway, that the guest gets
//! as one virtio-fs device with Nova's tag. The guest mounts a tag itself;
//! runtime-rs neither hotplugs these devices nor tells the agent about them.
//! An absent annotation changes nothing.

use std::{
    collections::{HashMap, HashSet},
    os::unix::fs::FileTypeExt,
    path::Path,
    process::Stdio,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use tokio::{
    process::Command,
    sync::{mpsc::channel, Mutex, RwLock},
};

use hypervisor::{
    device::{
        device_manager::{do_handle_device, DeviceManager},
        DeviceConfig,
    },
    Hypervisor, ShareFsConfig,
};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use kata_types::{
    config::hypervisor::{HYPERVISOR_NAME_CH, HYPERVISOR_NAME_DRAGONBALL, HYPERVISOR_NAME_QEMU},
    rootless::is_rootless,
};

use super::{
    kata_host_shared_dir,
    share_virtio_fs::MOUNT_GUEST_TAG,
    share_virtio_fs_standalone::{virtiofsd_base_args, VirtiofsProcess},
    VIRTIO_FS,
};

/// The OCI annotation on the sandbox container that requests shares.
pub const SHARES_KEY: &str = "io.katacontainers.shares.v1";
const SHARES_PREFIX: &str = "io.katacontainers.shares.";
const MAX_TEXT: usize = 65536;
const MAX_SHARES: usize = 32;
// The RLIMIT_NOFILE of a share's virtiofsd, the gateway's part of the
// instance's budget: every file the guest has open on the share is a host
// file handle, which reaches the neighbours.
const MIN_MAX_FILES: u64 = 256;
const MAX_MAX_FILES: u64 = 1 << 20;
/// The tag field of the virtio-fs device configuration is 36 bytes.
const MAX_TAG: usize = 36;
/// sun_path holds 108 bytes including the terminating NUL.
const MAX_SOCKET_PATH: usize = 107;
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// One requested share: the guest tag and the host directory it exports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NovaShare {
    pub tag: String,
    pub source: String,
    pub max_files: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    tag: String,
    source: String,
    max_files: u64,
}

/// Parse and audit the share request of a sandbox container's annotations.
pub fn parse(annotations: &HashMap<String, String>) -> Result<Vec<NovaShare>> {
    let keys: Vec<_> = annotations
        .keys()
        .filter(|key| key.starts_with(SHARES_PREFIX))
        .collect();
    if keys.is_empty() {
        return Ok(vec![]);
    }
    if keys.len() != 1 || keys[0] != SHARES_KEY {
        bail!("share_invalid: unknown share protocol");
    }
    let text = &annotations[SHARES_KEY];
    if text.len() > MAX_TEXT {
        bail!("share_invalid: share list too large");
    }
    let entries: Vec<Entry> = serde_json::from_str(text)
        .map_err(|error| anyhow!("share_invalid: malformed share list: {}", error))?;
    if entries.len() > MAX_SHARES {
        bail!("share_invalid: too many shares");
    }
    let mut tags = HashSet::new();
    let mut sources = HashSet::new();
    let mut shares = Vec::with_capacity(entries.len());
    for entry in entries {
        validate_tag(&entry.tag)?;
        validate_source(&entry.source)?;
        if !tags.insert(entry.tag.clone()) {
            bail!("share_invalid: duplicate tag {:?}", entry.tag);
        }
        if !sources.insert(entry.source.clone()) {
            bail!("share_invalid: duplicate source {:?}", entry.source);
        }
        if !(MIN_MAX_FILES..=MAX_MAX_FILES).contains(&entry.max_files) {
            bail!("share_invalid: max_files {} out of range", entry.max_files);
        }
        shares.push(NovaShare {
            tag: entry.tag,
            source: entry.source,
            max_files: entry.max_files,
        });
    }
    Ok(shares)
}

fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty()
        || tag.len() > MAX_TAG
        || !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("share_invalid: invalid tag {:?}", tag);
    }
    if tag == MOUNT_GUEST_TAG {
        bail!("share_invalid: tag {:?} is reserved", tag);
    }
    Ok(())
}

/// The source must be an absolute canonical path whose every component is
/// not a symlink, ending in a directory. It is checked again just before its
/// virtiofsd starts.
fn validate_source(source: &str) -> Result<()> {
    let invalid = || anyhow!("share_invalid: invalid source {:?}", source);
    let Some(rest) = source.strip_prefix('/') else {
        return Err(invalid());
    };
    if rest.is_empty() || source.contains('\0') {
        return Err(invalid());
    }
    if rest
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(invalid());
    }
    // The device manager knows a share-fs device by its host path; never
    // let a share alias the sandbox's own shared directory.
    let own = kata_host_shared_dir();
    if source.starts_with(own.as_str()) || own.trim_end_matches('/') == source {
        bail!("share_invalid: source {:?} is runtime-owned", source);
    }
    let mut path = String::new();
    for component in rest.split('/') {
        path.push('/');
        path.push_str(component);
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| anyhow!("share_invalid: source {:?}: {}", source, error))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            bail!(
                "share_invalid: source {:?} has a symlink at {:?}",
                source,
                path
            );
        }
        if !file_type.is_dir() {
            bail!(
                "share_invalid: source {:?} is not a directory at {:?}",
                source,
                path
            );
        }
    }
    Ok(())
}

/// Refuse a share the configured VMM cannot give the guest. The VM is never
/// started without a requested share.
pub fn check_supported(
    hypervisor_name: &str,
    config: &HypervisorConfig,
    fs_sharing_supported: bool,
) -> Result<()> {
    if ![
        HYPERVISOR_NAME_QEMU,
        HYPERVISOR_NAME_CH,
        HYPERVISOR_NAME_DRAGONBALL,
    ]
    .contains(&hypervisor_name)
    {
        bail!(
            "share_unsupported: hypervisor {:?} has no vhost-user-fs device",
            hypervisor_name
        );
    }
    if !fs_sharing_supported {
        bail!("share_unsupported: the VMM configuration has no file system sharing");
    }
    if is_rootless() {
        bail!("share_unsupported: rootless runtime");
    }
    if !config.shared_fs.virtio_fs_daemon.starts_with('/') {
        bail!("share_unsupported: virtio_fs_daemon is not configured");
    }
    for arg in &config.shared_fs.virtio_fs_extra_args {
        if arg.starts_with("--sandbox") || arg.starts_with("--seccomp") {
            bail!("share_unsupported: virtio_fs_extra_args sets {}", arg);
        }
    }
    Ok(())
}

/// The socket of share `index`, under the sandbox's runtime directory so that
/// the path names the sandbox.
pub(crate) fn share_socket_path(jailer_root: &str, index: usize) -> Result<String> {
    let path = Path::new(jailer_root)
        .join(format!("virtiofsd-share-{index}.sock"))
        .to_str()
        .context("share socket path")?
        .to_string();
    if path.len() > MAX_SOCKET_PATH {
        bail!("share_unsupported: socket path {:?} too long", path);
    }
    Ok(path)
}

/// virtiofsd arguments of one share: those of the sandbox daemon plus an
/// explicit namespace sandbox, a killing seccomp filter and the share's
/// file limit, which replaces one the sandbox daemon's arguments set.
pub(crate) fn share_virtiofsd_args(
    sock_path: &str,
    source: &str,
    max_files: u64,
    config: &HypervisorConfig,
) -> Vec<String> {
    let mut extra = Vec::with_capacity(config.shared_fs.virtio_fs_extra_args.len());
    let mut skip = false;
    for arg in &config.shared_fs.virtio_fs_extra_args {
        if std::mem::take(&mut skip) {
            continue;
        }
        if arg == "--rlimit-nofile" {
            skip = true;
        } else if !arg.starts_with("--rlimit-nofile=") {
            extra.push(arg.clone());
        }
    }
    let mut args = virtiofsd_base_args(
        sock_path,
        source,
        &config.shared_fs.virtio_fs_cache,
        &extra,
        config.disable_guest_selinux,
    );
    args.extend(
        ["--sandbox", "namespace", "--seccomp", "kill"]
            .iter()
            .map(|arg| arg.to_string()),
    );
    args.push(format!("--rlimit-nofile={}", max_files));
    args
}

/// The device of one share; queues like the sandbox's own device.
pub(crate) fn share_fs_config(
    share: &NovaShare,
    sock_path: &str,
    queue_size: u64,
) -> ShareFsConfig {
    ShareFsConfig {
        host_shared_path: share.source.clone(),
        fs_type: VIRTIO_FS.to_string(),
        sock_path: sock_path.to_string(),
        mount_tag: share.tag.clone(),
        queue_size,
        queue_num: 1,
        options: vec![],
        mount_config: None,
    }
}

/// The virtiofsd processes of a sandbox's shares.
#[derive(Debug, Default)]
pub(crate) struct NovaShareDaemons {
    processes: Mutex<Vec<(String, VirtiofsProcess)>>,
}

impl NovaShareDaemons {
    /// Start one virtiofsd per share and add its device, before the VM boots.
    /// On failure every daemon already started is killed; a cleanup failure
    /// is logged and never replaces the primary error.
    pub(crate) async fn setup(
        &self,
        hypervisor_name: &str,
        h: &dyn Hypervisor,
        d: &RwLock<DeviceManager>,
        shares: &[NovaShare],
    ) -> Result<()> {
        if shares.is_empty() {
            return Ok(());
        }
        let config = h.hypervisor_config().await;
        let supported = h.capabilities().await?.is_fs_sharing_supported();
        check_supported(hypervisor_name, &config, supported)?;
        if let Err(error) = self.start(h, d, &config, shares).await {
            if let Err(cleanup) = self.stop(false).await {
                warn!(sl!(), "share virtiofsd cleanup failed: {:#}", cleanup);
            }
            return Err(error);
        }
        Ok(())
    }

    async fn start(
        &self,
        h: &dyn Hypervisor,
        d: &RwLock<DeviceManager>,
        config: &HypervisorConfig,
        shares: &[NovaShare],
    ) -> Result<()> {
        let jailer_root = h.get_jailer_root().await?;
        std::fs::create_dir_all(&jailer_root).context("create sandbox runtime directory")?;
        let queue_size = config.shared_fs.virtio_fs_queue_size as u64;
        for (index, share) in shares.iter().enumerate() {
            validate_source(&share.source)?;
            let sock_path = share_socket_path(&jailer_root, index)?;
            match std::fs::symlink_metadata(&sock_path) {
                Ok(metadata) if metadata.file_type().is_socket() => {
                    std::fs::remove_file(&sock_path).context("remove stale share socket")?
                }
                Ok(_) => bail!("share socket path {:?} is not a socket", sock_path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect share socket path"),
            }
            let args = share_virtiofsd_args(&sock_path, &share.source, share.max_files, config);
            let child = Command::new(&config.shared_fs.virtio_fs_daemon)
                .args(&args)
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .with_context(|| format!("spawn virtiofsd for share {}", share.tag))?;
            let (ready_tx, mut ready_rx) = channel(100);
            self.processes.lock().await.push((
                share.tag.clone(),
                VirtiofsProcess::spawn_group_leader(child, ready_tx),
            ));
            match tokio::time::timeout(READY_TIMEOUT, ready_rx.recv()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(error))) => {
                    return Err(error).with_context(|| format!("virtiofsd of share {}", share.tag))
                }
                Ok(None) => bail!("virtiofsd of share {} ended before readiness", share.tag),
                Err(_) => bail!("virtiofsd of share {} not ready in time", share.tag),
            }
            info!(sl!(), "share virtiofsd ready"; "tag" => &share.tag, "socket" => &sock_path);
            do_handle_device(
                d,
                &DeviceConfig::ShareFsCfg(share_fs_config(share, &sock_path, queue_size)),
            )
            .await
            .with_context(|| format!("add virtio-fs device of share {}", share.tag))?;
        }
        Ok(())
    }

    /// Stop and reap every share daemon. After a VMM stop each daemon exits
    /// by itself as its socket closes; one that does not (`graceful` false,
    /// or the bounded wait expired) has its process group killed.
    pub(crate) async fn stop(&self, graceful: bool) -> Result<()> {
        let mut processes = self.processes.lock().await;
        let results =
            futures::future::join_all(processes.iter_mut().map(|(tag, process)| async move {
                if graceful {
                    match process.stop().await {
                        Ok(()) => return Ok(()),
                        Err(error) => warn!(
                            sl!(),
                            "share virtiofsd {} did not stop: {:#}; killing", tag, error
                        ),
                    }
                }
                process
                    .kill_group()
                    .await
                    .with_context(|| format!("stop virtiofsd of share {tag}"))
            }))
            .await;
        let mut first = None;
        for result in results {
            if let Err(error) = result {
                if first.is_none() {
                    first = Some(error);
                } else {
                    warn!(sl!(), "share virtiofsd stop failed: {:#}", error);
                }
            }
        }
        match first {
            Some(error) => Err(error),
            None => {
                processes.clear();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn annotations(value: &str) -> HashMap<String, String> {
        HashMap::from([(SHARES_KEY.to_string(), value.to_string())])
    }

    fn entry(tag: &str, source: &str) -> serde_json::Value {
        serde_json::json!({"tag": tag, "source": source, "max_files": 4096})
    }

    fn list(entries: &[serde_json::Value]) -> HashMap<String, String> {
        annotations(&serde_json::to_string(entries).unwrap())
    }

    fn refused(annotations: &HashMap<String, String>) -> String {
        format!("{:#}", parse(annotations).unwrap_err())
    }

    fn dirs() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let a = root.join("a");
        let b = root.join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        (
            dir,
            a.to_str().unwrap().to_string(),
            b.to_str().unwrap().to_string(),
        )
    }

    #[test]
    fn nova_shares_absent_annotation_is_empty() {
        assert!(parse(&HashMap::new()).unwrap().is_empty());
        let other = HashMap::from([("io.katacontainers.volume-initial.v1".into(), "[]".into())]);
        assert!(parse(&other).unwrap().is_empty());
        assert!(parse(&annotations("[]")).unwrap().is_empty());
    }

    #[test]
    fn nova_shares_accepts_two_shares() {
        let (_dir, a, b) = dirs();
        let tag = "a".repeat(36);
        let shares = parse(&list(&[entry("share-1", &a), entry(&tag, &b)])).unwrap();
        assert_eq!(
            shares,
            vec![
                NovaShare {
                    tag: "share-1".into(),
                    source: a,
                    max_files: 4096
                },
                NovaShare {
                    tag,
                    source: b,
                    max_files: 4096
                },
            ]
        );
    }

    #[test]
    fn nova_shares_refuses_a_share_without_its_file_limit() {
        let (_dir, a, _) = dirs();
        for value in [
            serde_json::json!({"tag": "t", "source": a}),
            serde_json::json!({"tag": "t", "source": a, "max_files": 255}),
            serde_json::json!({"tag": "t", "source": a, "max_files": (1u64 << 20) + 1}),
        ] {
            assert!(refused(&list(&[value])).starts_with("share_invalid:"));
        }
    }

    #[test]
    fn nova_shares_refuses_unknown_key_and_field() {
        let (_dir, a, _) = dirs();
        let mut both = list(&[entry("t", &a)]);
        both.insert("io.katacontainers.shares.v2".into(), "[]".into());
        assert!(refused(&both).starts_with("share_invalid:"));
        let other = HashMap::from([("io.katacontainers.shares.v2".into(), "[]".into())]);
        assert!(refused(&other).starts_with("share_invalid:"));
        let extra = annotations(&format!(
            r#"[{{"tag":"t","source":"{a}","readonly":true}}]"#
        ));
        assert!(refused(&extra).starts_with("share_invalid:"));
        let missing = annotations(r#"[{"tag":"t"}]"#);
        assert!(refused(&missing).starts_with("share_invalid:"));
        assert!(refused(&annotations("{}")).starts_with("share_invalid:"));
    }

    #[test]
    fn nova_shares_refuses_bad_tags() {
        let (_dir, a, _) = dirs();
        for tag in ["", "kataShared", "a_b", "a/b", "a.b", "a b", "\u{e9}"] {
            assert!(
                refused(&list(&[entry(tag, &a)])).starts_with("share_invalid:"),
                "{}",
                tag
            );
        }
        let long = "a".repeat(37);
        assert!(refused(&list(&[entry(&long, &a)])).starts_with("share_invalid:"));
    }

    #[test]
    fn nova_shares_refuses_duplicates() {
        let (_dir, a, b) = dirs();
        let tags = refused(&list(&[entry("t", &a), entry("t", &b)]));
        assert!(tags.contains("duplicate tag"), "{}", tags);
        let sources = refused(&list(&[entry("t", &a), entry("u", &a)]));
        assert!(sources.contains("duplicate source"), "{}", sources);
    }

    #[test]
    fn nova_shares_refuses_bad_sources() {
        let (dir, a, _) = dirs();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let file = root.join("file");
        std::fs::write(&file, b"x").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&a, &link).unwrap();
        std::fs::create_dir(a.clone() + "/inner").unwrap();
        let through = link.join("inner");
        let candidates = [
            "relative".to_string(),
            "/".to_string(),
            format!("{a}/"),
            format!("{a}//inner"),
            format!("{a}/./inner"),
            format!("{a}/../a"),
            format!("{a}/missing"),
            file.to_str().unwrap().to_string(),
            link.to_str().unwrap().to_string(),
            through.to_str().unwrap().to_string(),
            format!("{}abc/passthrough", kata_host_shared_dir()),
        ];
        for source in candidates {
            assert!(
                refused(&list(&[entry("t", &source)])).starts_with("share_invalid:"),
                "{}",
                source
            );
        }
        assert!(parse(&list(&[entry("t", &(a + "/inner"))])).is_ok());
    }

    #[test]
    fn nova_shares_refuses_size_and_count() {
        let (_dir, a, _) = dirs();
        let big = annotations(&format!("[{}]", " ".repeat(MAX_TEXT)));
        assert!(refused(&big).contains("too large"));
        let mut many = vec![];
        for i in 0..33 {
            let path = format!("{a}/{i}");
            std::fs::create_dir(&path).unwrap();
            many.push(entry(&format!("t{i}"), &path));
        }
        assert!(refused(&list(&many)).contains("too many"));
        assert_eq!(parse(&list(&many[..32])).unwrap().len(), 32);
    }

    fn config(daemon: &str) -> HypervisorConfig {
        let mut config = HypervisorConfig::default();
        config.shared_fs.virtio_fs_daemon = daemon.to_string();
        config.shared_fs.virtio_fs_cache = "auto".to_string();
        config.shared_fs.virtio_fs_extra_args = vec![
            "--thread-pool-size=1".to_string(),
            "-o".to_string(),
            "announce_submounts".to_string(),
        ];
        config
    }

    #[test]
    fn nova_shares_virtiofsd_args() {
        let sid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let root = hypervisor::utils::get_jailer_root(sid);
        let sock = share_socket_path(&root, 31).unwrap();
        assert!(sock.starts_with(&root) && sock.contains(sid), "{}", sock);
        let mut config = config("/opt/kata/libexec/virtiofsd");
        let args = share_virtiofsd_args(&sock, "/srv/share", 4096, &config);
        let pairs = |args: &[String], flag: &str, value: &str| {
            args.windows(2).any(|w| w[0] == flag && w[1] == value)
        };
        assert!(pairs(&args, "--socket-path", &sock));
        assert!(pairs(&args, "--shared-dir", "/srv/share"));
        assert!(pairs(&args, "--sandbox", "namespace"));
        assert!(pairs(&args, "--seccomp", "kill"));
        assert!(pairs(&args, "--cache", "auto"));
        assert!(pairs(&args, "-o", "announce_submounts"));
        assert!(args.contains(&"--thread-pool-size=1".to_string()));
        assert!(args.contains(&"--xattr".to_string()));
        assert_eq!(args.last().unwrap(), "--rlimit-nofile=4096");
        // The sandbox daemon's own limit is not the share's.
        for own in [
            vec!["--rlimit-nofile=65536".to_string()],
            vec!["--rlimit-nofile".to_string(), "65536".to_string()],
        ] {
            let mut limited = config.clone();
            limited.shared_fs.virtio_fs_extra_args.extend(own);
            let args = share_virtiofsd_args(&sock, "/srv/share", 4096, &limited);
            let limits: Vec<_> = args.iter().filter(|a| a.contains("rlimit")).collect();
            assert_eq!(limits, vec!["--rlimit-nofile=4096"]);
            assert!(!args.contains(&"65536".to_string()));
            assert!(args.contains(&"--thread-pool-size=1".to_string()));
        }
        config.disable_guest_selinux = true;
        let args = share_virtiofsd_args(&sock, "/srv/share", 4096, &config);
        assert!(!args.contains(&"--xattr".to_string()));
        let long = format!("/{}", "x".repeat(100));
        assert!(share_socket_path(&long, 0).is_err());
    }

    #[test]
    fn nova_shares_device_config() {
        let share = NovaShare {
            tag: "t".into(),
            source: "/srv/share".into(),
            max_files: 4096,
        };
        let cfg = share_fs_config(&share, "/run/kata/s/root/virtiofsd-share-0.sock", 1024);
        assert_eq!(cfg.fs_type, "virtio-fs");
        assert_eq!(cfg.mount_tag, "t");
        assert_eq!(cfg.host_shared_path, "/srv/share");
        assert_eq!(cfg.sock_path, "/run/kata/s/root/virtiofsd-share-0.sock");
        assert_eq!((cfg.queue_size, cfg.queue_num), (1024, 1));
        assert!(cfg.mount_config.is_none());
    }

    #[test]
    fn nova_shares_check_supported() {
        let ok = config("/opt/kata/libexec/virtiofsd");
        for name in [
            HYPERVISOR_NAME_QEMU,
            HYPERVISOR_NAME_CH,
            HYPERVISOR_NAME_DRAGONBALL,
        ] {
            check_supported(name, &ok, true).unwrap();
        }
        let refuse = |name: &str, config: &HypervisorConfig, fs: bool| {
            let text = format!("{:#}", check_supported(name, config, fs).unwrap_err());
            assert!(text.starts_with("share_unsupported:"), "{}", text);
        };
        refuse("firecracker", &ok, true);
        refuse("remote", &ok, true);
        refuse("openvmm", &ok, true);
        refuse(HYPERVISOR_NAME_QEMU, &ok, false);
        refuse(HYPERVISOR_NAME_DRAGONBALL, &config(""), true);
        let mut sandbox = ok.clone();
        sandbox
            .shared_fs
            .virtio_fs_extra_args
            .push("--sandbox=none".into());
        refuse(HYPERVISOR_NAME_CH, &sandbox, true);
        let mut seccomp = ok;
        seccomp
            .shared_fs
            .virtio_fs_extra_args
            .push("--seccomp".into());
        refuse(HYPERVISOR_NAME_CH, &seccomp, true);
    }

    #[tokio::test]
    async fn nova_shares_kill_group_reaps_the_daemon_and_its_child() {
        let marker = std::env::temp_dir().join(format!(
            "kata-share-group-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // A daemon whose own child never ends, like virtiofsd waiting for a
        // VMM that never connects.
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                "sleep 1000 & echo $! > \"$KATA_GROUP_MARKER\"; \
                 echo 'Waiting for vhost-user socket connection' >&2; wait",
            ])
            .env("KATA_GROUP_MARKER", &marker)
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let (ready, mut receiver) = channel(2);
        let mut process = VirtiofsProcess::spawn_group_leader(child, ready);
        tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let grandchild: i32 = std::fs::read_to_string(&marker)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::fs::remove_file(&marker).unwrap();
        tokio::time::timeout(Duration::from_secs(3), process.kill_group())
            .await
            .unwrap()
            .unwrap();
        // The grandchild was killed (it may linger as a zombie of init).
        let status = std::fs::read_to_string(format!("/proc/{grandchild}/stat"));
        assert!(
            status.map_or(true, |s| s.contains(") Z ")),
            "grandchild survived"
        );
        process.stop().await.unwrap();
    }

    #[tokio::test]
    async fn nova_shares_kill_group_is_refused_for_a_shared_group() {
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                "echo 'Waiting for vhost-user socket connection' >&2; sleep 0.2",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (ready, _receiver) = channel(2);
        let mut process = VirtiofsProcess::spawn(child, ready);
        // A daemon in the shim's own group never gets a group signal.
        assert!(process.kill_group().await.is_err());
        process.stop().await.unwrap();
    }
}
