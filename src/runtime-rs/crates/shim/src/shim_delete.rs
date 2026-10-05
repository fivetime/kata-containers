// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};
use containerd_shim_protos::api;
use kata_sys_util::spec::{get_bundle_path, get_container_type, load_oci_spec};
use kata_types::container::ContainerType;
use nix::{sys::signal::kill, sys::signal::SIGKILL, unistd::Pid};
use protobuf::Message;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{shim::ShimExecutor, Error};

impl ShimExecutor {
    pub async fn delete(&mut self) -> Result<()> {
        self.args.validate(true).context("validate")?;
        let rsp = self.do_cleanup().await.context("shim do cleanup")?;
        rsp.write_to_writer(&mut std::io::stdout())
            .context(Error::FileWrite(format!("write {rsp:?} to stdout")))?;
        Ok(())
    }

    async fn do_cleanup(&self) -> Result<api::DeleteResponse> {
        let mut rsp = api::DeleteResponse::new();
        rsp.set_exit_status(128 + libc::SIGKILL as u32);
        let mut exited_time = protobuf::well_known_types::timestamp::Timestamp::new();
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(Error::SystemTime)?
            .as_secs() as i64;
        exited_time.seconds = seconds;
        rsp.set_exited_at(exited_time);

        let address = self
            .socket_address(&self.args.id)
            .context("socket address")?;
        let trim_path = address.strip_prefix("unix://").context("trim path")?;
        let file_path = Path::new("/").join(trim_path);
        let file_path = file_path.as_path();
        if std::fs::metadata(file_path).is_ok() {
            info!(sl!(), "remote socket path: {:?}", &file_path);
            fs::remove_file(file_path).ok();
        }

        kill_orphaned_sandbox_processes(&self.args.id);

        if let Err(e) = service::ServiceManager::cleanup(&self.args.id).await {
            error!(
                sl!(),
                "failed to cleanup in service manager: {:?}. force shutdown shim process", e
            );

            let bundle_path = get_bundle_path().context("get bundle path")?;
            if let Ok(spec) = load_oci_spec() {
                if let Ok(ContainerType::PodSandbox) = get_container_type(&spec) {
                    // only force shutdown for sandbox container
                    if let Ok(shim_pid) = self.read_pid_file(&bundle_path) {
                        info!(sl!(), "force to shutdown shim process {}", shim_pid);
                        let pid = Pid::from_raw(shim_pid as i32);
                        if let Err(_e) = kill(pid, SIGKILL) {
                            // ignore kill errors
                        }
                    }
                }
            }
        }

        Ok(rsp)
    }
}

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const KILL_SETTLE_POLLS: u32 = 100;
const KILL_SETTLE_INTERVAL: Duration = Duration::from_millis(100);

// The sandbox cgroup of `id`, only when the OCI cgroups path names this
// sandbox: a shared or foreign parent cgroup is never a kill target.
fn sandbox_cgroup_dir(id: &str, cgroups_path: &Path) -> Option<PathBuf> {
    let name = cgroups_path.file_name()?.to_str()?;
    if id.is_empty() || !name.contains(id) {
        return None;
    }
    let relative = cgroups_path.strip_prefix("/").unwrap_or(cgroups_path);
    if relative
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return None;
    }
    Some(Path::new(CGROUP_ROOT).join(relative))
}

// QEMU, Cloud Hypervisor and virtiofsd run outside the shim, in the sandbox
// cgroup. containerd runs this delete only when the shim is gone, so they are
// unmanaged: left alone, the guest keeps running with its disks open while
// containerd reports no task. Kill every process of the sandbox cgroup (cgroup
// v2 cgroup.kill) before the cleanup removes their state. Dragonball runs in
// the shim and leaves nothing to kill.
fn kill_orphaned_sandbox_processes(id: &str) {
    let spec = match load_oci_spec() {
        Ok(spec) => spec,
        Err(_) => return,
    };
    if let Ok(ContainerType::PodContainer) = get_container_type(&spec) {
        return;
    }
    let Some(cgroups_path) = spec.linux().as_ref().and_then(|l| l.cgroups_path().clone()) else {
        return;
    };
    let Some(dir) = sandbox_cgroup_dir(id, &cgroups_path) else {
        return;
    };
    let kill_file = dir.join("cgroup.kill");
    if !kill_file.exists() {
        return;
    }
    info!(sl!(), "kill processes left in sandbox cgroup {:?}", &dir);
    if let Err(e) = fs::write(&kill_file, "1") {
        warn!(sl!(), "failed to kill sandbox cgroup {:?}: {:?}", &dir, e);
        return;
    }
    for _ in 0..KILL_SETTLE_POLLS {
        match fs::read_to_string(dir.join("cgroup.events")) {
            Ok(events) if events.lines().any(|l| l == "populated 0") => return,
            Ok(_) => std::thread::sleep(KILL_SETTLE_INTERVAL),
            Err(_) => return,
        }
    }
    warn!(
        sl!(),
        "sandbox cgroup {:?} still populated after kill", &dir
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_cgroup_dir_names_only_this_sandbox() {
        let id = "nova-5566370f-5245-4fd3-9e5c-d2423abfdb03";
        assert_eq!(
            sandbox_cgroup_dir(
                id,
                Path::new("/openstack/nova-5566370f-5245-4fd3-9e5c-d2423abfdb03")
            ),
            Some(PathBuf::from(
                "/sys/fs/cgroup/openstack/nova-5566370f-5245-4fd3-9e5c-d2423abfdb03"
            ))
        );
        // A parent, another sandbox, traversal or an empty id is never a target.
        assert_eq!(sandbox_cgroup_dir(id, Path::new("/openstack")), None);
        assert_eq!(
            sandbox_cgroup_dir(id, Path::new("/openstack/nova-other")),
            None
        );
        assert_eq!(
            sandbox_cgroup_dir(
                id,
                Path::new("/openstack/../nova-5566370f-5245-4fd3-9e5c-d2423abfdb03")
            ),
            None
        );
        assert_eq!(sandbox_cgroup_dir("", Path::new("/openstack/nova-x")), None);
        assert_eq!(sandbox_cgroup_dir(id, Path::new("/")), None);
    }
}
