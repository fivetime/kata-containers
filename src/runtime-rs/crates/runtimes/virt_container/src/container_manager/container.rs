// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::sync::Arc;

use agent::Agent;
use anyhow::{anyhow, Context, Result};
use common::{
    error::{is_no_such_process_error, Error},
    types::{
        ContainerConfig, ContainerID, ContainerProcess, ProcessStateInfo, ProcessStatus,
        ProcessType,
    },
};
use kata_sys_util::k8s::update_ephemeral_storage_type;
use kata_types::{
    annotations::{BUNDLE_PATH_KEY, CONTAINER_TYPE_KEY, KATA_ANNO_CFG_HYPERVISOR_INIT_DATA},
    config::TomlConfig,
    container::update_ocispec_annotations,
    k8s::{self, container_type},
};
use oci_spec::runtime as oci;

use oci::{LinuxResources, Process as OCIProcess};
use resource::{
    cdi_devices::container_device::annotate_container_devices, ResourceManager, ResourceUpdateOp,
};
use tokio::sync::RwLock;

use super::{
    process::{Process, ProcessWatcher},
    ContainerInner,
};
use crate::container_manager::{is_termination_signal, logger_with_process};

pub struct Exec {
    pub(crate) process: Process,
    pub(crate) oci_process: OCIProcess,
}

pub struct Container {
    pid: u32,
    pub container_id: ContainerID,
    config: ContainerConfig,
    spec: oci::Spec,
    inner: Arc<RwLock<ContainerInner>>,
    agent: Arc<dyn Agent>,
    resource_manager: Arc<ResourceManager>,
    logger: slog::Logger,
    pub(crate) passfd_listener_addr: Option<(String, u32)>,
}

fn process_uses_passfd_io(inner: &ContainerInner, process: &ContainerProcess) -> Result<bool> {
    match process.process_type {
        ProcessType::Container => Ok(inner.init_process.passfd_io.is_some()),
        ProcessType::Exec => Ok(inner
            .exec_processes
            .get(&process.exec_id)
            .ok_or_else(|| Error::ProcessNotFound(process.clone()))?
            .process
            .passfd_io
            .is_some()),
    }
}

impl Container {
    pub async fn new(
        pid: u32,
        config: ContainerConfig,
        spec: oci::Spec,
        agent: Arc<dyn Agent>,
        resource_manager: Arc<ResourceManager>,
        passfd_listener_addr: Option<(String, u32)>,
    ) -> Result<Self> {
        let container_id = ContainerID::new(&config.container_id).context("new container id")?;
        let logger = sl!().new(o!("container_id" => config.container_id.clone()));
        let process = ContainerProcess::new(&config.container_id, "")?;
        let init_process = Process::new(
            &process,
            pid,
            &config.bundle,
            config.stdin.clone(),
            config.stdout.clone(),
            config.stderr.clone(),
            config.terminal,
        );
        let linux_resources = spec
            .linux()
            .as_ref()
            .and_then(|linux| linux.resources().clone());

        Ok(Self {
            pid,
            container_id,
            config,
            spec,
            inner: Arc::new(RwLock::new(ContainerInner::new(
                agent.clone(),
                init_process,
                logger.clone(),
                linux_resources,
            ))),
            agent,
            resource_manager,
            logger,
            passfd_listener_addr,
        })
    }

    pub async fn create(&self, mut spec: oci::Spec) -> Result<()> {
        // process oci spec
        let mut inner = self.inner.write().await;
        let toml_config = self.resource_manager.config().await;
        let config = &self.config;
        let sandbox_pidns = is_pid_namespace_enabled(&spec);
        let disable_guest_selinux = get_disable_guest_selinux(&toml_config);
        let annotations = spec.annotations().clone().unwrap_or_default();
        // Tag the spec with the actual container type. Previously every
        // non-pod-container was forced to "pod_sandbox", which made standalone
        // engines (Docker/nerdctl/podman) look like a pod sandbox. The agent
        // skips CDI device injection for "pod_sandbox", so the NVIDIA CDI edits
        // carried in the "cdi.k8s.io/*" annotations were never applied and the
        // GPU userspace (e.g. nvidia-smi) was missing in the guest. Emitting
        // "single_container" matches the Go runtime and lets the agent inject.
        let container_typ = container_type(&spec);
        let pod_type_anno = (CONTAINER_TYPE_KEY.to_string(), container_typ.to_string());

        let bund_path_anno = (BUNDLE_PATH_KEY.to_string(), config.bundle.clone());
        let updated_annotations = update_ocispec_annotations(
            &annotations,
            &[KATA_ANNO_CFG_HYPERVISOR_INIT_DATA],
            &[pod_type_anno, bund_path_anno],
        );
        spec.set_annotations(Some(updated_annotations.clone()));

        amend_spec(
            &mut spec,
            toml_config.runtime.disable_guest_seccomp,
            disable_guest_selinux,
        )
        .context("amend spec")?;

        // get mutable root from oci spec
        let root = match spec.root_mut() {
            Some(root) => root,
            None => return Err(anyhow!("spec miss root field")),
        };

        // handler rootfs
        let rootfs = self
            .resource_manager
            .handler_rootfs(
                &config.container_id,
                root,
                &config.bundle,
                &config.rootfs_mounts,
                &updated_annotations,
            )
            .await
            .context("handler rootfs")?;

        // update rootfs
        root.set_path(
            rootfs
                .get_guest_rootfs_path()
                .await
                .context("get guest rootfs path")?
                .into(),
        );

        let mut storages = vec![];
        if let Some(mut storage_list) = rootfs.get_storage().await {
            storages.append(&mut storage_list);
        }
        inner.rootfs.push(rootfs);

        // Nova Kata (ADR-052): the container of a guest that arrives by a
        // live migration runs in it already: its devices are placed on the
        // host as on the source, and nothing is said to its agent.
        let migrated_in = migrated_in(&self.spec);
        let initial = super::live_volume_created::parse_initial(&config.container_id, &self.spec)?;
        if !initial.is_empty() && !migrated_in {
            let details = self.agent.get_guest_details(agent::GetGuestDetailsRequest::default()).await?;
            let dm = self.resource_manager.get_device_manager().await;
            let block = hypervisor::device::device_manager::get_block_device_info(&dm).await;
            super::live_volume_created::validate_capability(&details, &block.block_device_driver)?;
        }
        let initial = super::live_volume_created::audit_initial(initial)?;
        // handler volumes
        let volumes = self
            .resource_manager
            .handler_volumes(&config.container_id, &spec)
            .await
            .context("handler volumes")?;
        inner.volumes.extend(volumes.iter().cloned());
        let created = super::live_volume_created::bind_initial(initial, &volumes)?;
        let mut oci_mounts = vec![];
        for v in volumes {
            let mut volume_mounts = v.get_volume_mount().context("get volume mount")?;
            if volume_mounts.iter().any(|m| m.destination().to_str().is_some_and(|d| created.destinations.contains(d))) {
                continue;
            }
            if !volume_mounts.is_empty() {
                oci_mounts.append(&mut volume_mounts);
            }

            let mut s = v.get_storage().context("get storage")?;
            if !s.is_empty() {
                storages.append(&mut s);
            }
        }
        spec.set_mounts(Some(oci_mounts));

        let linux = spec
            .linux()
            .as_ref()
            .context("OCI spec missing linux field")?;

        let container_devices = self
            .resource_manager
            .handler_devices(&config.container_id, linux)
            .await?;
        let mut devices_agent = annotate_container_devices(&mut spec, container_devices)
            .context("annotate container devices failed")?;
        created.apply(&mut spec, &mut devices_agent, &mut inner.live_volumes)?;

        // update vcpus, mems and host cgroups
        let resources = self
            .resource_manager
            .update_linux_resource(
                &config.container_id,
                inner.linux_resources.as_ref(),
                ResourceUpdateOp::Add,
            )
            .await?;
        if let Some(linux) = &mut spec.linux_mut() {
            linux.set_resources(resources);

            // Only CPU and Memory constraints are supported in the guest.
            // Clear unsupported resource fields to match the Go runtime
            // and satisfy the agent policy checks.
            if let Some(resource) = linux.resources_mut() {
                resource.set_devices(None);
                resource.set_pids(None);
                resource.set_block_io(None);
                resource.set_network(None);
            }

            // VFIO device filtering depends on vfio_mode configuration:
            //
            // - guest-kernel mode: Devices are managed by the guest kernel driver and
            //   are not presented to the container. Remove them from the OCI spec to
            //   match the Go runtime (kata_agent.go:1093-1105) and satisfy the agent
            //   policy's allow_linux_devices check.
            //   * vfio-pci-gk: PCI device passthrough with guest kernel driver
            //
            // - vfio mode: Devices appear as VFIO character devices
            //   (/dev/vfio/*) inside the container. Keep them in the OCI spec so the
            //   agent can validate and bind them properly. This is required for:
            //   * vfio-pci: PCI device passthrough with VFIO in container
            //   * vfio-ap: Adjunct Processor (AP) device passthrough with VFIO-AP
            let vfio_mode = toml_config.runtime.vfio_mode.as_str();
            filter_vfio_devices(linux, vfio_mode);
        }

        let container_name = k8s::container_name(&spec);
        let mut shared_mounts = Vec::new();
        for shared_mount in &toml_config.runtime.shared_mounts {
            if shared_mount.dst_ctr == container_name {
                let m = agent::types::SharedMount {
                    name: shared_mount.name.clone(),
                    src_ctr: shared_mount.src_ctr.clone(),
                    src_path: shared_mount.src_path.clone(),
                    dst_ctr: shared_mount.dst_ctr.clone(),
                    dst_path: shared_mount.dst_path.clone(),
                };
                shared_mounts.push(m);
            }
        }

        // In passfd io mode, we create vsock connections for io in advance
        // and pass port info to agent in `CreateContainerRequest`.
        // These vsock connections will be used as stdin/stdout/stderr of the container process.
        // See agent/src/passfd_io.rs for more details.
        if let Some((hvsock_uds_path, passfd_port)) = &self.passfd_listener_addr {
            inner
                .init_process
                .passfd_io_init(hvsock_uds_path, *passfd_port)
                .await?;
        }

        info!(
            sl!(),
            "OCI Spec {:?} within CreateContainerRequest.",
            spec.clone()
        );

        // create container
        let r = agent::CreateContainerRequest {
            process_id: agent::ContainerProcessID::new(&config.container_id, ""),
            storages,
            oci: Some(spec),
            sandbox_pidns,
            devices: devices_agent,
            shared_mounts,
            stdin_port: inner
                .init_process
                .passfd_io
                .as_ref()
                .and_then(|io| io.stdin_port),
            stdout_port: inner
                .init_process
                .passfd_io
                .as_ref()
                .and_then(|io| io.stdout_port),
            stderr_port: inner
                .init_process
                .passfd_io
                .as_ref()
                .and_then(|io| io.stderr_port),
            ..Default::default()
        };

        if migrated_in {
            info!(
                sl!(),
                "container {} is in the guest that arrives", &config.container_id
            );
        } else {
            self.agent
                .create_container(r)
                .await
                .context("agent create container")?;
        }
        self.resource_manager.dump().await;
        Ok(())
    }

    pub async fn start(
        &self,
        containers: Arc<RwLock<HashMap<String, Container>>>,
        process: &ContainerProcess,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        match process.process_type {
            ProcessType::Container => {
                let res: Result<()> = async {
                    if let Some(incoming) = migrated_in_as(&self.spec)? {
                        inner.adopt_container(incoming.paused).await?;
                    } else {
                        inner.start_container(&process.container_id).await?;
                    }

                    if process_uses_passfd_io(&inner, process)? {
                        inner
                            .init_process
                            .passfd_io_wait(containers, self.agent.clone())
                            .await?;
                    } else {
                        let container_io = inner.new_container_io(process).await?;
                        inner
                            .init_process
                            .start_io_and_wait(containers, self.agent.clone(), container_io)
                            .await?;
                    }
                    Ok(())
                }
                .await;

                if let Err(err) = res {
                    let device_manager = self.resource_manager.get_device_manager().await;
                    let _ = inner.stop_process(process, true, &device_manager).await;

                    if let Err(e) = self
                        .resource_manager
                        .update_linux_resource(
                            &self.config.container_id,
                            inner.linux_resources.as_ref(),
                            ResourceUpdateOp::Del,
                        )
                        .await
                    {
                        warn!(
                            self.logger,
                            "failed to release linux resources after start failure: {:?}", e
                        );
                    }
                    return Err(err);
                }
            }
            ProcessType::Exec => {
                // In passfd io mode, we create vsock connections for io in advance
                // and pass port info to agent in `ExecProcessRequest`.
                // These vsock connections will be used as stdin/stdout/stderr of the exec process.
                // See agent/src/passfd_io.rs for more details.
                if let Some((hvsock_uds_path, passfd_port)) = &self.passfd_listener_addr {
                    let exec = inner
                        .exec_processes
                        .get_mut(&process.exec_id)
                        .ok_or_else(|| Error::ProcessNotFound(process.clone()))?;
                    exec.process
                        .passfd_io_init(hvsock_uds_path, *passfd_port)
                        .await?;
                }

                if let Err(e) = inner.start_exec_process(process).await {
                    let device_manager = self.resource_manager.get_device_manager().await;
                    let _ = inner.stop_process(process, true, &device_manager).await;
                    return Err(e).context("enter process");
                }

                {
                    let exec = inner
                        .exec_processes
                        .get(&process.exec_id)
                        .ok_or_else(|| Error::ProcessNotFound(process.clone()))?;
                    if exec.process.height != 0 && exec.process.width != 0 {
                        inner
                            .win_resize_process(process, exec.process.height, exec.process.width)
                            .await
                            .context("win resize")?;
                    }
                }

                if process_uses_passfd_io(&inner, process)? {
                    // In passfd io mode, we don't bother with the IO.
                    // We send `WaitProcessRequest` immediately to the agent
                    // and wait for the response in a separate thread.
                    // The agent will only respond after IO is done.
                    let exec = inner
                        .exec_processes
                        .get_mut(&process.exec_id)
                        .ok_or_else(|| Error::ProcessNotFound(process.clone()))?;
                    exec.process
                        .passfd_io_wait(containers, self.agent.clone())
                        .await?;
                } else {
                    // In legacy io mode, we handle IO by polling the agent.
                    // When IO is done, we send `WaitProcessRequest` to agent
                    // to get the exit status.
                    let container_io =
                        inner.new_container_io(process).await.context("io stream")?;

                    let exec = inner
                        .exec_processes
                        .get_mut(&process.exec_id)
                        .ok_or_else(|| Error::ProcessNotFound(process.clone()))?;
                    exec.process
                        .start_io_and_wait(containers, self.agent.clone(), container_io)
                        .await
                        .context("start io and wait")?;
                }
            }
        }

        Ok(())
    }

    pub async fn delete_exec_process(&self, container_process: &ContainerProcess) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner
            .delete_exec_process(&container_process.exec_id)
            .await
            .context("delete process")
    }

    pub async fn state_process(
        &self,
        container_process: &ContainerProcess,
    ) -> Result<ProcessStateInfo> {
        let inner = self.inner.read().await;
        match container_process.process_type {
            ProcessType::Container => inner.init_process.state().await,
            ProcessType::Exec => {
                let exec = inner
                    .exec_processes
                    .get(&container_process.exec_id)
                    .ok_or_else(|| Error::ProcessNotFound(container_process.clone()))?;
                exec.process.state().await
            }
        }
    }

    pub async fn wait_process(
        &self,
        container_process: &ContainerProcess,
    ) -> Result<ProcessWatcher> {
        let logger = logger_with_process(container_process);
        info!(logger, "start wait process");

        let inner = self.inner.read().await;
        inner
            .fetch_exit_watcher(container_process)
            .context("fetch exit watcher")
    }

    pub async fn kill_process(
        &self,
        container_process: &ContainerProcess,
        signal: u32,
        all: bool,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;

        // Check if process is already stopped before signaling.
        // For SIGKILL/SIGTERM, if the process is already stopped, return success immediately.
        // This is critical for proper cleanup when VM dies - the wait thread sets status to
        // Stopped even on error, so subsequent Kill() calls will see it as already stopped.
        let is_term_signal = is_termination_signal(signal);
        let process_status = if container_process.exec_id.is_empty() {
            inner.init_process.get_status().await
        } else if let Some(exec) = inner.exec_processes.get(&container_process.exec_id) {
            exec.process.get_status().await
        } else {
            ProcessStatus::Unknown
        };

        if is_term_signal && process_status == ProcessStatus::Stopped {
            info!(
                self.logger,
                "process has already stopped, skipping signal";
                "container" => &self.container_id.container_id,
                "process" => ?container_process,
                "signal" => signal
            );
            return Ok(());
        }

        match inner.signal_process(container_process, signal, all).await {
            Ok(()) => Ok(()),
            Err(e) if is_term_signal && is_no_such_process_error(&e) => {
                info!(
                    self.logger,
                    "process already gone during kill, treating as success";
                    "container" => &self.container_id.container_id,
                    "process" => ?container_process,
                    "signal" => signal
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub async fn exec_process(
        &self,
        container_process: &ContainerProcess,
        stdin: Option<String>,
        stdout: Option<String>,
        stderr: Option<String>,
        terminal: bool,
        mut oci_process: OCIProcess,
    ) -> Result<()> {
        let toml_config = self.resource_manager.config().await;
        if get_disable_guest_selinux(&toml_config) {
            oci_process.set_selinux_label(None);
        }

        let process = Process::new(
            container_process,
            self.pid,
            &self.config.bundle,
            stdin,
            stdout,
            stderr,
            terminal,
        );
        let exec = Exec {
            process,
            oci_process,
        };
        let mut inner = self.inner.write().await;
        inner.add_exec_process(&container_process.exec_id, exec);
        Ok(())
    }

    pub async fn close_io(&self, container_process: &ContainerProcess) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.close_io(container_process).await
    }

    pub async fn stop_process(&self, container_process: &ContainerProcess) -> Result<()> {
        if container_process.process_type == ProcessType::Container {
            self.copy_termination_log().await;
        }

        let mut inner = self.inner.write().await;
        let device_manager = self.resource_manager.get_device_manager().await;
        inner
            .stop_process(container_process, true, &device_manager)
            .await
            .context("stop process")?;

        // update vcpus, mems and host cgroups
        if container_process.process_type == ProcessType::Container {
            self.resource_manager
                .update_linux_resource(
                    &self.config.container_id,
                    inner.linux_resources.as_ref(),
                    ResourceUpdateOp::Del,
                )
                .await?;
        }

        Ok(())
    }

    async fn copy_termination_log(&self) {
        let toml_config = self.resource_manager.config().await;
        let shared_fs = toml_config
            .hypervisor
            .get(&toml_config.runtime.hypervisor_name)
            .and_then(|h| h.shared_fs.shared_fs.as_deref());

        // When a shared filesystem is configured the host can read the
        // termination log directly.  shared_fs == None means no shared
        // filesystem (the "none" config value is normalised to None by
        // SharedFsInfo::adjust_config).
        if shared_fs.is_some() {
            return;
        }

        let annotations = self.spec.annotations().clone().unwrap_or_default();
        let policy = annotations.get("io.kubernetes.container.terminationMessagePolicy");
        if policy.map(|p| p.as_str()) != Some("File") {
            return;
        }

        let termination_path =
            match annotations.get("io.kubernetes.container.terminationMessagePath") {
                Some(p) if !p.is_empty() => p.clone(),
                _ => return,
            };

        let req = agent::GetDiagnosticDataRequest {
            log_type: "termination_log".to_string(),
            container_id: self.container_id.container_id.clone(),
        };

        // The kubelet bind-mounts a host file into the container at
        // terminationMessagePath, then reads back from that host file.
        // With shared_fs=none the guest cannot write through that mount,
        // so we locate the host-side source path from the OCI mounts and
        // write the data there directly.
        let host_path = self.spec.mounts().as_ref().and_then(|mounts| {
            mounts
                .iter()
                .find(|m| m.destination() == std::path::Path::new(&termination_path))
                .and_then(|m| m.source().clone())
        });

        let host_path = match host_path {
            Some(p) => p,
            None => {
                warn!(
                    self.logger,
                    "No host mount found for termination message path"
                );
                return;
            }
        };

        match self.agent.get_diagnostic_data(req).await {
            Ok(resp) if !resp.data.is_empty() => {
                if let Err(e) = tokio::fs::write(&host_path, resp.data.as_bytes()).await {
                    warn!(self.logger, "Failed to write termination message: {}", e);
                }
            }
            Ok(_) => {}
            Err(e) => {
                warn!(
                    self.logger,
                    "Failed to get termination message from guest: {}", e
                );
            }
        }
    }

    pub async fn pause(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        let status = inner.init_process.get_status().await;
        if status != ProcessStatus::Running {
            warn!(
                self.logger,
                "container is in {:?} state, will not pause", status
            );
            return Ok(());
        }

        self.agent
            .pause_container(self.container_id.clone().into())
            .await
            .context("agent pause container")?;
        inner.set_state(ProcessStatus::Paused).await;

        Ok(())
    }

    pub async fn resume(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.live_volumes.values().any(|v| v.detach.as_ref().is_some_and(|d| !d.complete)) {
            return Err(anyhow!("volume_update_pending: detach must finish before external resume"));
        }
        let status = inner.init_process.get_status().await;
        if status != ProcessStatus::Paused {
            warn!(
                self.logger,
                "container is in {:?} state, will not resume", status
            );
            return Ok(());
        }

        self.agent
            .resume_container(self.container_id.clone().into())
            .await
            .context("agent pause container")?;
        inner.set_state(ProcessStatus::Running).await;

        Ok(())
    }

    pub async fn resize_pty(
        &self,
        process: &ContainerProcess,
        width: u32,
        height: u32,
    ) -> Result<()> {
        let logger = logger_with_process(process);
        let mut inner = self.inner.write().await;
        if inner.init_process.get_status().await != ProcessStatus::Running {
            warn!(logger, "container is not running");
            return Ok(());
        }

        if process.exec_id.is_empty() {
            inner.init_process.height = height;
            inner.init_process.width = width;
        } else if let Some(exec) = inner.exec_processes.get_mut(&process.exec_id) {
            exec.process.height = height;
            exec.process.width = width;

            // for some case, resize_pty request should be handled while the process has not been started in agent
            // just return here, and truly resize_pty will happen in start_process
            if exec.process.get_status().await != ProcessStatus::Running {
                return Ok(());
            }
        } else {
            return Err(anyhow!(
                "could not find process {} in container {}",
                process.exec_id(),
                process.container_id()
            ));
        }

        inner.win_resize_process(process, height, width).await
    }

    pub async fn stats(&self) -> Result<Option<agent::StatsContainerResponse>> {
        let stats_resp = self
            .agent
            .stats_container(self.container_id.clone().into())
            .await
            .context("agent stats container")?;
        Ok(Some(stats_resp))
    }

    pub async fn update(&self, resources: &LinuxResources) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.linux_resources = Some(resources.clone());
        // update vcpus, mems and host cgroups
        let agent_resources = self
            .resource_manager
            .update_linux_resource(
                &self.config.container_id,
                Some(resources),
                ResourceUpdateOp::Update,
            )
            .await?;

        let req = agent::UpdateContainerRequest {
            container_id: self.container_id.container_id.clone(),
            resources: agent_resources,
            mounts: Vec::new(),
        };
        self.agent
            .update_container(req)
            .await
            .context("agent update container")?;
        Ok(())
    }

    pub async fn config(&self) -> ContainerConfig {
        self.config.clone()
    }

    pub async fn spec(&self) -> oci::Spec {
        self.spec.clone()
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        let mut inner = self.inner.write().await;
        let device_manager = self.resource_manager.get_device_manager().await;
        let res = inner
            .cleanup_container(
                self.container_id.container_id.as_str(),
                true,
                &device_manager,
            )
            .await;

        if let Err(e) = self
            .resource_manager
            .update_linux_resource(
                &self.config.container_id,
                inner.linux_resources.as_ref(),
                ResourceUpdateOp::Del,
            )
            .await
        {
            warn!(self.logger, "failed to cleanup linux resources: {:?}", e);
        }

        res
    }
}

fn amend_spec(
    spec: &mut oci::Spec,
    disable_guest_seccomp: bool,
    disable_guest_selinux: bool,
) -> Result<()> {
    // Only the StartContainer hook needs to be reserved for execution in the guest
    if let Some(hooks) = spec.hooks().as_ref() {
        let mut oci_hooks = oci::Hooks::default();
        oci_hooks.set_start_container(hooks.start_container().clone());
        spec.set_hooks(Some(oci_hooks));
    }

    // special process K8s ephemeral volumes.
    update_ephemeral_storage_type(spec);

    if let Some(linux) = &mut spec.linux_mut() {
        if disable_guest_seccomp {
            linux.set_seccomp(None);
        }

        // Host pid/net/time namespace paths do not make sense in kata.
        // Pid is aligned with the sandbox namespace whenever it is set.
        let ns: Vec<oci::LinuxNamespace> = linux
            .namespaces()
            .clone()
            .unwrap_or_default()
            .iter()
            .filter(|n| {
                n.typ() != oci::LinuxNamespaceType::Pid
                    && n.typ() != oci::LinuxNamespaceType::Network
                    && n.typ() != oci::LinuxNamespaceType::Time
            })
            .map(|n| {
                let mut ns = oci::LinuxNamespace::default();
                ns.set_typ(n.typ());
                ns
            })
            .collect();

        linux.set_namespaces(if ns.is_empty() { None } else { Some(ns) });
    }

    if disable_guest_selinux {
        if let Some(ref mut process) = spec.process_mut() {
            process.set_selinux_label(None);
        }
        if let Some(ref mut linux) = spec.linux_mut() {
            linux.set_mount_label(None);
        }
    }

    Ok(())
}

fn get_disable_guest_selinux(toml_config: &TomlConfig) -> bool {
    match toml_config
        .hypervisor
        .get(&toml_config.runtime.hypervisor_name)
    {
        Some(hypervisor_config) => hypervisor_config.disable_guest_selinux,
        // This shouldn't happen due to how logic in the config crate works
        // but we need to handle it anyway so we stick with the default
        // value of disable_guest_selinux in configuration.toml which
        // is 'true'.
        None => true,
    }
}

// is_pid_namespace_enabled checks if Pid namespace for a container needs to be shared with its sandbox
// pid namespace.
fn is_pid_namespace_enabled(spec: &oci::Spec) -> bool {
    if let Some(linux) = spec.linux().as_ref() {
        let namespaces = linux.namespaces().clone().unwrap_or_default();
        for n in namespaces.iter() {
            if n.typ() == oci::LinuxNamespaceType::Pid {
                return !n.path().is_none();
            }
        }
    }

    false
}

/// Filter VFIO devices from the Linux device list based on vfio_mode configuration.
/// - vfio mode: Keeps all devices including /dev/vfio/*
/// - guest-kernel mode: Removes /dev/vfio/* devices as they're managed by guest kernel
///   Note that the guest-kernel mode is assumed if vfio_mode is unset/empty.
fn filter_vfio_devices(linux: &mut oci::Linux, vfio_mode: &str) {
    if vfio_mode == "vfio" {
        return;
    }

    const VFIO_PATH: &str = "/dev/vfio/";
    let filtered = linux.devices().as_ref().map(|devices| {
        devices
            .iter()
            .filter(|d| {
                !(d.typ() == oci::LinuxDeviceType::C
                    && d.path().to_str().is_some_and(|p| p.starts_with(VFIO_PATH)))
            })
            .cloned()
            .collect::<Vec<_>>()
    });
    linux.set_devices(match filtered {
        Some(v) if v.is_empty() => None,
        other => other,
    });
}

#[cfg(test)]
mod tests {
    use super::amend_spec;
    use super::is_pid_namespace_enabled;
    use super::*;
    use oci_spec::runtime::LinuxNamespaceType;
    use oci_spec::runtime::{LinuxBuilder, LinuxNamespaceBuilder};

    #[test]
    fn test_amend_spec_disable_guest_seccomp() {
        let mut spec = oci::Spec::default();
        let mut linux = oci::Linux::default();
        linux.set_seccomp(Some(oci::LinuxSeccomp::default()));
        spec.set_linux(Some(linux));

        assert!(spec.linux().as_ref().unwrap().seccomp().is_some());

        // disable_guest_seccomp = false
        amend_spec(&mut spec, false, false).unwrap();
        assert!(spec.linux().as_ref().unwrap().seccomp().is_some());

        // disable_guest_seccomp = true
        amend_spec(&mut spec, true, false).unwrap();
        assert!(spec.linux().as_ref().unwrap().seccomp().is_none());
    }

    #[test]
    fn test_amend_spec_strips_host_time_namespace() {
        let mut spec = oci::Spec::default();
        let linux = LinuxBuilder::default()
            .namespaces(vec![
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Time)
                    .path("/proc/1/ns/time")
                    .build()
                    .unwrap(),
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Uts)
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap();
        spec.set_linux(Some(linux));

        amend_spec(&mut spec, false, false).unwrap();

        let namespaces = spec
            .linux()
            .as_ref()
            .unwrap()
            .namespaces()
            .as_ref()
            .unwrap();
        assert_eq!(namespaces.len(), 1);
        assert_eq!(namespaces[0].typ(), LinuxNamespaceType::Uts);
    }

    #[test]
    fn test_amend_spec_disable_guest_selinux() {
        let mut spec = oci::SpecBuilder::default()
            .process(
                oci::ProcessBuilder::default()
                    .selinux_label("xxx".to_owned())
                    .build()
                    .unwrap(),
            )
            .linux(
                oci::LinuxBuilder::default()
                    .mount_label("yyy".to_owned())
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        // disable_guest_selinux = false, selinux labels are left alone
        amend_spec(&mut spec, false, false).unwrap();
        assert!(spec.process().as_ref().unwrap().selinux_label() == &Some("xxx".to_owned()));
        assert!(spec.linux().as_ref().unwrap().mount_label() == &Some("yyy".to_owned()));

        // disable_guest_selinux = true, selinux labels are reset
        amend_spec(&mut spec, false, true).unwrap();
        assert!(spec.process().as_ref().unwrap().selinux_label().is_none());
        assert!(spec.linux().as_ref().unwrap().mount_label().is_none());
    }

    #[test]
    fn test_is_pid_namespace_enabled() {
        struct TestData<'a> {
            desc: &'a str,
            namespaces: Vec<oci::LinuxNamespace>,
            result: bool,
        }

        let tests = &[
            TestData {
                desc: "no pid namespace",
                namespaces: vec![LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Network)
                    .path("/dev/null")
                    .build()
                    .unwrap()],
                result: false,
            },
            TestData {
                desc: "empty pid namespace path",
                namespaces: vec![
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Network)
                        .build()
                        .unwrap(),
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Pid)
                        .build()
                        .unwrap(),
                ],
                result: false,
            },
            TestData {
                desc: "pid namespace is set",
                namespaces: vec![
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Network)
                        .path("/some/path")
                        .build()
                        .unwrap(),
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Pid)
                        .path("/dev/null")
                        .build()
                        .unwrap(),
                ],
                result: true,
            },
        ];

        let mut spec = oci::Spec::default();

        for (i, d) in tests.iter().enumerate() {
            spec.set_linux(Some(
                LinuxBuilder::default()
                    .namespaces(d.namespaces.clone())
                    .build()
                    .unwrap(),
            ));
            // spec.linux = Some(oci::Linux {
            //     namespaces: d.namespaces.clone(),
            //     ..Default::default()
            // });

            assert_eq!(
                d.result,
                is_pid_namespace_enabled(&spec),
                "test[{}]: {:?}",
                i,
                d.desc
            );
        }
    }

    #[test]
    fn test_filter_vfio_devices_guest_kernel_mode() {
        // Test that VFIO devices are filtered out in guest-kernel mode
        let vfio_device = oci::LinuxDeviceBuilder::default()
            .path("/dev/vfio/1")
            .typ(oci::LinuxDeviceType::C)
            .major(10)
            .minor(196)
            .build()
            .unwrap();

        let non_vfio_device = oci::LinuxDeviceBuilder::default()
            .path("/dev/null")
            .typ(oci::LinuxDeviceType::C)
            .major(1)
            .minor(3)
            .build()
            .unwrap();

        let mut linux = oci::LinuxBuilder::default()
            .devices(vec![vfio_device, non_vfio_device.clone()])
            .build()
            .unwrap();

        filter_vfio_devices(&mut linux, "guest-kernel");

        let devices = linux.devices().as_ref().unwrap();
        assert_eq!(
            devices.len(),
            1,
            "Should have only 1 device after filtering"
        );
        assert_eq!(
            devices[0].path(),
            non_vfio_device.path(),
            "Non-VFIO device should be preserved"
        );
    }

    #[test]
    fn test_filter_vfio_devices_vfio_mode() {
        // Test that VFIO devices are preserved in vfio mode
        let vfio_device = oci::LinuxDeviceBuilder::default()
            .path("/dev/vfio/1")
            .typ(oci::LinuxDeviceType::C)
            .major(10)
            .minor(196)
            .build()
            .unwrap();

        let non_vfio_device = oci::LinuxDeviceBuilder::default()
            .path("/dev/null")
            .typ(oci::LinuxDeviceType::C)
            .major(1)
            .minor(3)
            .build()
            .unwrap();

        let mut linux = oci::LinuxBuilder::default()
            .devices(vec![vfio_device, non_vfio_device])
            .build()
            .unwrap();

        filter_vfio_devices(&mut linux, "vfio");

        let devices = linux.devices().as_ref().unwrap();
        assert_eq!(devices.len(), 2, "Should have both devices in vfio mode");
    }

    #[test]
    fn test_filter_vfio_devices_only_vfio_filtered() {
        // Test that only /dev/vfio/* devices are filtered in guest-kernel mode
        let vfio_device = oci::LinuxDeviceBuilder::default()
            .path("/dev/vfio/1")
            .typ(oci::LinuxDeviceType::C)
            .major(10)
            .minor(196)
            .build()
            .unwrap();

        let vfio_container = oci::LinuxDeviceBuilder::default()
            .path("/dev/vfio/vfio")
            .typ(oci::LinuxDeviceType::C)
            .major(10)
            .minor(196)
            .build()
            .unwrap();

        let similar_path = oci::LinuxDeviceBuilder::default()
            .path("/dev/vfio-test")
            .typ(oci::LinuxDeviceType::C)
            .major(1)
            .minor(1)
            .build()
            .unwrap();

        let mut linux = oci::LinuxBuilder::default()
            .devices(vec![vfio_device, vfio_container, similar_path.clone()])
            .build()
            .unwrap();

        filter_vfio_devices(&mut linux, "guest-kernel");

        let devices = linux.devices().as_ref().unwrap();
        assert_eq!(
            devices.len(),
            1,
            "Should only filter devices starting with /dev/vfio/"
        );
        assert_eq!(
            devices[0].path(),
            similar_path.path(),
            "Device with similar but different path should be preserved"
        );
    }

    #[test]
    fn test_filter_vfio_devices_empty_mode() {
        // Test default/empty mode behavior (should filter /dev/vfio/* like guest-kernel mode)
        let vfio_device = oci::LinuxDeviceBuilder::default()
            .path("/dev/vfio/1")
            .typ(oci::LinuxDeviceType::C)
            .major(10)
            .minor(196)
            .build()
            .unwrap();

        let mut linux = oci::LinuxBuilder::default()
            .devices(vec![vfio_device])
            .build()
            .unwrap();

        filter_vfio_devices(&mut linux, "");

        assert!(
            linux.devices().is_none(),
            "Should filter out VFIO device with empty mode"
        );
    }

    #[test]
    fn test_filter_vfio_devices_no_devices() {
        // Test that filtering works when there are no devices
        let mut linux = oci::LinuxBuilder::default().build().unwrap();

        filter_vfio_devices(&mut linux, "guest-kernel");

        assert!(
            linux.devices().is_none(),
            "Should remain None when no devices"
        );
    }
}

impl Container {
    pub async fn attach_live_volume(&self, request: super::live_volume::BlockAttach) -> Result<()> {
        if request.action == "detach" { return self.detach_live_volume(request).await; }
        use super::live_volume::{PendingVolume, validate_metadata, validate_generation, validate_agent_capability};
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        validate_generation(&request, &self.spec)?;
        let mut inner = self.inner.write().await;
        inner.check_state(vec![ProcessStatus::Running, ProcessStatus::Paused]).await?;
        if inner.live_growth.contains_key(&request.request_id) {
            return Err(anyhow!("volume_update_conflict: ID already used for growth"));
        }
        let paused = inner.init_process.get_status().await == ProcessStatus::Paused;
        // Capability absence, an old guest, or a failed query must stop before
        // native device insertion, request reservation or guest mutation.
        let details = self.agent.get_guest_details(agent::GetGuestDetailsRequest::default()).await?;
        let device_manager = self.resource_manager.get_device_manager().await;
        let config = hypervisor::device::device_manager::get_block_device_info(&device_manager).await;
        validate_agent_capability(&details, &config.block_device_driver)?;
        if paused {
            super::live_volume::validate_paused_verification(
                inner.live_volumes.get(&request.request_id), &request, &details)?;
        }
        let metadata = resource::volume::direct_volumes::volume_mount_info(&request.source)?;
        validate_metadata(&request, &metadata)?;
        let host = std::fs::symlink_metadata(&metadata.device)?;
        let number = format!("{}:{}", libc::major(host.rdev()), libc::minor(host.rdev()));
        if !host.file_type().is_block_device()
            || metadata.metadata.get("openstack.device_number") != Some(&number) {
            return Err(anyhow!("volume_update_conflict: host device identity differs"));
        }
        // Compare the parsed record on replay without depending on HashMap order.
        let metadata_identity = serde_json::to_value(&metadata)?;
        if let Some(prior) = inner.live_volumes.get(&request.request_id) {
            if prior.detach.is_some() { return Err(anyhow!("volume_update_conflict: original attach is detaching or detached")); }
            if prior.request != request || prior.metadata_identity != metadata_identity {
                return Err(anyhow!("volume_update_conflict: request ID reused"));
            }
        } else {
            if inner.live_volumes.values().any(|v| !v.detach.as_ref().is_some_and(|d| d.complete)
                && (v.request.destination == request.destination || v.request.volume_uuid == request.volume_uuid))
                || self.spec.mounts().as_ref().is_some_and(|mounts| mounts.iter()
                    .any(|m| m.destination().to_str() == Some(request.destination.as_str())
                        && !inner.live_volumes.values().any(|v| v.created
                            && v.request.destination == request.destination
                            && m.source().as_ref().and_then(|s| s.to_str()) == Some(v.request.source.as_str())
                            && v.detach.as_ref().is_some_and(|d| d.complete))))
                || self.spec.linux().as_ref().and_then(|l| l.devices().as_ref())
                    .is_some_and(|devices| devices.iter()
                        .any(|d| d.path().to_str() == Some(request.destination.as_str()))) {
                return Err(anyhow!("volume_update_conflict: destination or volume already owned"));
            }
            // Reserve before native insertion: an insertion error can be partial.
            // A retry must not blindly insert again after ambiguous failure.
            inner.live_volumes.insert(request.request_id.clone(), PendingVolume {
                request: request.clone(), metadata_identity, volume: None, device: None, detach: None, created: false,
            });
            let mut mount = oci::Mount::default();
            mount.set_typ(Some("directvol".into()));
            mount.set_source(Some(request.source.clone().into()));
            mount.set_destination(request.destination.clone().into());
            mount.set_options(Some(vec!["rbind".into(),
                if request.readonly { "ro".into() } else { "rw".into() }]));
            let mut spec = oci::Spec::default();
            spec.set_mounts(Some(vec![mount]));
            let volumes = self.resource_manager.handler_volumes(&self.config.container_id, &spec).await?;
            // Retain every native result for normal container cleanup even if the
            // following shape/descriptor checks fail.
            inner.volumes.extend(volumes.iter().cloned());
            if volumes.len() != 1 { return Err(anyhow!("volume_update_pending: unexpected native volume result")); }
            let volume = volumes[0].clone();
            inner.live_volumes.get_mut(&request.request_id).unwrap().volume = Some(volume.clone());
            let storage = volume.get_storage()?;
            if storage.len() != 1 || !matches!(storage[0].driver.as_str(), "blk" | "scsi")
                || storage[0].source.is_empty() || volume.get_device_id()?.is_none() {
                return Err(anyhow!("volume_update_pending: unsupported native device descriptor"));
            }
            let device = agent::types::Device {
                id: storage[0].source.clone(), field_type: storage[0].driver.clone(),
                container_path: request.destination.clone(), ..Default::default()
            };
            inner.live_volumes.get_mut(&request.request_id).unwrap().device = Some(device);
        }
        let device = inner.live_volumes[&request.request_id].device.clone()
            .ok_or_else(|| anyhow!("volume_update_pending: native insertion requires reconciliation"))?;
        // On timeout/error retain the native volume and retry this same agent
        // operation. Never infer non-use or unmap storage from a failed reply.
        self.agent.attach_block_device(agent::AttachBlockDeviceRequest {
            container_id: self.container_id.container_id.clone(),
            request_id: request.request_id, device,
        }).await.context("agent attach live volume")?;
        Ok(())
    }

    pub async fn detach_live_volume(&self, request: super::live_volume::BlockAttach) -> Result<()> {
        use super::live_volume::{PendingDetach, validate_generation, validate_detach_target, DETACH_FEATURE};
        use agent::types::{block_detach_refusal, BlockDetachRefusal};
        validate_generation(&request, &self.spec)?;
        let mut inner = self.inner.write().await;
        if inner.live_growth.contains_key(&request.request_id) || inner.live_growth.values().any(|g|
            !g.complete && Some(&g.request.attachment.request_id) == request.attach_request_id.as_ref()) {
            return Err(anyhow!("volume_update_pending: reconcile growth before detach"));
        }
        let attach_id = request.attach_request_id.clone().ok_or_else(|| anyhow!("original attach request required"))?;
        let prior = inner.live_volumes.get(&attach_id).ok_or_else(|| anyhow!("volume_update_conflict: unknown attachment"))?;
        validate_detach_target(&request, &prior.request)?;
        if let Some(detach) = &prior.detach {
            if detach.request != request { return Err(anyhow!("volume_update_conflict: detach request changed")); }
            if detach.complete { return Ok(()); }
            if detach.resume_attempted { return Err(anyhow!("volume_update_pending: ambiguous resume requires reconciliation")); }
        }
        let details = self.agent.get_guest_details(agent::GetGuestDetailsRequest::default()).await?;
        if !details.agent_details.as_ref().is_some_and(|a| a.extra_features.iter().any(|f| f == DETACH_FEATURE)) {
            return Err(anyhow!("volume_update_unsupported: guest detach capability absent"));
        }
        let dm = self.resource_manager.get_device_manager().await;
        if inner.live_volumes[&attach_id].detach.is_none() {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let metadata = resource::volume::direct_volumes::volume_mount_info(&request.source)?;
            super::live_volume::validate_metadata(&request, &metadata)?;
            if serde_json::to_value(&metadata)? != inner.live_volumes[&attach_id].metadata_identity {
                return Err(anyhow!("volume_update_conflict: detach metadata changed"));
            }
            let host = std::fs::symlink_metadata(&metadata.device)?;
            if !host.file_type().is_block_device() || metadata.metadata.get("openstack.device_number")
                != Some(&format!("{}:{}", libc::major(host.rdev()), libc::minor(host.rdev()))) {
                return Err(anyhow!("volume_update_conflict: detach host device changed"));
            }
            inner.check_state(vec![ProcessStatus::Running, ProcessStatus::Paused]).await?;
            if inner.live_volumes.contains_key(&request.request_id) || inner.live_volumes.values()
                .any(|v| v.detach.as_ref().is_some_and(|d| d.request.request_id == request.request_id)) {
                return Err(anyhow!("volume_update_conflict: request ID already used"));
            }
            if inner.live_volumes[&attach_id].device.is_none() || inner.live_volumes[&attach_id].volume.is_none() {
                return Err(anyhow!("volume_update_pending: incomplete native attachment"));
            }
            let running = inner.init_process.get_status().await == ProcessStatus::Running;
            inner.live_volumes.get_mut(&attach_id).unwrap().detach = Some(PendingDetach {
                request: request.clone(), resume_required: running, pause_attempted: false,
                paused: !running, prepared: false, prepare_uncertain: false, removal_attempted: false, removed: false,
                committed: false, resume_attempted: false, complete: false,
            });
        }
        if !inner.live_volumes[&attach_id].detach.as_ref().unwrap().paused {
            let state = inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap();
            if state.pause_attempted { return Err(anyhow!("volume_update_pending: ambiguous pause requires reconciliation")); }
            state.pause_attempted = true;
            self.agent.pause_container(self.container_id.clone().into()).await.context("detach pause")?;
            inner.set_state(ProcessStatus::Paused).await;
            inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap().paused = true;
        }
        let rpc = |phase: &str| agent::DetachBlockDeviceRequest {
            container_id: self.container_id.container_id.clone(), request_id: request.request_id.clone(),
            attach_request_id: attach_id.clone(), phase: phase.into(),
        };
        if !inner.live_volumes[&attach_id].detach.as_ref().unwrap().prepared {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let previous_uncertain = inner.live_volumes[&attach_id].detach.as_ref().unwrap().prepare_uncertain;
                inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap().prepare_uncertain = true;
                match self.agent.detach_block_device(rpc("prepare")).await {
                    Ok(_) => break,
                    Err(error) => {
                      let refusal = block_detach_refusal(&error);
                      if refusal.is_some() && previous_uncertain {
                          return Err(error.context("earlier prepare is uncertain; no compensation authorized"));
                      }
                      if refusal.is_some() {
                          inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap().prepare_uncertain = false;
                      }
                      match refusal {
                        Some(BlockDetachRefusal::FreezePending) if tokio::time::Instant::now() < deadline => {
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                        Some(_) => {
                            // Only these explicit pre-mutation refusals authorize
                            // restoration. Unknown failures retain paused state.
                            if inner.live_volumes[&attach_id].detach.as_ref().unwrap().resume_required {
                                inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap().resume_attempted = true;
                                if let Err(resume) = self.agent.resume_container(self.container_id.clone().into()).await {
                                    return Err(error.context(format!("detach refused; resume also failed: {resume:#}")));
                                }
                                inner.set_state(ProcessStatus::Running).await;
                            }
                            inner.live_volumes.get_mut(&attach_id).unwrap().detach = None;
                            return Err(error.context("detach admission refused without withdrawal"));
                        }
                        None => return Err(error.context("detach prepare uncertain; retain paused operation")),
                      }
                    }
                }
            }
            inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap().prepared = true;
            inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap().prepare_uncertain = false;
        }
        if !inner.live_volumes[&attach_id].detach.as_ref().unwrap().removed {
            let state = inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap();
            if state.removal_attempted { return Err(anyhow!("volume_update_pending: ambiguous native removal requires reconciliation")); }
            state.removal_attempted = true;
            let volume = inner.live_volumes[&attach_id].volume.clone().ok_or_else(|| anyhow!("native volume missing"))?;
            volume.cleanup(&dm).await.context("native live volume removal")?;
            inner.volumes.retain(|v| !std::sync::Arc::ptr_eq(v, &volume));
            let prior = inner.live_volumes.get_mut(&attach_id).unwrap();
            prior.volume = None;
            prior.detach.as_mut().unwrap().removed = true;
        }
        if !inner.live_volumes[&attach_id].detach.as_ref().unwrap().committed {
            self.agent.detach_block_device(rpc("complete")).await.context("guest detach completion")?;
            inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap().committed = true;
        }
        if inner.live_volumes[&attach_id].detach.as_ref().unwrap().resume_required {
            let state = inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap();
            if state.resume_attempted { return Err(anyhow!("volume_update_pending: ambiguous resume requires reconciliation")); }
            state.resume_attempted = true;
            self.agent.resume_container(self.container_id.clone().into()).await.context("detach resume")?;
            inner.set_state(ProcessStatus::Running).await;
        }
        inner.live_volumes.get_mut(&attach_id).unwrap().detach.as_mut().unwrap().complete = true;
        Ok(())
    }
}

// SPDX-License-Identifier: Apache-2.0
impl Container {
    pub async fn grow_live_volume(&self, request: super::live_volume_growth::GrowthRequest) -> Result<()> {
        use super::live_volume::{validate_generation, validate_metadata};
        use super::live_volume_growth::{validate_history, PendingGrowth};
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        validate_generation(&request.attachment, &self.spec)?;
        let mut inner = self.inner.write().await;
        inner.check_state(vec![ProcessStatus::Running]).await?;
        let manager = self.resource_manager.get_device_manager().await;
        if !manager.read().await.supports_block_growth() {
            return Err(anyhow!("volume_update_unsupported: hypervisor block growth unavailable"));
        }
        validate_history(&request, &inner.live_growth)?;
        if inner.live_volumes.contains_key(&request.request_id) || inner.live_volumes.values()
            .any(|v| v.detach.as_ref().is_some_and(|d| d.request.request_id == request.request_id)) {
            return Err(anyhow!("volume_update_conflict: growth ID used by another operation"));
        }
        let original = &request.attachment;
        let prior = inner.live_volumes.get(&original.request_id)
            .ok_or_else(|| anyhow!("volume_update_conflict: unknown growth attachment"))?;
        if prior.request != *original || prior.detach.is_some() {
            return Err(anyhow!("volume_update_conflict: growth attachment changed or is detaching"));
        }
        let metadata = resource::volume::direct_volumes::volume_mount_info(&original.source)?;
        validate_metadata(original, &metadata)?;
        if serde_json::to_value(&metadata)? != prior.metadata_identity {
            return Err(anyhow!("volume_update_conflict: growth metadata changed"));
        }
        let host = std::fs::symlink_metadata(&metadata.device)?;
        if !host.file_type().is_block_device() || metadata.metadata.get("openstack.device_number")
            != Some(&format!("{}:{}", libc::major(host.rdev()), libc::minor(host.rdev()))) {
            return Err(anyhow!("volume_update_conflict: growth mapping changed"));
        }
        let volume = prior.volume.as_ref().context("volume_update_pending: native volume absent")?;
        let device_id = volume.get_device_id()?.context("volume_update_pending: native device absent")?;
        let device = prior.device.clone().context("volume_update_pending: guest descriptor absent")?;
        // Reserve before any guest/runtime call. Lost replies retain the original
        // attachment and block conflicting growth/detach until this request retries.
        inner.live_growth.entry(request.request_id.clone()).or_insert_with(|| PendingGrowth {
            request: request.clone(), complete: false,
        });
        // Confirm/replay exposure using the original idempotent attach identity;
        // PendingVolume alone can represent a lost agent attach reply.
        self.agent.attach_block_device(agent::AttachBlockDeviceRequest {
            container_id: self.container_id.container_id.clone(),
            request_id: original.request_id.clone(), device,
        }).await.context("confirm original attachment before growth")?;
        manager.write().await.grow_block_device(&device_id, request.requested_bytes).await?;
        inner.live_growth.get_mut(&request.request_id).unwrap().complete = true;
        Ok(())
    }
}

// Nova Kata (ADR-044).
impl Container {
    pub async fn update_live_network(
        &self,
        update: super::live_network::NetworkUpdate,
    ) -> Result<()> {
        super::live_network::validate_generation(&update, &self.spec)?;
        // The container's state is held: no stop and no pause runs while
        // the guest is given or loses an interface.
        let inner = self.inner.write().await;
        inner
            .check_state(vec![ProcessStatus::Running])
            .await
            .context("network_update_conflict: the instance does not run")?;
        info!(
            self.logger,
            "network update {} of {}: {} {:?}",
            update.request_id,
            self.container_id.container_id,
            update.action,
            update.interface
        );
        match update.endpoint() {
            Some(endpoint) => {
                self.resource_manager
                    .update_network(endpoint, update.attaches())
                    .await
            }
            None => self.resource_manager.refresh_network().await,
        }
    }
}

/// Nova Kata (ADR-052): the spec asks the sandbox to receive a VM.
fn migrated_in(spec: &oci::Spec) -> bool {
    spec.annotations()
        .as_ref()
        .map(|annotations| annotations.contains_key(hypervisor::migration::MIGRATE_IN_KEY))
        .unwrap_or(false)
}

/// The migrate-in request of the spec, if any.
fn migrated_in_as(spec: &oci::Spec) -> Result<Option<hypervisor::migration::MigrateIn>> {
    match spec.annotations() {
        Some(annotations) => hypervisor::migration::migrate_in(annotations),
        None => Ok(None),
    }
}
