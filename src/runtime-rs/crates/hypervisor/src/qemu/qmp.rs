// Copyright (c) 2024 Red Hat
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::device::pci_path::PciPath;
use crate::qemu::block_source::{block_fd_node_name, block_fd_opaque, prepare_block_source};
use crate::qemu::cmdline_generator::{CcwSubChannel, DeviceVirtioNet, Netdev, QMP_SOCKET_FILE};
use crate::utils::get_jailer_root;
use crate::VcpuThreadIds;
use crate::VmdkConfig;
use crate::BlockIoLimits;

use anyhow::{anyhow, Context, Result};
use kata_types::config::hypervisor::{VIRTIO_BLK_CCW, VIRTIO_SCSI};
use kata_types::rootless::is_rootless;
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use qapi_qmp::{
    self as qmp, BlockdevAioOptions, BlockdevDiscardOptions, BlockdevOptions, BlockdevOptionsBase,
    BlockdevOptionsGenericCOWFormat, BlockdevOptionsGenericFormat, BlockdevOptionsRaw, BlockdevRef,
    MigrationInfo, PciDeviceInfo,
};
use qapi_qmp::{migrate, migrate_incoming, migrate_set_capabilities};
use qapi_qmp::{MigrationCapability, MigrationCapabilityStatus, MigrationStatus};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{Debug, Error, Formatter};
use std::io::BufReader;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

// Nova Kata (ADR-052): the names under which the shim hands QEMU the
// migration's sockets (QMP getfd).
const MIGRATION_OUT_FD: &str = "nova-migration-out";
const MIGRATION_IN_FD: &str = "nova-migration-in";
use std::str::FromStr;
use std::time::Duration;

use qapi_spec::Dictionary;
use std::thread;
use std::time::Instant;

/// default qmp connection read timeout
const DEFAULT_QMP_READ_TIMEOUT: u64 = 250;
const DEFAULT_QMP_INIT_READ_TIMEOUT: u64 = 5000;
const DEFAULT_QMP_CONNECT_DEADLINE_MS: u64 = 50000;
const DEFAULT_QMP_RETRY_SLEEP_MS: u64 = 50;

const DEVICE_DELETED_TIMEOUT: Duration = Duration::from_secs(10);

fn collect_block_fdsets(fdsets: Vec<qmp::FdsetInfo>) -> HashMap<String, Vec<i64>> {
    let mut block_fdsets: HashMap<String, Vec<i64>> = HashMap::new();
    for fdset in fdsets {
        for fd in fdset.fds {
            let Some(node_name) = fd.opaque.as_deref().and_then(block_fd_node_name) else {
                continue;
            };
            let ids = block_fdsets.entry(node_name.to_string()).or_default();
            if !ids.contains(&fdset.fdset_id) {
                ids.push(fdset.fdset_id);
            }
        }
    }
    block_fdsets
}

pub struct Qmp {
    qmp: qapi::Qmp<qapi::Stream<BufReader<UnixStream>, UnixStream>>,

    // This is basically the output of
    // `cat /sys/devices/system/memory/block_size_bytes`
    // on the guest.  Note a slightly peculiar behaviour with relation to
    // the size of hotplugged memory blocks: if an amount of memory is being
    // hotplugged whose size is not an integral multiple of page size
    // (4k usually) hotplugging fails immediately.  However, if the amount
    // is fine wrt the page size *but* isn't wrt this "guest memory block size"
    // hotplugging apparently succeeds, even though none of the hotplugged
    // blocks seem ever to be onlined in the guest by kata-agent.
    // Store as u64 to keep up the convention of bytes being represented as u64.
    guest_memory_block_size: u64,

    // CCW subchannel for s390x device address management.
    // Transferred from QemuCmdLine after boot so that hotplug allocations
    // continue from where boot-time allocations left off.
    ccw_subchannel: Option<CcwSubChannel>,

    // Hot-plug slot tracking for cold-plugged pci-bridge-N devices. Mirrors
    // virtcontainers/types/bridges.go Bridge.Devices (slots 1..30).
    pci_bridge_devices: HashMap<String, HashMap<i64, String>>,

    // QMP fdsets backing hot-plugged block devices. Keep them until the
    // backend is removed because format drivers such as VMDK may reopen an
    // extent after blockdev-add completes.
    block_fdsets: HashMap<String, Vec<i64>>,

    // Nova Kata (ADR-052): the guest MAC of each network device on a bridge
    // (by its frontend id), and, on a migration's destination, the place
    // each MAC had on the source.
    network_macs: HashMap<String, String>,
    /// Nova Kata (ADR-052): by frontend id, whether the NIC is modern virtio.
    network_modern: HashMap<String, bool>,
    network_pins: HashMap<String, (String, i64, bool)>,
}

// We have to implement Debug since the Hypervisor trait requires it and Qmp
// is ultimately stored in one of Hypervisor's implementations (Qemu).
// We can't do it automatically since the type of Qmp::qmp isn't Debug.
impl Debug for Qmp {
    fn fmt(&self, _f: &mut Formatter<'_>) -> Result<(), Error> {
        Ok(())
    }
}

impl Qmp {
    pub fn new(qmp_sock_path: &str) -> Result<Self> {
        let try_new_once_fn = || -> Result<Qmp> {
            let stream = UnixStream::connect(qmp_sock_path)?;

            stream
                .set_read_timeout(Some(Duration::from_millis(DEFAULT_QMP_INIT_READ_TIMEOUT)))
                .context("set qmp read timeout")?;

            let mut qmp = Qmp {
                qmp: qapi::Qmp::new(qapi::Stream::new(
                    BufReader::new(stream.try_clone()?),
                    stream,
                )),
                guest_memory_block_size: 0,
                ccw_subchannel: None,
                pci_bridge_devices: HashMap::new(),
                block_fdsets: HashMap::new(),
                network_macs: HashMap::new(),
                network_modern: HashMap::new(),
                network_pins: HashMap::new(),
            };

            let info = qmp.qmp.handshake().context("qmp handshake failed")?;
            info!(sl!(), "QMP initialized: {:#?}", info);
            qmp.refresh_block_fdsets()?;

            Ok(qmp)
        };

        let deadline = Instant::now() + Duration::from_millis(DEFAULT_QMP_CONNECT_DEADLINE_MS);
        let mut last_err: Option<anyhow::Error> = None;

        while Instant::now() < deadline {
            match try_new_once_fn() {
                Ok(qmp) => return Ok(qmp),
                Err(e) => {
                    debug!(sl!(), "QMP not ready yet: {}", e);
                    last_err = Some(e);
                    thread::sleep(Duration::from_millis(DEFAULT_QMP_RETRY_SLEEP_MS));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("QMP init timed out")))
            .with_context(|| format!("timed out waiting for QMP ready: {}", qmp_sock_path))
    }

    fn refresh_block_fdsets(&mut self) -> Result<()> {
        let fdsets = self
            .qmp
            .execute(&qmp::query_fdsets {})
            .context("query QEMU fdsets")?;
        self.block_fdsets = collect_block_fdsets(fdsets);
        Ok(())
    }

    pub fn verify_block_fdsets(&self, mut expected: HashMap<String, Vec<i64>>) -> Result<()> {
        let mut actual = self.block_fdsets.clone();
        for ids in expected.values_mut() {
            ids.sort_unstable();
        }
        for ids in actual.values_mut() {
            ids.sort_unstable();
        }
        if actual != expected {
            return Err(anyhow!(
                "QEMU startup block fdsets do not match the descriptors passed by the shim"
            ));
        }
        Ok(())
    }

    pub fn set_ccw_subchannel(&mut self, subchannel: CcwSubChannel) {
        self.ccw_subchannel = Some(subchannel);
    }

    /// Initialise PCI bridge slot maps for cold-plugged `pci-bridge-N` devices.
    pub fn init_pci_bridges(&mut self, count: u32) {
        for idx in 0..count {
            self.pci_bridge_devices
                .insert(format!("pci-bridge-{idx}"), HashMap::new());
        }
    }

    pub fn set_ignore_shared_memory_capability(&mut self) -> Result<()> {
        self.qmp
            .execute(&migrate_set_capabilities {
                capabilities: vec![MigrationCapabilityStatus {
                    capability: MigrationCapability::x_ignore_shared,
                    state: true,
                }],
            })
            .map(|_| ())
            .context("set ignore shared memory capability")
    }

    pub fn execute_migration(&mut self, uri: &str) -> Result<()> {
        self.qmp
            .execute(&migrate {
                channels: None,
                detach: None,
                resume: None,
                uri: Some(uri.to_string()),
            })
            .map(|_| ())
            .context("execute migration")
    }

    pub async fn execute_query_migrate(&mut self) -> Result<MigrationInfo> {
        let migrate_info = self.qmp.execute(&qmp::query_migrate {})?;

        Ok(migrate_info)
    }

    /// Nova Kata (ADR-052): on a migration's destination, the place each
    /// network device had on the source, by its guest MAC.
    pub fn set_network_pins(&mut self, pins: HashMap<String, (String, i64, bool)>) {
        self.network_pins = pins;
    }

    /// Nova Kata (ADR-052): the network devices on the bridges, by MAC.
    pub fn migration_networks(&self) -> Vec<crate::migration::NetworkPin> {
        let mut pins = Vec::new();
        for (bus, slots) in &self.pci_bridge_devices {
            for (slot, frontend) in slots {
                if let Some(mac) = self.network_macs.get(frontend) {
                    pins.push(crate::migration::NetworkPin {
                        mac: mac.clone(),
                        bus: bus.clone(),
                        slot: *slot,
                        modern: self.network_modern.get(frontend).copied().unwrap_or(true),
                    });
                }
            }
        }
        pins.sort_by(|a, b| (a.bus.as_str(), a.slot).cmp(&(b.bus.as_str(), b.slot)));
        pins
    }

    /// Nova Kata (ADR-052): send the VM over `stream`, which the shim
    /// connected in the host's network namespace: QEMU runs in the
    /// sandbox's, which has no route to the migration network. QEMU's
    /// `migrate` returns once the transfer began; query-migrate follows it.
    pub fn migration_send(
        &mut self,
        stream: &impl AsRawFd,
        params: &crate::migration::MigrationParams,
    ) -> Result<()> {
        // return-path: the source's transfer completes only once the
        // destination has loaded the state; one that fails to load it fails
        // the migration and the source runs on (ADR-052, one writer).
        self.qmp
            .execute(&migrate_set_capabilities {
                capabilities: vec![
                    MigrationCapabilityStatus {
                        capability: MigrationCapability::events,
                        state: true,
                    },
                    MigrationCapabilityStatus {
                        capability: MigrationCapability::return_path,
                        state: true,
                    },
                ],
            })
            .context("set the migration's capabilities")?;
        let mut parameters = qapi_qmp::MigrateSetParameters::default();
        if params.downtime_ms > 0 {
            parameters.downtime_limit = Some(params.downtime_ms);
        }
        if params.max_bandwidth > 0 {
            parameters.max_bandwidth = Some(params.max_bandwidth);
        }
        self.qmp
            .execute(&qapi_qmp::migrate_set_parameters(parameters))
            .context("set the migration's parameters")?;
        self.pass_fd(stream.as_raw_fd(), MIGRATION_OUT_FD)
            .context("hand the migration's connection to QEMU")?;
        self.execute_migration(&format!("fd:{MIGRATION_OUT_FD}"))
    }

    pub fn migration_cancel(&mut self) -> Result<()> {
        self.qmp
            .execute(&qapi_qmp::migrate_cancel {})
            .map(|_| ())
            .context("cancel the migration")
    }

    /// Nova Kata (ADR-052): query-migrate, as the shim reports it.
    pub fn migration_progress(&mut self) -> Result<crate::migration::MigrationProgress> {
        let info = self
            .qmp
            .execute(&qmp::query_migrate {})
            .context("query the migration")?;
        let status = match info.status {
            None | Some(MigrationStatus::none) => "none",
            Some(MigrationStatus::completed) => "completed",
            Some(MigrationStatus::failed) => "failed",
            Some(MigrationStatus::cancelled) => "cancelled",
            Some(_) => "active",
        };
        let ram = info.ram.as_ref();
        let positive = |value: Option<i64>| value.unwrap_or(0).max(0) as u64;
        Ok(crate::migration::MigrationProgress {
            status: status.to_string(),
            transferred: positive(ram.map(|r| r.transferred)),
            remaining: positive(ram.map(|r| r.remaining)),
            total_ms: positive(info.total_time),
            downtime_ms: positive(info.downtime),
            error: info.error_desc.clone().unwrap_or_default(),
            ..Default::default()
        })
    }

    /// Nova Kata (ADR-052): the block copy of a live migration, QEMU's
    /// mirror into an NBD export, as libvirt's. The destination exports
    /// the devices the source copies, on a unix socket of the sandbox the
    /// shim bridges to the migration's TCP side.
    pub fn nbd_exports_start(&mut self, socket: &str, indexes: &[u64]) -> Result<()> {
        self.qmp
            .execute(&qmp::nbd_server_start {
                addr: qmp::SocketAddressLegacy::unix(qmp::UnixSocketAddressWrapper {
                    data: qmp::UnixSocketAddress {
                        path: socket.to_string(),
                        abstract_: None,
                        tight: None,
                    },
                }),
                // A migration's TLS ends at the shim (migration_tls).
                tls_creds: None,
                tls_authz: None,
                max_connections: None,
            })
            .context("start the NBD server")?;
        for &index in indexes {
            let name = export_name(index);
            self.qmp
                .execute(&qmp::block_export_add(qmp::BlockExportOptions::nbd {
                    base: qmp::BlockExportOptionsBase {
                        id: name.clone(),
                        node_name: block_node_name(index),
                        writable: Some(true),
                        writethrough: None,
                        fixed_iothread: None,
                        iothread: None,
                    },
                    nbd: qmp::BlockExportOptionsNbd {
                        base: qmp::BlockExportOptionsNbdBase {
                            name: Some(name.clone()),
                            description: None,
                        },
                        allocation_depth: None,
                        bitmaps: None,
                    },
                }))
                .with_context(|| format!("export {name}"))?;
        }
        Ok(())
    }

    /// The exports end before the VM runs: a device the guest writes is
    /// not exported.
    pub fn nbd_exports_stop(&mut self, indexes: &[u64]) -> Result<()> {
        for &index in indexes {
            if let Err(error) = self.qmp.execute(&qmp::block_export_del {
                id: export_name(index),
                mode: Some(qmp::BlockExportRemoveMode::hard),
            }) {
                debug!(sl!(), "drop the export {}: {:?}", export_name(index), error);
            }
        }
        self.qmp
            .execute(&qmp::nbd_server_stop {})
            .map(|_| ())
            .context("stop the NBD server")
    }

    /// The source: mirror the device into the destination's export over
    /// `stream`, a connection the shim made (QEMU has no route to the
    /// migration network). The job keeps its end until it is dismissed, so
    /// that its error is read.
    pub fn mirror_start(
        &mut self,
        index: u64,
        stream: &impl AsRawFd,
        speed: u64,
    ) -> Result<()> {
        let fdname = format!("nova-nbd-{index}");
        self.pass_fd(stream.as_raw_fd(), &fdname)
            .context("hand the copy's connection to QEMU")?;
        let target = mirror_node_name(index);
        self.qmp
            .execute(&qmp::blockdev_add(qmp::BlockdevOptions::nbd {
                base: qmp::BlockdevOptionsBase {
                    auto_read_only: None,
                    cache: None,
                    detect_zeroes: None,
                    discard: None,
                    force_share: None,
                    node_name: Some(target.clone()),
                    read_only: None,
                },
                nbd: qmp::BlockdevOptionsNbd {
                    server: qmp::SocketAddress::fd(qmp::FdSocketAddress { str: fdname }),
                    export: Some(export_name(index)),
                    tls_creds: None,
                    tls_hostname: None,
                    x_dirty_bitmap: None,
                    reconnect_delay: None,
                    open_timeout: None,
                },
            }))
            .with_context(|| format!("open the destination's {}", export_name(index)))?;
        // The destination's device is a blank sparse file (the snapshotter's
        // blank root): the mirror copies what the source has and skips its
        // holes, which it would otherwise write as zeroes, counted against
        // the bandwidth and allocated on the destination (target-is-zero,
        // QEMU 10.1, which the crate's schema predates).
        self.qmp
            .execute(&BlockdevMirrorOfBlank {
                job_id: job_name(index),
                device: block_node_name(index),
                target,
                sync: "full",
                speed: (speed > 0).then_some(speed as i64),
                auto_dismiss: false,
                target_is_zero: true,
            })
            .map(|_| ())
            .with_context(|| format!("mirror {}", block_node_name(index)))
    }

    /// The mirror jobs of the copy, as they stand.
    pub fn mirror_jobs(&mut self) -> Result<Vec<MirrorJob>> {
        let jobs = self
            .qmp
            .execute(&qmp::query_block_jobs {})
            .context("query the block jobs")?;
        let mut result = Vec::new();
        for job in jobs {
            let qmp::BlockJobInfo::mirror { base, .. } = &job else {
                continue;
            };
            let Some(index) = base
                .device
                .strip_prefix(JOB_PREFIX)
                .and_then(|rest| rest.parse::<u64>().ok())
            else {
                continue;
            };
            result.push(MirrorJob {
                index,
                ready: base.ready,
                concluded: matches!(base.status, qmp::JobStatus::concluded | qmp::JobStatus::null),
                offset: base.offset.max(0) as u64,
                len: base.len.max(0) as u64,
                error: base.error.clone().unwrap_or_default(),
            });
        }
        Ok(result)
    }

    /// Cancel a mirror: a ready one writes its last blocks first (the
    /// source keeps its own device; nothing pivots), a forced one stops.
    pub fn mirror_cancel(&mut self, index: u64, force: bool) -> Result<()> {
        self.qmp
            .execute(&qmp::block_job_cancel {
                device: job_name(index),
                force: Some(force),
            })
            .map(|_| ())
            .with_context(|| format!("cancel {}", job_name(index)))
    }

    /// Drop a concluded job and its target node; absent is fine.
    pub fn mirror_dismiss(&mut self, index: u64) {
        if let Err(error) = self.qmp.execute(&qmp::job_dismiss { id: job_name(index) }) {
            debug!(sl!(), "dismiss {}: {:?}", job_name(index), error);
        }
        if let Err(error) = self.qmp.execute(&qmp::blockdev_del {
            node_name: mirror_node_name(index),
        }) {
            debug!(sl!(), "drop {}: {:?}", mirror_node_name(index), error);
        }
    }

    pub fn execute_migration_incoming(&mut self, uri: &str) -> Result<()> {
        self.qmp
            .execute(&migrate_incoming {
                channels: None,
                exit_on_error: None,
                uri: Some(uri.to_string()),
            })
            .map(|_| ())
            .context("execute migration incoming")
    }

    /// Nova Kata (ADR-052): receive the VM over `stream`, a connection the
    /// shim accepted in the host's network namespace. QEMU reads an fd it is
    /// given as a connected stream, never as a listener.
    pub fn migration_incoming_stream(&mut self, stream: &impl AsRawFd) -> Result<()> {
        // Both ends need return-path, which the source sets too. The block
        // devices are activated at the resume, not at the transfer's end:
        // a device exported for the source's copy is written until then.
        self.qmp
            .execute(&migrate_set_capabilities {
                capabilities: vec![
                    MigrationCapabilityStatus {
                        capability: MigrationCapability::return_path,
                        state: true,
                    },
                    MigrationCapabilityStatus {
                        capability: MigrationCapability::late_block_activate,
                        state: true,
                    },
                ],
            })
            .context("set the migration's capabilities")?;
        self.pass_fd(stream.as_raw_fd(), MIGRATION_IN_FD)
            .context("hand the migration's connection to QEMU")?;
        self.execute_migration_incoming(&format!("fd:{MIGRATION_IN_FD}"))
    }

    pub fn hotplug_vcpus(&mut self, vcpu_cnt: u32) -> Result<u32> {
        let hotpluggable_cpus = self.qmp.execute(&qmp::query_hotpluggable_cpus {})?;
        //info!(sl!(), "hotpluggable CPUs: {:#?}", hotpluggable_cpus);

        let mut hotplugged = 0;
        for vcpu in &hotpluggable_cpus {
            if hotplugged >= vcpu_cnt {
                break;
            }
            let core_id = match vcpu.props.core_id {
                Some(id) => id,
                None => {
                    warn!(sl!(), "hotpluggable vcpu has no core_id, skipping");
                    continue;
                }
            };
            if vcpu.qom_path.is_some() {
                info!(sl!(), "hotpluggable vcpu {} hotplugged already", core_id);
                continue;
            }
            let driver = &vcpu.type_;
            let mut cpu_args = Dictionary::new();
            cpu_args.insert("core-id".to_owned(), core_id.into());
            if !is_flat_cpu_topology(driver) {
                match (vcpu.props.socket_id, vcpu.props.thread_id) {
                    (Some(socket_id), Some(thread_id)) => {
                        cpu_args.insert("socket-id".to_owned(), socket_id.into());
                        cpu_args.insert("thread-id".to_owned(), thread_id.into());
                    }
                    (None, None) => {
                        warn!(sl!(), "hotpluggable vcpu {} has no socket_id and thread_id for driver {}, skipping", core_id, driver);
                        continue;
                    }
                    (None, _) => {
                        warn!(
                            sl!(),
                            "hotpluggable vcpu {} has no socket_id for driver {}, skipping",
                            core_id,
                            driver
                        );
                        continue;
                    }
                    (_, None) => {
                        warn!(
                            sl!(),
                            "hotpluggable vcpu {} has no thread_id for driver {}, skipping",
                            core_id,
                            driver
                        );
                        continue;
                    }
                }
            }
            self.qmp.execute(&qmp::device_add {
                bus: None,
                id: Some(vcpu_id_from_core_id(core_id)),
                driver: driver.clone(),
                arguments: cpu_args,
            })?;

            hotplugged += 1;
        }

        info!(
            sl!(),
            "Qmp::hotplug_vcpus(): hotplugged {}/{} vcpus", hotplugged, vcpu_cnt
        );

        Ok(hotplugged)
    }

    pub fn hotunplug_vcpus(&mut self, vcpu_cnt: u32) -> Result<u32> {
        let hotpluggable_cpus = self.qmp.execute(&qmp::query_hotpluggable_cpus {})?;

        let mut hotunplugged = 0;
        for vcpu in &hotpluggable_cpus {
            if hotunplugged >= vcpu_cnt {
                break;
            }
            let core_id = match vcpu.props.core_id {
                Some(id) => id,
                None => continue,
            };
            if vcpu.qom_path.is_none() {
                info!(sl!(), "hotpluggable vcpu {} not hotplugged yet", core_id);
                continue;
            }
            self.qmp.execute(&qmp::device_del {
                id: vcpu_id_from_core_id(core_id),
            })?;
            hotunplugged += 1;
        }

        info!(
            sl!(),
            "Qmp::hotunplug_vcpus(): hotunplugged {}/{} vcpus", hotunplugged, vcpu_cnt
        );

        Ok(hotunplugged)
    }

    pub fn set_guest_memory_block_size(&mut self, size: u64) {
        self.guest_memory_block_size = size;
    }

    pub fn guest_memory_block_size(&self) -> u64 {
        self.guest_memory_block_size
    }

    pub fn hotplugged_memory_size(&mut self) -> Result<u64> {
        let memory_frontends = self.qmp.execute(&qapi_qmp::query_memory_devices {})?;

        let mut hotplugged_mem_size = 0_u64;

        info!(
            sl!(),
            "hotplugged_memory_size(): iterating over memory devices"
        );
        for mem_frontend in &memory_frontends {
            match mem_frontend {
                qapi_qmp::MemoryDeviceInfo::dimm(dimm_info) => {
                    let id = match dimm_info.data.id {
                        Some(ref id) => id.clone(),
                        None => "".to_owned(),
                    };

                    info!(
                        sl!(),
                        "dimm id: {} size={}, hotplugged: {}",
                        id,
                        dimm_info.data.size,
                        dimm_info.data.hotplugged
                    );

                    if dimm_info.data.hotpluggable && dimm_info.data.hotplugged {
                        hotplugged_mem_size += dimm_info.data.size as u64;
                    }
                }
                qapi_qmp::MemoryDeviceInfo::virtio_mem(vm_info) => {
                    // For virtio-mem, the 'size' field is the requested-size
                    info!(
                        sl!(),
                        "virtio-mem device: requested-size={} bytes ({} MB)",
                        vm_info.data.size,
                        vm_info.data.size / (1024 * 1024)
                    );
                    hotplugged_mem_size += vm_info.data.size;
                }
                _ => {}
            }
        }

        info!(
            sl!(),
            "Total hotplugged memory: {} bytes ({} MB)",
            hotplugged_mem_size,
            hotplugged_mem_size / (1024 * 1024)
        );

        Ok(hotplugged_mem_size)
    }

    /// Hotplug memory into the VM.
    /// Automatically detects if virtio-mem is available and uses it; otherwise falls back to pc-dimm.
    pub fn hotplug_memory(&mut self, size: u64) -> Result<()> {
        // Query existing memory devices to detect virtio-mem
        let memory_devices = self.qmp.execute(&qapi_qmp::query_memory_devices {})?;

        // Check if virtio-mem device exists
        let has_virtio_mem = memory_devices
            .iter()
            .any(|memdev| matches!(memdev, qapi_qmp::MemoryDeviceInfo::virtio_mem(_)));

        if has_virtio_mem {
            self.hotplug_virtio_mem(size, memory_devices)
        } else {
            self.hotplug_pc_dimm(size, memory_devices)
        }
    }

    /// Hotplug memory using virtio-mem resize method.
    fn hotplug_virtio_mem(
        &mut self,
        size: u64,
        memory_devices: Vec<qapi_qmp::MemoryDeviceInfo>,
    ) -> Result<()> {
        info!(sl!(), "Detected virtio-mem device, using resize method");

        // Calculate current hotplugged memory from virtio-mem device
        let current_hotplugged_mb = memory_devices
            .iter()
            .filter_map(|memdev| {
                if let qapi_qmp::MemoryDeviceInfo::virtio_mem(vm_info) = memdev {
                    Some(vm_info.data.size / (1024 * 1024))
                } else {
                    None
                }
            })
            .sum::<u64>();

        let size_mb = size / (1024 * 1024);
        let new_total_mb = (current_hotplugged_mb + size_mb) as i64;

        info!(
            sl!(),
            "Hotplugging {} MB using virtio-mem (current: {} MB, new total: {} MB)",
            size_mb,
            current_hotplugged_mb,
            new_total_mb
        );

        self.resize_virtio_mem(new_total_mb)
    }

    /// Hotplug memory using pc-dimm device.
    fn hotplug_pc_dimm(
        &mut self,
        size: u64,
        memory_devices: Vec<qapi_qmp::MemoryDeviceInfo>,
    ) -> Result<()> {
        info!(sl!(), "No virtio-mem detected, using pc-dimm hotplug");

        let memdev_idx = memory_devices
            .into_iter()
            .filter(|memdev| {
                if let qapi_qmp::MemoryDeviceInfo::dimm(dimm_info) = memdev {
                    return dimm_info.data.hotpluggable && dimm_info.data.hotplugged;
                }
                false
            })
            .count();

        let memory_backend_id = format!("hotplugged-{memdev_idx}");

        let memory_backend = qmp::object_add(qapi_qmp::ObjectOptions::memory_backend_file {
            id: memory_backend_id.clone(),
            memory_backend_file: qapi_qmp::MemoryBackendFileProperties {
                base: qapi_qmp::MemoryBackendProperties {
                    dump: None,
                    host_nodes: None,
                    merge: None,
                    policy: None,
                    prealloc: None,
                    prealloc_context: None,
                    prealloc_threads: None,
                    reserve: None,
                    share: Some(true),
                    x_use_canonical_path_for_ramblock_id: None,
                    size,
                },
                align: None,
                discard_data: None,
                offset: None,
                pmem: None,
                readonly: None,
                mem_path: "/dev/shm".to_owned(),
                rom: None,
            },
        });
        self.qmp.execute(&memory_backend)?;

        let memory_frontend_id = format!("frontend-to-{memory_backend_id}");

        let mut mem_frontend_args = Dictionary::new();
        mem_frontend_args.insert("memdev".to_owned(), memory_backend_id.into());
        self.qmp.execute(&qmp::device_add {
            bus: None,
            id: Some(memory_frontend_id),
            driver: "pc-dimm".to_owned(),
            arguments: mem_frontend_args,
        })?;

        Ok(())
    }

    /// Cleanup virtio-mem resources on setup failure
    fn cleanup_virtio_mem_setup(&mut self, device_id: &str) {
        // Remove memory backend object
        let _ = self.qmp.execute(&qmp::object_del {
            id: "virtiomem".to_owned(),
        });

        // Remove CCW device slot
        if let Some(ccw) = self.ccw_subchannel.as_mut() {
            ccw.remove_device(device_id).ok();
        }
    }

    pub fn setup_virtio_mem(
        &mut self,
        default_memory: u32,
        default_maxmemory: u32,
        machine_type: &str,
        shared_fs: Option<&str>,
    ) -> Result<()> {
        // Calculate virtio-mem size: (default_maxmemory - default_memory) aligned to 4MB
        // default_maxmemory is already validated during sandbox initialization
        let diff_mb = default_maxmemory
            .checked_sub(default_memory)
            .ok_or_else(|| {
                anyhow!(
                    "default_maxmemory ({}) must be >= default_memory ({}) for virtio-mem setup",
                    default_maxmemory,
                    default_memory
                )
            })?;
        let size_mb = u64::from(diff_mb & !3u32);

        if size_mb == 0 {
            info!(sl!(), "virtio-mem size is 0, skipping setup");
            return Ok(());
        }

        // Validate machine type for virtio-mem support
        // TODO: support more architectures
        if machine_type != "s390-ccw-virtio" {
            return Err(anyhow!(
                "virtio-mem supports multiple architectures, the current implementation is only for s390x (s390-ccw-virtio). Current machine type: {}",
                machine_type
            ));
        }

        // Determine memory backend based on shared filesystem
        let uses_virtio_fs = shared_fs
            .map(|fs| fs == "virtio-fs" || fs == "virtio-fs-nydus")
            .unwrap_or(false);

        let (qomtype, mempath, share) = if uses_virtio_fs {
            ("memory-backend-file", "/dev/shm", true)
        } else {
            ("memory-backend-ram", "", false)
        };

        let size_bytes = size_mb * 1024 * 1024;

        // Allocate CCW slot and format address
        // Use same ID for both CCW subchannel tracking and QMP device
        let device_id = "virtiomem0";
        let ccw = self
            .ccw_subchannel
            .as_mut()
            .ok_or_else(|| anyhow!("CCW subchannel not initialized for s390x"))?;
        let slot = ccw
            .add_device(device_id)
            .map_err(|e| anyhow!("Failed to add CCW device: {:?}", e))?;
        let devno = ccw.address_format_ccw(slot);

        info!(
            sl!(),
            "Setting up virtio-mem-ccw: backend={}, path={}, share={}, devno={}",
            qomtype,
            if mempath.is_empty() { "none" } else { mempath },
            share,
            devno
        );

        // Helper to create common MemoryBackendProperties
        let create_backend_props = || qapi_qmp::MemoryBackendProperties {
            dump: None,
            host_nodes: None,
            merge: None,
            policy: None,
            prealloc: None,
            prealloc_context: None,
            prealloc_threads: None,
            reserve: None,
            share: Some(share),
            x_use_canonical_path_for_ramblock_id: None,
            size: size_bytes,
        };

        // STEP 1: Create memory backend
        let memory_backend = if mempath.is_empty() {
            qmp::object_add(qapi_qmp::ObjectOptions::memory_backend_ram {
                id: "virtiomem".to_owned(),
                memory_backend_ram: create_backend_props(),
            })
        } else {
            qmp::object_add(qapi_qmp::ObjectOptions::memory_backend_file {
                id: "virtiomem".to_owned(),
                memory_backend_file: qapi_qmp::MemoryBackendFileProperties {
                    base: create_backend_props(),
                    align: None,
                    discard_data: None,
                    offset: None,
                    pmem: None,
                    readonly: None,
                    rom: None,
                    mem_path: mempath.to_owned(),
                },
            })
        };

        // Execute backend creation with cleanup on error
        if let Err(e) = self.qmp.execute(&memory_backend) {
            self.cleanup_virtio_mem_setup(device_id);
            return if e.to_string().contains("Cannot allocate memory") {
                Err(anyhow!("Failed to allocate {} MB for virtio-mem: {}. \
                            Please use command 'echo 1 > /proc/sys/vm/overcommit_memory' to handle it.",
                            size_mb, e))
            } else {
                Err(e.into())
            };
        }

        // STEP 2: Create virtio-mem-ccw device
        let mut device_args = Dictionary::new();
        device_args.insert("memdev".to_owned(), "virtiomem".into());
        device_args.insert("devno".to_owned(), devno.into());

        if let Err(e) = self.qmp.execute(&qmp::device_add {
            bus: None,
            id: Some(device_id.to_owned()),
            driver: "virtio-mem-ccw".to_owned(),
            arguments: device_args,
        }) {
            self.cleanup_virtio_mem_setup(device_id);
            return Err(anyhow!("Failed to add virtio-mem-ccw device: {}", e));
        }

        info!(
            sl!(),
            "Successfully set up virtio-mem-ccw with max capacity {} MB", size_mb
        );
        Ok(())
    }

    /// Resize virtio-mem device to the specified size in MB.
    /// This uses QMP qom-set to change the requested-size property.
    ///
    /// # Arguments
    /// * `new_size_mb` - New size in MB for the virtio-mem device
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err` if resize fails or size is negative
    pub fn resize_virtio_mem(&mut self, new_size_mb: i64) -> Result<()> {
        // Validate and convert size from MB to bytes
        if new_size_mb < 0 {
            return Err(anyhow!(
                "cannot resize virtio-mem device to negative size ({}) memory",
                new_size_mb
            ));
        }
        let size_bytes = (new_size_mb as u64) * 1024 * 1024;

        info!(
            sl!(),
            "Resizing virtio-mem device to {} MB ({} bytes)", new_size_mb, size_bytes
        );

        // Use qom-set to change the requested-size property of virtiomem0
        self.qmp.execute(&qmp::qom_set {
            path: "virtiomem0".to_owned(),
            property: "requested-size".to_owned(),
            value: serde_json::json!(size_bytes),
        })?;

        info!(
            sl!(),
            "Successfully resized virtio-mem to {} MB", new_size_mb
        );
        Ok(())
    }

    pub fn hotunplug_memory(&mut self, size: i64) -> Result<()> {
        // Query existing memory devices to detect virtio-mem
        let memory_devices = self.qmp.execute(&qapi_qmp::query_memory_devices {})?;

        // Check if virtio-mem device exists
        let has_virtio_mem = memory_devices
            .iter()
            .any(|memdev| matches!(memdev, qapi_qmp::MemoryDeviceInfo::virtio_mem(_)));

        if has_virtio_mem {
            self.hotunplug_virtio_mem(size, memory_devices)
        } else {
            self.hotunplug_pc_dimm(size, memory_devices)
        }
    }

    /// Hotunplug memory using virtio-mem resize method.
    fn hotunplug_virtio_mem(
        &mut self,
        size: i64,
        memory_devices: Vec<qapi_qmp::MemoryDeviceInfo>,
    ) -> Result<()> {
        // Validate size is non-negative before casting
        if size < 0 {
            return Err(anyhow!(
                "cannot hotunplug negative memory size: {} bytes",
                size
            ));
        }

        // Get current size from virtio-mem device (this is the requested-size, not actual size)
        let current_size_bytes = memory_devices
            .iter()
            .filter_map(|memdev| {
                if let qapi_qmp::MemoryDeviceInfo::virtio_mem(vm_info) = memdev {
                    Some(vm_info.data.size)
                } else {
                    None
                }
            })
            .sum::<u64>();

        // size parameter is the amount to REMOVE (in bytes)
        let new_size_bytes = current_size_bytes.saturating_sub(size as u64);
        let new_size_mb = (new_size_bytes / (1024 * 1024)) as i64;

        info!(
            sl!(),
            "Decreasing virtio-mem by {} bytes (current: {} bytes, new: {} bytes = {} MB)",
            size,
            current_size_bytes,
            new_size_bytes,
            new_size_mb
        );

        self.resize_virtio_mem(new_size_mb)
    }

    /// Hotunplug memory using pc-dimm device removal.
    fn hotunplug_pc_dimm(
        &mut self,
        size: i64,
        memory_devices: Vec<qapi_qmp::MemoryDeviceInfo>,
    ) -> Result<()> {
        info!(sl!(), "No virtio-mem detected, using pc-dimm hotunplug");

        let frontend = memory_devices.into_iter().find(|memdev| {
            if let qapi_qmp::MemoryDeviceInfo::dimm(dimm_info) = memdev {
                let dimm_id = match dimm_info.data.id {
                    Some(ref id) => id,
                    None => return false,
                };
                if dimm_info.data.hotpluggable
                    && dimm_info.data.hotplugged
                    && dimm_info.data.size == size
                    && dimm_id.starts_with("frontend-to-hotplugged-")
                {
                    return true;
                }
            }
            false
        });

        if let Some(frontend) = frontend {
            if let qapi_qmp::MemoryDeviceInfo::dimm(frontend) = frontend {
                info!(sl!(), "found frontend to hotunplug: {:#?}", frontend);

                let frontend_id = match frontend.data.id {
                    Some(id) => id,
                    // This shouldn't happen as it was checked by find() above already.
                    None => return Err(anyhow!("memory frontend to hotunplug has empty id")),
                };

                let backend_id = match frontend_id.strip_prefix("frontend-to-") {
                    Some(id) => id.to_owned(),
                    // This shouldn't happen as it was checked by find() above already.
                    None => {
                        return Err(anyhow!(
                        "memory backend to hotunplug has id that doesn't have the expected prefix"
                    ))
                    }
                };

                self.qmp.execute(&qmp::device_del { id: frontend_id })?;
                self.qmp.execute(&qmp::object_del { id: backend_id })?;
            } else {
                // This shouldn't happen as it was checked by find() above already.
                return Err(anyhow!("memory device to hotunplug is not a dimm"));
            }
        } else {
            return Err(anyhow!(
                "couldn't find a suitable memory device to hotunplug"
            ));
        }
        Ok(())
    }

    fn find_free_slot(&mut self) -> Result<(String, i64)> {
        // Prefer in-memory bridge state (matches Go virtcontainers/types/bridges.go).
        let mut bridge_ids: Vec<&str> =
            self.pci_bridge_devices.keys().map(String::as_str).collect();
        bridge_ids.sort_by(|a, b| {
            let parse_idx = |id: &str| {
                id.strip_prefix("pci-bridge-")
                    .and_then(|n| n.parse::<u32>().ok())
            };
            match (parse_idx(a), parse_idx(b)) {
                (Some(ai), Some(bi)) => ai.cmp(&bi),
                _ => a.cmp(b),
            }
        });

        for bridge_id in bridge_ids {
            let occupied = self.pci_bridge_devices.get(bridge_id).unwrap();
            for slot in PCI_BRIDGE_FIRST_HOTPLUG_SLOT..=PCI_BRIDGE_MAX_CAPACITY {
                if !occupied.contains_key(&slot) {
                    info!(sl!(), "found free slot on bridge {}: {}", bridge_id, slot);
                    return Ok((bridge_id.to_string(), slot));
                }
            }
        }

        // Fallback: walk query-pci tree. Under OVMF, pcie-pci-bridge (pci-bridge-N)
        // is nested under rp-pci-bridge-N, not at the root of the PCI tree.
        let pci = self.qmp.execute(&qapi_qmp::query_pci {})?;
        for pci_info in &pci {
            if let Some((bus, slot)) = find_free_slot_in_pci_devices(&pci_info.devices) {
                info!(
                    sl!(),
                    "found free slot on bridge {} via query-pci: {}", bus, slot
                );
                return Ok((bus, slot));
            }
        }

        Err(anyhow!("no free slots on PCI bridges"))
    }

    fn record_pci_bridge_slot(&mut self, bridge_id: &str, slot: i64, device_id: &str) {
        if let Some(devices) = self.pci_bridge_devices.get_mut(bridge_id) {
            devices.insert(slot, device_id.to_owned());
        } else {
            warn!(
                sl!(),
                "record_pci_bridge_slot: bridge {} not in pci_bridge_devices, slot {} for device {} not tracked",
                bridge_id,
                slot,
                device_id
            );
        }
    }

    fn pass_fd(&mut self, fd: RawFd, fdname: &str) -> Result<()> {
        info!(sl!(), "passing fd {:?} as {}", fd, fdname);

        // Put the QMP 'getfd' command itself into the message payload.
        let getfd_cmd =
            format!("{{ \"execute\": \"getfd\", \"arguments\": {{ \"fdname\": \"{fdname}\" }} }}");
        let buf = getfd_cmd.as_bytes();
        let bufs = &mut [std::io::IoSlice::new(buf)][..];

        debug!(sl!(), "bufs: {:?}", bufs);

        let fds = [fd];
        let cmsg = [ControlMessage::ScmRights(&fds)];

        let result = sendmsg::<()>(
            self.qmp.inner_mut().get_mut_write().as_raw_fd(),
            bufs,
            &cmsg,
            MsgFlags::empty(),
            None,
        );
        info!(sl!(), "sendmsg() result: {:#?}", result);

        let result = self.qmp.read_response::<&qmp::getfd>();

        match result {
            Ok(_) => {
                info!(sl!(), "successfully passed {} ({})", fdname, fd);
                Ok(())
            }
            Err(err) => Err(anyhow!("failed to pass {} ({}): {}", fdname, fd, err)),
        }
    }

    fn pass_block_fd(&mut self, fd: RawFd, opaque: &str) -> Result<qmp::AddfdInfo> {
        let command = serde_json::json!({
            "execute": "add-fd",
            "arguments": { "opaque": opaque },
        })
        .to_string();
        let bufs = &mut [std::io::IoSlice::new(command.as_bytes())][..];
        let fds = [fd];
        let cmsg = [ControlMessage::ScmRights(&fds)];

        sendmsg::<()>(
            self.qmp.inner_mut().get_mut_write().as_raw_fd(),
            bufs,
            &cmsg,
            MsgFlags::empty(),
            None,
        )
        .with_context(|| format!("send QEMU block fd for {opaque}"))?;

        self.qmp
            .read_response::<&qmp::add_fd>()
            .with_context(|| format!("add QEMU block fd for {opaque}"))
    }

    fn remove_block_fdsets(&mut self, node_name: &str) {
        let Some(fdset_ids) = self.block_fdsets.remove(node_name) else {
            return;
        };

        self.remove_fdset_ids(node_name, fdset_ids);
    }

    fn remove_fdset_ids(&mut self, node_name: &str, fdset_ids: Vec<i64>) {
        let mut failed = Vec::new();
        for fdset_id in fdset_ids {
            if let Err(err) = self.qmp.execute(&qmp::remove_fd { fd: None, fdset_id }) {
                warn!(
                    sl!(),
                    "failed to remove QEMU block fdset {} for {}: {:?}", fdset_id, node_name, err
                );
                failed.push(fdset_id);
            }
        }
        if !failed.is_empty() {
            self.block_fdsets
                .entry(node_name.to_string())
                .or_default()
                .extend(failed);
        }
    }

    pub fn hotplug_network_device(
        &mut self,
        netdev: &Netdev,
        virtio_net_device: &DeviceVirtioNet,
    ) -> Result<()> {
        let use_ccw_bus = crate::utils::uses_native_ccw_bus();
        let netdev_id = netdev.get_id().clone();

        let mut netdev_frontend_args = Dictionary::new();
        netdev_frontend_args.insert(
            "netdev".to_owned(),
            virtio_net_device.get_netdev_id().clone().into(),
        );
        netdev_frontend_args.insert("mac".to_owned(), virtio_net_device.get_mac_addr().into());
        netdev_frontend_args.insert("mq".to_owned(), true.into());

        let frontend_id = format!("frontend-{}", virtio_net_device.get_netdev_id());

        let pci_hotplug = if use_ccw_bus {
            let subchannel = self.ccw_subchannel.as_mut().ok_or_else(|| {
                anyhow!("CCW subchannel not available for virtio-net-ccw hotplug")
            })?;
            let slot = subchannel
                .add_device(&frontend_id)
                .map_err(|e| anyhow!("CCW subchannel add_device failed: {:?}", e))?;
            let devno = subchannel.address_format_ccw(slot);
            netdev_frontend_args.insert("devno".to_owned(), devno.into());
            None
        } else {
            let (bus, slot) = match self.network_pins.get(&virtio_net_device.get_mac_addr()) {
                Some((bus, slot, _modern)) => {
                    let taken = self
                        .pci_bridge_devices
                        .get(bus)
                        .map(|slots| slots.contains_key(slot))
                        .unwrap_or(true);
                    if taken {
                        return Err(anyhow!(
                            "migration_invalid: the place {bus}/{slot} of a network device is taken"
                        ));
                    }
                    (bus.clone(), *slot)
                }
                None => self.find_free_slot()?,
            };
            netdev_frontend_args.insert("addr".to_owned(), format!("{slot:02}").into());
            // As the golang runtime documents the vectors computation, it's
            // 2N+2 vectors, N for tx queues, N for rx queues, 1 for config,
            // and one for possible control vq.  PCI-specific (MSI-X).
            netdev_frontend_args.insert(
                "vectors".to_owned(),
                (2 * virtio_net_device.get_num_queues() + 2).into(),
            );
            // Never force legacy (disable-modern) virtio on a hot-plugged PCI
            // NIC.  A legacy-only virtio device needs an I/O BAR, but the NIC is
            // hot-plugged behind a pcie-pci-bridge whose I/O window can be
            // exhausted (e.g. by the GPU root-port pool), making the I/O BAR
            // unassignable and the guest virtio-pci probe fail with -EIO.  The
            // Go runtime hot-plugs NICs with disable-modern=false for the same
            // reason; modern/transitional virtio uses MMIO and has no such
            // dependency.  disable-modern is only meaningful for cold-plug.
            Some((bus, slot))
        };

        let bus = pci_hotplug.as_ref().map(|(bus, _)| bus.clone());

        let mut fd_names = vec![];
        for (idx, fd) in netdev.get_fds().iter().enumerate() {
            let fdname = format!("fd{idx}");
            self.pass_fd(fd.as_raw_fd(), fdname.as_ref())?;
            fd_names.push(fdname);
        }

        let mut vhostfd_names = vec![];
        for (idx, fd) in netdev.get_vhostfds().iter().enumerate() {
            let vhostfdname = format!("vhostfd{idx}");
            self.pass_fd(fd.as_raw_fd(), vhostfdname.as_ref())?;
            vhostfd_names.push(vhostfdname);
        }

        self.qmp
            .execute(&qapi_qmp::netdev_add(qapi_qmp::Netdev::tap {
                id: netdev_id.clone(),
                tap: qapi_qmp::NetdevTapOptions {
                    br: None,
                    downscript: None,
                    fd: None,
                    // Logic in cmdline_generator::Netdev::new() seems to
                    // guarantee that there will always be at least one fd.
                    fds: Some(fd_names.join(",")),
                    helper: None,
                    ifname: None,
                    poll_us: None,
                    queues: None,
                    script: None,
                    sndbuf: None,
                    vhost: if vhostfd_names.is_empty() {
                        None
                    } else {
                        Some(true)
                    },
                    vhostfd: None,
                    vhostfds: if vhostfd_names.is_empty() {
                        None
                    } else {
                        Some(vhostfd_names.join(","))
                    },
                    vhostforce: None,
                    vnet_hdr: None,
                },
            }))
            .map_err(|e| {
                if use_ccw_bus {
                    if let Some(subchannel) = self.ccw_subchannel.as_mut() {
                        let _ = subchannel.remove_device(&frontend_id);
                    }
                }

                anyhow!(e)
            })?;

        let device_add_result = self.qmp.execute(&qmp::device_add {
            bus,
            id: Some(frontend_id.clone()),
            driver: virtio_net_device.get_device_driver().clone(),
            arguments: netdev_frontend_args,
        });
        if let Err(e) = device_add_result {
            if use_ccw_bus {
                if let Some(subchannel) = self.ccw_subchannel.as_mut() {
                    let _ = subchannel.remove_device(&frontend_id);
                }
            }

            if let Err(del_err) = self.qmp.execute(&qmp::netdev_del {
                id: netdev_id.clone(),
            }) {
                warn!(
                    sl!(),
                    "hotplug_network_device(): netdev_del failed for {} after device_add error {:?}: {:?}",
                    netdev_id,
                    e,
                    del_err
                );
            }

            return Err(e.into());
        }

        debug!(
            sl!(),
            "hotplug_network_device(): successfully added {}", frontend_id
        );

        if let Some((bridge_id, slot)) = pci_hotplug {
            self.record_pci_bridge_slot(&bridge_id, slot, &frontend_id);
        }
        self.network_macs
            .insert(frontend_id.clone(), virtio_net_device.get_mac_addr());
        // Hot-plugged as modern virtio, above.
        self.network_modern.insert(frontend_id, true);

        Ok(())
    }

    /// Nova Kata (ADR-044): a network device of the command line holds this
    /// slot of the bridge.
    pub fn record_network_device(
        &mut self,
        bridge_id: &str,
        slot: i64,
        host_dev_name: &str,
        mac: &str,
        modern: bool,
    ) {
        let frontend = format!("frontend-network-{host_dev_name}");
        self.record_pci_bridge_slot(bridge_id, slot, &frontend);
        self.network_macs
            .insert(frontend.clone(), mac.to_ascii_lowercase());
        self.network_modern.insert(frontend, modern);
    }

    /// Nova Kata (ADR-044): the inverse of hotplug_network_device. The tap
    /// backend is deleted only after the guest has released the device;
    /// with it QEMU closes the descriptors of the host interface.
    pub fn hotunplug_network_device(&mut self, host_dev_name: &str) -> Result<()> {
        let netdev_id = format!("network-{host_dev_name}");
        let frontend_id = format!("frontend-{netdev_id}");

        self.qmp
            .execute(&qmp::device_del {
                id: frontend_id.clone(),
            })
            .map_err(|e| anyhow!("device_del for network device {}: {:?}", frontend_id, e))?;
        self.wait_for_device_deleted(&frontend_id, DEVICE_DELETED_TIMEOUT)
            .context("hotunplug_network_device(): waiting for DEVICE_DELETED")?;
        self.qmp
            .execute(&qmp::netdev_del {
                id: netdev_id.clone(),
            })
            .map_err(|e| anyhow!("netdev_del for network device {}: {:?}", netdev_id, e))?;

        for devices in self.pci_bridge_devices.values_mut() {
            devices.retain(|_, id| id != &frontend_id);
        }
        self.network_macs.remove(&frontend_id);
        if crate::utils::uses_native_ccw_bus() {
            if let Some(subchannel) = self.ccw_subchannel.as_mut() {
                let _ = subchannel.remove_device(&frontend_id);
            }
        }
        info!(
            sl!(),
            "hotunplug_network_device(): successfully removed {}", frontend_id
        );
        Ok(())
    }

    pub fn get_device_by_qdev_id(&mut self, qdev_id: &str) -> Result<PciPath> {
        let format_str = |vec: &Vec<i64>| -> String {
            vec.iter()
                .map(|num| format!("{num:02x}"))
                .collect::<Vec<String>>()
                .join("/")
        };

        let mut path = vec![];
        let pci = self.qmp.execute(&qapi_qmp::query_pci {})?;
        for pci_info in pci.iter() {
            if let Some(_device) = get_pci_path_by_qdev_id(&pci_info.devices, qdev_id, &mut path) {
                let pci_path = format_str(&path);
                return PciPath::try_from(pci_path.as_str());
            }
        }

        Err(anyhow!("no target device found"))
    }

    /// Execute device_add for a block device. On failure, automatically
    /// rolls back the blockdev node added earlier to avoid orphaned resources.
    fn device_add_with_rollback(
        &mut self,
        node_name: &str,
        bus: Option<String>,
        driver: &str,
        arguments: Dictionary,
    ) -> Result<()> {
        if let Err(e) = self.qmp.execute(&qmp::device_add {
            bus,
            id: Some(node_name.to_owned()),
            driver: driver.to_owned(),
            arguments,
        }) {
            if let Err(blockdev_err) = self.qmp.execute(&qapi_qmp::blockdev_del {
                node_name: node_name.to_owned(),
            }) {
                warn!(
                    sl!(),
                    "device_add_with_rollback(): blockdev_del failed for {}: {:?}",
                    node_name,
                    blockdev_err
                );
            } else {
                self.remove_block_fdsets(node_name);
            }
            return Err(anyhow!("device_add {:?}", e));
        }
        Ok(())
    }

    fn wait_for_device_deleted(&mut self, device_id: &str, timeout: Duration) -> Result<()> {
        const POLL_INTERVAL: Duration = Duration::from_millis(100);
        let deadline = Instant::now() + timeout;

        self.qmp
            .inner_mut()
            .get_mut_write()
            .set_read_timeout(Some(timeout))?;

        let result = loop {
            if let Err(e) = self.qmp.nop() {
                warn!(sl!(), "The QMP nop() failed for {}: {:?}", device_id, e);
            }

            let found = self.qmp.events().any(|event| {
                matches!(event, qapi_qmp::Event::DEVICE_DELETED { ref data, .. }
                    if data.device.as_deref() == Some(device_id))
            });
            if found {
                info!(
                    sl!(),
                    "The QMP received DEVICE_DELETED event for {}", device_id
                );
                break Ok(());
            }

            let now = Instant::now();
            if now >= deadline {
                break Err(anyhow!(
                    "timed out ({:?}) waiting for DEVICE_DELETED event for {}",
                    timeout,
                    device_id
                ));
            }
            thread::sleep(POLL_INTERVAL.min(deadline - now));
        };

        // Reset the default read timeout for subsequent QMP operations.
        // Failure here is non-fatal — a stale timeout only affects the next
        // QMP read, not the already-completed device removal.
        if let Err(e) = self
            .qmp
            .inner_mut()
            .get_mut_write()
            .set_read_timeout(Some(Duration::from_millis(DEFAULT_QMP_READ_TIMEOUT)))
        {
            warn!(sl!(), "Failed to reset read timeout: {:?}", e);
        }

        result
    }

    /// Hotplug block device:
    /// {
    ///     "execute": "blockdev-add",
    ///     "arguments": {
    ///         "node-name": "drive-0",
    ///         "file": {"driver": "file", "filename": "/path/to/block"},
    ///         "cache": {"direct": true},
    ///         "read-only": false
    ///     }
    /// }
    ///
    /// {
    ///     "execute": "device_add",
    ///     "arguments": {
    ///         "id": "drive-0",
    ///         "driver": "virtio-blk-pci",
    ///         "drive": "drive-0",
    ///         "addr":"0x0",
    ///         "bus": "pcie.1"
    ///     }
    /// }
    /// Hotplug SCSI block device
    /// # virtio-scsi0
    /// {"execute":"device_add","arguments":{"driver":"virtio-scsi-pci","id":"virtio-scsi0","bus":"bus1"}}
    /// {"return": {}}
    ///
    /// {"execute":"blockdev_add", "arguments": {"file":"/path/to/block.image","format":"qcow2","id":"virtio-scsi0"}}
    /// {"return": {}}
    /// {"execute":"device_add","arguments":{"driver":"scsi-hd","drive":"virtio-scsi0","id":"scsi_device_0","bus":"virtio-scsi1.0"}}
    /// {"return": {}}
    ///
    /// Hotplug virtio-blk-ccw block device on s390x
    /// # virtio-blk-ccw0
    /// {"execute":"blockdev_add", "arguments": {"file":"/path/to/block.image","format":"qcow2","id":"virtio-blk-ccw0"}}
    /// {"return": {}}
    /// {"execute":"device_add","arguments":{"driver":"virtio-blk-ccw","id":"virtio-blk-ccw0","drive":"virtio-blk-ccw0","devno":"fe.0.0005","share-rw":true}}
    /// {"return": {}}
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn hotplug_block_device(
        &mut self,
        block_driver: &str,
        index: u64,
        path_on_host: &str,
        blkdev_aio: &str,
        is_direct: Option<bool>,
        is_readonly: bool,
        no_drop: bool,
        discard_unmap: bool,
        logical_block_size: u32,
        physical_block_size: u32,
        vmdk: Option<&VmdkConfig>,
        iothread: Option<&str>,
        io_limits: Option<&BlockIoLimits>,
    ) -> Result<(Option<PciPath>, Option<String>)> {
        // `blockdev-add`
        let node_name = block_node_name(index);
        if self.block_fdsets.contains_key(&node_name) {
            return Err(anyhow!("duplicate QEMU block device ID {node_name}"));
        }
        let discard_option = || discard_unmap.then_some(BlockdevDiscardOptions::unmap);

        let create_base_options = || qapi_qmp::BlockdevOptionsBase {
            auto_read_only: None,
            cache: if is_direct.is_none() {
                None
            } else {
                Some(qapi_qmp::BlockdevCacheOptions {
                    direct: is_direct,
                    no_flush: None,
                })
            },
            detect_zeroes: None,
            discard: discard_option(),
            force_share: None,
            node_name: None,
            read_only: Some(is_readonly),
        };

        let mut fdset_ids = Vec::new();
        let prepared_source = match prepare_block_source(
            path_on_host,
            vmdk,
            is_readonly,
            is_direct.unwrap_or(false),
            |file, label| {
                let opaque = block_fd_opaque(&node_name, label);
                let info = self.pass_block_fd(file.as_raw_fd(), &opaque)?;
                fdset_ids.push(info.fdset_id);
                Ok(format!("/dev/fdset/{}", info.fdset_id))
            },
        ) {
            Ok(source) => source,
            Err(err) => {
                self.remove_fdset_ids(&node_name, fdset_ids);
                return Err(err);
            }
        };

        let create_backend_options = || qapi_qmp::BlockdevOptionsFile {
            aio: Some(
                BlockdevAioOptions::from_str(blkdev_aio).unwrap_or(BlockdevAioOptions::io_uring),
            ),
            aio_max_batch: None,
            drop_cache: if !no_drop { None } else { Some(no_drop) },
            locking: None,
            pr_manager: None,
            x_check_cache_dropped: None,
            filename: prepared_source.filename.clone(),
        };

        // Add block device backend and check if the file is a regular file or device
        let blockdev_file = if prepared_source.is_regular_file {
            // Regular file
            qmp::BlockdevOptions::file {
                base: create_base_options(),
                file: create_backend_options(),
            }
        } else {
            // Host device (e.g., /dev/sdx, /dev/loopX)
            qmp::BlockdevOptions::host_device {
                base: create_base_options(),
                host_device: create_backend_options(),
            }
        };

        let blockdev_options = if vmdk.is_none() {
            BlockdevOptions::raw {
                base: BlockdevOptionsBase {
                    detect_zeroes: None,
                    cache: None,
                    discard: discard_option(),
                    force_share: if is_readonly { Some(true) } else { None },
                    auto_read_only: None,
                    node_name: Some(node_name.clone()),
                    read_only: Some(is_readonly),
                },
                raw: BlockdevOptionsRaw {
                    base: BlockdevOptionsGenericFormat {
                        file: BlockdevRef::definition(Box::new(blockdev_file)),
                    },
                    offset: None,
                    size: None,
                },
            }
        } else {
            info!(
                sl!(),
                "hotplug_block_device: using VMDK format driver for {} (read_only={}, force_share=true)",
                path_on_host,
                is_readonly
            );
            BlockdevOptions::vmdk {
                base: BlockdevOptionsBase {
                    detect_zeroes: None,
                    cache: None,
                    discard: discard_option(),
                    force_share: Some(true),
                    auto_read_only: None,
                    node_name: Some(node_name.clone()),
                    read_only: Some(is_readonly),
                },
                vmdk: BlockdevOptionsGenericCOWFormat {
                    base: BlockdevOptionsGenericFormat {
                        file: BlockdevRef::definition(Box::new(blockdev_file)),
                    },
                    backing: None,
                },
            }
        };

        if !fdset_ids.is_empty() {
            self.block_fdsets.insert(node_name.clone(), fdset_ids);
        }

        if let Err(err) = self.qmp.execute(&qapi_qmp::blockdev_add(blockdev_options)) {
            self.remove_block_fdsets(&node_name);
            return Err(anyhow!("blockdev-add backend {:?}", err));
        }

        // block device
        // `device_add`
        let mut blkdev_add_args = Dictionary::new();
        blkdev_add_args.insert("drive".to_owned(), node_name.clone().into());
        if discard_unmap && block_driver != VIRTIO_SCSI {
            blkdev_add_args.insert("discard".to_owned(), true.into());
        }

        if logical_block_size > 0 {
            blkdev_add_args.insert("logical_block_size".to_owned(), logical_block_size.into());
        }
        if physical_block_size > 0 {
            blkdev_add_args.insert("physical_block_size".to_owned(), physical_block_size.into());
        }

        if block_driver == VIRTIO_SCSI {
            // Helper closure to decode a flattened u16 SCSI index into an (ID, LUN) pair.
            let get_scsi_id_lun = |index_u16: u16| -> Result<(u8, u8)> {
                // Uses bitwise operations for efficient and clear conversion.
                let scsi_id = (index_u16 >> 8) as u8; // Equivalent to index_u16 / 256
                let lun = (index_u16 & 0xFF) as u8; // Equivalent to index_u16 % 256

                Ok((scsi_id, lun))
            };

            // Safely convert the u64 index to u16, ensuring it does not exceed `u16::MAX` (65535).
            let (scsi_id, lun) = get_scsi_id_lun(u16::try_from(index)?)?;
            let scsi_addr = format!("{scsi_id}:{lun}");

            // add SCSI frontend device
            blkdev_add_args.insert("scsi-id".to_string(), scsi_id.into());
            blkdev_add_args.insert("lun".to_string(), lun.into());
            if !is_readonly {
                blkdev_add_args.insert("share-rw".to_string(), true.into());
            }

            info!(
                sl!(),
                "hotplug_block_device(): device_add arguments: bus: {}, id: {}, driver: {}, blkdev_add_args: {:#?}",
                "scsi0.0",
                node_name,
                "scsi-hd",
                blkdev_add_args
            );
            self.device_add_with_rollback(
                &node_name,
                Some("scsi0.0".to_string()),
                "scsi-hd",
                blkdev_add_args,
            )?;
            self.set_block_io_limits(&node_name, io_limits)?;

            info!(
                sl!(),
                "hotplug scsi block device return scsi address: {:?}", &scsi_addr
            );

            Ok((None, Some(scsi_addr)))
        } else if block_driver == VIRTIO_BLK_CCW {
            let subchannel = match self.ccw_subchannel.as_mut() {
                Some(sub) => sub,
                None => {
                    self.qmp.execute(&qapi_qmp::blockdev_del {
                        node_name: node_name.to_owned(),
                    })?;
                    self.remove_block_fdsets(&node_name);

                    return Err(anyhow!(
                        "CCW subchannel not available for virtio-blk-ccw hotplug"
                    ));
                }
            };

            let slot = match subchannel.add_device(&node_name) {
                Ok(s) => s,
                Err(e) => {
                    self.qmp.execute(&qapi_qmp::blockdev_del {
                        node_name: node_name.to_owned(),
                    })?;
                    self.remove_block_fdsets(&node_name);

                    return Err(anyhow!("CCW subchannel add_device failed: {:?}", e));
                }
            };
            let devno = subchannel.address_format_ccw(slot);
            let ccw_addr = subchannel.address_format_ccw_for_virt_server(slot);

            blkdev_add_args.insert("devno".to_owned(), devno.clone().into());
            if !is_readonly {
                blkdev_add_args.insert("share-rw".to_string(), true.into());
            }

            info!(
                sl!(),
                "hotplug_block_device(): CCW device_add: id: {}, driver: {}, blkdev_add_args: {:#?}, ccw_addr: {}",
                node_name,
                block_driver,
                blkdev_add_args,
                ccw_addr
            );
            if let Err(e) =
                self.device_add_with_rollback(&node_name, None, block_driver, blkdev_add_args)
            {
                if let Some(ref mut sub) = self.ccw_subchannel {
                    // Roll back CCW subchannel state if QMP device_add fails
                    let _ = sub.remove_device(&node_name);
                }
                return Err(e);
            }
            if let Err(e) = self.set_block_io_limits(&node_name, io_limits) {
                if let Some(ref mut sub) = self.ccw_subchannel {
                    let _ = sub.remove_device(&node_name);
                }
                return Err(e);
            }

            info!(
                sl!(),
                "hotplug CCW block device return ccw address: {:?}", &ccw_addr
            );

            Ok((None, Some(ccw_addr)))
        } else {
            let (bus, slot) = match self.find_free_slot() {
                Ok(value) => value,
                Err(err) => {
                    if self
                        .qmp
                        .execute(&qapi_qmp::blockdev_del {
                            node_name: node_name.clone(),
                        })
                        .is_ok()
                    {
                        self.remove_block_fdsets(&node_name);
                    }
                    return Err(err);
                }
            };
            blkdev_add_args.insert("addr".to_owned(), format!("{slot:02}").into());
            if !is_readonly {
                blkdev_add_args.insert("share-rw".to_string(), true.into());
            }

            // Add iothread parameter for virtio-blk devices if specified
            if let Some(iothread_id) = iothread {
                info!(
                    sl!(),
                    "hotplug_block_device(): attaching to iothread: {}", iothread_id
                );
                blkdev_add_args.insert("iothread".to_owned(), iothread_id.to_string().into());
            }

            info!(
                sl!(),
                "hotplug_block_device(): device_add arguments: bus: {}, id: {}, driver: {}, blkdev_add_args: {:#?}",
                bus,
                node_name,
                block_driver,
                blkdev_add_args
            );

            self.device_add_with_rollback(
                &node_name,
                Some(bus.clone()),
                block_driver,
                blkdev_add_args,
            )?;
            self.set_block_io_limits(&node_name, io_limits)?;

            let pci_path = self
                .get_device_by_qdev_id(&node_name)
                .context("get device by qdev_id failed")?;
            self.record_pci_bridge_slot(&bus, slot, &node_name);
            info!(
                sl!(),
                "hotplug block device return pci path: {:?}", &pci_path
            );

            Ok((Some(pci_path), None))
        }
    }

    /// Gives a block device its own limits (openstack-nova-kata ADR-051) as
    /// libvirt gives a disk its <iotune>: block_set_io_throttle on the device,
    /// in a throttle group of its own, right after device_add. The node graph
    /// stays as it is (the raw node that growth resizes remains the device's
    /// root). The group belongs to the device's block backend and goes with
    /// device_del. If the limits cannot be set the device is removed again
    /// and the attachment fails: it never stays without its limits.
    fn set_block_io_limits(
        &mut self,
        node_name: &str,
        io_limits: Option<&BlockIoLimits>,
    ) -> Result<()> {
        let Some(limits) = io_limits else {
            return Ok(());
        };
        let throttle = block_io_throttle(node_name, limits);
        info!(sl!(), "set_block_io_limits(): {:?}", throttle);
        let error = match self.qmp.execute(&qmp::block_set_io_throttle(throttle)) {
            Ok(_) => return Ok(()),
            Err(e) => anyhow!("volume_qos: block_set_io_throttle for {}: {:?}", node_name, e),
        };
        let rollback = (|| -> Result<()> {
            self.qmp
                .execute(&qmp::device_del {
                    id: node_name.to_owned(),
                })
                .map_err(|e| anyhow!("device_del: {:?}", e))?;
            self.wait_for_device_deleted(node_name, DEVICE_DELETED_TIMEOUT)?;
            self.qmp
                .execute(&qapi_qmp::blockdev_del {
                    node_name: node_name.to_owned(),
                })
                .map_err(|e| anyhow!("blockdev_del: {:?}", e))?;
            self.remove_block_fdsets(node_name);
            Ok(())
        })();
        match rollback {
            Ok(()) => Err(error),
            // The node keeps its fdsets, so its name is not reused, and the
            // error says the device is still in the VM.
            Err(rollback) => Err(error.context(format!(
                "volume_qos: device {node_name} without its limits could not be removed: {rollback:?}"
            ))),
        }
    }

    /// Hotunplug block device.
    pub fn hotunplug_block_device(&mut self, block_driver: &str, index: u64) -> Result<()> {
        let node_name = block_node_name(index);

        let result = (|| -> Result<()> {
            // Remove the frontend device (virtio-blk-pci / scsi-hd / virtio-blk-ccw).
            self.qmp
                .execute(&qmp::device_del {
                    id: node_name.clone(),
                })
                .map_err(|e| anyhow!("device_del for block device {}: {:?}", node_name, e))?;

            // device_del is asynchronous — wait for the guest to acknowledge removal
            // before tearing down the backend, otherwise blockdev_del may fail with
            // "Node is still in use".
            self.wait_for_device_deleted(&node_name, DEVICE_DELETED_TIMEOUT)
                .context("hotunplug_block_device(): waiting for DEVICE_DELETED")?;

            // Remove the blockdev backend node.
            self.qmp
                .execute(&qapi_qmp::blockdev_del {
                    node_name: node_name.clone(),
                })
                .map_err(|e| anyhow!("blockdev_del for block device {}: {:?}", node_name, e))?;

            self.remove_block_fdsets(&node_name);

            Ok(())
        })();

        if let Err(ref e) = result {
            warn!(
                sl!(),
                "hotunplug_block_device(): failed for {}, cleaning up CCW state: {:?}",
                node_name,
                e
            );
        }

        // Clean up CCW subchannel state (s390x) on all paths.
        if block_driver == VIRTIO_BLK_CCW {
            if let Some(ref mut subchannel) = self.ccw_subchannel {
                let _ = subchannel.remove_device(&node_name);
            }
        }

        result?;

        info!(
            sl!(),
            "hotunplug_block_device(): successfully removed {}", node_name
        );

        Ok(())
    }

    pub fn hotplug_vfio_device(
        &mut self,
        hostdev_id: &str,
        sysfs_path: &str,
        bus_slot_func: &str,
        driver: &str,
        bus: &str,
    ) -> Result<Option<PciPath>> {
        let mut vfio_args = Dictionary::new();

        let (vfio_device_add, early_return) = match driver {
            "vfio-ap" => {
                vfio_args.insert("sysfsdev".to_owned(), sysfs_path.to_string().into());
                let device_add = qmp::device_add {
                    driver: driver.to_string(),
                    bus: None,
                    id: Some(hostdev_id.to_string()),
                    arguments: vfio_args,
                };
                (device_add, Some(Ok(None)))
            }
            _ => {
                let bdf = if !bus_slot_func.starts_with("0000") {
                    format!("0000:{bus_slot_func}")
                } else {
                    bus_slot_func.to_owned()
                };
                vfio_args.insert("addr".to_owned(), "0x0".into());
                vfio_args.insert("host".to_owned(), bdf.into());
                vfio_args.insert("multifunction".to_owned(), "off".into());
                let device_add = qmp::device_add {
                    driver: driver.to_string(),
                    bus: Some(bus.to_string()),
                    id: Some(hostdev_id.to_string()),
                    arguments: vfio_args,
                };
                (device_add, None)
            }
        };
        info!(sl!(), "vfio_device_add: {:?}", vfio_device_add.clone());

        // We've chosen to set a 5-second read timeout on Unix sockets for QMP operations. We consider set_read_timeout()
        // a lightweight operation that shouldn't significantly impact performance, even with multiple VFIO devices.
        // However, we also need to ensure its debuggability.
        // As it could obscure the root cause of connection failures as set an excessively long QMP timeout.
        // For example, if QEMU fails to launch, a 5-second QMP timeout will immediately provide a "QMP connection failed" log message,
        // clearly pinpointing the issue. Conversely, a prolonged timeout might only result in vague error messages, making debugging
        // difficult as it won't explicitly indicate where the problem lies.

        // Given our current inability to comprehensively test across a wide range of hardware and configurations, we've made a pragmatic
        // decision: we'll maintain the 5-second timeout for now. A configurable timeout option will be introduced if future use cases
        // clearly demonstrate a justified need.
        {
            // set read timeout with 5000
            self.qmp
                .inner_mut()
                .get_mut_write()
                .set_read_timeout(Some(Duration::from_millis(5000)))?;
            // send the VFIO hotplug request
            self.qmp
                .execute(&vfio_device_add)
                .map_err(|e| anyhow!("device_add vfio device failed {:?}", e))?;
            // reset read timeout with 250
            self.qmp
                .inner_mut()
                .get_mut_write()
                .set_read_timeout(Some(Duration::from_millis(DEFAULT_QMP_READ_TIMEOUT)))?;
        }

        // For AP devices, we don't need to get the PCI path as it's not available.
        if let Some(result) = early_return {
            return result;
        }

        let pci_path = self
            .get_device_by_qdev_id(hostdev_id)
            .context("get device by qdev_id failed")?;

        Ok(Some(pci_path))
    }

    pub fn qmp_stop(&mut self) -> Result<()> {
        self.qmp
            .execute(&qmp::stop {})
            .map(|_| ())
            .context("execute qmp stop")
    }

    pub fn qmp_cont(&mut self) -> Result<()> {
        self.qmp
            .execute(&qmp::cont {})
            .map(|_| ())
            .context("execute qmp cont")
    }

    /// Get vCPU thread IDs through QMP query_cpus_fast.
    pub fn get_vcpu_thread_ids(&mut self) -> Result<VcpuThreadIds> {
        let vcpu_info = self
            .qmp
            .execute(&qmp::query_cpus_fast {})
            .map_err(|e| anyhow!("query_cpus_fast failed: {:?}", e))?;

        let vcpus: HashMap<u32, u32> = vcpu_info
            .iter()
            .map(|info| match info {
                qmp::CpuInfoFast::aarch64(cpu_info)
                | qmp::CpuInfoFast::alpha(cpu_info)
                | qmp::CpuInfoFast::arm(cpu_info)
                | qmp::CpuInfoFast::avr(cpu_info)
                | qmp::CpuInfoFast::cris(cpu_info)
                | qmp::CpuInfoFast::hppa(cpu_info)
                | qmp::CpuInfoFast::i386(cpu_info)
                | qmp::CpuInfoFast::loongarch64(cpu_info)
                | qmp::CpuInfoFast::m68k(cpu_info)
                | qmp::CpuInfoFast::microblaze(cpu_info)
                | qmp::CpuInfoFast::microblazeel(cpu_info)
                | qmp::CpuInfoFast::mips(cpu_info)
                | qmp::CpuInfoFast::mips64(cpu_info)
                | qmp::CpuInfoFast::mips64el(cpu_info)
                | qmp::CpuInfoFast::mipsel(cpu_info)
                | qmp::CpuInfoFast::or1k(cpu_info)
                | qmp::CpuInfoFast::ppc(cpu_info)
                | qmp::CpuInfoFast::ppc64(cpu_info)
                | qmp::CpuInfoFast::riscv32(cpu_info)
                | qmp::CpuInfoFast::riscv64(cpu_info)
                | qmp::CpuInfoFast::rx(cpu_info)
                | qmp::CpuInfoFast::sh4(cpu_info)
                | qmp::CpuInfoFast::sh4eb(cpu_info)
                | qmp::CpuInfoFast::sparc(cpu_info)
                | qmp::CpuInfoFast::sparc64(cpu_info)
                | qmp::CpuInfoFast::tricore(cpu_info)
                | qmp::CpuInfoFast::x86_64(cpu_info)
                | qmp::CpuInfoFast::xtensa(cpu_info)
                | qmp::CpuInfoFast::xtensaeb(cpu_info) => {
                    let vcpu_id = cpu_info.cpu_index as u32;
                    let thread_id = cpu_info.thread_id as u32;
                    (vcpu_id, thread_id)
                }
                qmp::CpuInfoFast::s390x { base, .. } => {
                    let vcpu_id = base.cpu_index as u32;
                    let thread_id = base.thread_id as u32;
                    (vcpu_id, thread_id)
                }
            })
            .collect();

        Ok(VcpuThreadIds { vcpus })
    }
}

fn vcpu_id_from_core_id(core_id: i64) -> String {
    format!("cpu-{core_id}")
}

/// Returns whether the CPU driver uses a flat topology.
/// s390x and ppc64le use a flat CPU topology.
fn is_flat_cpu_topology(driver: &str) -> bool {
    matches!(driver, "host-s390x-cpu" | "host-powerpc64-cpu")
}

const PCI_BRIDGE_MAX_CAPACITY: i64 = 30;
const PCI_BRIDGE_FIRST_HOTPLUG_SLOT: i64 = 1;

fn free_slot_on_pci_bridge(pci_dev: &PciDeviceInfo) -> Option<i64> {
    if !pci_dev.qdev_id.starts_with("pci-bridge-") {
        return None;
    }

    let occupied_slots: Vec<i64> = pci_dev
        .pci_bridge
        .as_ref()
        .and_then(|bridge| bridge.devices.as_ref())
        .map(|devices| devices.iter().map(|dev| dev.slot).collect())
        .unwrap_or_default();

    (PCI_BRIDGE_FIRST_HOTPLUG_SLOT..=PCI_BRIDGE_MAX_CAPACITY)
        .find(|slot| !occupied_slots.contains(slot))
}

fn find_free_slot_in_pci_devices(devices: &[PciDeviceInfo]) -> Option<(String, i64)> {
    for pci_dev in devices {
        if let Some(slot) = free_slot_on_pci_bridge(pci_dev) {
            return Some((pci_dev.qdev_id.clone(), slot));
        }

        if let Some(ref bridge) = pci_dev.pci_bridge {
            if let Some(ref children) = bridge.devices {
                if let Some(found) = find_free_slot_in_pci_devices(children) {
                    return Some(found);
                }
            }
        }
    }

    None
}

// The get_pci_path_by_qdev_id function searches a device list for a device matching a given qdev_id,
// tracking the device's path. It recursively explores bridge devices and returns the found device along
// with its updated path.
pub fn get_pci_path_by_qdev_id(
    devices: &[PciDeviceInfo],
    qdev_id: &str,
    path: &mut Vec<i64>,
) -> Option<PciDeviceInfo> {
    for device in devices {
        path.push(device.slot);
        if device.qdev_id == qdev_id {
            return Some(device.clone());
        }

        if let Some(ref bridge) = device.pci_bridge {
            if let Some(ref bridge_devices) = bridge.devices {
                if let Some(found_device) = get_pci_path_by_qdev_id(bridge_devices, qdev_id, path) {
                    return Some(found_device);
                }
            }
        }

        // If the device not found, pop the current slot before moving to next device
        path.pop();
    }
    None
}

pub fn get_qmp_socket_path(sid: &str) -> String {
    if is_rootless() {
        [get_jailer_root(sid).as_str(), QMP_SOCKET_FILE].join("/")
    } else {
        QMP_SOCKET_FILE.to_string()
    }
}

/// QMP block_set_io_throttle of a device's limits, with libvirt's mapping of
/// its <iotune> keys (qemuMonitorJSONSetBlockIoThrottle). A key that is
/// absent is 0 (no limit) or left out.
#[allow(deprecated)]
fn block_io_throttle(qdev_id: &str, limits: &BlockIoLimits) -> qmp::BlockIOThrottle {
    // Values are at most 10^15 (BlockIoLimits), so they fit an i64.
    let value = |v: Option<u64>| v.map(|v| v as i64);
    qmp::BlockIOThrottle {
        device: None,
        id: Some(qdev_id.to_owned()),
        group: Some(format!("nova-qos-{qdev_id}")),
        bps: value(limits.total_bytes_sec).unwrap_or(0),
        bps_rd: value(limits.read_bytes_sec).unwrap_or(0),
        bps_wr: value(limits.write_bytes_sec).unwrap_or(0),
        iops: value(limits.total_iops_sec).unwrap_or(0),
        iops_rd: value(limits.read_iops_sec).unwrap_or(0),
        iops_wr: value(limits.write_iops_sec).unwrap_or(0),
        bps_max: value(limits.total_bytes_sec_max),
        bps_rd_max: value(limits.read_bytes_sec_max),
        bps_wr_max: value(limits.write_bytes_sec_max),
        iops_max: value(limits.total_iops_sec_max),
        iops_rd_max: value(limits.read_iops_sec_max),
        iops_wr_max: value(limits.write_iops_sec_max),
        iops_size: value(limits.size_iops_sec),
        bps_max_length: None,
        bps_rd_max_length: None,
        bps_wr_max_length: None,
        iops_max_length: None,
        iops_rd_max_length: None,
        iops_wr_max_length: None,
    }
}

#[cfg(test)]
mod nova_volume_qos_tests {
    use super::*;
    use std::collections::HashMap;

    fn limits(pairs: &[(&str, &str)]) -> BlockIoLimits {
        let metadata: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (format!("{}{k}", crate::VOLUME_QOS_PREFIX), v.to_string()))
            .collect();
        BlockIoLimits::from_volume_metadata(&metadata).unwrap().unwrap()
    }

    #[test]
    fn nova_volume_qos_qmp_all_keys() {
        let throttle = block_io_throttle(
            "drive-3",
            &limits(&[
                ("read_bytes_sec", "1000"),
                ("write_bytes_sec", "2000"),
                ("read_iops_sec", "10"),
                ("write_iops_sec", "20"),
                ("read_bytes_sec_max", "3000"),
                ("write_bytes_sec_max", "4000"),
                ("read_iops_sec_max", "30"),
                ("write_iops_sec_max", "40"),
                ("size_iops_sec", "4096"),
            ]),
        );
        assert_eq!(
            serde_json::to_value(&throttle).unwrap(),
            serde_json::json!({
                "id": "drive-3", "group": "nova-qos-drive-3",
                "bps": 0, "bps_rd": 1000, "bps_wr": 2000,
                "iops": 0, "iops_rd": 10, "iops_wr": 20,
                "bps_rd_max": 3000, "bps_wr_max": 4000,
                "iops_rd_max": 30, "iops_wr_max": 40, "iops_size": 4096
            })
        );
    }

    #[test]
    fn nova_volume_qos_qmp_totals() {
        let throttle = block_io_throttle(
            "drive-1",
            &limits(&[
                ("total_bytes_sec", "1048576"),
                ("total_bytes_sec_max", "2097152"),
                ("total_iops_sec", "100"),
                ("total_iops_sec_max", "200"),
            ]),
        );
        assert_eq!(
            serde_json::to_value(&throttle).unwrap(),
            serde_json::json!({
                "id": "drive-1", "group": "nova-qos-drive-1",
                "bps": 1048576, "bps_rd": 0, "bps_wr": 0,
                "iops": 100, "iops_rd": 0, "iops_wr": 0,
                "bps_max": 2097152, "iops_max": 200
            })
        );
    }
}

/// Generate a blockdev node name based on the given index.
pub(crate) fn block_node_name(index: u64) -> String {
    format!("drive-{index}")
}

// Nova Kata (ADR-052): the names of a block copy's parts, by the device's
// index: the destination's export, the source's node of it and its job.
const JOB_PREFIX: &str = "copy-";

fn export_name(index: u64) -> String {
    format!("block-{index}")
}

fn mirror_node_name(index: u64) -> String {
    format!("mirror-{index}")
}

fn job_name(index: u64) -> String {
    format!("{JOB_PREFIX}{index}")
}

/// blockdev-mirror with target-is-zero, which qapi-qmp 0.15 lacks.
#[derive(serde::Serialize)]
struct BlockdevMirrorOfBlank {
    #[serde(rename = "job-id")]
    job_id: String,
    device: String,
    target: String,
    sync: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    speed: Option<i64>,
    #[serde(rename = "auto-dismiss")]
    auto_dismiss: bool,
    #[serde(rename = "target-is-zero")]
    target_is_zero: bool,
}

impl qapi_spec::Command for BlockdevMirrorOfBlank {
    const NAME: &'static str = "blockdev-mirror";
    const ALLOW_OOB: bool = false;
    type Ok = qapi_spec::Empty;
}

/// A mirror job of a block copy, as query-block-jobs has it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MirrorJob {
    pub index: u64,
    /// The mirror converged: the target has every block, and follows.
    pub ready: bool,
    /// The job ended, with `error` if it failed; it waits to be dismissed.
    pub concluded: bool,
    pub offset: u64,
    pub len: u64,
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_kata_block_fdsets_from_qmp() {
        let fdsets = vec![
            qmp::FdsetInfo {
                fdset_id: 7,
                fds: vec![
                    qmp::FdsetFdInfo {
                        fd: 21,
                        opaque: Some(block_fd_opaque("drive-2", "vmdk-extent-0")),
                    },
                    qmp::FdsetFdInfo {
                        fd: 22,
                        opaque: Some(block_fd_opaque("drive-2", "vmdk-extent-1")),
                    },
                ],
            },
            qmp::FdsetInfo {
                fdset_id: 8,
                fds: vec![qmp::FdsetFdInfo {
                    fd: 23,
                    opaque: Some(block_fd_opaque("drive-2", "vmdk-descriptor")),
                }],
            },
            qmp::FdsetInfo {
                fdset_id: 9,
                fds: vec![qmp::FdsetFdInfo {
                    fd: 24,
                    opaque: Some("unrelated".to_string()),
                }],
            },
        ];

        assert_eq!(
            collect_block_fdsets(fdsets),
            HashMap::from([("drive-2".to_string(), vec![7, 8])])
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
// Candidate included inside qemu::qmp; callers must hold native device ownership.

fn validate_block_growth(current: i64, host_bytes: u64, requested: u64) -> Result<i64> {
    let requested = i64::try_from(requested).context("block growth exceeds QMP size range")?;
    if current <= 0 || requested <= 0 || requested % 512 != 0 {
        return Err(anyhow!("block growth requires positive sector-aligned capacity"));
    }
    if requested < current {
        return Err(anyhow!("block shrink is unsupported"));
    }
    // QMP must refresh an already-grown backend, never resize storage on behalf
    // of Cinder. Exact agreement also refuses a stale, smaller concurrent event.
    if host_bytes != requested as u64 {
        return Err(anyhow!("host capacity differs from requested block growth"));
    }
    Ok(requested)
}

/// Kata passes raw block sources to QEMU by file descriptor, so the node's file
/// is "/dev/fdset/<id>" rather than the host device path.
fn growth_fdset_id(file: &str) -> Result<i64> {
    let id = file.strip_prefix("/dev/fdset/")
        .ok_or_else(|| anyhow!("block growth node is not backed by a shim-passed descriptor"))?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("block growth node has an invalid fdset path"));
    }
    id.parse().context("block growth fdset id")
}

/// The fdset must hold exactly the one descriptor the shim registered as this
/// node's raw block source; returns that descriptor's number inside QEMU.
fn growth_source_fd(fdsets: &[(i64, Vec<(i64, Option<String>)>)], node_name: &str,
                    fdset_id: i64) -> Result<i64> {
    let expected = block_fd_opaque(node_name, "block-source");
    let mut matching = fdsets.iter().filter(|(id, _)| *id == fdset_id);
    let (_, fds) = matching.next().ok_or_else(|| anyhow!("block growth fdset is absent"))?;
    if matching.next().is_some() {
        return Err(anyhow!("block growth fdset id is ambiguous"));
    }
    match fds.as_slice() {
        [(fd, Some(opaque))] if *opaque == expected && *fd >= 0 => Ok(*fd),
        _ => Err(anyhow!("block growth fdset is not this node's raw block source")),
    }
}

impl Qmp {
    fn owned_raw_block_capacity(&mut self, index: u64, qemu_pid: u32, major: i64,
                                minor: i64) -> Result<i64> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let name = block_node_name(index);
        let nodes = self.qmp.execute(&qmp::query_named_block_nodes { flat: Some(true) })?;
        let mut owned = nodes.into_iter().filter(|node| node.node_name.as_deref() == Some(&name));
        let node = owned.next().context("block growth node is absent")?;
        if owned.next().is_some() || node.drv != "raw" || node.ro || node.encrypted
            || node.backing_file.is_some() || node.backing_file_depth != 0
            || node.image.base.filename != node.file {
            return Err(anyhow!("block growth requires a unique writable raw node without backing chain"));
        }
        let fdset_id = growth_fdset_id(&node.file)?;
        // Both the live QMP state and the shim's own registration must name
        // this fdset for this node.
        if self.block_fdsets.get(&name).map(Vec::as_slice) != Some(&[fdset_id][..]) {
            return Err(anyhow!("block growth fdset is not registered for this node"));
        }
        let fdsets: Vec<(i64, Vec<(i64, Option<String>)>)> = self.qmp
            .execute(&qmp::query_fdsets {})
            .context("query QEMU fdsets for block growth")?
            .into_iter()
            .map(|set| (set.fdset_id, set.fds.into_iter().map(|fd| (fd.fd, fd.opaque)).collect()))
            .collect();
        let fd = growth_source_fd(&fdsets, &name, fdset_id)?;
        // The descriptor QEMU actually holds must be the owned host device.
        let held = std::fs::metadata(format!("/proc/{qemu_pid}/fd/{fd}"))
            .context("inspect QEMU block growth descriptor")?;
        if !held.file_type().is_block_device()
            || libc::major(held.rdev()) as i64 != major
            || libc::minor(held.rdev()) as i64 != minor {
            return Err(anyhow!("QEMU block growth descriptor is not the owned host device"));
        }
        Ok(node.image.base.virtual_size)
    }

    /// Refresh capacity of an existing native raw block device after backend
    /// growth. The caller must obtain host_bytes and the device number from the
    /// exact owned mapping under the same attachment lock; an arbitrary path or
    /// tenant size is not ownership evidence. This method does not grow
    /// filesystems or Cinder RBD.
    pub fn grow_block_device(&mut self, index: u64, qemu_pid: u32, major: i64, minor: i64,
                             host_bytes: u64, requested: u64) -> Result<()> {
        let current = self.owned_raw_block_capacity(index, qemu_pid, major, minor)?;
        let size = validate_block_growth(current, host_bytes, requested)?;
        if current == size {
            return Ok(());
        }
        self.qmp.execute(&qmp::block_resize {
            device: None, node_name: Some(block_node_name(index)), size,
        }).context("QMP block growth outcome may be uncertain; retain attachment")?;
        if self.owned_raw_block_capacity(index, qemu_pid, major, minor)? != size {
            return Err(anyhow!("QMP block growth capacity not confirmed; retain attachment"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod nova_block_growth_tests {
    use super::*;

    #[test]
    fn growth_and_equal_capacity_replay() {
        assert_eq!(validate_block_growth(512, 1024, 1024).unwrap(), 1024);
        assert_eq!(validate_block_growth(1024, 1024, 1024).unwrap(), 1024);
    }

    #[test]
    fn refuse_shrink_and_stale_backend_observation() {
        for (current, host, requested) in [(1024, 1024, 512), (512, 512, 1024),
                                          (512, 2048, 1024), (2048, 2048, 1024)] {
            assert!(validate_block_growth(current, host, requested).is_err());
        }
    }

    #[test]
    fn refuse_unknown_unaligned_and_overflow_capacity() {
        for (current, host, requested) in [(0, 512, 512), (-1, 512, 512),
            (512, 0, 0), (512, 513, 513), (512, u64::MAX, u64::MAX)] {
            assert!(validate_block_growth(current, host, requested).is_err());
        }
    }

    #[test]
    fn fdset_path_is_the_only_accepted_node_file() {
        assert_eq!(growth_fdset_id("/dev/fdset/7").unwrap(), 7);
        for file in ["/dev/sdc", "/dev/fdset/", "/dev/fdset/-1", "/dev/fdset/7/x",
                     "/dev/fdset/ 7", "fdset/7"] {
            assert!(growth_fdset_id(file).is_err(), "{file}");
        }
    }

    #[test]
    fn source_fd_requires_the_nodes_single_block_source() {
        let own = Some(block_fd_opaque("drive-3", "block-source"));
        let sets = vec![(7, vec![(41, own.clone())]),
                        (8, vec![(42, Some(block_fd_opaque("drive-4", "block-source")))])];
        assert_eq!(growth_source_fd(&sets, "drive-3", 7).unwrap(), 41);
        // Another node's fdset, a missing set, or a mislabeled descriptor.
        assert!(growth_source_fd(&sets, "drive-3", 8).is_err());
        assert!(growth_source_fd(&sets, "drive-3", 9).is_err());
        for fds in [vec![], vec![(41, None)], vec![(41, own.clone()), (43, own.clone())],
                    vec![(41, Some(block_fd_opaque("drive-3", "vmdk-extent-0")))],
                    vec![(-1, own.clone())]] {
            assert!(growth_source_fd(&[(7, fds.clone())], "drive-3", 7).is_err(), "{fds:?}");
        }
        assert!(growth_source_fd(&[(7, vec![(41, own.clone())]), (7, vec![(41, own)])],
                                 "drive-3", 7).is_err());
    }
}
