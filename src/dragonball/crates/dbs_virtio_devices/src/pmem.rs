// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtio-pmem device (Nova Kata).
//!
//! A host file is mapped into guest physical memory above 4 GiB, so a guest
//! mounts it with DAX and reads the host's page cache in place: one copy for
//! every guest on the host and none in each guest's own page cache. It
//! takes no virtio-blk name in the guest. The mapping is private, so a write
//! by a guest stays its own and the file is never changed. The guest finds
//! the range in the device configuration (start and size, both 2 MiB
//! aligned); a file whose size is not 2 MiB aligned is followed by zero
//! pages up to the alignment. The queue takes the guest's flush requests,
//! which become an fsync of the file.

use std::any::Any;
use std::fs::{File, OpenOptions};
use std::io;
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use dbs_device::resources::{DeviceResources, ResourceConstraint};
use dbs_utils::epoll_manager::{
    EpollManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberId,
};
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::VmFd;
use log::{debug, error, trace};
use virtio_bindings::bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_queue::{QueueOwnedT, QueueSync, QueueT};
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryRegion, GuestRegionMmap};

use crate::device::{VirtioDevice, VirtioDeviceConfig, VirtioDeviceInfo};
use crate::{
    ActivateError, ActivateResult, ConfigResult, DbsGuestAddressSpace, Error, Result,
    VirtioSharedMemoryList, TYPE_PMEM,
};

const PMEM_DRIVER_NAME: &str = "virtio-pmem";

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 1;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

/// The alignment of the guest range: Linux's memremap of a pmem region and
/// huge pages both need 2 MiB.
pub const PMEM_ALIGNMENT: u64 = 0x20_0000;

// The guest's request (struct virtio_pmem_req) and the device's answer
// (struct virtio_pmem_resp), each a little-endian u32.
const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_EIO: u32 = 1;

/// The guest range a file takes: its size rounded up to the alignment.
pub fn pmem_region_size(file_size: u64) -> u64 {
    file_size.div_ceil(PMEM_ALIGNMENT) * PMEM_ALIGNMENT
}

/// A private mapping of the file followed by anonymous zero pages up to the
/// region size; unmapped when dropped.
struct PmemMapping {
    addr: *mut libc::c_void,
    len: usize,
}

// The mapping is only read and written by the guest through KVM; the device
// keeps it alive and unmaps it once.
unsafe impl Send for PmemMapping {}
unsafe impl Sync for PmemMapping {}

impl PmemMapping {
    fn new(file: &File, file_size: u64, region_size: u64) -> io::Result<Self> {
        let len = region_size as usize;
        // SAFETY: a new anonymous mapping, checked below.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mapping = PmemMapping { addr, len };
        if file_size > 0 {
            // SAFETY: replaces the start of the anonymous mapping just made,
            // which this struct owns.
            let file_addr = unsafe {
                libc::mmap(
                    addr,
                    file_size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_NORESERVE | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    0,
                )
            };
            if file_addr == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(mapping)
    }
}

impl Drop for PmemMapping {
    fn drop(&mut self) {
        // SAFETY: the mapping this struct made.
        unsafe { libc::munmap(self.addr, self.len) };
    }
}

pub(crate) struct PmemEpollHandler<
    AS: GuestAddressSpace,
    Q: QueueT + Send = QueueSync,
    R: GuestMemoryRegion = GuestRegionMmap,
> {
    pub(crate) config: VirtioDeviceConfig<AS, Q, R>,
    pub(crate) file: File,
    id: String,
}

impl<AS: DbsGuestAddressSpace, Q: QueueT + Send, R: GuestMemoryRegion> PmemEpollHandler<AS, Q, R> {
    fn process_queue(&mut self, queue_index: usize) -> bool {
        let guard = self.config.lock_guest_memory();
        let mem = guard.deref().memory();
        let queue = &mut self.config.queues[queue_index];
        let mut queue_guard = queue.queue_mut().lock();
        let queue_size = queue_guard.size();
        let mut used_desc_heads = Vec::with_capacity(queue_size as usize);

        let mut iter = match queue_guard.iter(mem) {
            Err(e) => {
                error!("{}: failed to process queue. {}", self.id, e);
                return false;
            }
            Ok(iter) => iter,
        };

        let mut first_error: Option<String> = None;
        for mut desc_chain in &mut iter {
            let head_index = desc_chain.head_index();
            if head_index >= queue_size {
                first_error.get_or_insert(format!("invalid descriptor chain head {head_index}"));
                continue;
            }
            // A request descriptor the guest wrote, then a response one.
            let request = desc_chain.next();
            let response = desc_chain.next();
            let (request, response) = match (request, response) {
                (Some(req), Some(resp))
                    if !req.is_write_only()
                        && req.len() >= 4
                        && resp.is_write_only()
                        && resp.len() >= 4 =>
                {
                    (req, resp)
                }
                _ => {
                    first_error.get_or_insert("malformed pmem request".to_string());
                    used_desc_heads.push((head_index, 0));
                    continue;
                }
            };
            let ret = match mem.read_obj::<u32>(request.addr()) {
                Ok(t) if u32::from_le(t) == VIRTIO_PMEM_REQ_TYPE_FLUSH => {
                    match self.file.sync_all() {
                        Ok(()) => VIRTIO_PMEM_RESP_TYPE_OK,
                        Err(e) => {
                            first_error.get_or_insert(format!("flush failed: {e}"));
                            VIRTIO_PMEM_RESP_TYPE_EIO
                        }
                    }
                }
                Ok(t) => {
                    first_error.get_or_insert(format!("unknown request type {}", u32::from_le(t)));
                    VIRTIO_PMEM_RESP_TYPE_EIO
                }
                Err(e) => {
                    first_error.get_or_insert(e.to_string());
                    VIRTIO_PMEM_RESP_TYPE_EIO
                }
            };
            match mem.write_obj(ret.to_le(), response.addr()) {
                Ok(()) => used_desc_heads.push((head_index, 4)),
                Err(e) => {
                    first_error.get_or_insert(e.to_string());
                    used_desc_heads.push((head_index, 0));
                }
            }
        }
        drop(queue_guard);

        if let Some(e) = first_error {
            error!("{}: pmem queue: {}", self.id, e);
        }

        let mut nr_used = 0;
        for &(desc_index, len) in &used_desc_heads {
            match queue.queue_mut().add_used(mem, desc_index, len) {
                Ok(()) => nr_used += 1,
                Err(e) => error!(
                    "{}: failed to add used descriptor {}: {}",
                    self.id, desc_index, e
                ),
            }
        }
        nr_used > 0
    }
}

impl<AS: DbsGuestAddressSpace, Q: QueueT + Send, R: GuestMemoryRegion> MutEventSubscriber
    for PmemEpollHandler<AS, Q, R>
where
    AS: 'static + GuestAddressSpace + Send + Sync,
{
    fn init(&mut self, ops: &mut EventOps) {
        trace!(target: PMEM_DRIVER_NAME, "{}: PmemEpollHandler::init()", self.id);
        for (idx, queue) in self.config.queues.iter().enumerate() {
            let events = Events::with_data(queue.eventfd.as_ref(), idx as u32, EventSet::IN);
            if let Err(e) = ops.add(events) {
                error!("{}: failed to register queue event, {:?}", self.id, e);
            }
        }
    }

    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        let idx = events.data() as usize;
        if idx >= self.config.queues.len() {
            error!("{}: invalid queue index {}", self.id, idx);
            return;
        }
        if let Err(e) = self.config.queues[idx].consume_event() {
            error!("{}: failed to get queue event: {:?}", self.id, e);
        } else if self.process_queue(idx) {
            if let Err(e) = self.config.queues[idx].notify() {
                error!("{}: failed to signal used queue: {}", self.id, e);
            }
        } else {
            debug!("{}: no request processed", self.id);
        }
    }
}

/// Virtio-pmem device backed by a host file.
pub struct Pmem<AS: GuestAddressSpace> {
    pub(crate) device_info: VirtioDeviceInfo,
    file: File,
    file_size: u64,
    mapping: Option<PmemMapping>,
    subscriber_id: Option<SubscriberId>,
    id: String,
    phantom: PhantomData<AS>,
}

impl<AS: GuestAddressSpace> Pmem<AS> {
    /// Create a virtio-pmem device of the file at `path`, opened read-only
    /// when `read_only`.
    pub fn new(path: String, read_only: bool, epoll_mgr: EpollManager) -> Result<Self> {
        trace!(target: PMEM_DRIVER_NAME, "{}: Pmem::new({})", PMEM_DRIVER_NAME, path);
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(&path)?;
        let file_size = file.metadata()?.len();
        if file_size == 0 {
            return Err(Error::InvalidInput);
        }
        let device_info = VirtioDeviceInfo::new(
            PMEM_DRIVER_NAME.to_string(),
            1u64 << VIRTIO_F_VERSION_1,
            Arc::new(vec![QUEUE_SIZE; NUM_QUEUES]),
            // start and size, filled in when the range is assigned
            vec![0u8; 16],
            epoll_mgr,
        );
        Ok(Pmem {
            device_info,
            file,
            file_size,
            mapping: None,
            subscriber_id: None,
            id: path,
            phantom: PhantomData,
        })
    }

    /// The size of the guest range the device takes.
    pub fn region_size(&self) -> u64 {
        pmem_region_size(self.file_size)
    }
}

impl<AS, Q, R> VirtioDevice<AS, Q, R> for Pmem<AS>
where
    AS: DbsGuestAddressSpace,
    Q: QueueT + Send + 'static,
    R: GuestMemoryRegion + Sync + Send + 'static,
{
    fn device_type(&self) -> u32 {
        TYPE_PMEM
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn get_avail_features(&self, page: u32) -> u32 {
        self.device_info.get_avail_features(page)
    }

    fn set_acked_features(&mut self, page: u32, value: u32) {
        self.device_info.set_acked_features(page, value)
    }

    fn read_config(&mut self, offset: u64, data: &mut [u8]) -> ConfigResult {
        self.device_info.read_config(offset, data)
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) -> ConfigResult {
        // The configuration is read-only for the guest.
        Ok(())
    }

    fn activate(&mut self, config: VirtioDeviceConfig<AS, Q, R>) -> ActivateResult {
        trace!(target: PMEM_DRIVER_NAME, "{}: VirtioDevice::activate()", self.id);
        self.device_info.check_queue_sizes(&config.queues)?;
        let file = self.file.try_clone().map_err(|e| {
            error!("{}: failed to clone the pmem file, {}", self.id, e);
            ActivateError::InternalError
        })?;
        let handler = Box::new(PmemEpollHandler {
            config,
            file,
            id: self.id.clone(),
        });
        self.subscriber_id = Some(self.device_info.register_event_handler(handler));
        Ok(())
    }

    fn get_resource_requirements(
        &self,
        requests: &mut Vec<ResourceConstraint>,
        use_generic_irq: bool,
    ) {
        requests.push(ResourceConstraint::LegacyIrq { irq: None });
        if use_generic_irq {
            requests.push(ResourceConstraint::GenericIrq {
                size: (self.device_info.queue_sizes.len() + 1) as u32,
            });
        }
        // The guest range: above 4 GiB, clear of the lapic and ioapic, and
        // 2 MiB aligned, as virtio-fs's DAX window.
        requests.push(ResourceConstraint::MmioAddress {
            range: Some((0x1_0000_0000, u64::MAX)),
            align: PMEM_ALIGNMENT,
            size: self.region_size(),
        });
        requests.push(ResourceConstraint::KvmMemSlot {
            slot: None,
            size: 1,
        });
    }

    fn set_resource(
        &mut self,
        vm_fd: Arc<VmFd>,
        resource: DeviceResources,
    ) -> Result<Option<VirtioSharedMemoryList<R>>> {
        let mmio_res = resource.get_mmio_address_ranges();
        let slot_res = resource.get_kvm_mem_slots();
        if mmio_res.len() != 1 || slot_res.len() != 1 || mmio_res[0].1 != self.region_size() {
            error!(
                "{}: wrong pmem resources ({:?}, {:?})",
                self.id, mmio_res, slot_res
            );
            return Err(Error::InvalidResource);
        }
        let (guest_addr, len) = mmio_res[0];
        let mapping = PmemMapping::new(&self.file, self.file_size, len)?;
        let region = kvm_userspace_memory_region {
            slot: slot_res[0],
            flags: 0,
            guest_phys_addr: guest_addr,
            memory_size: len,
            userspace_addr: mapping.addr as u64,
        };
        // SAFETY: the mapping lives as long as the device, and the slot was
        // allocated for this device by the resource manager.
        unsafe { vm_fd.set_user_memory_region(region) }.map_err(Error::SetUserMemoryRegion)?;
        self.mapping = Some(mapping);

        let mut config = guest_addr.to_le_bytes().to_vec();
        config.extend_from_slice(&len.to_le_bytes());
        self.device_info.config_space = config;
        debug!("{}: pmem at 0x{:x}, 0x{:x} bytes", self.id, guest_addr, len);
        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn test_pmem_region_size() {
        assert_eq!(pmem_region_size(1), PMEM_ALIGNMENT);
        assert_eq!(pmem_region_size(PMEM_ALIGNMENT), PMEM_ALIGNMENT);
        assert_eq!(pmem_region_size(254 << 20), 254 << 20);
        assert_eq!(pmem_region_size((253 << 20) + 1), 254 << 20);
    }

    #[test]
    fn test_pmem_mapping_is_private_and_zero_padded() {
        let mut file = vmm_sys_util::tempfile::TempFile::new().unwrap().into_file();
        file.write_all(b"pmem").unwrap();
        let mapping = PmemMapping::new(&file, 4, PMEM_ALIGNMENT).unwrap();
        // SAFETY: within the mapping just made.
        let bytes = unsafe { std::slice::from_raw_parts_mut(mapping.addr as *mut u8, mapping.len) };
        assert_eq!(&bytes[..4], b"pmem");
        assert!(bytes[4096..].iter().all(|b| *b == 0));
        // A guest's write stays in the mapping.
        bytes[0] = b'X';
        let mut on_disk = String::new();
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_string(&mut on_disk).unwrap();
        assert_eq!(on_disk, "pmem");
    }
}
