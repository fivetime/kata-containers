// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtio-pmem devices (Nova Kata): a host file mapped into the guest, as
//! the guest image a Kata guest boots from with DAX instead of a virtio-blk
//! disk. Cold-plug only.

use dbs_virtio_devices as virtio;
use serde_derive::{Deserialize, Serialize};
use slog::{error, info};
use virtio::pmem::Pmem;

use crate::config_manager::{ConfigItem, DeviceConfigInfo, DeviceConfigInfos};
use crate::device_manager::{DeviceManager, DeviceMgrError, DeviceOpContext};

// The flag of whether to use the shared irq.
const USE_SHARED_IRQ: bool = true;
// The flag of whether to use the generic irq (virtio-mmio's MSI extension,
// which the guest kernels in use do not support).
const USE_GENERIC_IRQ: bool = false;

/// Errors associated with `PmemDeviceConfigInfo`.
#[derive(Debug, thiserror::Error)]
pub enum PmemDeviceError {
    /// The file is already given to another pmem device.
    #[error("the virtio-pmem file was already added to a different device")]
    PmemDeviceAlreadyExists,

    /// Cannot perform the requested operation after booting the microVM.
    #[error("the update operation is not allowed after boot")]
    UpdateNotAllowedPostBoot,

    /// Failed to create a pmem device.
    #[error("failed to create virtio-pmem device, {0}")]
    CreatePmemDevice(#[source] virtio::Error),

    /// Cannot initialize a pmem device or add a device to the MMIO Bus.
    #[error("failure while registering pmem device: {0}")]
    RegisterPmemDevice(#[source] DeviceMgrError),

    /// The device manager errors.
    #[error("DeviceManager error: {0}")]
    DeviceManager(#[source] DeviceMgrError),
}

/// Configuration information for a virtio-pmem device.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PmemDeviceConfigInfo {
    /// Path of the host file, which doubles as the device id.
    pub path_on_host: String,
    /// Open the file read-only; guest writes stay in its private mapping.
    pub is_read_only: bool,
    /// Use shared irq
    pub use_shared_irq: Option<bool>,
    /// Use generic irq
    pub use_generic_irq: Option<bool>,
}

impl ConfigItem for PmemDeviceConfigInfo {
    type Err = PmemDeviceError;

    fn id(&self) -> &str {
        &self.path_on_host
    }

    fn check_conflicts(&self, other: &Self) -> Result<(), PmemDeviceError> {
        if self.path_on_host == other.path_on_host {
            Err(PmemDeviceError::PmemDeviceAlreadyExists)
        } else {
            Ok(())
        }
    }
}

/// Pmem Device Info
pub type PmemDeviceInfo = DeviceConfigInfo<PmemDeviceConfigInfo>;

impl ConfigItem for PmemDeviceInfo {
    type Err = PmemDeviceError;

    fn id(&self) -> &str {
        &self.config.path_on_host
    }

    fn check_conflicts(&self, other: &Self) -> Result<(), PmemDeviceError> {
        self.config.check_conflicts(&other.config)
    }
}

/// Wrapper for the collection that holds all the pmem device configurations.
#[derive(Clone)]
pub struct PmemDeviceMgr {
    info_list: DeviceConfigInfos<PmemDeviceConfigInfo>,
}

impl PmemDeviceMgr {
    /// Inserts `pmem_cfg` in the virtio-pmem device configuration list. A
    /// pmem device is cold-plug only, so a hotplug request is rejected.
    pub fn insert_or_update_device(
        &mut self,
        ctx: DeviceOpContext,
        pmem_cfg: PmemDeviceConfigInfo,
    ) -> std::result::Result<(), PmemDeviceError> {
        if ctx.is_hotplug {
            error!(ctx.logger(), "no support of virtio-pmem device hotplug";
                "subsystem" => "pmem_dev_mgr",
                "path_on_host" => &pmem_cfg.path_on_host,
            );
            return Err(PmemDeviceError::UpdateNotAllowedPostBoot);
        }

        info!(ctx.logger(), "add virtio-pmem device configuration";
            "subsystem" => "pmem_dev_mgr",
            "path_on_host" => &pmem_cfg.path_on_host,
        );
        self.info_list.insert_or_update(&pmem_cfg)?;
        Ok(())
    }

    /// Attaches all virtio-pmem devices of the configuration list.
    pub fn attach_devices(
        &mut self,
        ctx: &mut DeviceOpContext,
    ) -> std::result::Result<(), PmemDeviceError> {
        let epoll_mgr = ctx
            .get_epoll_mgr()
            .map_err(PmemDeviceError::DeviceManager)?;

        for info in self.info_list.iter_mut() {
            info!(ctx.logger(), "attach virtio-pmem device";
                "subsystem" => "pmem_dev_mgr",
                "path_on_host" => &info.config.path_on_host,
            );
            let device = Pmem::new(
                info.config.path_on_host.clone(),
                info.config.is_read_only,
                epoll_mgr.clone(),
            )
            .map_err(PmemDeviceError::CreatePmemDevice)?;
            let mmio_dev = DeviceManager::create_mmio_virtio_device(
                Box::new(device),
                ctx,
                info.config.use_shared_irq.unwrap_or(USE_SHARED_IRQ),
                info.config.use_generic_irq.unwrap_or(USE_GENERIC_IRQ),
            )
            .map_err(PmemDeviceError::RegisterPmemDevice)?;
            info.set_device(mmio_dev);
        }
        Ok(())
    }
}

impl Default for PmemDeviceMgr {
    fn default() -> Self {
        PmemDeviceMgr {
            info_list: DeviceConfigInfos::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_manager::tests::create_address_space;
    use crate::test_utils::tests::create_vm_for_test;
    use test_utils::skip_if_kvm_unaccessable;
    use vmm_sys_util::tempfile::TempFile;

    fn config(path: &str) -> PmemDeviceConfigInfo {
        PmemDeviceConfigInfo {
            path_on_host: path.to_string(),
            is_read_only: true,
            use_shared_irq: None,
            use_generic_irq: None,
        }
    }

    #[test]
    fn test_pmem_config_check_conflicts() {
        assert!(config("/a").check_conflicts(&config("/a")).is_err());
        assert!(config("/a").check_conflicts(&config("/b")).is_ok());
    }

    #[test]
    fn test_pmem_insert_and_attach_device() {
        skip_if_kvm_unaccessable!();
        let file = TempFile::new().unwrap();
        file.as_file().set_len(3 << 20).unwrap();
        let path = file.as_path().to_str().unwrap().to_string();
        let mut vm = create_vm_for_test();

        // Hotplug is rejected.
        let ctx = DeviceOpContext::new(
            Some(vm.epoll_manager().clone()),
            vm.device_manager(),
            Some(vm.vm_as().unwrap().clone()),
            None,
            true,
            Some(vm.vm_config().clone()),
            vm.shared_info().clone(),
        );
        assert!(matches!(
            vm.device_manager_mut()
                .pmem_manager
                .insert_or_update_device(ctx, config(&path)),
            Err(PmemDeviceError::UpdateNotAllowedPostBoot)
        ));

        let ctx = DeviceOpContext::new(
            Some(vm.epoll_manager().clone()),
            vm.device_manager(),
            Some(vm.vm_as().unwrap().clone()),
            None,
            false,
            Some(vm.vm_config().clone()),
            vm.shared_info().clone(),
        );
        vm.device_manager_mut()
            .pmem_manager
            .insert_or_update_device(ctx, config(&path))
            .unwrap();
        assert_eq!(vm.device_manager().pmem_manager.info_list.len(), 1);

        let mut ctx = DeviceOpContext::new(
            Some(vm.epoll_manager().clone()),
            vm.device_manager(),
            Some(vm.vm_as().unwrap().clone()),
            Some(create_address_space()),
            false,
            Some(vm.vm_config().clone()),
            vm.shared_info().clone(),
        );
        vm.device_manager_mut()
            .pmem_manager
            .attach_devices(&mut ctx)
            .unwrap();
    }
}
