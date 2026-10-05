// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use rtnetlink::Handle;
use scopeguard::defer;

use super::{NetworkModel, NetworkModelType};
use crate::network::NetworkPair;

const QDISC_ADD_ATTEMPTS: u64 = 5; // Number of attempts when adding an ingress qdisc
const QDISC_ADD_BACKOFF_MS: u64 = 10; // Base delay for the linear backoff between qdisc add retries on EBUSY

#[derive(Debug)]
pub(crate) struct TcFilterModel {}

impl TcFilterModel {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

#[async_trait]
impl NetworkModel for TcFilterModel {
    fn model_type(&self) -> NetworkModelType {
        NetworkModelType::TcFilter
    }

    async fn add(&self, pair: &NetworkPair) -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection().context("new connection")?;
        let thread_handler = tokio::spawn(connection);

        defer!({
            thread_handler.abort();
        });

        let tap_index = fetch_index(&handle, pair.tap.tap_iface.name.as_str())
            .await
            .context("fetch tap by index")?;
        let virt_index = fetch_index(&handle, pair.virt_iface.name.as_str())
            .await
            .context("fetch virt by index")?;

        add_ingress_qdisc(&handle, tap_index as i32)
            .await
            .context("add tap ingress")?;

        add_ingress_qdisc(&handle, virt_index as i32)
            .await
            .context("add virt ingress")?;

        handle
            .traffic_filter(tap_index as i32)
            .add()
            .parent(0xffff0000)
            // get protocol with network byte order
            .protocol(0x0003_u16.to_be())
            .redirect(virt_index)?
            .execute()
            .await
            .context("add redirect for tap")?;

        handle
            .traffic_filter(virt_index as i32)
            .add()
            .parent(0xffff0000)
            // get protocol with network byte order
            .protocol(0x0003_u16.to_be())
            .redirect(tap_index)?
            .execute()
            .await
            .context("add redirect for virt")?;

        Ok(())
    }

    async fn release(&self, pair: &NetworkPair) -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection().context("new connection")?;
        let thread_handler = tokio::spawn(connection);
        defer!({
            thread_handler.abort();
        });
        // The filters of an interface go with its ingress qdisc.
        for name in [&pair.virt_iface.name, &pair.tap.tap_iface.name] {
            let index = fetch_index(&handle, name).await?;
            let mut removal = handle.qdisc().del(index as i32);
            removal.message_mut().header.parent = netlink_packet_route::tc::TcHandle::INGRESS;
            removal.message_mut().header.handle = 0xffff0000u32.into();
            removal
                .execute()
                .await
                .with_context(|| format!("delete ingress qdisc of {name}"))?;
        }
        Ok(())
    }

    async fn del(&self, pair: &NetworkPair) -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection().context("new connection")?;
        let thread_handler = tokio::spawn(connection);
        defer!({
            thread_handler.abort();
        });
        // NetworkPair created this persistent TAP. Removing only the veth
        // qdisc leaves it in a caller-owned namespace and breaks the next boot.
        let tap = crate::network::network_pair::get_link_by_name(&handle, &pair.tap.tap_iface.name)
            .await?;
        let mac = crate::network::utils::get_mac_addr(&tap.attrs().hardware_addr)?;
        if tap.r#type() != "tuntap" || mac != pair.virt_iface.hard_addr {
            anyhow::bail!("owned TAP identity changed before detach");
        }
        let virt_index = fetch_index(&handle, &pair.virt_iface.name).await?;
        let mut removal = handle.qdisc().del(virt_index as i32);
        removal.message_mut().header.parent = netlink_packet_route::tc::TcHandle::INGRESS;
        removal.message_mut().header.handle = 0xffff0000u32.into();
        removal
            .execute()
            .await
            .context("delete peer ingress qdisc")?;
        handle
            .link()
            .del(tap.attrs().index)
            .execute()
            .await
            .context("delete owned TAP")?;
        Ok(())
    }
}

/// Add an ingress qdisc to the device at the given index, retrying on EBUSY
/// with linear backoff (10ms, 20ms, ...).
async fn add_ingress_qdisc(handle: &Handle, index: i32) -> Result<(), rtnetlink::Error> {
    let mut last_err = handle.qdisc().add(index).ingress().execute().await;
    for i in 1..QDISC_ADD_ATTEMPTS {
        match &last_err {
            Ok(()) => return Ok(()),
            Err(e) if !is_ebusy(e) => break,
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(QDISC_ADD_BACKOFF_MS * i)).await;
        last_err = handle.qdisc().add(index).ingress().execute().await;
    }
    last_err
}

fn is_ebusy(err: &rtnetlink::Error) -> bool {
    match err {
        rtnetlink::Error::NetlinkError(msg) => msg.code.is_some_and(|c| c.get() == -libc::EBUSY),
        _ => false,
    }
}

pub async fn fetch_index(handle: &Handle, name: &str) -> Result<u32> {
    let link = crate::network::network_pair::get_link_by_name(handle, name)
        .await
        .context("get link by name")?;
    let base = link.attrs();
    Ok(base.index)
}
