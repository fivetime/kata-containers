// Copyright 2026 OpenStack Nova Kata contributors
// SPDX-License-Identifier: Apache-2.0

//! Nova Kata (ADR-052): live migration under Cloud Hypervisor.
//!
//! Cloud Hypervisor sends or receives a VM over one connection, through an
//! API call that answers when the transfer ends, and knows no progress and
//! no cancel. The VMM runs in the sandbox's network namespace, which has
//! no route to the migration network, and takes `unix:` URLs: the shim,
//! in the host's namespace, connects (source) or accepts (destination) the
//! TCP side and bridges it to a unix socket of the sandbox, which the VMM
//! connects to or listens on. The bridge reads the protocol's frames as
//! they pass: the destination's acknowledgement of `Complete` says that it
//! holds the VM, whatever the API answers after that. A cancel drops the
//! bridge; the VMM reads a failed transfer and resumes its VM.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ch_config::ch_api::{
    cloud_hypervisor_vm_info_on, cloud_hypervisor_vm_pause_on,
    cloud_hypervisor_vm_receive_migration_on, cloud_hypervisor_vm_send_migration_on,
    VmReceiveMigrationData, VmSendMigrationData,
};
use ch_config::State;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::task::JoinHandle;

use super::inner::CloudHypervisorInner;
use super::utils::get_api_socket_path;
use crate::migration::{tcp_address, MigrateIn, MigrationParams, MigrationProgress, NetworkPin};
use crate::utils::get_sandbox_path;
use crate::VmmState;

/// The protocol's frames (cloud-hypervisor vm-migration/src/protocol.rs):
/// a 16-byte header, `command` or `status` as a u16, then the payload's
/// length as a u64 at offset 8; the payload follows.
const HEADER: usize = 16;
const COMMAND_COMPLETE: u16 = 5;
const STATUS_OK: u16 = 1;

pub(crate) const OUT_SOCKET: &str = "migrate-out.sock";
pub(crate) const IN_SOCKET: &str = "migrate-in.sock";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(600);
const VMM_LISTEN_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn socket_path(id: &str, name: &str) -> PathBuf {
    PathBuf::from(get_sandbox_path(id)).join(name)
}

#[derive(Debug, Default)]
pub(crate) struct TransferState {
    /// `active`, `completed`, `failed` or `cancelled`.
    pub status: String,
    pub error: String,
    pub cancel_requested: bool,
    /// The last command the source sent.
    last_command: u16,
    /// The destination answered `Complete` with Ok: it holds the VM.
    pub complete_acknowledged: bool,
    pub bytes: u64,
}

pub(crate) type Transfer = Arc<Mutex<TransferState>>;

pub(crate) fn new_transfer() -> Transfer {
    Arc::new(Mutex::new(TransferState {
        status: "active".to_string(),
        ..Default::default()
    }))
}

pub(crate) fn progress(transfer: &Transfer) -> MigrationProgress {
    let state = transfer.lock().unwrap_or_else(|e| e.into_inner());
    MigrationProgress {
        status: state.status.clone(),
        transferred: state.bytes,
        error: state.error.clone(),
        ..Default::default()
    }
}

fn set_status(transfer: &Transfer, status: &str, error: String) {
    let mut state = transfer.lock().unwrap_or_else(|e| e.into_inner());
    if state.status != "active" {
        return;
    }
    state.status = status.to_string();
    state.error = error;
}

/// The frames of one direction, read as the bytes pass.
#[derive(Default)]
struct Frames {
    header: Vec<u8>,
    payload_left: u64,
}

impl Frames {
    fn feed(&mut self, mut data: &[u8], requests: bool, transfer: &Transfer) {
        while !data.is_empty() {
            if self.payload_left > 0 {
                let skip = (data.len() as u64).min(self.payload_left) as usize;
                self.payload_left -= skip as u64;
                data = &data[skip..];
                continue;
            }
            let take = (HEADER - self.header.len()).min(data.len());
            self.header.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.header.len() < HEADER {
                return;
            }
            let word = u16::from_le_bytes([self.header[0], self.header[1]]);
            let mut length = [0u8; 8];
            length.copy_from_slice(&self.header[8..16]);
            self.payload_left = u64::from_le_bytes(length);
            self.header.clear();
            let mut state = transfer.lock().unwrap_or_else(|e| e.into_inner());
            if requests {
                state.last_command = word;
            } else if word == STATUS_OK && state.last_command == COMMAND_COMPLETE {
                state.complete_acknowledged = true;
            }
        }
    }
}

/// Copy one direction. The requests carry the VM; `max_bandwidth` bytes a
/// second, when not 0, paces them: Cloud Hypervisor has no limit of its
/// own, and Nova's is kept here.
async fn pump<R, W>(
    mut from: R,
    mut to: W,
    requests: bool,
    transfer: Transfer,
    max_bandwidth: u64,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 256 * 1024];
    let mut frames = Frames::default();
    let began = tokio::time::Instant::now();
    let mut sent: u64 = 0;
    loop {
        let n = from.read(&mut buffer).await.context("read")?;
        if n == 0 {
            let _ = to.shutdown().await;
            return Ok(());
        }
        frames.feed(&buffer[..n], requests, &transfer);
        if requests {
            let mut state = transfer.lock().unwrap_or_else(|e| e.into_inner());
            state.bytes += n as u64;
        }
        to.write_all(&buffer[..n]).await.context("write")?;
        if requests && max_bandwidth > 0 {
            sent += n as u64;
            let due = Duration::from_secs_f64(sent as f64 / max_bandwidth as f64);
            let elapsed = began.elapsed();
            if due > elapsed {
                tokio::time::sleep(due - elapsed).await;
            }
        }
    }
}

/// Copy both ways until either side ends. On the source the requests come
/// from the VMM's unix connection; on the destination from the TCP peer,
/// which TLS may wrap (migration_tls: Cloud Hypervisor has none of its own,
/// the shim ends it).
async fn bridge<S>(
    tcp: S,
    unix: UnixStream,
    transfer: Transfer,
    source: bool,
    max_bandwidth: u64,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (tcp_read, tcp_write) = tokio::io::split(tcp);
    let (unix_read, unix_write) = unix.into_split();
    let (requests, responses) = if source {
        tokio::join!(
            pump(unix_read, tcp_write, true, transfer.clone(), max_bandwidth),
            pump(tcp_read, unix_write, false, transfer.clone(), 0)
        )
    } else {
        tokio::join!(
            pump(tcp_read, unix_write, true, transfer.clone(), 0),
            pump(unix_read, tcp_write, false, transfer.clone(), 0)
        )
    };
    if let Err(error) = requests {
        debug!(sl!(), "the migration's requests ended: {:?}", error);
    }
    if let Err(error) = responses {
        debug!(sl!(), "the migration's responses ended: {:?}", error);
    }
}

/// Send the VM to `uri`: the shim connects, the VMM sends through a unix
/// socket of the sandbox. Returns the bridge, which a cancel aborts, and
/// the API call.
pub(crate) async fn send(
    id: &str,
    api_socket_path: String,
    uri: &str,
    transfer: Transfer,
    max_bandwidth: u64,
    tls: bool,
) -> Result<(JoinHandle<()>, JoinHandle<()>)> {
    let address = tcp_address(uri)?;
    let std_tcp = std::net::TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .with_context(|| format!("migration_failed: connect to {address}"))?;
    std_tcp
        .set_nonblocking(true)
        .context("migration_failed: the connection")?;
    let tcp = TcpStream::from_std(std_tcp).context("migration_failed: the connection")?;
    // With TLS the handshake is the send's, before the VMM is asked to
    // send: a destination whose certificate does not verify gets nothing.
    let tcp: Box<dyn Stream> = if tls {
        let config = crate::migration_tls::client_config(std::path::Path::new(
            crate::migration_tls::TLS_DIR,
        ))?;
        let secure = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_rustls::TlsConnector::from(config)
                .connect(crate::migration_tls::server_name(address.ip()), tcp),
        )
        .await
        .map_err(|_| anyhow!("migration_failed: the TLS of {address} timed out"))?
        .with_context(|| format!("migration_failed: the TLS of {address}"))?;
        Box::new(secure)
    } else {
        Box::new(tcp)
    };
    let path = socket_path(id, OUT_SOCKET);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("migration_failed: listen on {}", path.display()))?;
    let bridge_transfer = transfer.clone();
    let bridge_task = tokio::spawn(async move {
        match listener.accept().await {
            Ok((unix, _)) => bridge(tcp, unix, bridge_transfer, true, max_bandwidth).await,
            Err(error) => set_status(
                &bridge_transfer,
                "failed",
                format!("the VMM did not connect for the transfer: {error}"),
            ),
        }
    });
    let destination_url = format!("unix:{}", path.display());
    let api_task = tokio::spawn(async move {
        let result = cloud_hypervisor_vm_send_migration_on(
            &api_socket_path,
            VmSendMigrationData {
                destination_url,
                local: false,
            },
        )
        .await;
        let _ = std::fs::remove_file(&path);
        let pause_again = {
            let mut state = transfer.lock().unwrap_or_else(|e| e.into_inner());
            match result {
                Ok(_) => {
                    state.status = "completed".to_string();
                    false
                }
                Err(error) if state.complete_acknowledged => {
                    // The destination took the VM; the VMM's error came
                    // after that, and it resumed its own copy: one writer.
                    state.status = "completed".to_string();
                    state.error =
                        format!("the API answered after the destination took the VM: {error:#}");
                    true
                }
                Err(error) if state.cancel_requested => {
                    state.status = "cancelled".to_string();
                    state.error = format!("{error:#}");
                    false
                }
                Err(error) => {
                    state.status = "failed".to_string();
                    state.error = format!("{error:#}");
                    false
                }
            }
        };
        if pause_again {
            if let Err(error) = cloud_hypervisor_vm_pause_on(&api_socket_path).await {
                error!(sl!(), "stop the VM the destination took: {:?}", error);
            }
        }
    });
    Ok((bridge_task, api_task))
}

/// Receive the VM: the VMM listens on a unix socket of the sandbox, the
/// shim accepts the TCP side and bridges. The TCP listener is bound now, so
/// that a port in use fails the create.
pub(crate) async fn receive(
    id: &str,
    api_socket_path: String,
    uri: &str,
    transfer: Transfer,
    tls: bool,
) -> Result<(JoinHandle<()>, JoinHandle<()>)> {
    let address = tcp_address(uri)?;
    // The certificates are read now: a destination without them fails its
    // create, before the source sends anything.
    let tls = if tls {
        Some(crate::migration_tls::server_config(std::path::Path::new(
            crate::migration_tls::TLS_DIR,
        ))?)
    } else {
        None
    };
    let std_listener = std::net::TcpListener::bind(address)
        .with_context(|| format!("migration_failed: listen on {address}"))?;
    std_listener
        .set_nonblocking(true)
        .context("migration_failed: the listener")?;
    let listener =
        tokio::net::TcpListener::from_std(std_listener).context("migration_failed: the listener")?;
    let path = socket_path(id, IN_SOCKET);
    let _ = std::fs::remove_file(&path);
    let api_path = api_socket_path.clone();
    let api_transfer = transfer.clone();
    let receiver_url = format!("unix:{}", path.display());
    let api_task = tokio::spawn(async move {
        let result =
            cloud_hypervisor_vm_receive_migration_on(&api_path, VmReceiveMigrationData { receiver_url })
                .await;
        match result {
            Ok(_) => {
                // An abandoned transfer answers Ok too: the VM says.
                match cloud_hypervisor_vm_info_on(&api_path).await {
                    Ok(info) if matches!(info.state, State::Running | State::Paused) => {
                        set_status(&api_transfer, "completed", String::new());
                    }
                    Ok(info) => set_status(
                        &api_transfer,
                        "failed",
                        format!("the transfer was abandoned; the VM is {:?}", info.state),
                    ),
                    Err(error) => set_status(
                        &api_transfer,
                        "failed",
                        format!("the transfer was abandoned: {error:#}"),
                    ),
                }
            }
            Err(error) => set_status(&api_transfer, "failed", format!("{error:#}")),
        }
    });
    let bridge_transfer = transfer.clone();
    let accept_task = tokio::spawn(async move {
        let accepted = tokio::time::timeout(ACCEPT_TIMEOUT, listener.accept()).await;
        let tcp: Box<dyn Stream> = match accepted {
            Ok(Ok((stream, peer))) => {
                info!(sl!(), "the migration connected from {}", peer);
                match tls {
                    Some(config) => {
                        let accepted = tokio::time::timeout(
                            CONNECT_TIMEOUT,
                            tokio_rustls::TlsAcceptor::from(config).accept(stream),
                        )
                        .await;
                        match accepted {
                            Ok(Ok(secure)) => Box::new(secure),
                            Ok(Err(error)) => {
                                set_status(
                                    &bridge_transfer,
                                    "failed",
                                    format!("the migration's TLS from {peer}: {error}"),
                                );
                                return;
                            }
                            Err(_) => {
                                set_status(
                                    &bridge_transfer,
                                    "failed",
                                    format!("the migration's TLS from {peer} timed out"),
                                );
                                return;
                            }
                        }
                    }
                    None => Box::new(stream),
                }
            }
            Ok(Err(error)) => {
                set_status(
                    &bridge_transfer,
                    "failed",
                    format!("the migration's connection was not accepted: {error}"),
                );
                return;
            }
            Err(_) => {
                warn!(sl!(), "no migration connected within {:?}", ACCEPT_TIMEOUT);
                return;
            }
        };
        // The VMM binds the socket inside its API call.
        let deadline = tokio::time::Instant::now() + VMM_LISTEN_TIMEOUT;
        let unix = loop {
            match UnixStream::connect(&path).await {
                Ok(unix) => break unix,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    debug!(sl!(), "the VMM does not listen yet: {}", error);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => {
                    set_status(
                        &bridge_transfer,
                        "failed",
                        format!("the VMM does not listen for the transfer: {error}"),
                    );
                    return;
                }
            }
        };
        bridge(tcp, unix, bridge_transfer, false, 0).await;
    });
    Ok((accept_task, api_task))
}

/// A migration's connection, TLS or not.
trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

pub(crate) fn unsupported(what: &str) -> anyhow::Error {
    anyhow!("migration_unsupported: Cloud Hypervisor {what}")
}

impl CloudHypervisorInner {
    pub(crate) fn set_incoming(&mut self, incoming: Option<MigrateIn>) {
        self.incoming = incoming;
    }

    pub(crate) fn transfer_active(&self) -> bool {
        self.transfer
            .as_ref()
            .map(|transfer| progress(transfer).status == "active")
            .unwrap_or(false)
    }

    /// The VM was sent away: the VMM ended itself with it.
    pub(crate) fn vm_left(&self) -> bool {
        self.incoming.is_none()
            && self
                .transfer
                .as_ref()
                .map(|transfer| progress(transfer).status == "completed")
                .unwrap_or(false)
    }

    pub(crate) async fn migration_send(
        &mut self,
        uri: &str,
        params: &MigrationParams,
    ) -> Result<()> {
        if self.state != VmmState::VmRunning {
            return Err(anyhow!("migration_invalid: the VM does not run"));
        }
        if self.transfer_active() {
            return Err(anyhow!("migration_invalid: a migration is under way"));
        }
        if !params.copy.is_empty() {
            return Err(anyhow!(
                "migration_unsupported: Cloud Hypervisor copies no block device; only a Cinder root migrates under it"
            ));
        }
        if params.downtime_ms != 0 {
            info!(
                sl!(),
                "Cloud Hypervisor takes no downtime limit; {} ms is not applied",
                params.downtime_ms
            );
        }
        let transfer = new_transfer();
        let (bridge, api) = send(
            &self.id,
            get_api_socket_path(&self.id)?,
            uri,
            transfer.clone(),
            params.max_bandwidth,
            params.tls,
        )
        .await?;
        self.bridge = Some(bridge.abort_handle());
        self.migration_tasks.push(bridge);
        self.migration_tasks.push(api);
        self.transfer = Some(transfer);
        Ok(())
    }

    pub(crate) fn migration_progress(&self) -> Result<MigrationProgress> {
        Ok(match &self.transfer {
            Some(transfer) => progress(transfer),
            None => MigrationProgress {
                status: "none".to_string(),
                ..Default::default()
            },
        })
    }

    /// Drop the bridge: the VMM reads a failed transfer and resumes its VM.
    pub(crate) fn migration_cancel(&mut self) -> Result<()> {
        let transfer = self
            .transfer
            .as_ref()
            .context("migration_invalid: no migration is under way")?;
        {
            let mut state = transfer.lock().unwrap_or_else(|e| e.into_inner());
            if state.status != "active" {
                return Err(anyhow!("migration_invalid: the transfer ended"));
            }
            if state.complete_acknowledged {
                return Err(anyhow!(
                    "migration_invalid: the destination took the VM already"
                ));
            }
            state.cancel_requested = true;
        }
        if let Some(bridge) = self.bridge.take() {
            bridge.abort();
        }
        Ok(())
    }

    pub(crate) async fn migration_receive(&mut self) -> Result<()> {
        let incoming = self
            .incoming
            .clone()
            .context("migration_invalid: this VM does not receive a migration")?;
        if self.state != VmmState::VmmServerReady {
            return Err(anyhow!("migration_invalid: the VMM is not started"));
        }
        if !incoming.copied_indexes().is_empty() {
            return Err(anyhow!(
                "migration_unsupported: Cloud Hypervisor exports no block device for a copy"
            ));
        }
        if self.transfer.is_some() {
            return Ok(());
        }
        let transfer = new_transfer();
        let (accept, api) = receive(
            &self.id,
            get_api_socket_path(&self.id)?,
            &incoming.uri,
            transfer.clone(),
            incoming.tls,
        )
        .await?;
        self.migration_tasks.push(accept);
        self.migration_tasks.push(api);
        self.transfer = Some(transfer);
        Ok(())
    }

    /// The VMM carries its own configuration to the destination, taps by
    /// name included: no pins.
    pub(crate) fn migration_networks(&self) -> Result<Vec<NetworkPin>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(word: u16, length: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER];
        bytes[..2].copy_from_slice(&word.to_le_bytes());
        bytes[8..].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    #[test]
    fn the_acknowledged_complete_is_seen_across_split_reads() {
        let transfer = new_transfer();
        let mut requests = Frames::default();
        let mut responses = Frames::default();
        // Config with a payload, answered Ok; Complete, answered Ok.
        let mut config = frame(2, 5);
        config.extend_from_slice(b"hello");
        requests.feed(&config[..7], true, &transfer);
        requests.feed(&config[7..], true, &transfer);
        responses.feed(&frame(STATUS_OK, 0), false, &transfer);
        assert!(!transfer.lock().unwrap().complete_acknowledged);
        requests.feed(&frame(COMMAND_COMPLETE, 0), true, &transfer);
        let ok = frame(STATUS_OK, 0);
        responses.feed(&ok[..3], false, &transfer);
        assert!(!transfer.lock().unwrap().complete_acknowledged);
        responses.feed(&ok[3..], false, &transfer);
        assert!(transfer.lock().unwrap().complete_acknowledged);
    }

    #[test]
    fn an_error_to_complete_is_not_an_acknowledgement() {
        let transfer = new_transfer();
        let mut requests = Frames::default();
        let mut responses = Frames::default();
        requests.feed(&frame(COMMAND_COMPLETE, 0), true, &transfer);
        responses.feed(&frame(2, 0), false, &transfer);
        assert!(!transfer.lock().unwrap().complete_acknowledged);
    }

    #[test]
    fn progress_reads_the_state() {
        let transfer = new_transfer();
        assert_eq!(progress(&transfer).status, "active");
        set_status(&transfer, "failed", "x".into());
        set_status(&transfer, "completed", String::new());
        let read = progress(&transfer);
        assert_eq!((read.status.as_str(), read.error.as_str()), ("failed", "x"));
    }
}
