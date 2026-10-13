// SPDX-License-Identifier: Apache-2.0
//
// Nova Kata (ADR-052, revision of 2026-10-14): TLS of a live migration's
// connections, as libvirt's `live_migration_with_native_tls`.
//
// The certificates are libvirt's, in libvirt's default directory and by its
// file names: one CA, and on every host a server certificate (the host as a
// destination) and a client certificate (the host as a source). The shim
// ends the TLS of every connection: neither VMM has it (Cloud Hypervisor has
// none, and Kata's static QEMU is built without GnuTLS), so the VMM speaks
// over a unix connection of the host that the shim carries to the TLS one.
// Both ends verify the other: the client the server's name (the address it
// connects to), the server that the client's certificate is of the CA.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// libvirt's default (qemu.conf `default_tls_x509_cert_dir`).
pub const TLS_DIR: &str = "/etc/pki/qemu";

const CA: &str = "ca-cert.pem";
const SERVER_CERT: &str = "server-cert.pem";
const SERVER_KEY: &str = "server-key.pem";
const CLIENT_CERT: &str = "client-cert.pem";
const CLIENT_KEY: &str = "client-key.pem";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn certificates(dir: &Path, name: &str) -> Result<Vec<CertificateDer<'static>>> {
    let path = dir.join(name);
    let certs = CertificateDer::pem_file_iter(&path)
        .with_context(|| format!("migration_tls: read {}", path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("migration_tls: parse {}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("migration_tls: no certificate in {}", path.display()));
    }
    Ok(certs)
}

fn key(dir: &Path, name: &str) -> Result<PrivateKeyDer<'static>> {
    let path = dir.join(name);
    PrivateKeyDer::from_pem_file(&path)
        .with_context(|| format!("migration_tls: read the key {}", path.display()))
}

fn roots(dir: &Path) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(dir, CA)? {
        roots
            .add(cert)
            .context("migration_tls: the CA certificate")?;
    }
    Ok(roots)
}

/// The destination's: its server certificate, and only clients of the CA.
pub fn server_config(dir: &Path) -> Result<Arc<ServerConfig>> {
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots(dir)?), provider())
        .build()
        .context("migration_tls: the client verifier")?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("migration_tls: the protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(dir, SERVER_CERT)?, key(dir, SERVER_KEY)?)
        .context("migration_tls: the server certificate")?;
    Ok(Arc::new(config))
}

/// The source's: the CA's servers only, and its client certificate.
pub fn client_config(dir: &Path) -> Result<Arc<ClientConfig>> {
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("migration_tls: the protocol versions")?
        .with_root_certificates(roots(dir)?)
        .with_client_auth_cert(certificates(dir, CLIENT_CERT)?, key(dir, CLIENT_KEY)?)
        .context("migration_tls: the client certificate")?;
    Ok(Arc::new(config))
}

/// The name the destination's certificate must carry: the address the
/// source connects to (an IP address SAN), as QEMU's `tls-hostname`.
pub fn server_name(address: IpAddr) -> ServerName<'static> {
    ServerName::IpAddress(address.into())
}

/// Every file the migration's TLS needs, there and readable: refused
/// before anything else when one is not.
pub fn check(dir: &Path) -> Result<()> {
    server_config(dir)?;
    client_config(dir)?;
    Ok(())
}

/// A blocking client over a connected stream: the word of a block copy's
/// end, which the source's QEMU thread sends.
pub fn connect_blocking(
    stream: std::net::TcpStream,
    address: IpAddr,
    dir: &Path,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>> {
    let connection = rustls::ClientConnection::new(client_config(dir)?, server_name(address))
        .context("migration_tls: the client connection")?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    // The handshake now, so that its failure is the connect's, not the
    // first write's.
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .context("migration_tls: the handshake")?;
    }
    Ok(tls)
}

/// The runtime that carries the VMM's connections to their TLS ones. It is
/// the shim's own no more: the shim waits on QEMU synchronously (QMP), and
/// QEMU on these connections (an NBD client's disconnect waits for its
/// server), so carrying them on the shim's two workers stalled until QMP's
/// read timed out.
fn carrier() -> Result<&'static tokio::runtime::Runtime> {
    static CARRIER: std::sync::OnceLock<std::result::Result<tokio::runtime::Runtime, String>> =
        std::sync::OnceLock::new();
    CARRIER
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("migration-tls")
                .enable_all()
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| anyhow!("migration_failed: the TLS runtime: {error}"))
}

/// The source: connect to `address` in the host's network namespace, say
/// `preface` in plain text and make the connection TLS; the VMM gets the
/// returned end of a unix pair, which the carrier copies to the TLS
/// connection until either ends. Waits for the TLS (synchronously, as the
/// VMM's code that calls it).
pub fn connect_carried(
    address: std::net::SocketAddr,
    preface: Vec<u8>,
    timeout: std::time::Duration,
) -> Result<std::os::unix::net::UnixStream> {
    use tokio::io::AsyncWriteExt;
    let config = client_config(Path::new(TLS_DIR))?;
    let (vmm, shim) =
        std::os::unix::net::UnixStream::pair().context("migration_failed: the VMM's connection")?;
    let (made, wait) = std::sync::mpsc::channel();
    carrier()?.spawn(async move {
        let secure = async {
            let mut tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address))
                .await
                .map_err(|_| anyhow!("migration_failed: connect to {address} timed out"))?
                .with_context(|| format!("migration_failed: connect to {address}"))?;
            tcp.set_nodelay(true)
                .context("migration_failed: the connection")?;
            tcp.write_all(&preface)
                .await
                .with_context(|| format!("migration_failed: the preface to {address}"))?;
            tokio::time::timeout(
                timeout,
                tokio_rustls::TlsConnector::from(config).connect(server_name(address.ip()), tcp),
            )
            .await
            .map_err(|_| anyhow!("migration_failed: the TLS of {address} timed out"))?
            .with_context(|| format!("migration_failed: the TLS of {address}"))
        };
        let carried = match secure.await {
            Ok(secure) => unix_of(shim).map(|unix| (secure, unix)),
            Err(error) => Err(error),
        };
        match carried {
            Ok((secure, unix)) => {
                let _ = made.send(Ok(()));
                carry(secure, unix).await;
            }
            Err(error) => {
                let _ = made.send(Err(error));
            }
        }
    });
    wait.recv()
        .map_err(|_| anyhow!("migration_failed: the TLS of {address} was abandoned"))??;
    Ok(vmm)
}

/// The destination: make `tcp` TLS, of a client of the CA only, and carry
/// it to the VMM's `unix` connection. The answer says whether the TLS was
/// made; what fails it is dropped.
pub fn serve_carried(
    config: Arc<ServerConfig>,
    tcp: std::net::TcpStream,
    unix: std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
) -> Result<tokio::sync::oneshot::Receiver<Result<()>>> {
    let (made, answer) = tokio::sync::oneshot::channel();
    carrier()?.spawn(async move {
        let carried = async {
            tcp.set_nonblocking(true)
                .context("migration_failed: the connection")?;
            let tcp =
                tokio::net::TcpStream::from_std(tcp).context("migration_failed: the connection")?;
            let unix = unix_of(unix)?;
            let secure = tokio::time::timeout(
                timeout,
                tokio_rustls::TlsAcceptor::from(config).accept(tcp),
            )
            .await
            .map_err(|_| anyhow!("no TLS in time"))?
            .context("the TLS")?;
            Ok::<_, anyhow::Error>((secure, unix))
        };
        match carried.await {
            Ok((secure, unix)) => {
                let _ = made.send(Ok(()));
                carry(secure, unix).await;
            }
            Err(error) => {
                let _ = made.send(Err(error));
            }
        }
    });
    Ok(answer)
}

fn unix_of(unix: std::os::unix::net::UnixStream) -> Result<tokio::net::UnixStream> {
    unix.set_nonblocking(true)
        .context("migration_failed: the VMM's connection")?;
    tokio::net::UnixStream::from_std(unix).context("migration_failed: the VMM's connection")
}

/// Copy both ways between a TLS connection and the VMM's unix one until
/// either ends; the TLS end is closed with its close_notify.
async fn carry<S>(mut tls: S, mut unix: tokio::net::UnixStream)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut unix).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let error = check(dir.path()).unwrap_err().to_string();
        assert!(error.starts_with("migration_tls:"), "{error}");
        assert!(error.contains(CA), "{error}");
    }

    #[test]
    fn the_server_name_is_the_address() {
        let name = server_name("10.0.0.2".parse().unwrap());
        assert!(matches!(name, ServerName::IpAddress(_)));
    }
}
