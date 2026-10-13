// SPDX-License-Identifier: Apache-2.0
//
// Nova Kata (ADR-052, revision of 2026-10-14): TLS of a live migration's
// connections, as libvirt's `live_migration_with_native_tls`.
//
// The certificates are libvirt's, in libvirt's default directory and by its
// file names: one CA, and on every host a server certificate (the host as a
// destination) and a client certificate (the host as a source). QEMU reads
// them itself (`tls-creds-x509`); the shim reads them for the connections it
// carries itself: Cloud Hypervisor's, which has no TLS, and the word that a
// block copy's last blocks are written. Both ends verify the other: the
// client the server's name (the address it connects to), the server that the
// client's certificate is of the CA.

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
/// The id of QEMU's credentials object of a migration.
pub const QEMU_TLS_CREDS: &str = "nova-migration-tls";

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
