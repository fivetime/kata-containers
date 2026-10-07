// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use super::{ConnectConfig, Sock, Stream};

// Nova Kata (ADR-052): the VMM answers a connect once the guest accepts
// it, within milliseconds, or refuses it at once. A connect that gets no
// answer is one the guest dropped: after a live migration the VMM's
// first host ports are those the source's connections had, and the
// guest, which still holds those connections, takes the request for one
// of them and says nothing. The attempt is given up, which has the VMM
// reset that connection in the guest, and the next takes the next port.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, PartialEq)]
pub struct HybridVsock {
    uds: String,
    port: u32,
}

impl HybridVsock {
    pub fn new(uds: &str, port: u32) -> Self {
        Self {
            uds: uds.to_string(),
            port,
        }
    }
}

#[async_trait]
impl Sock for HybridVsock {
    async fn connect(&self, config: &ConnectConfig) -> Result<Stream> {
        let mut last_err = None;
        let retry_times = 1 + (config.reconnect_timeout_ms / config.dial_timeout_ms);

        for i in 0..retry_times {
            match connect_helper(&self.uds, self.port).await {
                Ok(stream) => {
                    info!(sl!(), "hybrid vsock: connected to {:?}", self);
                    return Ok(Stream::Unix(stream));
                }
                Err(err) => {
                    trace!(
                        sl!(),
                        "hybrid vsock: failed to connect to {:?}, err {:?}, attempts {}, will retry after {} ms",
                        self,
                        err,
                        i,
                        config.dial_timeout_ms,
                    );
                    last_err = Some(err);
                    tokio::time::sleep(std::time::Duration::from_millis(config.dial_timeout_ms))
                        .await;
                    continue;
                }
            }
        }

        // Safe to unwrap the last_err, as this line will be unreachable if
        // no errors occurred.
        Err(anyhow!(
            "hybrid vsock: failed to connect to {:?}, err {:?}",
            self,
            last_err.unwrap()
        ))
    }
}

async fn connect_helper(uds: &str, port: u32) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(&uds).await.context("connect")?;
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut stream, port)).await {
        Ok(result) => result?,
        Err(_) => {
            warn!(
                sl!(),
                "hybrid vsock: no answer to the connect to port {} within {:?}; the attempt is given up",
                port,
                HANDSHAKE_TIMEOUT
            );
            return Err(anyhow!(
                "handshake error: no answer within {:?}",
                HANDSHAKE_TIMEOUT
            ));
        }
    }
    Ok(stream)
}

async fn handshake(stream: &mut UnixStream, port: u32) -> Result<()> {
    stream
        .write_all(format!("connect {port}\n").as_bytes())
        .await
        .context("write all")?;
    let mut reads = BufReader::new(stream);
    let mut response = String::new();
    reads.read_line(&mut response).await.context("read line")?;
    //info!(sl!(), "get socket resp: {}", response);
    if !response.contains("OK") {
        return Err(anyhow!(
            "handshake error: malformed response code: {:?}",
            response
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn a_connect_the_guest_never_answers_is_given_up() {
        let dir = std::env::temp_dir().join(format!("hvsock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vm.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let silent = tokio::spawn(async move {
            // The VMM accepts and forwards the connect; the guest says
            // nothing: the peer is held open until the test ends.
            let (peer, _) = listener.accept().await.unwrap();
            tokio::time::sleep(HANDSHAKE_TIMEOUT * 3).await;
            drop(peer);
        });
        let began = std::time::Instant::now();
        let error = connect_helper(path.to_str().unwrap(), 1024)
            .await
            .err()
            .expect("a silent guest fails the connect");
        assert!(error.to_string().contains("no answer"), "{:#}", error);
        assert!(began.elapsed() < HANDSHAKE_TIMEOUT * 2);
        silent.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
