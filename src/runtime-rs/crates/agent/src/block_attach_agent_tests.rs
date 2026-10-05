// SPDX-License-Identifier: Apache-2.0
use crate::{Agent, AttachBlockDeviceRequest, kata::KataAgent, types::Device};
use protocols::{agent as proto, agent_ttrpc_async as rpc, empty::Empty};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use ttrpc::asynchronous::{Client, Server, TtrpcContext};

#[derive(Default)]
struct Capture {
    requests: Mutex<Vec<proto::AttachBlockDeviceRequest>>,
    detaches: Mutex<Vec<proto::DetachBlockDeviceRequest>>,
    fail: AtomicBool,
}

#[async_trait::async_trait]
impl rpc::AgentService for Capture {
    async fn detach_block_device(&self, _: &TtrpcContext,
        request: proto::DetachBlockDeviceRequest) -> ttrpc::Result<Empty> {
        self.detaches.lock().unwrap().push(request);
        if self.fail.load(Ordering::SeqCst) {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::FAILED_PRECONDITION, "injected detach refusal".to_owned())));
        }
        Ok(Empty::new())
    }
    async fn get_guest_details(&self, _: &TtrpcContext,
        _: proto::GuestDetailsRequest) -> ttrpc::Result<proto::GuestDetailsResponse> {
        Ok(proto::GuestDetailsResponse {
            agent_details: protobuf::MessageField::some(proto::AgentDetails {
                extra_features: vec!["block-device-attach-v1".into()], ..Default::default()
            }), ..Default::default()
        })
    }
    async fn attach_block_device(&self, _: &TtrpcContext,
        request: proto::AttachBlockDeviceRequest) -> ttrpc::Result<Empty> {
        self.requests.lock().unwrap().push(request);
        if self.fail.load(Ordering::SeqCst) {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::FAILED_PRECONDITION, "injected attach refusal".to_owned())));
        }
        Ok(Empty::new())
    }
}

struct Unsupported;
#[test]
fn nova_block_attach_detach_refusal_requires_exact_status_and_message() {
    use crate::types::{block_detach_refusal, BlockDetachRefusal};
    for (code, message, expected) in [
        (ttrpc::Code::FAILED_PRECONDITION, "block_detach_busy", Some(BlockDetachRefusal::Busy)),
        (ttrpc::Code::UNAVAILABLE, "block_detach_freeze_pending", Some(BlockDetachRefusal::FreezePending)),
        (ttrpc::Code::INTERNAL, "block_detach_busy", None),
        (ttrpc::Code::FAILED_PRECONDITION, "unclassified failure", None),
        (ttrpc::Code::UNAVAILABLE, "transport unavailable", None),
        (ttrpc::Code::FAILED_PRECONDITION, "block_detach_freeze_pending", None),
    ] {
        let error = anyhow::Error::new(ttrpc::Error::RpcStatus(ttrpc::get_status(code, message)))
            .context("RPC context");
        assert_eq!(block_detach_refusal(&error), expected);
    }
    assert_eq!(block_detach_refusal(&anyhow::anyhow!("block_detach_busy")), None);
}

#[async_trait::async_trait]
impl rpc::AgentService for Unsupported {}

fn request() -> AttachBlockDeviceRequest {
    AttachBlockDeviceRequest {
        container_id: "nova-transport-probe".into(),
        request_id: "generation-1-attachment-1".into(),
        device: Device { id: "0:1".into(), field_type: "scsi".into(),
            container_path: "/dev/sdc".into(), ..Default::default() },
    }
}

fn detach_request(phase: &str) -> crate::DetachBlockDeviceRequest {
    crate::DetachBlockDeviceRequest {
        container_id: "nova-transport-probe".into(), request_id: "detach-1".into(),
        attach_request_id: "generation-1-attachment-1".into(), phase: phase.into(),
    }
}

fn status(error: anyhow::Error) -> ttrpc::Code {
    match error.downcast::<ttrpc::Error>().unwrap() {
        ttrpc::Error::RpcStatus(status) => status.code(),
        other => panic!("unexpected transport error: {:?}", other),
    }
}

async fn client(address: &str) -> KataAgent {
    let mut config = kata_types::config::Agent::default();
    config.request_timeout_ms = 2000;
    let agent = KataAgent::new(config);
    let connection = Client::connect(address).await.unwrap();
    agent.inner.write().await.client = Some(connection);
    agent
}

#[tokio::test]
async fn nova_block_attach_native_client_transport() {
    use std::os::unix::fs::DirBuilderExt;
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("kata-block-{}-{}", std::process::id(), unique));
    std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let address = format!("unix://{}", root.join("agent.sock").display());
    let capture = Arc::new(Capture::default());
    let mut server = Server::new().bind(&address).unwrap()
        .register_service(rpc::create_agent_service(capture.clone()));
    server.start().await.unwrap();
    let agent = client(&address).await;
    let details = agent.get_guest_details(crate::GetGuestDetailsRequest::default()).await.unwrap();
    assert_eq!(details.agent_details.unwrap().extra_features, vec!["block-device-attach-v1"]);
    assert!(agent.attach_block_device(request()).await.is_ok());
    for phase in ["prepare", "complete"] {
        assert!(agent.detach_block_device(detach_request(phase)).await.is_ok());
    }
    capture.fail.store(true, Ordering::SeqCst);
    assert_eq!(status(agent.detach_block_device(detach_request("prepare")).await.err().unwrap()),
               ttrpc::Code::FAILED_PRECONDITION);
    {
        let calls = capture.detaches.lock().unwrap();
        assert_eq!(calls.len(), 3);
        for (call, phase) in calls.iter().zip(["prepare", "complete", "prepare"]) {
            assert_eq!(call.container_id, "nova-transport-probe");
            assert_eq!(call.request_id, "detach-1");
            assert_eq!(call.attach_request_id, "generation-1-attachment-1");
            assert_eq!(call.phase, phase);
        }
    }
    assert_eq!(status(agent.attach_block_device(request()).await.err().unwrap()),
               ttrpc::Code::FAILED_PRECONDITION);
    {
        let calls = capture.requests.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for call in calls.iter() {
            assert_eq!(call.container_id, "nova-transport-probe");
            assert_eq!(call.request_id, "generation-1-attachment-1");
            let device = call.device.as_ref().unwrap();
            assert_eq!(device.id, "0:1");
            assert_eq!(device.type_, "scsi");
            assert_eq!(device.container_path, "/dev/sdc");
            assert!(device.vm_path.is_empty() && device.options.is_empty());
        }
    }
    server.shutdown().await.unwrap();
    drop(agent);

    let address = format!("unix://{}", root.join("unsupported.sock").display());
    let mut server = Server::new().bind(&address).unwrap()
        .register_service(rpc::create_agent_service(Arc::new(Unsupported)));
    server.start().await.unwrap();
    let agent = client(&address).await;
    assert_eq!(status(agent.attach_block_device(request()).await.err().unwrap()),
               ttrpc::Code::NOT_FOUND); // generated default handler reports unsupported
    assert_eq!(status(agent.detach_block_device(detach_request("prepare")).await.err().unwrap()),
               ttrpc::Code::NOT_FOUND);
    server.shutdown().await.unwrap();
    drop(agent);
    // Only this freshly created, joined-server fixture directory is removed.
    std::fs::remove_dir_all(root).unwrap();
}
