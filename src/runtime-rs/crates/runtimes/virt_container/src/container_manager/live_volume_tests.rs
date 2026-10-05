use super::*;
use std::collections::HashMap;

fn initial_spec() -> (String, oci_spec::runtime::Spec) {
    use super::super::live_volume_created::INITIAL_KEY;
    let req = update();
    let body: serde_json::Value = serde_json::from_str(&req.annotations[UPDATE_KEY]).unwrap();
    let spec = serde_json::from_value(serde_json::json!({"ociVersion":"1.0.2",
        "annotations":{GENERATION_KEY:body["generation"], INITIAL_KEY:serde_json::to_string(&vec![body.clone()]).unwrap()},
        "mounts":[{"type":"directvol", "source":body["source"],"destination":body["destination"],"options":["rbind","rw"]}],
        "linux":{"devices":[]}})).unwrap();
    (req.container_id, spec)
}

#[test]
fn nova_live_volume_initial_requires_explicit_matching_creation_spec() {
    use super::super::live_volume_created::{parse_initial, INITIAL_KEY, CREATED_KEY};
    let (id, spec) = initial_spec();
    assert_eq!(parse_initial(&id, &spec).unwrap().len(), 1);
    let mut absent = spec.clone();
    absent.annotations_mut().as_mut().unwrap().remove(INITIAL_KEY);
    assert!(parse_initial(&id, &absent).unwrap().is_empty());
    for value in ["null", "{}", "[{}]", "not-json"] {
        let mut bad = spec.clone();
        bad.annotations_mut().as_mut().unwrap().insert(INITIAL_KEY.into(), value.into());
        assert!(parse_initial(&id, &bad).is_err());
    }
    let body: serde_json::Value = serde_json::from_str(&update().annotations[UPDATE_KEY]).unwrap();
    let mut duplicate = spec.clone();
    duplicate.annotations_mut().as_mut().unwrap().insert(INITIAL_KEY.into(),
        serde_json::to_string(&vec![body.clone(), body]).unwrap());
    assert!(parse_initial(&id, &duplicate).is_err());
    let mut absent_mount = spec.clone();
    absent_mount.set_mounts(Some(vec![]));
    assert!(parse_initial(&id, &absent_mount).is_err());
    let mut readonly = spec.clone();
    readonly.mounts_mut().as_mut().unwrap()[0].set_options(Some(vec!["rbind".into(), "ro".into()]));
    assert!(parse_initial(&id, &readonly).is_err());
    for key in [GENERATION_KEY, CREATED_KEY, "io.katacontainers.volume-initial.v2"] {
        let mut bad = spec.clone();
        bad.annotations_mut().as_mut().unwrap().insert(key.into(), "[]".into());
        assert!(parse_initial(&id, &bad).is_err());
    }
}

struct InitialTestVolume { destination: String, driver: String }
#[async_trait::async_trait]
impl resource::volume::Volume for InitialTestVolume {
    fn get_volume_mount(&self) -> Result<Vec<oci_spec::runtime::Mount>> {
        let mut mount = oci_spec::runtime::Mount::default();
        mount.set_destination(self.destination.clone().into());
        Ok(vec![mount])
    }
    fn get_storage(&self) -> Result<Vec<agent::Storage>> {
        Ok(vec![agent::Storage { driver: self.driver.clone(), source: "1:2".into(), fs_type:"bind".into(), ..Default::default() }])
    }
    fn get_device_id(&self) -> Result<Option<String>> { Ok(Some("native-device".into())) }
    async fn cleanup(&self, _: &tokio::sync::RwLock<hypervisor::device::device_manager::DeviceManager>) -> Result<()> {
        panic!("creation binding must not remove a device")
    }
}

fn initial_record() -> PendingVolume {
    PendingVolume { request: parse(&update()).unwrap().unwrap(), metadata_identity: serde_json::json!(
        {"metadata":{"openstack.device_number":"252:7"}}), volume: None, device: None, detach: None, created: true }
}

#[test]
fn nova_live_volume_paused_verification_requires_original_complete_creation() {
    let mut details = agent::GuestDetailsResponse::default();
    details.agent_details = Some(agent::types::AgentDetails::default());
    let mut prior = initial_record();
    let request = prior.request.clone();
    prior.device = Some(agent::types::Device::default());
    prior.volume = Some(std::sync::Arc::new(InitialTestVolume{destination:"/dev/sdc".into(),driver:"scsi".into()}));
    assert!(validate_paused_verification(Some(&prior), &request, &details).is_err());
    details.agent_details.as_mut().unwrap().extra_features.push(PAUSED_VERIFY_FEATURE.into());
    validate_paused_verification(Some(&prior), &request, &details).unwrap();
    assert!(validate_paused_verification(None, &request, &details).is_err());
    prior.created=false;
    assert!(validate_paused_verification(Some(&prior), &request, &details).is_err());
    prior.created=true;
    let mut changed=request.clone(); changed.request_id="other".into();
    assert!(validate_paused_verification(Some(&prior), &changed, &details).is_err());
    prior.device=None;
    assert!(validate_paused_verification(Some(&prior), &request, &details).is_err());
}

#[test]
fn nova_live_volume_initial_binds_original_native_volume_and_agent_device() {
    use super::super::live_volume_created::{bind_initial, CREATED_KEY};
    let original: Arc<dyn resource::volume::Volume> = Arc::new(InitialTestVolume {
        destination:"/dev/sdc".into(), driver:"scsi".into() });
    let bound = bind_initial(vec![initial_record()], &[original.clone()]).unwrap();
    assert!(bound.destinations.contains("/dev/sdc"));
    let (_, mut spec) = initial_spec();
    let mut devices = vec![];
    let mut registry = HashMap::new();
    bound.apply(&mut spec, &mut devices, &mut registry).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].container_path, "/dev/sdc");
    assert_eq!(devices[0].field_type, "scsi");
    assert_eq!(devices[0].id, "1:2");
    let node = &spec.linux().as_ref().unwrap().devices().as_ref().unwrap()[0];
    assert_eq!((node.major(), node.minor()), (252, 7));
    assert!(spec.annotations().as_ref().unwrap().contains_key(CREATED_KEY));
    let record = registry.values().next().unwrap();
    assert!(record.created);
    assert!(Arc::ptr_eq(record.volume.as_ref().unwrap(), &original));
    assert!(bind_initial(vec![initial_record()], &[]).is_err());
    assert!(bind_initial(vec![initial_record()], &[original.clone(), original]).is_err());
    let unsupported: Arc<dyn resource::volume::Volume> = Arc::new(InitialTestVolume {
        destination:"/dev/sdc".into(), driver:"nvdimm".into() });
    assert!(bind_initial(vec![initial_record()], &[unsupported]).is_err());
}

#[test]
fn nova_live_volume_initial_requires_created_guest_capability() {
    use super::super::live_volume_created::{validate_capability, CREATED_FEATURE};
    let mut details = agent::GuestDetailsResponse::default();
    details.agent_details = Some(agent::types::AgentDetails::default());
    details.agent_details.as_mut().unwrap().extra_features.push(ATTACH_FEATURE.into());
    assert!(validate_capability(&details, "virtio-scsi").is_err());
    details.agent_details.as_mut().unwrap().extra_features.push(CREATED_FEATURE.into());
    validate_capability(&details, "virtio-scsi").unwrap();
    assert!(validate_capability(&details, "nvdimm").is_err());
}

#[test]
fn nova_live_volume_initial_preserves_distinct_host_numbers_for_agent_resolution() {
    use super::super::live_volume_created::bind_initial;
    for duplicate_number in [false, true] {
        let mut second = initial_record();
        second.request.request_id = "00000000-0000-4000-8000-000000000005".into();
        second.request.destination = "/dev/sdd".into();
        if !duplicate_number {
            second.metadata_identity["metadata"]["openstack.device_number"] = "252:8".into();
        }
        let native: Vec<Arc<dyn resource::volume::Volume>> = ["/dev/sdc", "/dev/sdd"].iter()
            .map(|path| Arc::new(InitialTestVolume { destination:(*path).into(), driver:"scsi".into() })
                as Arc<dyn resource::volume::Volume>).collect();
        let bound = bind_initial(vec![initial_record(), second], &native).unwrap();
        let (_, mut spec) = initial_spec();
        let mut devices = vec![];
        let mut registry = HashMap::new();
        let result = bound.apply(&mut spec, &mut devices, &mut registry);
        if duplicate_number {
            assert!(result.is_err());
            assert!(devices.is_empty() && registry.is_empty());
            assert!(spec.linux().as_ref().unwrap().devices().as_ref().unwrap().is_empty());
        } else {
            result.unwrap();
            let nodes = spec.linux().as_ref().unwrap().devices().as_ref().unwrap();
            assert_eq!(nodes.len(), 2);
            assert_eq!((nodes[0].minor(), nodes[1].minor()), (7, 8));
            assert_eq!(devices.len(), 2);
        }
    }
}

#[test]
fn nova_live_volume_requires_explicit_guest_capability_before_insertion() {
    let mut details = agent::GuestDetailsResponse::default();
    assert!(validate_agent_capability(&details, "virtio-scsi").is_err());
    details.agent_details = Some(agent::types::AgentDetails::default());
    assert!(validate_agent_capability(&details, "virtio-scsi").is_err());
    details.agent_details.as_mut().unwrap().extra_features.push(ATTACH_FEATURE.into());
    validate_agent_capability(&details, "virtio-scsi").unwrap();
    validate_agent_capability(&details, "virtio-blk-pci").unwrap();
    for unsupported in ["blk", "scsi", "virtio-blk-mmio", "virtio-blk-ccw", "nvdimm", ""] {
        assert!(validate_agent_capability(&details, unsupported).is_err());
    }
}

fn update() -> UpdateRequest {
    let body = serde_json::json!({
        "action": "attach", "generation": "generation-1",
        "request_id": "00000000-0000-4000-8000-000000000001",
        "volume_uuid": "00000000-0000-4000-8000-000000000002",
        "attachment_uuid": "00000000-0000-4000-8000-000000000003",
        "source": "/openstack/nova/00000000-0000-4000-8000-000000000004/0123456789abcdef/volumes/00000000-0000-4000-8000-000000000002",
        "destination": "/dev/sdc", "readonly": false
    });
    UpdateRequest { container_id: "nova-00000000-0000-4000-8000-000000000004".into(),
        value: vec![], annotations: HashMap::from([(UPDATE_KEY.into(), body.to_string())]) }
}

#[test]
fn nova_live_volume_protocol_and_resource_separation() {
    let mut req = update();
    assert!(parse(&req).unwrap().is_some());
    req.value = b"{\"memory\":{\"limit\":1}}".to_vec();
    assert!(parse(&req).is_err());
    req.annotations.clear();
    assert!(parse(&req).unwrap().is_none());
    req.annotations.insert("io.katacontainers.volume-update.v2".into(), "{}".into());
    assert!(parse(&req).is_err());
    let mut req = update();
    req.annotations.insert("io.katacontainers.volume-update.v2".into(), "{}".into());
    assert!(parse(&req).is_err());
}

#[test]
fn nova_live_volume_rejects_wrong_identity_path_and_operation() {
    for (field, bad) in [("action", "detach"), ("destination", "/dev/sda"),
        ("destination", "/dev/null"), ("destination", "/dev/../sdc"),
        ("source", "/dev/rbd0"), ("request_id", ""), ("volume_uuid", "foreign"),
        ("unreviewed_field", "ignored")] {
        let mut req = update();
        let mut body: serde_json::Value = serde_json::from_str(&req.annotations[UPDATE_KEY]).unwrap();
        body[field] = bad.into();
        req.annotations.insert(UPDATE_KEY.into(), body.to_string());
        assert!(parse(&req).is_err(), "accepted {}={}", field, bad);
    }
    let mut req = update();
    req.container_id = "nova-00000000-0000-4000-8000-000000000005".into();
    assert!(parse(&req).is_err());
}

#[test]
fn nova_live_volume_generation_is_from_created_spec() {
    let request = parse(&update()).unwrap().unwrap();
    let mut spec = oci_spec::runtime::Spec::default();
    assert!(validate_generation(&request, &spec).is_err());
    spec.set_annotations(Some(HashMap::from([(GENERATION_KEY.into(), "older".into())])));
    assert!(validate_generation(&request, &spec).is_err());
    spec.set_annotations(Some(HashMap::from([(GENERATION_KEY.into(), request.generation.clone())])));
    validate_generation(&request, &spec).unwrap();
}

#[test]
fn nova_live_volume_detach_requires_original_request_and_exact_target() {
    let mut req = update();
    let original = parse(&req).unwrap().unwrap();
    let mut body: serde_json::Value = serde_json::from_str(&req.annotations[UPDATE_KEY]).unwrap();
    body["action"] = "detach".into();
    body["attach_request_id"] = original.request_id.clone().into();
    body["request_id"] = "00000000-0000-4000-8000-000000000006".into();
    req.annotations.insert(UPDATE_KEY.into(), body.to_string());
    let detach = parse(&req).unwrap().unwrap();
    validate_detach_target(&detach, &original).unwrap();
    for field in ["generation", "volume_uuid", "attachment_uuid", "source", "destination", "attach_request_id"] {
        let mut changed = body.clone();
        changed[field] = "foreign".into();
        let changed: BlockAttach = serde_json::from_value(changed).unwrap();
        assert!(validate_detach_target(&changed, &original).is_err(), "accepted changed {field}");
    }
    let mut changed = detach.clone();
    changed.readonly = !changed.readonly;
    assert!(validate_detach_target(&changed, &original).is_err());
    for id in ["", "foreign", "00000000-0000-4000-8000-000000000006"] {
        let mut changed = body.clone();
        changed["attach_request_id"] = id.into();
        req.annotations.insert(UPDATE_KEY.into(), changed.to_string());
        assert!(parse(&req).is_err());
    }
    body["action"] = "attach".into();
    req.annotations.insert(UPDATE_KEY.into(), body.to_string());
    assert!(parse(&req).is_err());
}

#[test]
fn nova_live_volume_metadata_fences_attachment_and_mode() {
    let request = parse(&update()).unwrap().unwrap();
    let mut info = kata_types::mount::DirectVolumeMountInfo::default();
    info.volume_type = "directvol".into();
    info.options = vec!["rw".into()];
    info.metadata = HashMap::from([
        ("openstack.generation".into(), request.generation.clone()),
        ("openstack.volume_uuid".into(), request.volume_uuid.clone()),
        ("openstack.attachment_uuid".into(), request.attachment_uuid.clone())]);
    validate_metadata(&request, &info).unwrap();
    for key in ["openstack.generation", "openstack.volume_uuid", "openstack.attachment_uuid"] {
        let mut changed = info.clone();
        changed.metadata.insert(key.into(), "foreign".into());
        assert!(validate_metadata(&request, &changed).is_err());
    }
    info.options = vec!["ro".into()];
    assert!(validate_metadata(&request, &info).is_err());
}
