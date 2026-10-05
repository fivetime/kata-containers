use super::*;
use std::collections::HashMap;

fn update() -> UpdateRequest {
    let attachment = serde_json::json!({"action":"attach", "generation":"generation-1",
        "request_id":"00000000-0000-4000-8000-000000000001",
        "volume_uuid":"00000000-0000-4000-8000-000000000002",
        "attachment_uuid":"00000000-0000-4000-8000-000000000003",
        "source":"/openstack/nova/00000000-0000-4000-8000-000000000004/0123456789abcdef/volumes/00000000-0000-4000-8000-000000000002",
        "destination":"/dev/sdc", "readonly":false});
    let body = serde_json::json!({"attachment":attachment,
        "request_id":"00000000-0000-4000-8000-000000000005", "requested_bytes":2147483648u64});
    UpdateRequest { container_id:"nova-00000000-0000-4000-8000-000000000004".into(),
        value:vec![], annotations:HashMap::from([(GROW_KEY.into(), body.to_string())]) }
}

#[test]
fn nova_live_volume_growth_protocol_refuses_mixed_and_old_routes() {
    let mut req = update();
    assert!(parse(&req).unwrap().is_some());
    assert!(super::super::live_volume::parse(&req).is_err());
    req.value = b"{\"memory\":{}}".to_vec();
    assert!(parse(&req).is_err());
    req = update(); req.annotations.insert(UPDATE_KEY.into(), "{}".into());
    assert!(parse(&req).is_err());
}

#[test]
fn nova_live_volume_growth_identity_mode_and_capacity_are_checked() {
    for (field, value) in [("requested_bytes", serde_json::json!(0)),
        ("requested_bytes", serde_json::json!(513)),
        ("requested_bytes", serde_json::json!(u64::MAX)),
        ("request_id", serde_json::json!("not-a-uuid")),
        ("unknown", serde_json::json!(true))] {
        let mut req = update();
        let mut body: serde_json::Value = serde_json::from_str(&req.annotations[GROW_KEY]).unwrap();
        body[field] = value; req.annotations.insert(GROW_KEY.into(), body.to_string());
        assert!(parse(&req).is_err());
    }
    for (field, value) in [("readonly", serde_json::json!(true)),
        ("destination", serde_json::json!("/dev/sda")),
        ("action", serde_json::json!("detach"))] {
        let mut req = update();
        let mut body: serde_json::Value = serde_json::from_str(&req.annotations[GROW_KEY]).unwrap();
        body["attachment"][field] = value; req.annotations.insert(GROW_KEY.into(), body.to_string());
        assert!(parse(&req).is_err());
    }
}

#[test]
fn nova_live_volume_growth_retry_retains_exact_identity_and_monotonic_size() {
    let request = parse(&update()).unwrap().unwrap();
    let mut history = HashMap::from([(request.request_id.clone(), PendingGrowth {
        request:request.clone(), complete:false })]);
    validate_history(&request, &history).unwrap();
    let mut changed = request.clone(); changed.requested_bytes += 512;
    assert!(validate_history(&changed, &history).is_err());
    changed.request_id = "00000000-0000-4000-8000-000000000006".into();
    assert!(validate_history(&changed, &history).is_err());
    history.get_mut(&request.request_id).unwrap().complete = true;
    validate_history(&changed, &history).unwrap();
    changed.requested_bytes = 512;
    assert!(validate_history(&changed, &history).is_err());
}
