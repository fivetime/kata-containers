// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::collections::HashMap;

const CONTAINER: &str = "nova-30d36e7b-5684-4f7a-90c4-69ed3b5f6b31";
const PORT: &str = "dc065497-3c8f-4f3f-bdb6-1f9f784f7c21";

fn body(changes: &[(&str, serde_json::Value)]) -> String {
    let mut value = serde_json::json!({
        "action": "attach",
        "generation": "50231917-1da2-45ce-86af-f15c1b99e9bb",
        "request_id": "0b0f6c1e-6a5f-5e0a-9d51-0c8f1d1b7a11",
        "port_id": PORT,
        "interface": "nkdc0654973c8f4",
        "mac": "fa:16:3e:11:22:33",
        "mtu": 1450,
    });
    for (key, change) in changes {
        if change.is_null() {
            value.as_object_mut().unwrap().remove(*key);
        } else {
            value[*key] = change.clone();
        }
    }
    value.to_string()
}

fn request(annotations: &[(&str, String)], value: &[u8], container: &str) -> UpdateRequest {
    UpdateRequest {
        container_id: container.to_owned(),
        value: value.to_vec(),
        annotations: annotations
            .iter()
            .map(|(key, text)| (key.to_string(), text.clone()))
            .collect::<HashMap<_, _>>(),
    }
}

fn announced(changes: &[(&str, serde_json::Value)]) -> Result<Option<NetworkUpdate>> {
    parse(&request(&[(UPDATE_KEY, body(changes))], b"{}", CONTAINER))
}

#[test]
fn nova_live_network_an_update_without_the_annotation_is_no_interface_update() {
    assert!(parse(&request(&[], b"{}", CONTAINER)).unwrap().is_none());
    let other = request(
        &[("io.katacontainers.volume-update.v1", "{}".to_owned())],
        b"{}",
        CONTAINER,
    );
    assert!(parse(&other).unwrap().is_none());
}

#[test]
fn nova_live_network_an_attach_and_a_detach_are_read() {
    let attach = announced(&[]).unwrap().unwrap();
    assert!(attach.attaches());
    let endpoint = EndpointUpdate {
        port_id: PORT.to_owned(),
        interface: "nkdc0654973c8f4".to_owned(),
        mac: "fa:16:3e:11:22:33".to_owned(),
        mtu: 1450,
    };
    assert_eq!(attach.endpoint(), Some(endpoint.clone()));
    assert_eq!(
        endpoint.alias("attached"),
        format!("nova-kata-net:{PORT}:attached")
    );
    let refresh = parse(&request(
        &[(
            UPDATE_KEY,
            serde_json::json!({"action": "refresh", "generation": "g",
                "request_id": "0b0f6c1e-6a5f-5e0a-9d51-0c8f1d1b7a11"})
            .to_string(),
        )],
        b"{}",
        CONTAINER,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(refresh.endpoint(), None);
    assert!(!refresh.attaches());
    let detach = announced(&[("action", "detach".into())]).unwrap().unwrap();
    assert!(!detach.attaches());
    // An update that names no resource has an empty value as well.
    assert!(parse(&request(&[(UPDATE_KEY, body(&[]))], b"", CONTAINER))
        .unwrap()
        .is_some());
}

#[test]
fn nova_live_network_what_is_not_one_whole_request_is_refused() {
    for (name, changes) in [
        ("an operation of the future", vec![("action", "replace".into())]),
        ("no operation", vec![("action", serde_json::Value::Null)]),
        ("no generation", vec![("generation", "".into())]),
        ("a generation without end", vec![("generation", "g".repeat(129).into())]),
        ("no request", vec![("request_id", "request".into())]),
        ("a request in capitals", vec![("request_id", "0B0F6C1E-6A5F-5E0A-9D51-0C8F1D1B7A11".into())]),
        ("no port", vec![("port_id", "port".into())]),
        ("a port that is not named", vec![("port_id", serde_json::Value::Null)]),
        ("an MTU that is not named", vec![("mtu", serde_json::Value::Null)]),
        ("a refresh of an interface", vec![("action", "refresh".into())]),
        ("an interface of another port", vec![("interface", "nkcb68e1a3fdd24".into())]),
        ("an interface of the host", vec![("interface", "eth0".into())]),
        ("a path", vec![("interface", "../nkdc0654973c8".into())]),
        ("a MAC in capitals", vec![("mac", "FA:16:3E:11:22:33".into())]),
        ("a MAC without colons", vec![("mac", "fa163e112233".into())]),
        ("a small MTU", vec![("mtu", 575.into())]),
        ("a large MTU", vec![("mtu", 65536.into())]),
        ("an MTU that is text", vec![("mtu", "1450".into())]),
        ("a field of the future", vec![("namespace", "/run/netns/other".into())]),
    ] {
        let error = announced(&changes).expect_err(name).to_string();
        assert!(error.starts_with("network_update_"), "{name}: {error}");
    }
    for (name, update) in [
        ("a resource update with it", request(&[(UPDATE_KEY, body(&[]))], b"{\"cpu\":{}}", CONTAINER)),
        ("a volume update with it", request(&[(UPDATE_KEY, body(&[])),
            ("io.katacontainers.volume-update.v1", "{}".to_owned())], b"{}", CONTAINER)),
        ("a protocol of the future", request(
            &[("io.katacontainers.network-update.v2", body(&[]))], b"{}", CONTAINER)),
        ("two protocols", request(&[(UPDATE_KEY, body(&[])),
            ("io.katacontainers.network-update.v2", body(&[]))], b"{}", CONTAINER)),
        ("a container that is no instance", request(&[(UPDATE_KEY, body(&[]))], b"{}", "pause")),
        ("a request without end", request(
            &[(UPDATE_KEY, format!("{}{}", body(&[]), " ".repeat(4096)))], b"{}", CONTAINER)),
        ("no request at all", request(&[(UPDATE_KEY, "".to_owned())], b"{}", CONTAINER)),
    ] {
        let error = parse(&update).expect_err(name).to_string();
        assert!(error.starts_with("network_update_"), "{name}: {error}");
    }
}

#[test]
fn nova_live_network_a_request_is_of_the_running_generation() {
    let update = announced(&[]).unwrap().unwrap();
    let mut spec = oci_spec::runtime::Spec::default();
    assert!(validate_generation(&update, &spec).is_err());
    spec.set_annotations(Some(HashMap::from([(
        GENERATION_KEY.to_owned(),
        "another".to_owned(),
    )])));
    assert!(validate_generation(&update, &spec).is_err());
    spec.set_annotations(Some(HashMap::from([(
        GENERATION_KEY.to_owned(),
        update.generation.clone(),
    )])));
    assert!(validate_generation(&update, &spec).is_ok());
}

#[test]
fn nova_live_network_the_resource_route_never_takes_an_interface_update() {
    let update = request(&[(UPDATE_KEY, body(&[]))], b"{}", CONTAINER);
    let error = update.ensure_resource_only().unwrap_err().to_string();
    assert!(error.starts_with("network_update_unsupported"), "{error}");
    assert!(request(&[], b"{}", CONTAINER).ensure_resource_only().is_ok());
}

#[test]
fn nova_live_network_the_resource_route_takes_no_update_it_does_not_know() {
    for key in [
        "io.katacontainers.memory-update.v1",
        "io.katacontainers.share-update.v2",
        "io.katacontainers.-update.",
    ] {
        let update = request(&[(key, "{}".to_owned())], b"{}", CONTAINER);
        let error = update.ensure_resource_only().unwrap_err().to_string();
        assert!(error.starts_with("device_update_unsupported"), "{key}: {error}");
    }
    // What is no announcement of an update is an annotation like any other.
    for key in [
        "io.katacontainers.config.hypervisor.default_memory",
        "io.katacontainers.update.v1",
        "io.katacontainers.memory-update",
        "io.kubernetes.memory-update.v1",
        "io.katacontainers.pkg.oci.bundle_path",
    ] {
        let update = request(&[(key, "{}".to_owned())], b"{}", CONTAINER);
        assert!(update.ensure_resource_only().is_ok(), "{key}");
    }
}
