// Copyright 2026 OpenStack Nova Kata contributors
//
// SPDX-License-Identifier: Apache-2.0

// Nova Kata (openstack-nova-kata ADR-032): a running container's root, a
// block device whose host device its owner grew, is shown the new size and
// its filesystem grown in the guest by the agent.

use anyhow::{bail, Context, Result};
use common::types::UpdateRequest;
use serde::Deserialize;

pub const ROOT_GROW_KEY: &str = "io.katacontainers.rootfs-update.v1";

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RootGrowth {
    pub request_id: String,
    pub requested_bytes: u64,
}

pub fn parse(req: &UpdateRequest) -> Result<Option<RootGrowth>> {
    let Some(text) = req.annotations.get(ROOT_GROW_KEY) else {
        return Ok(None);
    };
    if req
        .annotations
        .keys()
        .any(|k| k.starts_with("io.katacontainers.") && k != ROOT_GROW_KEY)
        || (!req.value.is_empty() && req.value != b"{}")
        || text.len() > 1024
    {
        bail!("rootfs_update_invalid: mixed or oversized root growth request");
    }
    let value: RootGrowth =
        serde_json::from_str(text).context("rootfs_update_invalid: root growth")?;
    let id = uuid::Uuid::parse_str(&value.request_id)
        .context("rootfs_update_invalid: root growth ID")?;
    if id.to_string() != value.request_id
        || value.requested_bytes == 0
        || value.requested_bytes > i64::MAX as u64
        || value.requested_bytes % 512 != 0
    {
        bail!("rootfs_update_invalid: root growth identity or capacity");
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn request(text: &str) -> UpdateRequest {
        UpdateRequest {
            container_id: "c".into(),
            value: vec![],
            annotations: HashMap::from([(ROOT_GROW_KEY.to_string(), text.to_string())]),
        }
    }

    #[test]
    fn nova_root_growth_parses_one_aligned_request() {
        let id = "6f0b7a52-6b3e-4f2b-9b1a-6f2b3c4d5e6f";
        let text = format!(r#"{{"request_id":"{id}","requested_bytes":2147483648}}"#);
        assert_eq!(
            parse(&request(&text)).unwrap(),
            Some(RootGrowth {
                request_id: id.into(),
                requested_bytes: 2 << 30
            })
        );
        let empty = UpdateRequest {
            container_id: "c".into(),
            value: vec![],
            annotations: HashMap::new(),
        };
        assert_eq!(parse(&empty).unwrap(), None);
    }

    #[test]
    fn nova_root_growth_refuses_bad_requests() {
        let id = "6f0b7a52-6b3e-4f2b-9b1a-6f2b3c4d5e6f";
        for text in [
            format!(r#"{{"request_id":"{id}","requested_bytes":0}}"#),
            format!(r#"{{"request_id":"{id}","requested_bytes":1000}}"#),
            r#"{"request_id":"not-a-uuid","requested_bytes":512}"#.to_string(),
            format!(r#"{{"request_id":"{id}","requested_bytes":512,"extra":1}}"#),
        ] {
            assert!(parse(&request(&text)).is_err(), "{text}");
        }
        let mut mixed = request(&format!(r#"{{"request_id":"{id}","requested_bytes":512}}"#));
        mixed
            .annotations
            .insert("io.katacontainers.volume-update.v2".into(), "{}".into());
        assert!(parse(&mixed).is_err());
    }
}
