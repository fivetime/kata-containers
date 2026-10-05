// SPDX-License-Identifier: Apache-2.0
//
// Nova Kata (ADR-052): what the gateway asks of the source of a live
// migration, with an annotation of a task update of the sandbox container.
// The destination is asked by the migrate-in annotation of its spec
// (hypervisor::migration). Files the shim writes are the gateway's, in its
// directory, named by the request.
use std::io::Write;
use std::path::{Component, Path};

use anyhow::{bail, Context, Result};
use common::types::UpdateRequest;
use serde::{Deserialize, Serialize};

pub const UPDATE_KEY: &str = "io.katacontainers.migration-update.v1";
pub const UPDATE_PREFIX: &str = "io.katacontainers.migration-update.";
pub const GENERATION_KEY: &str = "io.openstack.nova.generation";
pub const MIGRATION_DIR: &str = "/run/nova-kata/migration";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationUpdate {
    pub action: String,
    pub generation: String,
    pub request_id: String,
    /// manifest: where to write it; send: where to write the status.
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub downtime_ms: Option<u64>,
    #[serde(default)]
    pub max_bandwidth: Option<u64>,
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .map(|id| id.to_string() == value)
        .unwrap_or(false)
}

/// A file of the gateway's migration directory for this container:
/// `<dir>/<container id>.<anything>`, with no other component.
pub fn validate_path(container_id: &str, path: &str) -> Result<()> {
    let path = Path::new(path);
    let parent = path.parent().context("migration_invalid: path")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("migration_invalid: path")?;
    if parent != Path::new(MIGRATION_DIR)
        || path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || !name.starts_with(&format!("{container_id}."))
        || name.len() > 200
    {
        bail!("migration_invalid: the path is not the gateway's for this container");
    }
    Ok(())
}

pub fn parse(req: &UpdateRequest) -> Result<Option<MigrationUpdate>> {
    let keys: Vec<_> = req
        .annotations
        .keys()
        .filter(|key| key.starts_with(UPDATE_PREFIX))
        .collect();
    if keys.is_empty() {
        return Ok(None);
    }
    if keys.len() != 1 || keys[0] != UPDATE_KEY {
        bail!("migration_unsupported: unknown or multiple protocol versions");
    }
    if req.annotations.len() != 1 {
        bail!("migration_invalid: a migration update is alone in its request");
    }
    if !req.value.is_empty() && req.value != b"{}" {
        bail!("migration_invalid: combined resource and migration updates are unsupported");
    }
    let text = &req.annotations[UPDATE_KEY];
    if text.len() > 4096 {
        bail!("migration_invalid: request too large");
    }
    let value: MigrationUpdate = serde_json::from_str(text).context("migration_invalid")?;
    if !canonical_uuid(&value.request_id)
        || value.generation.is_empty()
        || value.generation.len() > 128
    {
        bail!("migration_invalid: identifiers");
    }
    req.container_id
        .strip_prefix("nova-")
        .filter(|id| canonical_uuid(id))
        .context("migration_invalid: instance identity")?;
    match value.action.as_str() {
        "manifest" => {
            if value.uri.is_some() || value.downtime_ms.is_some() || value.max_bandwidth.is_some()
            {
                bail!("migration_invalid: a manifest names a path only");
            }
            validate_path(&req.container_id, value.path.as_deref().unwrap_or(""))?;
        }
        "send" => {
            validate_path(&req.container_id, value.path.as_deref().unwrap_or(""))?;
            hypervisor::migration::validate_tcp_uri(value.uri.as_deref().unwrap_or(""))?;
        }
        "cancel" => {
            if value.path.is_some()
                || value.uri.is_some()
                || value.downtime_ms.is_some()
                || value.max_bandwidth.is_some()
            {
                bail!("migration_invalid: a cancel names nothing");
            }
        }
        _ => bail!("migration_unsupported: action"),
    }
    Ok(Some(value))
}

/// The generation of the update is the sandbox's own.
pub fn validate_generation(
    update: &MigrationUpdate,
    annotations: &std::collections::HashMap<String, String>,
) -> Result<()> {
    match annotations.get(GENERATION_KEY) {
        Some(generation) if *generation == update.generation => Ok(()),
        _ => bail!("migration_invalid: the generation is not the sandbox's"),
    }
}

/// Replace `path` with `value`, written whole first.
pub fn write_json<T: Serialize>(path: &str, value: &T) -> Result<()> {
    let text = serde_json::to_vec(value).context("encode")?;
    let temporary = format!("{path}.tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)
            .with_context(|| format!("open {temporary}"))?;
        file.write_all(&text).context("write")?;
        file.sync_all().context("sync")?;
    }
    std::fs::rename(&temporary, path).with_context(|| format!("rename to {path}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const CID: &str = "nova-6f0fec81-76a7-4876-b3bb-18263c85ee78";
    const REQ: &str = "5d0c5d8e-2c60-4c87-9d8f-1b1e8a1ad0b4";

    fn request(body: &str) -> UpdateRequest {
        UpdateRequest {
            container_id: CID.to_string(),
            value: vec![],
            annotations: HashMap::from([(UPDATE_KEY.to_string(), body.to_string())]),
        }
    }

    #[test]
    fn other_updates_are_not_migrations() {
        let req = UpdateRequest {
            container_id: CID.to_string(),
            value: vec![],
            annotations: HashMap::new(),
        };
        assert_eq!(parse(&req).unwrap(), None);
    }

    #[test]
    fn actions_are_read() {
        let send = format!(
            r#"{{"action":"send","generation":"g","request_id":"{REQ}",
               "path":"{MIGRATION_DIR}/{CID}.status","uri":"tcp:10.0.0.2:47000",
               "downtime_ms":300}}"#
        );
        let got = parse(&request(&send)).unwrap().unwrap();
        assert_eq!(got.action, "send");
        assert_eq!(got.downtime_ms, Some(300));
        let manifest = format!(
            r#"{{"action":"manifest","generation":"g","request_id":"{REQ}",
               "path":"{MIGRATION_DIR}/{CID}.manifest"}}"#
        );
        assert!(parse(&request(&manifest)).unwrap().is_some());
        let cancel = format!(r#"{{"action":"cancel","generation":"g","request_id":"{REQ}"}}"#);
        assert!(parse(&request(&cancel)).unwrap().is_some());
    }

    #[test]
    fn malformed_updates_are_refused() {
        for body in [
            format!(r#"{{"action":"resume","generation":"g","request_id":"{REQ}"}}"#),
            format!(r#"{{"action":"cancel","generation":"","request_id":"{REQ}"}}"#),
            r#"{"action":"cancel","generation":"g","request_id":"x"}"#.to_string(),
            format!(r#"{{"action":"cancel","generation":"g","request_id":"{REQ}","path":"/x"}}"#),
            format!(
                r#"{{"action":"send","generation":"g","request_id":"{REQ}",
                   "path":"{MIGRATION_DIR}/{CID}.status","uri":"unix:/x"}}"#
            ),
            format!(
                r#"{{"action":"send","generation":"g","request_id":"{REQ}",
                   "path":"/tmp/{CID}.status","uri":"tcp:10.0.0.2:1"}}"#
            ),
            format!(
                r#"{{"action":"manifest","generation":"g","request_id":"{REQ}",
                   "path":"{MIGRATION_DIR}/nova-other.manifest"}}"#
            ),
            format!(
                r#"{{"action":"manifest","generation":"g","request_id":"{REQ}",
                   "path":"{MIGRATION_DIR}/../{CID}.manifest"}}"#
            ),
            format!(r#"{{"action":"cancel","generation":"g","request_id":"{REQ}","x":1}}"#),
        ] {
            assert!(parse(&request(&body)).is_err(), "{}", body);
        }
        let mut two = request(&format!(
            r#"{{"action":"cancel","generation":"g","request_id":"{REQ}"}}"#
        ));
        two.annotations
            .insert("io.katacontainers.volume-update.v1".into(), "{}".into());
        assert!(parse(&two).is_err());
    }

    #[test]
    fn the_generation_is_the_sandboxs() {
        let update = MigrationUpdate {
            action: "cancel".into(),
            generation: "g1".into(),
            request_id: REQ.into(),
            path: None,
            uri: None,
            downtime_ms: None,
            max_bandwidth: None,
        };
        let own = HashMap::from([(GENERATION_KEY.to_string(), "g1".to_string())]);
        validate_generation(&update, &own).unwrap();
        let other = HashMap::from([(GENERATION_KEY.to_string(), "g2".to_string())]);
        assert!(validate_generation(&update, &other).is_err());
        assert!(validate_generation(&update, &HashMap::new()).is_err());
    }
}
