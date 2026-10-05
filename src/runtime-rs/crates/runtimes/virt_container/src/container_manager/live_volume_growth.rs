// SPDX-License-Identifier: Apache-2.0
use anyhow::{bail, Context, Result};
use common::types::UpdateRequest;
use serde::Deserialize;
use super::live_volume::{BlockAttach, UPDATE_KEY};

pub const GROW_KEY: &str = "io.katacontainers.volume-update.v2";

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrowthRequest {
    pub attachment: BlockAttach,
    pub request_id: String,
    pub requested_bytes: u64,
}

pub struct PendingGrowth {
    pub request: GrowthRequest,
    pub complete: bool,
}

pub fn parse(req: &UpdateRequest) -> Result<Option<GrowthRequest>> {
    let Some(text) = req.annotations.get(GROW_KEY) else { return Ok(None); };
    if req.annotations.keys().filter(|k| k.starts_with("io.katacontainers.volume-update.")).count() != 1
        || (!req.value.is_empty() && req.value != b"{}") || text.len() > 8192 {
        bail!("volume_update_invalid: mixed or oversized growth request");
    }
    let value: GrowthRequest = serde_json::from_str(text).context("volume_update_invalid: growth")?;
    let id = uuid::Uuid::parse_str(&value.request_id).context("volume_update_invalid: growth ID")?;
    if id.to_string() != value.request_id || value.request_id == value.attachment.request_id
        || value.attachment.action != "attach" || value.attachment.readonly
        || value.requested_bytes == 0 || value.requested_bytes > i64::MAX as u64
        || value.requested_bytes % 512 != 0 {
        bail!("volume_update_invalid: growth identity, mode or capacity");
    }
    let body: serde_json::Value = serde_json::from_str(text)?;
    let original = UpdateRequest { container_id: req.container_id.clone(), value: vec![],
        annotations: std::collections::HashMap::from([
            (UPDATE_KEY.to_string(), serde_json::to_string(&body["attachment"])?)]) };
    super::live_volume::parse(&original)?.context("volume_update_invalid: missing attachment")?;
    Ok(Some(value))
}

pub fn validate_history(request: &GrowthRequest,
    history: &std::collections::HashMap<String, PendingGrowth>) -> Result<()> {
    for (id, prior) in history {
        if id == &request.request_id && prior.request != *request {
            bail!("volume_update_conflict: growth request ID reused");
        }
        if prior.request.attachment.request_id == request.attachment.request_id {
            if id != &request.request_id && !prior.complete {
                bail!("volume_update_pending: previous growth must be reconciled");
            }
            if prior.request.requested_bytes > request.requested_bytes {
                bail!("volume_update_conflict: stale growth request");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path="live_volume_growth_tests.rs"]
mod tests;
