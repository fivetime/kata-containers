// SPDX-License-Identifier: Apache-2.0
//
// Front-end QoS of a Nova data volume (openstack-nova-kata ADR-051).
//
// The gateway writes Cinder's front-end QoS specs into the direct volume's
// mountInfo.json metadata as "io.katacontainers.volume.qos.<key>" with
// libvirt's thirteen key names, in bytes or operations per second. They become
// the limits of that one block device. A key or value that is not understood
// is refused, and a VMM refuses every limit it cannot keep: nothing is
// approximated and nothing is silently dropped.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use kata_types::config::hypervisor::RateLimiterConfig;

/// Prefix of the direct-volume metadata keys that carry the limits.
pub const VOLUME_QOS_PREFIX: &str = "io.katacontainers.volume.qos.";

/// QEMU's THROTTLE_VALUE_MAX; no VMM is given a larger limit.
const VOLUME_QOS_VALUE_MAX: u64 = 1_000_000_000_000_000;

/// Limits of one block device, with libvirt's `<iotune>` names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockIoLimits {
    pub total_bytes_sec: Option<u64>,
    pub read_bytes_sec: Option<u64>,
    pub write_bytes_sec: Option<u64>,
    pub total_iops_sec: Option<u64>,
    pub read_iops_sec: Option<u64>,
    pub write_iops_sec: Option<u64>,
    pub total_bytes_sec_max: Option<u64>,
    pub read_bytes_sec_max: Option<u64>,
    pub write_bytes_sec_max: Option<u64>,
    pub total_iops_sec_max: Option<u64>,
    pub read_iops_sec_max: Option<u64>,
    pub write_iops_sec_max: Option<u64>,
    pub size_iops_sec: Option<u64>,
}

impl BlockIoLimits {
    fn slot(&mut self, key: &str) -> Option<&mut Option<u64>> {
        Some(match key {
            "total_bytes_sec" => &mut self.total_bytes_sec,
            "read_bytes_sec" => &mut self.read_bytes_sec,
            "write_bytes_sec" => &mut self.write_bytes_sec,
            "total_iops_sec" => &mut self.total_iops_sec,
            "read_iops_sec" => &mut self.read_iops_sec,
            "write_iops_sec" => &mut self.write_iops_sec,
            "total_bytes_sec_max" => &mut self.total_bytes_sec_max,
            "read_bytes_sec_max" => &mut self.read_bytes_sec_max,
            "write_bytes_sec_max" => &mut self.write_bytes_sec_max,
            "total_iops_sec_max" => &mut self.total_iops_sec_max,
            "read_iops_sec_max" => &mut self.read_iops_sec_max,
            "write_iops_sec_max" => &mut self.write_iops_sec_max,
            "size_iops_sec" => &mut self.size_iops_sec,
            _ => return None,
        })
    }

    /// Every key with its value, in libvirt's order.
    pub fn entries(&self) -> [(&'static str, Option<u64>); 13] {
        [
            ("total_bytes_sec", self.total_bytes_sec),
            ("read_bytes_sec", self.read_bytes_sec),
            ("write_bytes_sec", self.write_bytes_sec),
            ("total_iops_sec", self.total_iops_sec),
            ("read_iops_sec", self.read_iops_sec),
            ("write_iops_sec", self.write_iops_sec),
            ("total_bytes_sec_max", self.total_bytes_sec_max),
            ("read_bytes_sec_max", self.read_bytes_sec_max),
            ("write_bytes_sec_max", self.write_bytes_sec_max),
            ("total_iops_sec_max", self.total_iops_sec_max),
            ("read_iops_sec_max", self.read_iops_sec_max),
            ("write_iops_sec_max", self.write_iops_sec_max),
            ("size_iops_sec", self.size_iops_sec),
        ]
    }

    /// Reads the limits of a direct volume's metadata. `None` when the volume
    /// has none; an error names the first key that is unknown or malformed, or
    /// the limits that contradict each other.
    pub fn from_volume_metadata(metadata: &HashMap<String, String>) -> Result<Option<Self>> {
        let mut limits = BlockIoLimits::default();
        let mut found = false;
        let mut keys: Vec<&String> = metadata
            .keys()
            .filter(|key| key.starts_with(VOLUME_QOS_PREFIX))
            .collect();
        keys.sort();
        for full in keys {
            let key = &full[VOLUME_QOS_PREFIX.len()..];
            let slot = limits
                .slot(key)
                .ok_or_else(|| anyhow!("volume_qos_invalid: unknown key {full}"))?;
            *slot = Some(parse_value(full, &metadata[full])?);
            found = true;
        }
        if !found {
            return Ok(None);
        }
        limits.validate()?;
        Ok(Some(limits))
    }

    /// The rules of libvirt's and QEMU's I/O limits, whatever the VMM.
    fn validate(&self) -> Result<()> {
        for (kind, total, read, write) in [
            (
                "bytes_sec",
                self.total_bytes_sec,
                self.read_bytes_sec,
                self.write_bytes_sec,
            ),
            (
                "iops_sec",
                self.total_iops_sec,
                self.read_iops_sec,
                self.write_iops_sec,
            ),
            (
                "bytes_sec_max",
                self.total_bytes_sec_max,
                self.read_bytes_sec_max,
                self.write_bytes_sec_max,
            ),
            (
                "iops_sec_max",
                self.total_iops_sec_max,
                self.read_iops_sec_max,
                self.write_iops_sec_max,
            ),
        ] {
            if total.is_some() && (read.is_some() || write.is_some()) {
                return Err(anyhow!(
                    "volume_qos_invalid: total_{kind} cannot be combined with read_{kind} or write_{kind}"
                ));
            }
        }
        for (name, base, max) in [
            (
                "total_bytes_sec",
                self.total_bytes_sec,
                self.total_bytes_sec_max,
            ),
            (
                "read_bytes_sec",
                self.read_bytes_sec,
                self.read_bytes_sec_max,
            ),
            (
                "write_bytes_sec",
                self.write_bytes_sec,
                self.write_bytes_sec_max,
            ),
            (
                "total_iops_sec",
                self.total_iops_sec,
                self.total_iops_sec_max,
            ),
            ("read_iops_sec", self.read_iops_sec, self.read_iops_sec_max),
            (
                "write_iops_sec",
                self.write_iops_sec,
                self.write_iops_sec_max,
            ),
        ] {
            match (base, max) {
                (None, Some(_)) => {
                    return Err(anyhow!("volume_qos_invalid: {name}_max requires {name}"))
                }
                (Some(base), Some(max)) if max < base => {
                    return Err(anyhow!(
                        "volume_qos_invalid: {name}_max is lower than {name}"
                    ))
                }
                _ => (),
            }
        }
        Ok(())
    }

    /// The rate limiter of a Cloud Hypervisor or Dragonball disk: one bucket
    /// for bytes from total_bytes_sec, one for operations from total_iops_sec,
    /// each refilled in 1000 ms. Any other key is refused with its name; the
    /// `_max` bursts too, since the VMM's one-time burst is spent once and
    /// never refills as QEMU's burst does.
    pub fn rate_limiter(&self, vmm: &str) -> Result<RateLimiterConfig> {
        let refused: Vec<&str> = self
            .entries()
            .iter()
            .filter(|(key, value)| {
                value.is_some() && *key != "total_bytes_sec" && *key != "total_iops_sec"
            })
            .map(|(key, _)| *key)
            .collect();
        if !refused.is_empty() {
            return Err(anyhow!(
                "volume_qos_unsupported: {vmm} cannot keep {}",
                refused.join(", ")
            ));
        }
        // A bucket of `size` tokens refilled in DEFAULT_RATE_LIMITER_REFILL_TIME
        // (1000 ms) keeps `size` per second.
        RateLimiterConfig::new(
            self.total_bytes_sec.unwrap_or(0),
            self.total_iops_sec.unwrap_or(0),
            None,
            None,
        )
        .ok_or_else(|| anyhow!("volume_qos_invalid: no limit for {vmm}"))
    }
}

/// A positive decimal without sign, spaces or leading zeros, at most
/// QEMU's largest limit.
fn parse_value(key: &str, value: &str) -> Result<u64> {
    let canonical = !value.is_empty()
        && value.len() <= 16
        && value.bytes().all(|b| b.is_ascii_digit())
        && !value.starts_with('0');
    let parsed = if canonical {
        value.parse::<u64>().ok()
    } else {
        None
    };
    match parsed {
        Some(number) if number <= VOLUME_QOS_VALUE_MAX => Ok(number),
        _ => Err(anyhow!(
            "volume_qos_invalid: value of {key} is not a positive integer"
        )),
    }
}

/// A device that VMM gives no limits of its own refuses limits.
pub fn refuse_volume_qos(limits: Option<&BlockIoLimits>, vmm: &str) -> Result<()> {
    match limits {
        Some(limits) => Err(anyhow!(
            "volume_qos_unsupported: {vmm} cannot keep {}",
            limits
                .entries()
                .iter()
                .filter(|(_, value)| value.is_some())
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
                .join(", ")
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod nova_volume_qos_tests {
    use super::*;

    fn metadata(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        let mut map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (format!("{VOLUME_QOS_PREFIX}{k}"), v.to_string()))
            .collect();
        map.insert("openstack.volume_uuid".into(), "x".into());
        map
    }

    #[test]
    fn nova_volume_qos_absent_is_none() {
        let mut map = HashMap::new();
        map.insert("openstack.generation".to_string(), "7".to_string());
        assert_eq!(BlockIoLimits::from_volume_metadata(&map).unwrap(), None);
    }

    #[test]
    fn nova_volume_qos_all_thirteen_keys() {
        let limits = BlockIoLimits::from_volume_metadata(&metadata(&[
            ("read_bytes_sec", "1000"),
            ("write_bytes_sec", "2000"),
            ("read_iops_sec", "10"),
            ("write_iops_sec", "20"),
            ("read_bytes_sec_max", "1500"),
            ("write_bytes_sec_max", "2500"),
            ("read_iops_sec_max", "15"),
            ("write_iops_sec_max", "25"),
            ("size_iops_sec", "4096"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(limits.read_bytes_sec, Some(1000));
        assert_eq!(limits.write_iops_sec_max, Some(25));
        assert_eq!(limits.size_iops_sec, Some(4096));
        assert_eq!(limits.total_bytes_sec, None);
        let totals = BlockIoLimits::from_volume_metadata(&metadata(&[
            ("total_bytes_sec", "1048576"),
            ("total_iops_sec", "100"),
            ("total_bytes_sec_max", "2097152"),
            ("total_iops_sec_max", "150"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(
            totals.entries().iter().filter(|(_, v)| v.is_some()).count(),
            4
        );
    }

    #[test]
    fn nova_volume_qos_refuses_unknown_key_and_bad_values() {
        assert!(
            BlockIoLimits::from_volume_metadata(&metadata(&[("total_bytes", "1")]))
                .unwrap_err()
                .to_string()
                .contains("unknown key io.katacontainers.volume.qos.total_bytes")
        );
        for bad in [
            "",
            "0",
            "-1",
            "+5",
            " 5",
            "5 ",
            "1.5",
            "1e3",
            "0x10",
            "007",
            "abc",
            "1000000000000001",
            "99999999999999999999",
        ] {
            let error = BlockIoLimits::from_volume_metadata(&metadata(&[("total_iops_sec", bad)]))
                .unwrap_err()
                .to_string();
            assert!(
                error.starts_with("volume_qos_invalid: value of"),
                "{}: {}",
                bad,
                error
            );
        }
        assert_eq!(
            BlockIoLimits::from_volume_metadata(&metadata(&[(
                "total_iops_sec",
                "1000000000000000"
            )]))
            .unwrap()
            .unwrap()
            .total_iops_sec,
            Some(VOLUME_QOS_VALUE_MAX)
        );
    }

    #[test]
    fn nova_volume_qos_refuses_contradictions() {
        for pairs in [
            &[("total_bytes_sec", "10"), ("read_bytes_sec", "5")][..],
            &[("total_iops_sec", "10"), ("write_iops_sec", "5")][..],
            &[("total_bytes_sec_max", "10")][..],
            &[("read_iops_sec_max", "10")][..],
            &[("total_iops_sec", "10"), ("total_iops_sec_max", "9")][..],
            &[("write_bytes_sec", "10"), ("write_bytes_sec_max", "5")][..],
            &[
                ("total_bytes_sec", "10"),
                ("total_bytes_sec_max", "20"),
                ("read_bytes_sec_max", "20"),
            ][..],
        ] {
            let error = BlockIoLimits::from_volume_metadata(&metadata(pairs)).unwrap_err();
            assert!(
                error.to_string().starts_with("volume_qos_invalid:"),
                "{:?}",
                pairs
            );
        }
    }

    #[test]
    fn nova_volume_qos_rate_limiter_buckets() {
        let limits = BlockIoLimits::from_volume_metadata(&metadata(&[
            ("total_bytes_sec", "1048576"),
            ("total_iops_sec", "100"),
        ]))
        .unwrap()
        .unwrap();
        let config = limits.rate_limiter("cloud-hypervisor").unwrap();
        let bandwidth = config.bandwidth.unwrap();
        assert_eq!(
            (
                bandwidth.size,
                bandwidth.one_time_burst,
                bandwidth.refill_time
            ),
            (1048576, None, 1000)
        );
        let ops = config.ops.unwrap();
        assert_eq!(
            (ops.size, ops.one_time_burst, ops.refill_time),
            (100, None, 1000)
        );
        let ops_only = BlockIoLimits {
            total_iops_sec: Some(5),
            ..Default::default()
        };
        let config = ops_only.rate_limiter("dragonball").unwrap();
        assert_eq!(config.bandwidth, None);
        assert_eq!(config.ops.unwrap().size, 5);
    }

    #[test]
    fn nova_volume_qos_rate_limiter_refuses_what_it_cannot_keep() {
        for (key, value) in [
            ("read_bytes_sec", "1"),
            ("write_bytes_sec", "1"),
            ("read_iops_sec", "1"),
            ("write_iops_sec", "1"),
            ("size_iops_sec", "4096"),
            ("total_iops_sec_max", "200"),
        ] {
            let limits = BlockIoLimits::from_volume_metadata(&metadata(&[
                ("total_iops_sec", "100"),
                (key, value),
            ]));
            // read_/write_ iops beside total_iops_sec is itself a contradiction.
            let Ok(Some(limits)) = limits else { continue };
            let error = limits.rate_limiter("dragonball").unwrap_err().to_string();
            assert_eq!(
                error,
                format!("volume_qos_unsupported: dragonball cannot keep {key}")
            );
        }
        let limits = BlockIoLimits {
            read_bytes_sec: Some(1),
            write_iops_sec: Some(2),
            write_iops_sec_max: Some(3),
            ..Default::default()
        };
        assert_eq!(
            limits.rate_limiter("cloud-hypervisor").unwrap_err().to_string(),
            "volume_qos_unsupported: cloud-hypervisor cannot keep read_bytes_sec, write_iops_sec, write_iops_sec_max"
        );
        assert!(refuse_volume_qos(None, "firecracker").is_ok());
        assert_eq!(
            refuse_volume_qos(Some(&limits), "firecracker").unwrap_err().to_string(),
            "volume_qos_unsupported: firecracker cannot keep read_bytes_sec, write_iops_sec, write_iops_sec_max"
        );
    }
}
