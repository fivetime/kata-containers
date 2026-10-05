// SPDX-License-Identifier: Apache-2.0
use rustjail::live_block_device::{create_block_node, pin_workload_dev, BlockDeviceNodes};
use std::{ffi::CString, io::{BufRead, BufReader, Read, Write}, fs::{self, File}, os::unix::fs::{symlink, MetadataExt}, process::{Command, Stdio}};

fn main() {
    if let Some(root) = std::env::args().nth(1) {
        let root = CString::new(root).unwrap();
        assert_eq!(unsafe { libc::chroot(root.as_ptr()) }, 0);
        std::env::set_current_dir("/").unwrap();
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut byte = [0u8];
        std::io::stdin().read_exact(&mut byte).unwrap();
        return;
    }
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_ne!(fs::read_link("/proc/self/ns/mnt").unwrap(),
               fs::read_link("/proc/1/ns/mnt").unwrap());
    let temp = tempfile::tempdir().unwrap();
    let mount = temp.path().join("tmpfs");
    fs::create_dir(&mount).unwrap();
    assert!(Command::new("mount").args(["-t", "tmpfs", "-o", "size=1m,nodev", "tmpfs"])
            .arg(&mount).status().unwrap().success());
    let dev = mount.join("dev");
    fs::create_dir(&dev).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap()).arg(&mount)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready).unwrap();
    assert_eq!(ready, "READY\n");
    let directory = pin_workload_dev(child.id() as i32).unwrap();
    assert!(pin_workload_dev(-1).is_err());
    assert!(pin_workload_dev(0).is_err());
    // The captured directory, not the numeric child PID, addresses later nodes.
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(pin_workload_dev(child.id() as i32).is_err());
    for name in ["", ".", "..", "../escape", "/dev/sdc", "nested/sdc", "bad\0name"] {
        assert!(create_block_node(&directory, name, 240, 0).is_err());
    }
    assert_eq!(fs::read_dir(&dev).unwrap().count(), 0);
    create_block_node(&directory, "sdc", 240, 17).unwrap();
    let first = fs::symlink_metadata(dev.join("sdc")).unwrap();
    assert_eq!(first.mode() & libc::S_IFMT, libc::S_IFBLK);
    assert_eq!(libc::major(first.rdev()), 240);
    assert_eq!(libc::minor(first.rdev()), 17);
    assert_eq!(first.uid(), 0);
    assert_eq!(first.mode() & 0o077, 0);
    assert!(create_block_node(&directory, "sdc", 240, 17).is_err());
    assert!(create_block_node(&directory, "sdc", 240, 18).is_err());
    assert_eq!(fs::symlink_metadata(dev.join("sdc")).unwrap().ino(), first.ino());
    fs::write(dev.join("regular"), b"preserve").unwrap();
    symlink("regular", dev.join("link")).unwrap();
    fs::create_dir(dev.join("subdir")).unwrap();
    for name in ["regular", "link", "subdir"] {
        assert!(create_block_node(&directory, name, 240, 0).is_err());
    }
    assert_eq!(fs::read(dev.join("regular")).unwrap(), b"preserve");
    assert_eq!(fs::read_link(dev.join("link")).unwrap().to_str(), Some("regular"));
    probe_created(&directory, &dev);
    let regular = File::open(dev.join("regular")).unwrap();
    assert!(create_block_node(&regular, "invalid", 240, 0).is_err());
    drop(regular);
    let mut owned = BlockDeviceNodes::default();
    owned.attach(&directory, "request1", "original", "sde", 240, 19).unwrap();
    let identity = fs::symlink_metadata(dev.join("sde")).unwrap().ino();
    owned.attach(&directory, "request1", "original", "sde", 240, 19).unwrap();
    assert_eq!(fs::symlink_metadata(dev.join("sde")).unwrap().ino(), identity);
    assert!(owned.attach(&directory, "request1", "changed", "sde", 240, 19).is_err());
    assert!(owned.attach(&directory, "request1", "original", "sde", 240, 20).is_err());
    assert!(owned.attach(&directory, "request2", "original", "sde", 240, 19).is_err());
    fs::remove_file(dev.join("sde")).unwrap();
    create_block_node(&directory, "sde", 240, 19).unwrap();
    assert!(owned.attach(&directory, "request1", "original", "sde", 240, 19).is_err());
    drop(owned);
    // Replacing the original directory pathname cannot redirect the operation.
    let retained = mount.join("retained");
    fs::rename(&dev, &retained).unwrap();
    fs::create_dir(&dev).unwrap();
    create_block_node(&directory, "sdd", 240, 18).unwrap();
    assert!(retained.join("sdd").exists());
    assert_eq!(fs::read_dir(&dev).unwrap().count(), 0);
    drop(directory);
    assert!(Command::new("umount").arg(&mount).status().unwrap().success());
    println!("PASS init-child root capture, handle after child exit, block node identity, conflicts, symlink/path refusal, directory replacement isolation; no device IO");
}

fn probe_created(directory: &File, dev: &std::path::Path) {
    const ID: &str = "10000000-0000-4000-8000-000000000001";
    const KEY: &str = "io.katacontainers.block-attachments.v1";
    let entry = serde_json::json!({"request_id": ID, "destination": "/dev/sdc"});
    let spec_value = serde_json::json!({"ociVersion":"1.0.2",
        "annotations": {KEY: serde_json::to_string(&vec![entry.clone()]).unwrap()},
        "linux": {"devices": [{"path":"/dev/sdc", "type":"b", "major":240, "minor":17}]}});
    let capture = |value: serde_json::Value| {
        let spec: oci_spec::runtime::Spec = serde_json::from_value(value).unwrap();
        BlockDeviceNodes::capture_created(directory, &spec)
    };
    let mut owned = capture(spec_value.clone()).unwrap();
    let signature = "verified-native-rpc".to_owned();
    assert!(owned.verify_existing(directory, "unknown", &signature, "sdd", 240, 17).is_err());
    assert!(!dev.join("sdd").exists());
    assert!(owned.verify_existing(directory, ID, &signature, "sdc", 240, 99).is_err());
    owned.verify_existing(directory, ID, &signature, "sdc", 240, 17).unwrap();
    assert!(owned.attach(directory, ID, "changed-rpc", "sdc", 240, 17).is_err());
    assert!(!owned.detach_completed(ID, "detach").unwrap());
    assert!(owned.detach_completed("unknown", "detach").is_err());
    assert_eq!(fs::symlink_metadata(dev.join("sdc")).unwrap().rdev(), libc::makedev(240, 17));
    for field in ["major", "minor"] {
        let mut bad = spec_value.clone();
        bad["linux"]["devices"][0][field] = serde_json::json!(999);
        assert!(capture(bad).is_err());
    }
    let mut duplicate = spec_value.clone();
    duplicate["annotations"][KEY] = serde_json::json!(serde_json::to_string(&vec![entry.clone(), entry]).unwrap());
    assert!(capture(duplicate).is_err());
    let mut duplicate_device = spec_value.clone();
    duplicate_device["linux"]["devices"].as_array_mut().unwrap()
        .push(spec_value["linux"]["devices"][0].clone());
    assert!(capture(duplicate_device).is_err());
    for destination in ["/dev/sda", "/dev/vda", "/dev/../sdc", "/dev/link", "/dev/regular", "/dev/sdz"] {
        let mut bad = spec_value.clone();
        bad["annotations"][KEY] = serde_json::json!(serde_json::to_string(&vec![serde_json::json!(
            {"request_id": ID, "destination": destination})]).unwrap());
        bad["linux"]["devices"][0]["path"] = serde_json::json!(destination);
        assert!(capture(bad).is_err());
    }
    for invalid in ["{", "null", "[{}]", "[{} , {}]"] {
        let mut bad = spec_value.clone();
        bad["annotations"][KEY] = serde_json::json!(invalid);
        assert!(capture(bad).is_err());
    }
    for invalid in ["", "not-a-uuid", "10000000-0000-4000-0000-000000000001"] {
        let mut bad = spec_value.clone();
        bad["annotations"][KEY] = serde_json::json!(serde_json::to_string(&vec![serde_json::json!(
            {"request_id": invalid, "destination": "/dev/sdc"})]).unwrap());
        assert!(capture(bad).is_err());
    }
    symlink("sdc", dev.join("sdg")).unwrap();
    fs::write(dev.join("sdh"), b"preserve").unwrap();
    for name in ["sdg", "sdh"] {
        let destination = format!("/dev/{name}");
        let mut bad = spec_value.clone();
        bad["annotations"][KEY] = serde_json::json!(serde_json::to_string(&vec![serde_json::json!(
            {"request_id": ID, "destination": destination})]).unwrap());
        bad["linux"]["devices"][0]["path"] = serde_json::json!(destination);
        assert!(capture(bad).is_err());
    }
    assert_eq!(fs::read(dev.join("sdh")).unwrap(), b"preserve");
    let mut missing = spec_value.clone();
    missing["linux"]["devices"] = serde_json::json!([]);
    assert!(capture(missing).is_err());
    let mut absent = spec_value.clone();
    absent["annotations"] = serde_json::json!({});
    assert!(capture(absent).unwrap().detach_completed(ID, "detach").is_err());
    let mut unknown = spec_value.clone();
    unknown["annotations"]["io.katacontainers.block-attachments.v2"] = serde_json::json!("[]");
    assert!(capture(unknown).is_err());
    // The original O_PATH identity remains retained, even if the same major/minor
    // is recreated under the name. Registration does not authorize that new inode.
    fs::remove_file(dev.join("sdc")).unwrap();
    create_block_node(directory, "sdc", 240, 17).unwrap();
    assert!(owned.attach(directory, ID, &signature, "sdc", 240, 17).is_err());
    println!("PASS created-device capture: resolved identity, duplicates, protocol, missing/changed nodes and replaced inode refusal; no device IO");
}
