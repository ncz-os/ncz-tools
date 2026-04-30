use std::process::Command;

#[test]
fn invalid_argument_exits_with_usage_code() {
    let status = Command::new(env!("CARGO_BIN_EXE_ncz"))
        .arg("--definitely-not-a-real-ncz-arg")
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(1));
}

#[test]
fn backup_create_exclude_volumes_conflicts_with_unsafe_live_volumes() {
    let status = Command::new(env!("CARGO_BIN_EXE_ncz"))
        .args([
            "backup",
            "create",
            "--to",
            "/tmp/x",
            "--exclude-volumes",
            "--unsafe-live-volumes",
        ])
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(1));
}

#[test]
fn agent_install_rejects_relative_image_source_before_persist() {
    let output = Command::new(env!("CARGO_BIN_EXE_ncz"))
        .args([
            "agent",
            "install",
            "--profile",
            "macos-arm64-docker",
            "--variant",
            "single=hermes",
            "--sandbox",
            "naked",
            "--from",
            "fleet-cache=./relative",
            // --dry-run guards against host-state writes if the
            // relative-path parser ever regresses; the parse rejection
            // happens before any persistence step, so dry-run does not
            // mask the assertion under test.
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("usage: image source path must be absolute"));
    assert!(stderr.contains("fleet-cache=/absolute/path"));
}
