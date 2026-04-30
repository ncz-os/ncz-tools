//! Atomic install-set metadata persisted by `ncz agent install`.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::agent_spec::{Agent, ContainerRuntime, ImageSource, ProfileTarget, SandboxKind};
use crate::error::NczError;
use crate::state::{self, Paths};

pub const INSTALL_SET_SCHEMA_VERSION: u32 = 1;
pub const AGENT_INSTALL_METADATA_SCHEMA_VERSION: u32 = 1;
pub const PENDING_IMAGE_REFERENCE: &str = "pending";
pub const PENDING_IMAGE_DIGEST: &str = "pending";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstallSet {
    pub schema_version: u32,
    pub agents: Vec<AgentInstallMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstallMetadata {
    pub schema_version: u32,
    pub agent: Agent,
    pub profile: ProfileTarget,
    pub runtime: ContainerRuntime,
    pub sandbox: SandboxKind,
    pub installed_at: String,
    pub image_source: ImageSource,
    pub image_reference: String,
    pub image_digest: String,
}

pub fn write_install_set(
    paths: &Paths,
    metadata: Vec<AgentInstallMetadata>,
) -> Result<(), NczError> {
    let path = paths.agent_install_set();
    let install_set = AgentInstallSet {
        schema_version: INSTALL_SET_SCHEMA_VERSION,
        agents: metadata,
    };
    let body = toml::to_string_pretty(&install_set).map_err(|err| {
        NczError::Precondition(format!("could not serialize install set metadata: {err}"))
    })?;
    state::atomic_write(&path, body.as_bytes(), 0o644)
}

pub fn read(paths: &Paths, agent: Agent) -> Result<AgentInstallMetadata, NczError> {
    let path = paths.agent_install_set();
    match fs::metadata(&path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(missing_metadata_error(agent, &path));
        }
        Err(err) => {
            return Err(corrupt_install_set_error(
                &path,
                format!("could not inspect file: {err}"),
            ));
        }
    }
    read_install_set(paths)?
        .agents
        .into_iter()
        .find(|metadata| metadata.agent == agent)
        .ok_or_else(|| missing_metadata_error(agent, &path))
}

pub fn read_all_installed(paths: &Paths) -> Result<Vec<AgentInstallMetadata>, NczError> {
    let path = paths.agent_install_set();
    match fs::metadata(&path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(NczError::Precondition(format!(
                "no agent install metadata found at {}; reinstall with `ncz agent install`",
                path.display()
            )));
        }
        Err(err) => {
            return Err(corrupt_install_set_error(
                &path,
                format!("could not inspect file: {err}"),
            ));
        }
    }
    let install_set = read_install_set(paths)?;
    if install_set.agents.is_empty() {
        return Err(NczError::Precondition(format!(
            "no agent install metadata found in {}; reinstall with `ncz agent install`",
            paths.agent_install_set().display()
        )));
    }
    Ok(install_set.agents)
}

pub fn read_install_set(paths: &Paths) -> Result<AgentInstallSet, NczError> {
    let path = paths.agent_install_set();
    let body = read_install_set_body(&path)?;
    let install_set: AgentInstallSet = toml::from_str(&body)
        .map_err(|err| corrupt_install_set_error(&path, format!("invalid TOML: {err}")))?;
    validate_install_set(&install_set, &path)?;
    Ok(install_set)
}

fn read_install_set_body(path: &Path) -> Result<String, NczError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            return Err(corrupt_install_set_error(path, "path is a directory"));
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(NczError::Precondition(format!(
                "missing install metadata at {}; reinstall with `ncz agent install`",
                path.display()
            )));
        }
        Err(err) => {
            return Err(corrupt_install_set_error(
                path,
                format!("could not inspect file: {err}"),
            ));
        }
    }

    let bytes = fs::read(path)
        .map_err(|err| corrupt_install_set_error(path, format!("could not read file: {err}")))?;
    String::from_utf8(bytes)
        .map_err(|err| corrupt_install_set_error(path, format!("invalid UTF-8: {err}")))
}

fn validate_install_set(install_set: &AgentInstallSet, path: &Path) -> Result<(), NczError> {
    if install_set.schema_version != INSTALL_SET_SCHEMA_VERSION {
        return Err(corrupt_install_set_error(
            path,
            format!(
                "unsupported install-set schema_version {}",
                install_set.schema_version
            ),
        ));
    }

    let mut seen = Vec::new();
    for metadata in &install_set.agents {
        if metadata.schema_version != AGENT_INSTALL_METADATA_SCHEMA_VERSION {
            return Err(corrupt_install_set_error(
                path,
                format!(
                    "unsupported metadata schema_version {} for {}",
                    metadata.schema_version, metadata.agent
                ),
            ));
        }
        if seen.contains(&metadata.agent) {
            return Err(corrupt_install_set_error(
                path,
                format!("duplicate install metadata for {}", metadata.agent),
            ));
        }
        seen.push(metadata.agent);
    }

    Ok(())
}

fn missing_metadata_error(agent: Agent, path: &Path) -> NczError {
    NczError::Precondition(format!(
        "missing install metadata for {agent} in {}; reinstall with `ncz agent install`",
        path.display()
    ))
}

fn corrupt_install_set_error(path: &Path, reason: impl std::fmt::Display) -> NczError {
    NczError::Inconsistent(format!(
        "invalid install metadata at {}: {reason}; reinstall with `ncz agent install`",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths(root: &std::path::Path) -> Paths {
        Paths {
            etc_dir: root.join("etc/nclawzero"),
            quadlet_dir: root.join("etc/containers/systemd"),
            lock_path: root.join("run/nclawzero.lock"),
        }
    }

    fn metadata(agent: Agent) -> AgentInstallMetadata {
        AgentInstallMetadata {
            schema_version: AGENT_INSTALL_METADATA_SCHEMA_VERSION,
            agent,
            profile: ProfileTarget::MacosArm64Docker,
            runtime: ContainerRuntime::Docker,
            sandbox: SandboxKind::OpenShell,
            installed_at: "2026-04-30T00:00:00Z".to_string(),
            image_source: ImageSource::Registry,
            image_reference: PENDING_IMAGE_REFERENCE.to_string(),
            image_digest: PENDING_IMAGE_DIGEST.to_string(),
        }
    }

    #[test]
    fn install_set_roundtrips_as_single_toml_file() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let expected = vec![metadata(Agent::Hermes)];

        write_install_set(&paths, expected.clone()).unwrap();

        let body = fs::read_to_string(paths.agent_install_set()).unwrap();
        assert!(body.contains("schema_version = 1"));
        assert!(body.contains("[[agents]]"));
        assert!(body.contains("agent = \"hermes\""));
        assert!(body.contains("runtime = \"docker\""));
        assert!(body.contains("image_source = \"registry\""));
        assert_eq!(read_all_installed(&paths).unwrap(), expected);
        assert_eq!(read(&paths, Agent::Hermes).unwrap(), expected[0]);
    }

    #[test]
    fn missing_metadata_mentions_reinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());

        let err = read(&paths, Agent::Zeroclaw).unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("missing install metadata")
                    && message.contains("reinstall with `ncz agent install`")
        ));
    }

    #[test]
    fn missing_agent_in_install_set_mentions_reinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        write_install_set(&paths, vec![metadata(Agent::Hermes)]).unwrap();

        let err = read(&paths, Agent::Zeroclaw).unwrap_err();

        assert!(matches!(
            err,
            NczError::Precondition(message)
                if message.contains("missing install metadata for zeroclaw")
                    && message.contains("install-set.toml")
                    && message.contains("reinstall with `ncz agent install`")
        ));
    }

    #[test]
    fn non_utf8_install_set_reports_inconsistent_reinstall_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        fs::create_dir_all(paths.agent_config_dir()).unwrap();
        fs::write(paths.agent_install_set(), [0xff, 0xfe]).unwrap();

        let err = read_all_installed(&paths).unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message)
                if message.contains("invalid install metadata")
                    && message.contains("invalid UTF-8")
                    && message.contains("reinstall with `ncz agent install`")
        ));
    }

    #[test]
    fn directory_at_install_set_reports_inconsistent_reinstall_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        fs::create_dir_all(paths.agent_install_set()).unwrap();

        let err = read_all_installed(&paths).unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message)
                if message.contains("invalid install metadata")
                    && message.contains("path is a directory")
                    && message.contains("reinstall with `ncz agent install`")
        ));
    }

    #[test]
    fn malformed_toml_install_set_reports_inconsistent_reinstall_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        fs::create_dir_all(paths.agent_config_dir()).unwrap();
        fs::write(paths.agent_install_set(), "not = [valid").unwrap();

        let err = read_all_installed(&paths).unwrap_err();

        assert!(matches!(
            err,
            NczError::Inconsistent(message)
                if message.contains("invalid install metadata")
                    && message.contains("invalid TOML")
                    && message.contains("reinstall with `ncz agent install`")
        ));
    }

    #[test]
    fn partial_tempfile_write_crash_does_not_change_authoritative_install_set() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let expected = vec![
            metadata(Agent::Zeroclaw),
            metadata(Agent::Openclaw),
            metadata(Agent::Hermes),
        ];
        write_install_set(&paths, expected.clone()).unwrap();
        fs::write(
            paths.agent_config_dir().join(".install-set.toml.partial"),
            "schema_version = 1\n[[agents",
        )
        .unwrap();

        assert_eq!(read_all_installed(&paths).unwrap(), expected);
    }

    #[test]
    fn stale_legacy_per_agent_metadata_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(tmp.path());
        let expected = vec![metadata(Agent::Hermes)];
        write_install_set(&paths, expected.clone()).unwrap();

        let stale_path = paths
            .agent_config_dir()
            .join("zeroclaw")
            .join("install-metadata.toml");
        fs::create_dir_all(stale_path.parent().unwrap()).unwrap();
        fs::write(
            stale_path,
            "agent = \"zeroclaw\"\nruntime = \"docker\"\nimage_digest = \"stale\"\n",
        )
        .unwrap();

        assert_eq!(read_all_installed(&paths).unwrap(), expected);
        assert!(matches!(
            read(&paths, Agent::Zeroclaw),
            Err(NczError::Precondition(message))
                if message.contains("missing install metadata for zeroclaw")
        ));
    }
}
